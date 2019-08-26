/* load a GIF with giflib
 *
 * 10/2/16
 * 	- from svgload.c
 * 25/4/16
 * 	- add giflib5 support
 * 26/7/16
 * 	- transparency was wrong if there was no EXTENSION_RECORD
 * 	- write 1, 2, 3, or 4 bands depending on file contents
 * 17/8/16
 * 	- support unicode on win
 * 19/8/16
 * 	- better transparency detection, thanks diegocsandrim
 * 25/11/16
 * 	- support @n, page-height
 * 5/10/17
 * 	- colormap can be missing thanks Kleis
 * 21/11/17
 * 	- add "gif-delay", "gif-loop", "gif-comment" metadata
 * 	- add dispose handling
 * 13/8/18
 * 	- init pages to 0 before load
 * 14/2/19
 * 	- rework as a sequential loader ... simpler, much lower mem use
 * 23/8/18
 * 	- allow GIF read errors during header scan
 * 	- better feof() handling
 */

/*

    This file is part of VIPS.
    
    VIPS is free software; you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
    02110-1301  USA

 */

/*

    These files are distributed with VIPS - http://www.vips.ecs.soton.ac.uk

 */

/*
#define DEBUG_VERBOSE
#define VIPS_DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>

#include <vips/vips.h>
#include <vips/buf.h>
#include <vips/internal.h>
#include <vips/debug.h>

#ifdef HAVE_GIFLIB

#include <gif_lib.h>

/* giflib 5 is rather different :-( functions have error returns and there's
 * no LastError().
 *
 * GIFLIB_MAJOR was introduced in 4.1.6. Use it to test for giflib 5.x.
 */
#ifdef GIFLIB_MAJOR
#  if GIFLIB_MAJOR > 4
#    define HAVE_GIFLIB_5
#  endif
#endif

/* Added in giflib5.
 */
#ifndef HAVE_GIFLIB_5
#define DISPOSAL_UNSPECIFIED      0       
#define DISPOSE_DO_NOT            1      
#define DISPOSE_BACKGROUND        2     
#define DISPOSE_PREVIOUS          3    
#endif

#define VIPS_TYPE_FOREIGN_LOAD_GIF (vips_foreign_load_gif_get_type())
#define VIPS_FOREIGN_LOAD_GIF( obj ) \
	(G_TYPE_CHECK_INSTANCE_CAST( (obj), \
	VIPS_TYPE_FOREIGN_LOAD_GIF, VipsForeignLoadGif ))
#define VIPS_FOREIGN_LOAD_GIF_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_CAST( (klass), \
	VIPS_TYPE_FOREIGN_LOAD_GIF, VipsForeignLoadGifClass))
#define VIPS_IS_FOREIGN_LOAD_GIF( obj ) \
	(G_TYPE_CHECK_INSTANCE_TYPE( (obj), VIPS_TYPE_FOREIGN_LOAD_GIF ))
#define VIPS_IS_FOREIGN_LOAD_GIF_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_TYPE( (klass), VIPS_TYPE_FOREIGN_LOAD_GIF ))
#define VIPS_FOREIGN_LOAD_GIF_GET_CLASS( obj ) \
	(G_TYPE_INSTANCE_GET_CLASS( (obj), \
	VIPS_TYPE_FOREIGN_LOAD_GIF, VipsForeignLoadGifClass ))

typedef struct _VipsForeignLoadGif {
	VipsForeignLoad parent_object;

	/* Load from this page (frame number).
	 */
	int page;

	/* Load this many pages.
	 */
	int n;

	GifFileType *file;

	/* We decompress the whole thing to a huge RGBA memory image, and
	 * as we render, watch for bands and transparency. At the end of
	 * loading, we copy 1 or 3 bands, with or without transparency to
	 * output.
	 */
	gboolean has_transparency;
	gboolean has_colour;

	/* Delay in 1/100ths of a second. We only track a single delay 
	 * value for the whole file, and we report the first delay we see. Some
	 * GIFs have a long delay on the final frame.
	 */
	gboolean has_delay;
	int delay;

	/* Number of times to loop the animation.
	 */
	int loop;

	/* The GIF comment, if any.
	 */
	char *comment; 

	/* The number of pages (frame) in the image.
	 */
	int n_pages;

	/* A memory image the sized of one frame ... we accumulate to this as
	 * we scan the image, and copy lines to the output on generate.
	 */
	VipsImage *frame;

	/* A copy of the previous frame, in case we need a DISPOSE_PREVIOUS.
	 */
	VipsImage *previous;

	/* The position of @frame, in pages.
	 */
	int current_page;

	/* Decompress lines of the gif file to here.
	 */
	GifPixelType *line;

	/* The current dispose method.
	 */
	int dispose;

	/* Set for EOF detected.
	 */
	gboolean eof;

	/* The current cmap unpacked to a simple LUT. Each uint32 is really an
	 * RGBA pixel ready to be blasted into @frame.
	 */
	guint32 cmap[256];

	/* As we scan the file, the index of the transparent pixel for this
	 * frame.
	 */
	int transparency;

	/* Params for DGifOpen(). Set by subclasses, called by base class in
	 * _open().
	 */
	InputFunc read_func;

} VipsForeignLoadGif;

typedef struct _VipsForeignLoadGifClass {
	VipsForeignLoadClass parent_class;

	/* Close and reopen gif->file.
	 */
	int (*open)( VipsForeignLoadGif *gif );
} VipsForeignLoadGifClass;

G_DEFINE_ABSTRACT_TYPE( VipsForeignLoadGif, vips_foreign_load_gif, 
	VIPS_TYPE_FOREIGN_LOAD );

/* From gif2rgb.c ... offsets and jumps for interlaced GIF images.
 */
static int 
	InterlacedOffset[] = { 0, 4, 2, 1 },
	InterlacedJumps[] = { 8, 8, 4, 2 };

/* giflib4 was missing this.
 */
static const char *
vips_foreign_load_gif_errstr( int error_code )
{
#ifdef HAVE_GIFLIB_5
	return( GifErrorString( error_code ) ); 
#else /*!HAVE_GIFLIB_5*/
	switch( error_code ) {
	case D_GIF_ERR_OPEN_FAILED:
		return( _( "Failed to open given file" ) ); 

	case D_GIF_ERR_READ_FAILED:
		return( _( "Failed to read from given file" ) ); 

	case D_GIF_ERR_NOT_GIF_FILE:
		return( _( "Data is not a GIF file" ) ); 

	case D_GIF_ERR_NO_SCRN_DSCR:
		return( _( "No screen descriptor detected" ) ); 

	case D_GIF_ERR_NO_IMAG_DSCR:
		return( _( "No image descriptor detected" ) ); 

	case D_GIF_ERR_NO_COLOR_MAP:
		return( _( "Neither global nor local color map" ) ); 

	case D_GIF_ERR_WRONG_RECORD:
		return( _( "Wrong record type detected" ) ); 

	case D_GIF_ERR_DATA_TOO_BIG:
		return( _( "Number of pixels bigger than width * height" ) ); 

	case D_GIF_ERR_NOT_ENOUGH_MEM:
		return( _( "Failed to allocate required memory" ) ); 

	case D_GIF_ERR_CLOSE_FAILED:
		return( _( "Failed to close given file" ) ); 

	case D_GIF_ERR_NOT_READABLE:
		return( _( "Given file was not opened for read" ) ); 

	case D_GIF_ERR_IMAGE_DEFECT:
		return( _( "Image is defective, decoding aborted" ) ); 

	case D_GIF_ERR_EOF_TOO_SOON:
		return( _( "Image EOF detected, before image complete" ) ); 

	default:
		return( _( "Unknown error" ) ); 
	}
#endif /*HAVE_GIFLIB_5*/
}

static void
vips_foreign_load_gif_error_vips( VipsForeignLoadGif *gif, int error )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( gif );

	const char *message;

	if( (message = vips_foreign_load_gif_errstr( error )) )
		vips_error( class->nickname, "%s", message ); 
}

static void
vips_foreign_load_gif_error( VipsForeignLoadGif *gif )
{
	int error;

	error = 0;

#ifdef HAVE_GIFLIB_5
	if( gif->file ) 
		error = gif->file->Error;
#else 
	error = GifLastError(); 
#endif

	if( error ) 
		vips_foreign_load_gif_error_vips( gif, error ); 
}

static void
vips_foreign_load_gif_close( VipsForeignLoadGif *gif )
{
#ifdef HAVE_GIFLIB_5
	if( gif->file ) {
		int error; 

		if( DGifCloseFile( gif->file, &error ) == GIF_ERROR ) 
			vips_foreign_load_gif_error_vips( gif, error );
		gif->file = NULL;
	}
#else 
	if( gif->file ) {
		if( DGifCloseFile( gif->file ) == GIF_ERROR ) 
			vips_foreign_load_gif_error_vips( gif, GifLastError() ); 
		gif->file = NULL;
	}
#endif
}

static void
vips_foreign_load_gif_dispose( GObject *gobject )
{
	VipsForeignLoadGif *gif = (VipsForeignLoadGif *) gobject;

	vips_foreign_load_gif_close( gif ); 

	VIPS_UNREF( gif->frame ); 
	VIPS_UNREF( gif->previous ); 
	VIPS_FREE( gif->comment ); 
	VIPS_FREE( gif->line ) 

	G_OBJECT_CLASS( vips_foreign_load_gif_parent_class )->
		dispose( gobject );
}

static VipsForeignFlags
vips_foreign_load_gif_get_flags_filename( const char *filename )
{
	return( VIPS_FOREIGN_SEQUENTIAL );
}

static VipsForeignFlags
vips_foreign_load_gif_get_flags( VipsForeignLoad *load )
{
	return( VIPS_FOREIGN_SEQUENTIAL );
}

static gboolean
vips_foreign_load_gif_is_a_buffer( const void *buf, size_t len )
{
	const guchar *str = (const guchar *) buf;

	if( len >= 4 &&
		str[0] == 'G' && 
		str[1] == 'I' &&
		str[2] == 'F' &&
		str[3] == '8' )
		return( 1 );

	return( 0 );
}

static gboolean
vips_foreign_load_gif_is_a( const char *filename )
{
	unsigned char buf[4];

	if( vips__get_bytes( filename, buf, 4 ) == 4 &&
		vips_foreign_load_gif_is_a_buffer( buf, 4 ) )
		return( 1 );

	return( 0 );
}

static int
vips_foreign_load_gif_ext_next( VipsForeignLoadGif *gif, 
	GifByteType **extension )
{
	if( DGifGetExtensionNext( gif->file, extension ) == GIF_ERROR ) {
		vips_foreign_load_gif_error( gif ); 
		return( -1 ); 
	}

	if( *extension ) 
		VIPS_DEBUG_MSG( "gifload: EXTENSION_NEXT\n" ); 

	return( 0 );
}

static int
vips_foreign_load_gif_code_next( VipsForeignLoadGif *gif, 
	GifByteType **extension )
{
	if( DGifGetCodeNext( gif->file, extension ) == GIF_ERROR ) {
		vips_foreign_load_gif_error( gif ); 
		return( -1 ); 
	}

	if( *extension ) 
		VIPS_DEBUG_MSG( "gifload: CODE_NEXT\n" ); 

	return( 0 );
}

/* Quickly scan an image record.
 */
static int
vips_foreign_load_gif_scan_image( VipsForeignLoadGif *gif ) 
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( gif );
	GifFileType *file = gif->file;
	ColorMapObject *map = file->Image.ColorMap ?
		file->Image.ColorMap : file->SColorMap;

	GifByteType *extension;

	if( DGifGetImageDesc( gif->file ) == GIF_ERROR ) {
		vips_foreign_load_gif_error( gif ); 
		return( -1 );
	}

	/* Check that the frame looks sane. Perhaps giflib checks
	 * this for us.
	 */
	if( file->Image.Left < 0 ||
		file->Image.Width < 1 ||
		file->Image.Width > 10000 ||
		file->Image.Left + file->Image.Width > file->SWidth ||
		file->Image.Top < 0 ||
		file->Image.Height < 1 ||
		file->Image.Height > 10000 ||
		file->Image.Top + file->Image.Height > file->SHeight ) {
		vips_error( class->nickname, "%s", _( "bad frame size" ) ); 
		return( -1 ); 
	}

	/* Test for a non-greyscale colourmap for this frame.
	 */
	if( !gif->has_colour &&
		map ) {
		int i;

		for( i = 0; i < map->ColorCount; i++ ) 
			if( map->Colors[i].Red != map->Colors[i].Green ||
				map->Colors[i].Green != map->Colors[i].Blue ) {
				gif->has_colour = TRUE;
				break;
			}
	}

	/* Step over compressed image data.
	 */
	do {
		if( vips_foreign_load_gif_code_next( gif, &extension ) ) 
			return( -1 );
	} while( extension != NULL );

	return( 0 );
}

static int
vips_foreign_load_gif_scan_application_ext( VipsForeignLoadGif *gif,
	GifByteType *extension )
{
	gboolean have_netscape;

	/* The 11-byte NETSCAPE extension.
	 */
	have_netscape = FALSE;
	if( extension[0] == 11 &&
		vips_isprefix( "NETSCAPE2.0", (const char*) (extension + 1) ) ) 
		have_netscape = TRUE;

	while( extension != NULL ) {
		if( vips_foreign_load_gif_ext_next( gif, &extension ) )
			return( -1 ); 

		if( have_netscape &&
			extension &&
			extension[0] == 3 &&
			extension[1] == 1 ) 
			gif->loop = extension[2] | (extension[3] << 8);
	}

	return( 0 );
}

static int
vips_foreign_load_gif_scan_comment_ext( VipsForeignLoadGif *gif,
	GifByteType *extension )
{
	VIPS_DEBUG_MSG( "gifload: type: comment\n" ); 

	if( !gif->comment ) { 
		/* Up to 257 with a NULL terminator.
		 */
		char comment[257];

		vips_strncpy( comment, (char *) (extension + 1), 256 );
		comment[extension[0]] = '\0';
		gif->comment = g_strdup( comment ); 
	}

	while( extension != NULL ) 
		if( vips_foreign_load_gif_ext_next( gif, &extension ) )
			return( -1 ); 

	return( 0 );
}

static int
vips_foreign_load_gif_scan_extension( VipsForeignLoadGif *gif )
{
	GifByteType *extension;
	int ext_code;

	if( DGifGetExtension( gif->file, &ext_code, &extension ) == 
		GIF_ERROR ) {
		vips_foreign_load_gif_error( gif ); 
		return( -1 ); 
	}

	if( extension ) 
		switch( ext_code ) { 
		case GRAPHICS_EXT_FUNC_CODE: 
			if( extension[0] == 4 &&
				extension[1] & 0x1 ) {
				VIPS_DEBUG_MSG( "gifload: has transp.\n" ); 
				gif->has_transparency = TRUE;
			}

			if( !gif->has_delay ) { 
				VIPS_DEBUG_MSG( "gifload: has delay\n" ); 
				gif->has_delay = TRUE;
				gif->delay = extension[2] | (extension[3] << 8);
			}

			while( extension != NULL ) 
				if( vips_foreign_load_gif_ext_next( gif, 
					&extension ) )
					return( -1 ); 

			break;

		case APPLICATION_EXT_FUNC_CODE: 
			if( vips_foreign_load_gif_scan_application_ext( gif, 
				extension ) )
				return( -1 ); 
			break;

		case COMMENT_EXT_FUNC_CODE:
			if( vips_foreign_load_gif_scan_comment_ext( gif, 
				extension ) )
				return( -1 ); 
			break;

		default:
			/* Step over any NEXT blocks for unknown extensions.
			 */
			while( extension != NULL ) 
				if( vips_foreign_load_gif_ext_next( gif, 
					&extension ) )
					return( -1 ); 
			break;
		}

	return( 0 );
}

static int
vips_foreign_load_gif_set_header( VipsForeignLoadGif *gif, VipsImage *image )
{
	vips_image_init_fields( image,
		gif->file->SWidth, gif->file->SHeight * gif->n, 
		(gif->has_colour ? 3 : 1) + (gif->has_transparency ? 1 : 0),
		VIPS_FORMAT_UCHAR, VIPS_CODING_NONE,
		gif->has_colour ? 
		 	VIPS_INTERPRETATION_sRGB : VIPS_INTERPRETATION_B_W,
		1.0, 1.0 );
	vips_image_pipelinev( image, VIPS_DEMAND_STYLE_FATSTRIP, NULL );

	if( vips_object_argument_isset( VIPS_OBJECT( gif ), "n" ) )
		vips_image_set_int( image, 
			VIPS_META_PAGE_HEIGHT, gif->file->SHeight );
	vips_image_set_int( image, VIPS_META_N_PAGES, gif->n_pages );
	vips_image_set_int( image, "gif-delay", gif->delay );
	vips_image_set_int( image, "gif-loop", gif->loop );
	if( gif->comment ) 
		vips_image_set_string( image, "gif-comment", gif->comment );

	return( 0 );
}

/* Attempt to quickly scan a GIF and discover what we need for our header. We
 * need to scan the whole file to get n_pages, transparency and colour. 
 *
 * Don't flag errors during header scan. Many GIFs do not follow spec.
 */
static int
vips_foreign_load_gif_header( VipsForeignLoad *load )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( load );
	VipsForeignLoadGifClass *gif_class = 
		(VipsForeignLoadGifClass *) VIPS_OBJECT_GET_CLASS( load );
	VipsForeignLoadGif *gif = (VipsForeignLoadGif *) load;

	GifRecordType record;

	if( gif_class->open( gif ) )
		return( -1 );

	gif->n_pages = 0;

	do {
		if( DGifGetRecordType( gif->file, &record ) == GIF_ERROR ) 
			continue;

		switch( record ) {
		case IMAGE_DESC_RECORD_TYPE:
			(void) vips_foreign_load_gif_scan_image( gif );

			gif->n_pages += 1;

			break;

		case EXTENSION_RECORD_TYPE:
			/* We will need to fetch the extensions to check for
			 * cmaps and transparency.
			 */
			(void) vips_foreign_load_gif_scan_extension( gif );
			break;

		case TERMINATE_RECORD_TYPE:
			gif->eof = TRUE;
			break;

		case SCREEN_DESC_RECORD_TYPE:
		case UNDEFINED_RECORD_TYPE:
			break;

		default:
			break;
		}
	} while( !gif->eof );

	if( gif->n == -1 )
		gif->n = gif->n_pages - gif->page;

	if( gif->page < 0 ||
		gif->n <= 0 ||
		gif->page + gif->n > gif->n_pages ) {
		vips_error( class->nickname, "%s", _( "bad page number" ) ); 
		return( -1 ); 
	}

	/* And set the output vips header from what we've learned.
	 */
	if( vips_foreign_load_gif_set_header( gif, load->out ) )
		return( -1 );

	return( 0 );
}

static void
vips_foreign_load_gif_build_cmap( VipsForeignLoadGif *gif )
{
	ColorMapObject *map = gif->file->Image.ColorMap ?
		gif->file->Image.ColorMap : gif->file->SColorMap;

	int v;

	for( v = 0; v < 256; v++ ) {
		VipsPel *q = (VipsPel *) &gif->cmap[v];

		if( map &&
			v < map->ColorCount ) {
			q[0] = map->Colors[v].Red;
			q[1] = map->Colors[v].Green;
			q[2] = map->Colors[v].Blue;
			q[3] = 255;
		}
		else {
			/* If there's no map, just save the index.
			 */
			q[0] = v;
			q[1] = v;
			q[2] = v;
			q[3] = 255;
		}
	}
}

static void
vips_foreign_load_gif_render_line( VipsForeignLoadGif *gif,
	int width, VipsPel * restrict q, VipsPel * restrict p )
{
	guint32 *iq;
	int x;

	iq = (guint32 *) q;
	for( x = 0; x < width; x++ ) {
		VipsPel v = p[x];
		
		if( v == gif->transparency ) {
			/* In DISPOSE_DO_NOT mode, the previous frame shows
			 * through (ie. we do nothing). In all other modes, 
			 * it's just transparent.
			 */
			if( gif->dispose != DISPOSE_DO_NOT ) 
				iq[x] = 0;
		}
		else
			/* Blast in the RGBA for this value.
			 */
			iq[x] = gif->cmap[v];
	}
}

/* Render the current gif frame into an RGBA buffer. GIFs can accumulate, 
 * depending on the current dispose mode.
 */
static int
vips_foreign_load_gif_render( VipsForeignLoadGif *gif ) 
{
	GifFileType *file = gif->file;

	/* Update the colour map for this frame.
	 */
	vips_foreign_load_gif_build_cmap( gif );

	/* BACKGROUND means we reset the frame to 0 (transparent) before we 
	 * render the next set of pixels.
	 */
	if( gif->dispose == DISPOSE_BACKGROUND ) 
		memset( VIPS_IMAGE_ADDR( gif->frame, 0, 0 ), 0, 
			VIPS_IMAGE_SIZEOF_IMAGE( gif->frame ) );

	/* PREVIOUS means we init the frame with the frame before last, ie. we
	 * undo the last render.
	 *
	 * Anything other than PREVIOUS, we must update the previous buffer,
	 */
	if( gif->dispose == DISPOSE_PREVIOUS ) 
		memcpy( VIPS_IMAGE_ADDR( gif->frame, 0, 0 ),
			VIPS_IMAGE_ADDR( gif->previous, 0, 0 ),
			VIPS_IMAGE_SIZEOF_IMAGE( gif->frame ) );
	else 
		memcpy( VIPS_IMAGE_ADDR( gif->previous, 0, 0 ),
			VIPS_IMAGE_ADDR( gif->frame, 0, 0 ),
			VIPS_IMAGE_SIZEOF_IMAGE( gif->frame ) );

	if( file->Image.Interlace ) {
		int i;

		VIPS_DEBUG_MSG( "vips_foreign_load_gif_render: "
			"interlaced frame of %d x %d pixels at %d x %d\n",
			file->Image.Width, file->Image.Height,
			file->Image.Left, file->Image.Top ); 

		for( i = 0; i < 4; i++ ) {
			int y;

			for( y = InterlacedOffset[i]; 
				y < file->Image.Height;
			  	y += InterlacedJumps[i] ) {
				VipsPel *q = VIPS_IMAGE_ADDR( gif->frame, 
					file->Image.Left, file->Image.Top + y );

				if( DGifGetLine( gif->file, gif->line, 
					file->Image.Width ) == GIF_ERROR ) {
					vips_foreign_load_gif_error( gif ); 
					return( -1 ); 
				}

				vips_foreign_load_gif_render_line( gif, 
					file->Image.Width, q, gif->line ); 
			}
		}
	}
	else {
		int y;

		VIPS_DEBUG_MSG( "vips_foreign_load_gif_render: "
			"non-interlaced frame of %d x %d pixels at %d x %d\n",
			file->Image.Width, file->Image.Height,
			file->Image.Left, file->Image.Top ); 

		for( y = 0; y < file->Image.Height; y++ ) {
			VipsPel *q = VIPS_IMAGE_ADDR( gif->frame, 
				file->Image.Left, file->Image.Top + y );

			if( DGifGetLine( gif->file, gif->line, 
				file->Image.Width ) == GIF_ERROR ) {
				vips_foreign_load_gif_error( gif ); 
				return( -1 ); 
			}

			vips_foreign_load_gif_render_line( gif, 
				file->Image.Width, q, gif->line ); 
		}
	}

	return( 0 );
}

static int
vips_foreign_load_gif_extension( VipsForeignLoadGif *gif )
{
	GifByteType *extension;
	int ext_code;

	VIPS_DEBUG_MSG( "vips_foreign_load_gif_extension:\n" ); 

	if( DGifGetExtension( gif->file, &ext_code, &extension ) == 
		GIF_ERROR ) {
		vips_foreign_load_gif_error( gif ); 
		return( -1 ); 
	}

	if( extension &&
		ext_code == GRAPHICS_EXT_FUNC_CODE &&
		extension[0] == 4 ) { 
		/* Bytes are flags, delay low, delay high,
		 * transparency. Flag bit 1 means transparency
		 * is being set.
		 */
		gif->transparency = -1;
		if( extension[1] & 0x1 ) 
			gif->transparency = extension[4];

		/* Set the current dispose mode. This is read during frame load
		 * to set the meaning of background and transparent pixels.
		 */
		gif->dispose = (extension[1] >> 2) & 0x7;
		VIPS_DEBUG_MSG( "vips_foreign_load_gif_extension: "
			"dispose = %d\n", gif->dispose ); 
	}

	while( extension != NULL ) 
		if( vips_foreign_load_gif_ext_next( gif, &extension ) )
			return( -1 ); 

	return( 0 );
}

/* Read the next page from the file into @frame.
 */
static int
vips_foreign_load_gif_next_page( VipsForeignLoadGif *gif )
{
	GifRecordType record;
	gboolean have_read_frame;

	have_read_frame = FALSE;
	do { 
		if( DGifGetRecordType( gif->file, &record ) == GIF_ERROR ) {
			vips_foreign_load_gif_error( gif ); 
			return( -1 ); 
		}

		switch( record ) {
		case IMAGE_DESC_RECORD_TYPE:
			VIPS_DEBUG_MSG( "vips_foreign_load_gif_next_page: "
				"IMAGE_DESC_RECORD_TYPE\n" ); 

			if( DGifGetImageDesc( gif->file ) == GIF_ERROR ) {
				vips_foreign_load_gif_error( gif ); 
				return( -1 ); 
			}

			if( vips_foreign_load_gif_render( gif ) )
				return( -1 ); 

			have_read_frame = TRUE;

			break;

		case EXTENSION_RECORD_TYPE:
			if( vips_foreign_load_gif_extension( gif ) )
				return( -1 );
			break;

		case TERMINATE_RECORD_TYPE:
			VIPS_DEBUG_MSG( "vips_foreign_load_gif_next_page: "
				"TERMINATE_RECORD_TYPE\n" ); 
			gif->eof = TRUE;
			break;

		case SCREEN_DESC_RECORD_TYPE:
			VIPS_DEBUG_MSG( "vips_foreign_load_gif_next_page: "
				"SCREEN_DESC_RECORD_TYPE\n" );
			break;

		case UNDEFINED_RECORD_TYPE:
			VIPS_DEBUG_MSG( "vips_foreign_load_gif_next_page: "
				"UNDEFINED_RECORD_TYPE\n" );
			break;

		default:
			break;
		}
	} while( !have_read_frame &&
		!gif->eof );

	return( 0 );
}

static int
vips_foreign_load_gif_generate( VipsRegion *or, 
	void *seq, void *a, void *b, gboolean *stop )
{
        VipsRect *r = &or->valid;
	VipsForeignLoadGif *gif = (VipsForeignLoadGif *) a;

	int y;

	for( y = 0; y < r->height; y++ ) {
		/* The page for this output line, and the line number in page.
		 */
		int page = (r->top + y) / gif->file->SHeight + gif->page;
		int line = (r->top + y) % gif->file->SHeight;

		VipsPel *p, *q;
		int x;

		g_assert( line >= 0 && line < gif->frame->Ysize );
		g_assert( page >= 0 && page < gif->n_pages );

		/* current_page == 0 means we've not loaded any pages yet. So 
		 * we need to have loaded the page beyond the page we want.
		 */
		while( gif->current_page <= page ) {
			if( vips_foreign_load_gif_next_page( gif ) )
				return( -1 );

			gif->current_page += 1; 
		}

		/* @frame is always RGBA, but or may be G, GA, RGB or RGBA. 
		 * We have to pick out the values we want.
		 */
		p = VIPS_IMAGE_ADDR( gif->frame, 0, line );
		q = VIPS_REGION_ADDR( or, 0, r->top + y );
		switch( or->im->Bands ) {
		case 1:
			for( x = 0; x < gif->frame->Xsize; x++ ) {
				q[0] = p[1];

				q += 1;
				p += 4;
			}
			break;

		case 2:
			for( x = 0; x < gif->frame->Xsize; x++ ) {
				q[0] = p[1];
				q[1] = p[3];

				q += 2;
				p += 4;
			}
			break;

		case 3:
			for( x = 0; x < gif->frame->Xsize; x++ ) {
				q[0] = p[0];
				q[1] = p[1];
				q[2] = p[2];

				q += 3;
				p += 4;
			}
			break;

		case 4:
			memcpy( q, p, VIPS_IMAGE_SIZEOF_LINE( gif->frame ) );
			break;

		default:
			g_assert_not_reached();
			break;
		}
	}

	return( 0 );
}

static int
vips_foreign_load_gif_load( VipsForeignLoad *load )
{
	VipsForeignLoadGifClass *class = 
		(VipsForeignLoadGifClass *) VIPS_OBJECT_GET_CLASS( load );
	VipsForeignLoadGif *gif = (VipsForeignLoadGif *) load;
	VipsImage **t = (VipsImage **) 
		vips_object_local_array( VIPS_OBJECT( load ), 4 );

	/* Rewind.
	 */
	if( class->open( gif ) )
		return( -1 );

	VIPS_DEBUG_MSG( "vips_foreign_load_gif_load:\n" ); 

	/* Make the memory image we accumulate pixels in. We always accumulate
	 * to RGBA, then trim down to whatever the output image needs on
	 * _generate.
	 */
	gif->frame = vips_image_new_memory();
	vips_image_init_fields( gif->frame, 
		gif->file->SWidth, gif->file->SHeight, 4, VIPS_FORMAT_UCHAR,
		VIPS_CODING_NONE, VIPS_INTERPRETATION_sRGB, 1.0, 1.0 );
	if( vips_image_write_prepare( gif->frame ) ) 
		return( -1 );

	/* A copy of the previous state of the frame, in case we have to
	 * process a DISPOSE_PREVIOUS.
	 */
	gif->previous = vips_image_new_memory();
	vips_image_init_fields( gif->previous, 
		gif->file->SWidth, gif->file->SHeight, 4, VIPS_FORMAT_UCHAR,
		VIPS_CODING_NONE, VIPS_INTERPRETATION_sRGB, 1.0, 1.0 );
	if( vips_image_write_prepare( gif->previous ) ) 
		return( -1 );

	/* Make the output pipeline.
	 */
	t[0] = vips_image_new();
	if( vips_foreign_load_gif_set_header( gif, t[0] ) )
		return( -1 );

	/* Strips 8 pixels high to avoid too many tiny regions.
	 */
	if( vips_image_generate( t[0], 
		NULL, vips_foreign_load_gif_generate, NULL, gif, NULL ) ||
		vips_sequential( t[0], &t[1], 
			"tile_height", VIPS__FATSTRIP_HEIGHT, 
			NULL ) ||
		vips_image_write( t[1], load->real ) )
		return( -1 );

	return( 0 );
}

static int
vips_foreign_load_gif_open( VipsForeignLoadGif *gif )
{
#ifdef HAVE_GIFLIB_5
{
	int error;

	if( !(gif->file = DGifOpen( gif, gif->read_func, &error )) ) {
		vips_foreign_load_gif_error_vips( gif, error );
		return( -1 ); 
	}
}
#else 
	if( !(gif->file = DGifOpen( gif, gif->read_func )) ) { 
		vips_foreign_load_gif_error_vips( gif, GifLastError() ); 
		return( -1 ); 
	}
#endif

	gif->eof = FALSE;
	gif->current_page = 0;

	/* Allocate a line buffer now that we have the GIF width.
	 */
	VIPS_FREE( gif->line ) 
	if( !(gif->line = VIPS_ARRAY( NULL, gif->file->SWidth, GifPixelType )) )
		return( -1 ); 

	return( 0 );
}

static void
vips_foreign_load_gif_class_init( VipsForeignLoadGifClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;
	VipsForeignLoadGifClass *gif_class = (VipsForeignLoadGifClass *) class;

	gobject_class->dispose = vips_foreign_load_gif_dispose;
	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	gif_class->open = vips_foreign_load_gif_open;
	load_class->header = vips_foreign_load_gif_header;
	load_class->load = vips_foreign_load_gif_load;

	object_class->nickname = "gifload_base";
	object_class->description = _( "load GIF with giflib" );

	load_class->get_flags_filename = 
		vips_foreign_load_gif_get_flags_filename;
	load_class->get_flags = vips_foreign_load_gif_get_flags;

	VIPS_ARG_INT( class, "page", 20,
		_( "Page" ),
		_( "Load this page from the file" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignLoadGif, page ),
		0, 100000, 0 );

	VIPS_ARG_INT( class, "n", 21,
		_( "n" ),
		_( "Load this many pages" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignLoadGif, n ),
		-1, 100000, 1 );

}

static void
vips_foreign_load_gif_init( VipsForeignLoadGif *gif )
{
	gif->n = 1;
	gif->transparency = -1;
	gif->delay = 4;
	gif->loop = 0;
	gif->comment = NULL;
	gif->dispose = 0;
}

typedef struct _VipsForeignLoadGifFile {
	VipsForeignLoadGif parent_object;

	/* Filename for load.
	 */
	char *filename; 

	/* The FILE* we read from.
	 */
	FILE *fp;

} VipsForeignLoadGifFile;

typedef VipsForeignLoadGifClass VipsForeignLoadGifFileClass;

G_DEFINE_TYPE( VipsForeignLoadGifFile, vips_foreign_load_gif_file, 
	vips_foreign_load_gif_get_type() );

static void
vips_foreign_load_gif_file_dispose( GObject *gobject )
{
	VipsForeignLoadGifFile *file = (VipsForeignLoadGifFile *) gobject;

	VIPS_FREEF( fclose, file->fp ); 

	G_OBJECT_CLASS( vips_foreign_load_gif_file_parent_class )->
		dispose( gobject );
}

/* Our input function for file open. We can't use DGifOpenFileName(), since
 * that just calls open() and won't work with unicode on win32. We can't use
 * DGifOpenFileHandle() since that's an fd from open() and you can't pass those
 * across DLL boundaries on Windows. 
 */
static int 
vips_giflib_file_read( GifFileType *gfile, GifByteType *buffer, int n )
{
	VipsForeignLoadGif *gif = (VipsForeignLoadGif *) gfile->UserData;
	VipsForeignLoadGifFile *file = (VipsForeignLoadGifFile *) gif;

	if( feof( file->fp ) )
		gif->eof = TRUE;

	return( (int) fread( (void *) buffer, 1, n, file->fp ) );
}

static int
vips_foreign_load_gif_file_open( VipsForeignLoadGif *gif )
{
	VipsForeignLoad *load = (VipsForeignLoad *) gif;
	VipsForeignLoadGifFile *file = (VipsForeignLoadGifFile *) gif;

	if( !file->fp ) {
		if( !(file->fp = 
			vips__file_open_read( file->filename, NULL, FALSE )) ) 
			return( -1 ); 

		VIPS_SETSTR( load->out->filename, file->filename );
	}
	else 
		rewind( file->fp );

	vips_foreign_load_gif_close( gif );
	gif->read_func = vips_giflib_file_read;

	return( VIPS_FOREIGN_LOAD_GIF_CLASS( 
		vips_foreign_load_gif_file_parent_class )->open( gif ) );
}

static const char *vips_foreign_gif_suffs[] = {
	".gif",
	NULL
};

static void
vips_foreign_load_gif_file_class_init( 
	VipsForeignLoadGifFileClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;
	VipsForeignLoadGifClass *gif_class = (VipsForeignLoadGifClass *) class;

	gobject_class->dispose = vips_foreign_load_gif_file_dispose;
	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "gifload";
	object_class->description = _( "load GIF with giflib" );

	foreign_class->suffs = vips_foreign_gif_suffs;

	load_class->is_a = vips_foreign_load_gif_is_a;

	gif_class->open = vips_foreign_load_gif_file_open;

	VIPS_ARG_STRING( class, "filename", 1, 
		_( "Filename" ),
		_( "Filename to load from" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignLoadGifFile, filename ),
		NULL );

}

static void
vips_foreign_load_gif_file_init( VipsForeignLoadGifFile *file )
{
}

typedef struct _VipsForeignLoadGifBuffer {
	VipsForeignLoadGif parent_object;

	/* Load from a buffer.
	 */
	VipsArea *buf;

	/* Current read point, bytes left in buffer.
	 */
	VipsPel *p;
	size_t bytes_to_go;

} VipsForeignLoadGifBuffer;

typedef VipsForeignLoadGifClass VipsForeignLoadGifBufferClass;

G_DEFINE_TYPE( VipsForeignLoadGifBuffer, vips_foreign_load_gif_buffer, 
	vips_foreign_load_gif_get_type() );

/* Callback from the gif loader.
 *
 * Read up to len bytes into buffer, return number of bytes read, 0 for EOF.
 */
static int
vips_giflib_buffer_read( GifFileType *file, GifByteType *buf, int n )
{
	VipsForeignLoadGif *gif = (VipsForeignLoadGif *) file->UserData;
	VipsForeignLoadGifBuffer *buffer = (VipsForeignLoadGifBuffer *) gif;
	size_t will_read = VIPS_MIN( n, buffer->bytes_to_go );

	memcpy( buf, buffer->p, will_read );
	buffer->p += will_read;
	buffer->bytes_to_go -= will_read;

	if( will_read == 0 )
		gif->eof = TRUE;

	return( will_read ); 
}

static int
vips_foreign_load_gif_buffer_open( VipsForeignLoadGif *gif )
{
	VipsForeignLoadGifBuffer *buffer = (VipsForeignLoadGifBuffer *) gif;

	vips_foreign_load_gif_close( gif );
	buffer->p = buffer->buf->data;
	buffer->bytes_to_go = buffer->buf->length;
	gif->read_func = vips_giflib_buffer_read;;

	return( VIPS_FOREIGN_LOAD_GIF_CLASS( 
		vips_foreign_load_gif_file_parent_class )->open( gif ) );
}

static void
vips_foreign_load_gif_buffer_class_init( 
	VipsForeignLoadGifBufferClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;
	VipsForeignLoadGifClass *gif_class = (VipsForeignLoadGifClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "gifload_buffer";
	object_class->description = _( "load GIF with giflib" );

	load_class->is_a_buffer = vips_foreign_load_gif_is_a_buffer;

	gif_class->open = vips_foreign_load_gif_buffer_open;

	VIPS_ARG_BOXED( class, "buffer", 1, 
		_( "Buffer" ),
		_( "Buffer to load from" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignLoadGifBuffer, buf ),
		VIPS_TYPE_BLOB );

}

static void
vips_foreign_load_gif_buffer_init( VipsForeignLoadGifBuffer *buffer )
{
}

#endif /*HAVE_GIFLIB*/

/**
 * vips_gifload:
 * @filename: file to load
 * @out: (out): output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @page: %gint, page (frame) to read
 * * @n: %gint, load this many pages
 *
 * Read a GIF file into a VIPS image.
 *
 * Use @page to select a page to render, numbering from zero.
 *
 * Use @n to select the number of pages to render. The default is 1. Pages are
 * rendered in a vertical column, with each individual page aligned to the
 * left. Set to -1 to mean "until the end of the document". Use vips_grid() 
 * to change page layout.
 *
 * The whole GIF is rendered into memory on header access. The output image
 * will be 1, 2, 3 or 4 bands depending on what the reader finds in the file. 
 *
 * See also: vips_image_new_from_file().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_gifload( const char *filename, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "gifload", ap, filename, out );
	va_end( ap );

	return( result );
}

/**
 * vips_gifload_buffer:
 * @buf: (array length=len) (element-type guint8): memory area to load
 * @len: (type gsize): size of memory area
 * @out: (out): image to write
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @page: %gint, page (frame) to read
 * * @n: %gint, load this many pages
 *
 * Read a GIF-formatted memory block into a VIPS image. Exactly as
 * vips_gifload(), but read from a memory buffer. 
 *
 * You must not free the buffer while @out is active. The 
 * #VipsObject::postclose signal on @out is a good place to free. 
 *
 * See also: vips_gifload().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_gifload_buffer( void *buf, size_t len, VipsImage **out, ... )
{
	va_list ap;
	VipsBlob *blob;
	int result;

	/* We don't take a copy of the data or free it.
	 */
	blob = vips_blob_new( NULL, buf, len );

	va_start( ap, out );
	result = vips_call_split( "gifload_buffer", ap, blob, out );
	va_end( ap );

	vips_area_unref( VIPS_AREA( blob ) );

	return( result );
}

