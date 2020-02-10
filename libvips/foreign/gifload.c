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
 * 6/7/19 [deftomat]
 * 	- support array of delays 
 * 24/7/19
 * 	- close early on minimise 
 * 	- close early on error
 * 23/8/18
 * 	- allow GIF read errors during header scan
 * 	- better feof() handling
 * 27/8/19
 * 	- check image and frame bounds, since giflib does not
 * 1/9/19
 * 	- improve early close again
 * 30/1/19
 * 	- rework on top of VipsSource
 * 	- add gifload_source
 * 5/2/20 alon-ne
 * 	- fix DISPOSE_BACKGROUND and DISPOSE_PREVIOUS
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


#define NO_TRANSPARENT_INDEX      -1
#define TRANSPARENT_MASK          0x01
#define DISPOSE_MASK              0x07
#define DISPOSE_SHIFT             2

#define VIPS_TYPE_FOREIGN_LOAD_GIF (vips_foreign_load_gif_get_type())
#define VIPS_FOREIGN_LOAD_GIF( obj ) \
	(G_TYPE_CHECK_INSTANCE_CAST( (obj), \
	VIPS_TYPE_FOREIGN_LOAD_GIF, VipsForeignLoadGif ))
#define VIPS_FOREIGN_LOAD_GIF_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_CAST( (klass), \
	VIPS_TYPE_FOREIGN_LOAD_GIF, VipsForeignLoadGifClass))
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

	/* Load from this source (set by subclasses).
	 */
	VipsSource *source;

	GifFileType *file;

	/* We decompress the whole thing to a huge RGBA memory image, and
	 * as we render, watch for bands and transparency. At the end of
	 * loading, we copy 1 or 3 bands, with or without transparency to
	 * output.
	 */
	gboolean has_transparency;
	gboolean has_colour;

	/* Delays between frames (in milliseconds).
	 */
	int *delays;
	int delays_length;

	/* Number of times to loop the animation.
	 */
	int loop;

	/* The GIF comment, if any.
	 */
	char *comment;

	/* The number of pages (frame) in the image.
	 */
	int n_pages;

	/* A memory image the size of one frame ... we accumulate to this as
	 * we scan the image, and copy lines to the output on generate.
	 */
	VipsImage *frame;

	/* A scratch buffer the size of frame, used for rendering.
	 */
	VipsImage *scratch;

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
	int transparent_index;

	/* Params for DGifOpen(). Set by subclasses, called by base class in
	 * _open().
	 */
	InputFunc read_func;

} VipsForeignLoadGif;

typedef VipsForeignLoadClass VipsForeignLoadGifClass;

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

/* Shut down giflib plus any underlying file resource.
 */
static int
vips_foreign_load_gif_close_giflib( VipsForeignLoadGif *gif )
{
	VIPS_DEBUG_MSG( "vips_foreign_load_gif_close_giflib:\n" );

#ifdef HAVE_GIFLIB_5
	if( gif->file ) {
		int error;

		if( DGifCloseFile( gif->file, &error ) == GIF_ERROR ) {
			vips_foreign_load_gif_error_vips( gif, error );
			gif->file = NULL;

			return( -1 );
		}
		gif->file = NULL;
	}
#else
	if( gif->file ) {
		if( DGifCloseFile( gif->file ) == GIF_ERROR ) {
			vips_foreign_load_gif_error_vips( gif, GifLastError() );
			gif->file = NULL;

			return( -1 );
		}
		gif->file = NULL;
	}
#endif

	if( gif->source )
		vips_source_minimise( gif->source );

	return( 0 );
}

/* Callback from the gif loader.
 *
 * Read up to len bytes into buffer, return number of bytes read, 0 for EOF.
 */
static int
vips_giflib_read( GifFileType *file, GifByteType *buf, int n )
{
	VipsForeignLoadGif *gif = (VipsForeignLoadGif *) file->UserData;

	gint64 read;

	read = vips_source_read( gif->source, buf, n );
	if( read == 0 )
		gif->eof = TRUE;

	return( (int) read );
}

/* Open any underlying file resource, then giflib.
 */
static int
vips_foreign_load_gif_open_giflib( VipsForeignLoadGif *gif )
{
	VIPS_DEBUG_MSG( "vips_foreign_load_gif_open_giflib:\n" );

	g_assert( !gif->file );

	/* Must always rewind before opening giflib again.
	 */
	vips_source_rewind( gif->source );

#ifdef HAVE_GIFLIB_5
{
	int error;

	if( !(gif->file = DGifOpen( gif, vips_giflib_read, &error )) ) {
		vips_foreign_load_gif_error_vips( gif, error );
		(void) vips_foreign_load_gif_close_giflib( gif );
		return( -1 );
	}
}
#else
	if( !(gif->file = DGifOpen( gif, vips_giflib_read )) ) {
		vips_foreign_load_gif_error_vips( gif, GifLastError() );
		(void) vips_foreign_load_gif_close_giflib( gif );
		return( -1 );
	}
#endif

	gif->eof = FALSE;
	gif->current_page = 0;

	return( 0 );
}

static void
vips_foreign_load_gif_dispose( GObject *gobject )
{
	VipsForeignLoadGif *gif = (VipsForeignLoadGif *) gobject;

	VIPS_DEBUG_MSG( "vips_foreign_load_gif_dispose:\n" );

	vips_foreign_load_gif_close_giflib( gif );

	VIPS_UNREF( gif->source );
	VIPS_UNREF( gif->frame );
	VIPS_UNREF( gif->scratch );
	VIPS_UNREF( gif->previous );
	VIPS_FREE( gif->comment );
	VIPS_FREE( gif->line );
	VIPS_FREE( gif->delays );

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
vips_foreign_load_gif_is_a_source( VipsSource *source )
{
	const unsigned char *data;

	if( (data = vips_source_sniff( source, 4 )) &&
		data[0] == 'G' &&
		data[1] == 'I' &&
		data[2] == 'F' &&
		data[3] == '8' )
		return( TRUE );

	return( FALSE );
}

/* Make sure delays is allocated and large enough.
 */
static void
vips_foreign_load_gif_allocate_delays( VipsForeignLoadGif *gif )
{
	if( gif->n_pages >= gif->delays_length ) {
		int old = gif->delays_length;
		int i;

		gif->delays_length = gif->delays_length + gif->n_pages + 64;
		gif->delays = (int *) g_realloc( gif->delays,
			gif->delays_length * sizeof( int ) );
		for( i = old; i < gif->delays_length; i++ )
			gif->delays[i] = 40;
	}
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

	ColorMapObject *map;
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
	map = file->Image.ColorMap ? file->Image.ColorMap : file->SColorMap;
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
		(vips_isprefix( "NETSCAPE2.0", 
			(const char*) (extension + 1) )  ||
		 vips_isprefix( "ANIMEXTS1.0", 
			(const char*) (extension + 1) )) )
		have_netscape = TRUE;

	while( extension != NULL ) {
		if( vips_foreign_load_gif_ext_next( gif, &extension ) )
			return( -1 );

		if( have_netscape &&
			extension &&
			extension[0] == 3 &&
			extension[1] == 1 ) {
				gif->loop = extension[2] | (extension[3] << 8);
				if( gif->loop != 0 )
					gif->loop += 1;
			}
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
				extension[1] & TRANSPARENT_MASK ) {
				VIPS_DEBUG_MSG( "gifload: has transp.\n" );
				gif->has_transparency = TRUE;
			}

			/* giflib uses centiseconds, we use ms.
			 */
			gif->delays[gif->n_pages] =
				(extension[2] | (extension[3] << 8)) * 10;

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
	vips_image_set_int( image, "loop", gif->loop );

	/* DEPRECATED "gif-loop"
	 *
	 * Not the correct behavior as loop=1 became gif-loop=0
	 * but we want to keep the old behavior untouched!
	 */
	vips_image_set_int( image,
		"gif-loop", gif->loop == 0 ? 0 : gif->loop - 1 );

	if( gif->delays ) {
		/* The deprecated gif-delay field is in centiseconds.
		 */
		vips_image_set_int( image,
			"gif-delay", VIPS_RINT( gif->delays[0] / 10.0 ) );
		vips_image_set_array_int( image,
			"delay", gif->delays, gif->n_pages );
	}
	else
		vips_image_set_int( image, "gif-delay", 4 );

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
vips_foreign_load_gif_scan( VipsForeignLoadGif *gif )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( gif );

	GifRecordType record;

	VIPS_DEBUG_MSG( "vips_foreign_load_gif_scan:\n" );

	gif->n_pages = 0;

	do {
		if( DGifGetRecordType( gif->file, &record ) == GIF_ERROR )
			continue;

		switch( record ) {
		case IMAGE_DESC_RECORD_TYPE:
			(void) vips_foreign_load_gif_scan_image( gif );
			gif->n_pages += 1;
			vips_foreign_load_gif_allocate_delays( gif );
			break;

		case EXTENSION_RECORD_TYPE:
			/* We need to fetch the extensions to check for
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

	return( 0 );
}

/* Scan the GIF and set the libvips header. We always close after scan, even
 * on an error.
 */
static int
vips_foreign_load_gif_header( VipsForeignLoad *load )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( load );
	VipsForeignLoadGif *gif = VIPS_FOREIGN_LOAD_GIF( load );

	VIPS_DEBUG_MSG( "vips_foreign_load_gif_header: %p\n", gif );

	if( vips_foreign_load_gif_open_giflib( gif ) )
		return( -1 );

	/* giflib does no checking of image dimensions, not even for 0.
	 */
	if( gif->file->SWidth <= 0 ||
		gif->file->SWidth > VIPS_MAX_COORD ||
		gif->file->SHeight <= 0 ||
		gif->file->SHeight > VIPS_MAX_COORD ) {
		vips_error( class->nickname,
			"%s", _( "image size out of bounds" ) );
		(void) vips_foreign_load_gif_close_giflib( gif );

		return( -1 );
	}

	/* Allocate a line buffer now that we have the GIF width.
	 */
	if( !(gif->line =
		VIPS_ARRAY( NULL, gif->file->SWidth, GifPixelType )) ||
		vips_foreign_load_gif_scan( gif ) ||
		vips_foreign_load_gif_set_header( gif, load->out ) ) {
		(void) vips_foreign_load_gif_close_giflib( gif );

		return( -1 );
	}

	(void) vips_foreign_load_gif_close_giflib( gif );

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
	int width, VipsPel * restrict dst )
{
	guint32 *idst = (guint32 *) dst;

	int x;

	for( x = 0; x < width; x++ ) {
		VipsPel v = gif->line[x];

		if( v != gif->transparent_index ) 
			idst[x] = gif->cmap[v];
	}
}

/* Render the current gif frame into an RGBA buffer. GIFs can accumulate,
 * depending on the current dispose mode.
 */
static int
vips_foreign_load_gif_render( VipsForeignLoadGif *gif )
{
	GifFileType *file = gif->file;

	if( DGifGetImageDesc( file ) == GIF_ERROR ) {
		vips_foreign_load_gif_error( gif );
		return( -1 );
	}

	/* Update the colour map for this frame.
	 */
	vips_foreign_load_gif_build_cmap( gif );

	/* PREVIOUS means we init the frame with the last un-disposed frame. 
	 * So the last un-disposed frame is used as a backdrop for the new 
	 * frame.
	 */
	if( gif->dispose == DISPOSE_PREVIOUS ) 
		memcpy( VIPS_IMAGE_ADDR( gif->scratch, 0, 0 ),
			VIPS_IMAGE_ADDR( gif->previous, 0, 0 ),
			VIPS_IMAGE_SIZEOF_IMAGE( gif->scratch ) );

	/* giflib does not check that the Left / Top / Width / Height for this
	 * Image is inside the canvas.
	 *
	 * We could clip against the canvas, but for now, just ignore out of
	 * bounds frames. Watch for int overflow too.
	 */
	if( file->Image.Left < 0 ||
		file->Image.Left > VIPS_MAX_COORD ||
		file->Image.Width <= 0 ||
		file->Image.Width > VIPS_MAX_COORD ||
		file->Image.Left + file->Image.Width > file->SWidth ||
		file->Image.Top < 0 ||
		file->Image.Top > VIPS_MAX_COORD ||
		file->Image.Height <= 0 ||
		file->Image.Height > VIPS_MAX_COORD ||
		file->Image.Top + file->Image.Height > file->SHeight ) {
		VIPS_DEBUG_MSG( "vips_foreign_load_gif_render: "
			"out of bounds frame of %d x %d pixels at %d x %d\n",
			file->Image.Width, file->Image.Height,
			file->Image.Left, file->Image.Top );
	}
	else if( file->Image.Interlace ) {
		int i;

		VIPS_DEBUG_MSG( "vips_foreign_load_gif_render: "
			"interlaced frame of %d x %d pixels at %d x %d\n",
			file->Image.Width, file->Image.Height,
			file->Image.Left, file->Image.Top );

		for( i = 0; i < 4; i++ ) {
			int y;

			for( y = InterlacedOffset[i]; y < file->Image.Height; 
				y += InterlacedJumps[i] ) {
				VipsPel *dst = VIPS_IMAGE_ADDR( gif->scratch, 
					file->Image.Left, file->Image.Top + y );

				if( DGifGetLine( gif->file, 
					gif->line, file->Image.Width ) == 
						GIF_ERROR ) {
					vips_foreign_load_gif_error( gif );
					return( -1 );
				}

				vips_foreign_load_gif_render_line( gif, 
					file->Image.Width, dst );
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
			VipsPel *dst = VIPS_IMAGE_ADDR( gif->scratch, 
				file->Image.Left, file->Image.Top + y );

			if( DGifGetLine( gif->file, 
				gif->line, file->Image.Width ) == GIF_ERROR ) {
				vips_foreign_load_gif_error( gif );
				return( -1 );
			}

			vips_foreign_load_gif_render_line( gif, 
				file->Image.Width, dst );
		}
	}

	/* Copy the result to frame, which then is picked up from outside
	 */
	memcpy( VIPS_IMAGE_ADDR( gif->frame, 0, 0 ),
		VIPS_IMAGE_ADDR(gif->scratch, 0, 0 ),
		VIPS_IMAGE_SIZEOF_IMAGE( gif->frame ) );

	if( gif->dispose == DISPOSE_BACKGROUND ) {
		/* BACKGROUND means we reset the frame to transparent before we
		 * render the next set of pixels.
		 */
		guint32 *q = (guint32 *) VIPS_IMAGE_ADDR( gif->scratch, 
			file->Image.Left, file->Image.Top );

		/* What we write for transparent pixels. We want RGB to be
		 * 255, and A to be 0.
		 */
		guint32 ink = GUINT32_TO_BE( 0xffffff00 );

		int x, y;

		/* Generate the first line a pixel at a time, memcpy() for
		 * subsequent lines.
		 */
		if( file->Image.Height > 0 ) 
			for( x = 0; x < file->Image.Width; x++ )
				q[x] = ink;

		for( y = 1; y < file->Image.Height; y++ )
			memcpy( q + gif->scratch->Xsize * y, 
				q, 
				file->Image.Width * sizeof( guint32 ) );
	}
	else if( gif->dispose == DISPOSAL_UNSPECIFIED || 
		gif->dispose == DISPOSE_DO_NOT ) 
		/* Copy the frame to previous, so it can be restored if 
		 * DISPOSE_PREVIOUS is specified in a later frame.
		 */
		memcpy( VIPS_IMAGE_ADDR( gif->previous, 0, 0 ),
			VIPS_IMAGE_ADDR(gif->frame, 0, 0 ),
			VIPS_IMAGE_SIZEOF_IMAGE( gif->previous ) );

	/* Reset values, as Graphic Control Extension is optional
	 */
	gif->dispose = DISPOSAL_UNSPECIFIED;
	gif->transparent_index = NO_TRANSPARENT_INDEX;

	return( 0 );
}

#ifdef VIPS_DEBUG
static const char *
dispose2str( int dispose )
{
	switch( dispose ) {
	case DISPOSAL_UNSPECIFIED: return( "DISPOSAL_UNSPECIFIED" );
	case DISPOSE_DO_NOT: return( "DISPOSE_DO_NOT" );
	case DISPOSE_BACKGROUND: return( "DISPOSE_BACKGROUND" );
	case DISPOSE_PREVIOUS: return( "DISPOSE_PREVIOUS" );
	default: return( "<unknown>" );
	}
}
#endif /*VIPS_DEBUG*/

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
		int flags = extension[1];

		/* Bytes are flags, delay low, delay high, transparency. 
		 * Flag bit 1 means transparency is being set.
		 */
		gif->transparent_index = (flags & TRANSPARENT_MASK) ? 
			extension[4] : NO_TRANSPARENT_INDEX;
		VIPS_DEBUG_MSG( "vips_foreign_load_gif_extension: "
			"transparency = %d\n", gif->transparent_index );

		/* Set the current dispose mode. This is read during frame load
		 * to set the meaning of background and transparent pixels.
		 */
		gif->dispose = (flags >> DISPOSE_SHIFT) & DISPOSE_MASK;

		VIPS_DEBUG_MSG( "vips_foreign_load_gif_extension: "
			"dispose = %s\n", dispose2str( gif->dispose ) );
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

#ifdef DEBUG_VERBOSE
	printf( "vips_foreign_load_gif_generate: %p "
		"left = %d, top = %d, width = %d, height = %d\n",
		gif,
		r->left, r->top, r->width, r->height );
#endif /*DEBUG_VERBOSE*/

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

static void
vips_foreign_load_gif_minimise( VipsObject *object, VipsForeignLoadGif *gif )
{
	vips_source_minimise( gif->source );
}

static VipsImage *
vips_foreign_load_gif_temp( VipsForeignLoadGif *gif )
{
	VipsImage *temp;

	temp = vips_image_new_memory();
	vips_image_init_fields( temp,
		gif->file->SWidth, gif->file->SHeight, 4, VIPS_FORMAT_UCHAR,
		VIPS_CODING_NONE, VIPS_INTERPRETATION_sRGB, 1.0, 1.0 );
	if( vips_image_write_prepare( temp ) ) {
		VIPS_UNREF( temp );
		return( NULL );
	}

	return( temp );
}

static int
vips_foreign_load_gif_load( VipsForeignLoad *load )
{
	VipsForeignLoadGif *gif = VIPS_FOREIGN_LOAD_GIF( load );
	VipsImage **t = (VipsImage **)
		vips_object_local_array( VIPS_OBJECT( load ), 4 );

	VIPS_DEBUG_MSG( "vips_foreign_load_gif_load: %p\n", gif );

	if( vips_foreign_load_gif_open_giflib( gif ) )
		return( -1 );

	/* Set of temp images we use during rendering.
	 */
	if( !(gif->frame = vips_foreign_load_gif_temp( gif )) ||
		!(gif->scratch = vips_foreign_load_gif_temp( gif )) ||
		!(gif->previous = vips_foreign_load_gif_temp( gif )) )
		return( -1 );

	/* Make the output pipeline.
	 */
	t[0] = vips_image_new();
	if( vips_foreign_load_gif_set_header( gif, t[0] ) )
		return( -1 );

	/* Close input immediately at end of read.
	 */
	g_signal_connect( t[0], "minimise",
		G_CALLBACK( vips_foreign_load_gif_minimise ), gif );

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

static void
vips_foreign_load_gif_class_init( VipsForeignLoadGifClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->dispose = vips_foreign_load_gif_dispose;
	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "gifload_base";
	object_class->description = _( "load GIF with giflib" );

	load_class->header = vips_foreign_load_gif_header;
	load_class->load = vips_foreign_load_gif_load;
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
	gif->transparent_index = NO_TRANSPARENT_INDEX;
	gif->delays = NULL;
	gif->delays_length = 0;
	gif->loop = 1;
	gif->comment = NULL;
	gif->dispose = DISPOSAL_UNSPECIFIED;

	vips_foreign_load_gif_allocate_delays( gif );
}

typedef struct _VipsForeignLoadGifFile {
	VipsForeignLoadGif parent_object;

	/* Filename for load.
	 */
	char *filename;

} VipsForeignLoadGifFile;

typedef VipsForeignLoadGifClass VipsForeignLoadGifFileClass;

G_DEFINE_TYPE( VipsForeignLoadGifFile, vips_foreign_load_gif_file,
	vips_foreign_load_gif_get_type() );

static int
vips_foreign_load_gif_file_build( VipsObject *object )
{
	VipsForeignLoadGifFile *file = (VipsForeignLoadGifFile *) object;
	VipsForeignLoadGif *gif = (VipsForeignLoadGif *) object;

	if( file->filename )
		if( !(gif->source =
			vips_source_new_from_file( file->filename )) )
			return( -1 );

	if( VIPS_OBJECT_CLASS( vips_foreign_load_gif_file_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

static const char *vips_foreign_gif_suffs[] = {
	".gif",
	NULL
};

static gboolean
vips_foreign_load_gif_file_is_a( const char *filename )
{
	VipsSource *source;
	gboolean result;

	if( !(source = vips_source_new_from_file( filename )) )
		return( FALSE );
	result = vips_foreign_load_gif_is_a_source( source );
	VIPS_UNREF( source );

	return( result );
}

static void
vips_foreign_load_gif_file_class_init(
	VipsForeignLoadGifFileClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "gifload";
	object_class->description = _( "load GIF with giflib" );
	object_class->build = vips_foreign_load_gif_file_build;

	foreign_class->suffs = vips_foreign_gif_suffs;

	load_class->is_a = vips_foreign_load_gif_file_is_a;

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
	VipsArea *blob;

} VipsForeignLoadGifBuffer;

typedef VipsForeignLoadGifClass VipsForeignLoadGifBufferClass;

G_DEFINE_TYPE( VipsForeignLoadGifBuffer, vips_foreign_load_gif_buffer,
	vips_foreign_load_gif_get_type() );

static int
vips_foreign_load_gif_buffer_build( VipsObject *object )
{
	VipsForeignLoadGif *gif = (VipsForeignLoadGif *) object;
	VipsForeignLoadGifBuffer *buffer = 
		(VipsForeignLoadGifBuffer *) object;

	if( buffer->blob &&
		!(gif->source = vips_source_new_from_memory( 
			VIPS_AREA( buffer->blob )->data, 
			VIPS_AREA( buffer->blob )->length )) )
		return( -1 );

	if( VIPS_OBJECT_CLASS( vips_foreign_load_gif_buffer_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

static gboolean
vips_foreign_load_gif_buffer_is_a_buffer( const void *buf, size_t len )
{
	VipsSource *source;
	gboolean result;

	if( !(source = vips_source_new_from_memory( buf, len )) )
		return( FALSE );
	result = vips_foreign_load_gif_is_a_source( source );
	VIPS_UNREF( source );

	return( result );
}

static void
vips_foreign_load_gif_buffer_class_init(
	VipsForeignLoadGifBufferClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "gifload_buffer";
	object_class->description = _( "load GIF with giflib" );
	object_class->build = vips_foreign_load_gif_buffer_build;

	load_class->is_a_buffer = vips_foreign_load_gif_buffer_is_a_buffer;

	VIPS_ARG_BOXED( class, "buffer", 1,
		_( "Buffer" ),
		_( "Buffer to load from" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsForeignLoadGifBuffer, blob ),
		VIPS_TYPE_BLOB );

}

static void
vips_foreign_load_gif_buffer_init( VipsForeignLoadGifBuffer *buffer )
{
}

typedef struct _VipsForeignLoadGifSource {
	VipsForeignLoadGif parent_object;

	/* Load from a source.
	 */
	VipsSource *source;

} VipsForeignLoadGifSource;

typedef VipsForeignLoadGifClass VipsForeignLoadGifSourceClass;

G_DEFINE_TYPE( VipsForeignLoadGifSource, vips_foreign_load_gif_source,
	vips_foreign_load_gif_get_type() );

static int
vips_foreign_load_gif_source_build( VipsObject *object )
{
	VipsForeignLoadGif *gif = (VipsForeignLoadGif *) object;
	VipsForeignLoadGifSource *source =
		(VipsForeignLoadGifSource *) object;

	if( source->source ) {
		gif->source = source->source;
		g_object_ref( gif->source );
	}

	if( VIPS_OBJECT_CLASS( vips_foreign_load_gif_source_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

static void
vips_foreign_load_gif_source_class_init(
	VipsForeignLoadGifSourceClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "gifload_source";
	object_class->description = _( "load GIF with giflib" );
	object_class->build = vips_foreign_load_gif_source_build;

	load_class->is_a_source = vips_foreign_load_gif_is_a_source;

	VIPS_ARG_OBJECT( class, "source", 1,
		_( "Source" ),
		_( "Source to load from" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsForeignLoadGifSource, source ),
		VIPS_TYPE_SOURCE );

}

static void
vips_foreign_load_gif_source_init( VipsForeignLoadGifSource *source )
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

/**
 * vips_gifload_source:
 * @source: source to load
 * @out: (out): image to write
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @page: %gint, page (frame) to read
 * * @n: %gint, load this many pages
 *
 * Exactly as vips_gifload(), but read from a source.
 *
 * See also: vips_gifload().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_gifload_source( VipsSource *source, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "gifload_source", ap, source, out );
	va_end( ap );

	return( result );
}
