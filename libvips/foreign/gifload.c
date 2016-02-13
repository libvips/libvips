/* load a GIF with giflib
 *
 * 10/2/16
 * 	- from svgload.c
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
#define VIPS_DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#ifdef HAVE_GIFLIB

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>

#include <vips/vips.h>
#include <vips/buf.h>
#include <vips/internal.h>
#include <vips/debug.h>

#include <gif_lib.h>

typedef struct _VipsForeignLoadGif {
	VipsForeignLoad parent_object;

	/* Load this page (frame number).
	 */
	int page;

	GifFileType *file;

	/* As we scan the file, the index of the transparent pixel for this
	 * frame.
	 */
	int transparency;

	/* Decompress lines of the gif file to here.
	 */
	GifPixelType *line;

} VipsForeignLoadGif;

typedef VipsForeignLoadClass VipsForeignLoadGifClass;

G_DEFINE_ABSTRACT_TYPE( VipsForeignLoadGif, vips_foreign_load_gif, 
	VIPS_TYPE_FOREIGN_LOAD );

/* From gif2rgb.c ... offsets and jumps for interlaced GIF images.
 */
static int 
	InterlacedOffset[] = { 0, 4, 2, 1 },
	InterlacedJumps[] = { 8, 8, 4, 2 };

/* From gif-lib.h
 */
static const char *
vips_foreign_load_gif_errstr( int error_code )
{
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
}

static void
vips_foreign_load_gif_error( VipsForeignLoadGif *gif )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( gif );

	vips_error( class->nickname, _( "giflib error: %s" ),
		vips_foreign_load_gif_errstr( GifLastError() ) );
}

static void
vips_foreign_load_gif_dispose( GObject *gobject )
{
	VipsForeignLoadGif *gif = (VipsForeignLoadGif *) gobject;

	VIPS_FREEF( DGifCloseFile, gif->file );

	G_OBJECT_CLASS( vips_foreign_load_gif_parent_class )->
		dispose( gobject );
}

static VipsForeignFlags
vips_foreign_load_gif_get_flags_filename( const char *filename )
{
	/* We can render any part of the image on demand.
	 */
	return( VIPS_FOREIGN_PARTIAL );
}

static VipsForeignFlags
vips_foreign_load_gif_get_flags( VipsForeignLoad *load )
{
	return( VIPS_FOREIGN_PARTIAL );
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

	if( vips__get_bytes( filename, buf, 4 ) &&
		vips_foreign_load_gif_is_a_buffer( buf, 4 ) )
		return( 1 );

	return( 0 );
}

static void
vips_foreign_load_gif_parse( VipsForeignLoadGif *gif, 
	VipsImage *out )
{
	vips_image_init_fields( out, 
		gif->file->SWidth, gif->file->SHeight,
		4, VIPS_FORMAT_UCHAR,
		VIPS_CODING_NONE, VIPS_INTERPRETATION_sRGB, 1.0, 1.0 );

	/* We will have the whole GIF frame in memory, so we can render any 
	 * area.
	 */
        vips_image_pipelinev( out, VIPS_DEMAND_STYLE_ANY, NULL );

	/* We need a line buffer to decompress to.
	 */
	gif->line = VIPS_ARRAY( gif, gif->file->SWidth, GifPixelType );
}

static int
vips_foreign_load_gif_header( VipsForeignLoad *load )
{
	VipsForeignLoadGif *gif = (VipsForeignLoadGif *) load;

	vips_foreign_load_gif_parse( gif, load->out ); 

	return( 0 );
}

static void
vips_foreign_load_gif_render_line( VipsForeignLoadGif *gif,
	int width, VipsPel * restrict q, VipsPel * restrict p )
{
	ColorMapObject *map = gif->file->Image.ColorMap ?
		gif->file->Image.ColorMap : gif->file->SColorMap;

	int x;

	for( x = 0; x < width; x++ ) {
		VipsPel v = p[x];

		if( v != gif->transparency &&
			v < map->ColorCount ) {
			q[0] = map->Colors[v].Red;
			q[1] = map->Colors[v].Green;
			q[2] = map->Colors[v].Blue;
			q[3] = 255;
		}
		else {
			q[0] = 0;
			q[1] = 0;
			q[2] = 0;
			q[3] = 0;
		}

		q += 4;
	}
}

/* Render the current gif frame into an RGBA buffer. GIFs 
 * accumulate, so don't clear the buffer first, so that we can paint a 
 * series of frames on top of each other. 
 */
static int
vips_foreign_load_gif_render( VipsForeignLoadGif *gif, VipsImage *out ) 
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( gif );
	GifFileType *file = gif->file;

	/* Check that the frame lies within our image.
	 */
	if( file->Image.Left < 0 ||
		file->Image.Left + file->Image.Width > out->Xsize ||
		file->Image.Top < 0 ||
		file->Image.Top + file->Image.Height > out->Ysize ) {
		vips_error( class->nickname, 
			"%s", _( "frame is outside image area" ) ); 
		return( -1 ); 
	}

	if( file->Image.Interlace ) {
		int i;

		VIPS_DEBUG_MSG( "gifload: interlaced frame\n" ); 

		for( i = 0; i < 4; i++ ) {
			int y;

			for( y = InterlacedOffset[i]; 
				y < file->Image.Height;
			  	y += InterlacedJumps[i] ) {
				VipsPel *q = VIPS_IMAGE_ADDR( out, 
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

		for( y = 0; y < file->Image.Height; y++ ) {
			VipsPel *q = VIPS_IMAGE_ADDR( out, 
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
vips_foreign_load_gif_load( VipsForeignLoad *load )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( load );
	VipsForeignLoadGif *gif = (VipsForeignLoadGif *) load;

	int frame_n;
	GifRecordType record;

	vips_foreign_load_gif_parse( gif, load->real ); 

	/* Turn out into a memory image which we then render the GIF frames
	 * into.
	 */
	if( vips_image_write_prepare( load->real ) )
		return( -1 );

	/* Scan the GIF until we have enough to have completely rendered the
	 * frame we need.
	 */
	frame_n = 0;
	do { 
		GifByteType *extension;
		int ext_code;

		if( DGifGetRecordType( gif->file, &record) == GIF_ERROR ) {
			vips_foreign_load_gif_error( gif );
			return( -1 ); 
		}

		switch( record ) {
		case IMAGE_DESC_RECORD_TYPE:
			VIPS_DEBUG_MSG( "gifload: IMAGE_DESC_RECORD_TYPE:\n" ); 

			if( DGifGetImageDesc( gif->file ) == GIF_ERROR ) {
				vips_foreign_load_gif_error( gif );
				return( -1 ); 
			}

			if( vips_foreign_load_gif_render( gif, load->real ) )
				return( -1 ); 

			frame_n += 1;

			VIPS_DEBUG_MSG( "gifload: start frame %d:\n", frame_n );

			break;

		case EXTENSION_RECORD_TYPE:
			VIPS_DEBUG_MSG( "gifload: EXTENSION_RECORD_TYPE:\n" ); 

			gif->transparency = -1;

			if( DGifGetExtension( gif->file, 
				&ext_code, &extension) == GIF_ERROR ) {
				vips_foreign_load_gif_error( gif );
				return( -1 ); 
			}

			if( ext_code == GRAPHICS_EXT_FUNC_CODE &&
				extension &&
				extension[0] == 4 && 
				extension[1] == 1 ) {
				/* Bytes are 4, 1, delay low, delay high,
				 * transparency.
				 */
				gif->transparency = extension[4];

				VIPS_DEBUG_MSG( "gifload: "
					"seen transparency %d\n", 
					gif->transparency );
			}

			while( extension != NULL ) {
				if( DGifGetExtensionNext( gif->file, 
					&extension) == GIF_ERROR ) {
					vips_foreign_load_gif_error( gif );
					return( -1 ); 
				}

#ifdef VIPS_DEBUG
				if( extension ) 
					VIPS_DEBUG_MSG( "gifload: "
						"EXTENSION_NEXT:\n" ); 
#endif
			}

			break;

		case TERMINATE_RECORD_TYPE:
			VIPS_DEBUG_MSG( "gifload: TERMINATE_RECORD_TYPE:\n" ); 
			break;

		case SCREEN_DESC_RECORD_TYPE:
			VIPS_DEBUG_MSG( "gifload: SCREEN_DESC_RECORD_TYPE:\n" );
			break;

		case UNDEFINED_RECORD_TYPE:
			VIPS_DEBUG_MSG( "gifload: UNDEFINED_RECORD_TYPE:\n" );
			break;

		default:
			break;
		}
	} while( frame_n <= gif->page && 
		record != TERMINATE_RECORD_TYPE );

	if( frame_n <= gif->page ) {
		vips_error( class->nickname, 
			"%s", _( "too few frames in GIF file" ) );
		return( -1 );
	}

	/* We've rendered to a memory image ... we can shut down the GIF
	 * reader now.
	 */
	VIPS_FREEF( DGifCloseFile, gif->file );

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

	object_class->nickname = "gifload";
	object_class->description = _( "load GIF with giflib" );

	load_class->get_flags_filename = 
		vips_foreign_load_gif_get_flags_filename;
	load_class->get_flags = vips_foreign_load_gif_get_flags;
	load_class->load = vips_foreign_load_gif_load;

	VIPS_ARG_INT( class, "page", 10,
		_( "Page" ),
		_( "Load this page from the file" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignLoadGif, page ),
		0, 100000, 0 );

}

static void
vips_foreign_load_gif_init( VipsForeignLoadGif *gif )
{
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
vips_foreign_load_gif_file_header( VipsForeignLoad *load )
{
	VipsForeignLoadGif *gif = (VipsForeignLoadGif *) load;
	VipsForeignLoadGifFile *file = (VipsForeignLoadGifFile *) load;

	if( !(gif->file = DGifOpenFileName( file->filename )) ) { 
		vips_foreign_load_gif_error( gif );
		return( -1 ); 
	}

	return( vips_foreign_load_gif_header( load ) );
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

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "gifload";
	object_class->description = _( "load GIF with giflib" );

	foreign_class->suffs = vips_foreign_gif_suffs;

	load_class->is_a = vips_foreign_load_gif_is_a;
	load_class->header = vips_foreign_load_gif_file_header;

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
vips_foreign_load_gif_buffer_read( GifFileType *file, 
	GifByteType *buf, int len )
{
	VipsForeignLoadGifBuffer *buffer = (VipsForeignLoadGifBuffer *)
		file->UserData;
	size_t will_read = VIPS_MIN( len, buffer->bytes_to_go );

	memcpy( buf, buffer->p, will_read );
	buffer->p += will_read;
	buffer->bytes_to_go -= will_read;

	return( will_read ); 
}

static int
vips_foreign_load_gif_buffer_header( VipsForeignLoad *load )
{
	VipsForeignLoadGif *gif = (VipsForeignLoadGif *) load;
	VipsForeignLoadGifBuffer *buffer = (VipsForeignLoadGifBuffer *) load;

	/* Init the read point.
	 */
	buffer->p = buffer->buf->data;
	buffer->bytes_to_go = buffer->buf->length;

	if( !(gif->file = DGifOpen( gif, 
		vips_foreign_load_gif_buffer_read )) ) { 
		vips_foreign_load_gif_error( gif );
		return( -1 ); 
	}

	return( vips_foreign_load_gif_header( load ) );
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

	load_class->is_a_buffer = vips_foreign_load_gif_is_a_buffer;
	load_class->header = vips_foreign_load_gif_buffer_header;

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

#endif /*HAVE_RSVG*/

