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
#define DEBUG
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

#include <gif_lib.h>

typedef struct _VipsForeignLoadGif {
	VipsForeignLoad parent_object;

	GifFileType *file;

	/* The bitmap for the frame we fetch.
	 */
	unsigned char *RasterBits;

} VipsForeignLoadGif;

typedef VipsForeignLoadClass VipsForeignLoadGifClass;

G_DEFINE_ABSTRACT_TYPE( VipsForeignLoadGif, vips_foreign_load_gif, 
	VIPS_TYPE_FOREIGN_LOAD );

/* From gif-lib.h

#define D_GIF_ERR_OPEN_FAILED    101    
#define D_GIF_ERR_READ_FAILED    102
#define D_GIF_ERR_NOT_GIF_FILE   103
#define D_GIF_ERR_NO_SCRN_DSCR   104
#define D_GIF_ERR_NO_IMAG_DSCR   105
#define D_GIF_ERR_NO_COLOR_MAP   106
#define D_GIF_ERR_WRONG_RECORD   107
#define D_GIF_ERR_DATA_TOO_BIG   108
#define D_GIF_ERR_NOT_ENOUGH_MEM 109
#define D_GIF_ERR_CLOSE_FAILED   110
#define D_GIF_ERR_NOT_READABLE   111
#define D_GIF_ERR_IMAGE_DEFECT   112
#define D_GIF_ERR_EOF_TOO_SOON   113

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
vips_foreign_load_gif_dispose( GObject *gobject )
{
	VipsForeignLoadGif *gif = (VipsForeignLoadGif *) gobject;

	VIPS_FREEF( EGifCloseFile, gif->file );

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

	/* We have the whole GIF in memory, so we can render any area.
	 */
        vips_image_pipelinev( out, VIPS_DEMAND_STYLE_ANY, NULL );

}

static int
vips_foreign_load_gif_header( VipsForeignLoad *load )
{
	VipsForeignLoadGif *gif = (VipsForeignLoadGif *) load;
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( gif );

	if( DGifSlurp( gif->file ) != GIF_OK ) { 
		vips_error( class->nickname, 
			_( "unable to decode GIF file: %s" ), 
			vips_foreign_load_gif_errstr( GifLastError() ) ); 
		return( -1 ); 
	}

	if( gif->file->SavedImages &&
		gif->file->SavedImages->RasterBits )
		gif->RasterBits = gif->file->SavedImages->RasterBits;

	vips_foreign_load_gif_parse( gif, load->out ); 

	return( 0 );
}

static int
vips_foreign_load_gif_generate( VipsRegion *or, 
	void *seq, void *a, void *b, gboolean *stop )
{
	VipsForeignLoadGif *gif = (VipsForeignLoadGif *) a;
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( gif );
	VipsRect *r = &or->valid;
	unsigned char *bits = gif->RasterBits;
	ColorMapObject *map = gif->file->SColorMap;
	int width = gif->file->Image.Width;

	if( bits && 
		map ) { 
		int count = map->ColorCount;

		int x, y;

		for( y = 0; y < r->height; y++ ) {
			VipsPel * restrict p;
			VipsPel * restrict q;

			p = bits + r->left + (r->top + y) * width;
			q = VIPS_REGION_ADDR( or, r->left, r->top + y );
			for( x = 0; x < r->width; x++ ) {
				if( p[x] < count &&
				 	p[x] != gif->file->SBackGroundColor ) { 
					q[0] = map->Colors[p[x]].Red;
					q[1] = map->Colors[p[x]].Green;
					q[2] = map->Colors[p[x]].Blue;
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
	}

	return( 0 ); 
}

static int
vips_foreign_load_gif_load( VipsForeignLoad *load )
{
	VipsForeignLoadGif *gif = (VipsForeignLoadGif *) load;

	vips_foreign_load_gif_parse( gif, load->real ); 
	if( vips_image_generate( load->real,
		NULL, vips_foreign_load_gif_generate, NULL, gif, NULL ) )
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

	object_class->nickname = "gifload";
	object_class->description = _( "load GIF with giflib" );

	load_class->get_flags_filename = 
		vips_foreign_load_gif_get_flags_filename;
	load_class->get_flags = vips_foreign_load_gif_get_flags;
	load_class->load = vips_foreign_load_gif_load;


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
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( load );
	VipsForeignLoadGif *gif = (VipsForeignLoadGif *) load;
	VipsForeignLoadGifFile *file = (VipsForeignLoadGifFile *) load;

	if( !(gif->file = DGifOpenFileName( file->filename )) ) { 
		vips_error( class->nickname, 
			"%s", _( "unable to open GIF file" ) ); 
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

} VipsForeignLoadGifBuffer;

typedef VipsForeignLoadGifClass VipsForeignLoadGifBufferClass;

G_DEFINE_TYPE( VipsForeignLoadGifBuffer, vips_foreign_load_gif_buffer, 
	vips_foreign_load_gif_get_type() );

static int
vips_foreign_load_gif_buffer_header( VipsForeignLoad *load )
{
	VipsForeignLoadGif *gif = (VipsForeignLoadGif *) load;
	VipsForeignLoadGifBuffer *buffer = 
		(VipsForeignLoadGifBuffer *) load;

	/*
	if( !(gif->page = rgif_handle_new_from_data( 
		buffer->buf->data, buffer->buf->length, &error )) ) { 
		vips_g_error( &error );
		return( -1 ); 
	}
	 */

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

