/* load a GIF with libnsgif
 *
 * 6/10/18
 * 	- from gifload.c
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>

#include <vips/vips.h>
#include <vips/buf.h>
#include <vips/internal.h>
#include <vips/debug.h>

#ifdef HAVE_LIBNSGIF

#include <libnsgif/libnsgif.h>

typedef struct _VipsForeignLoadGif {
	VipsForeignLoad parent_object;

	/* Load this page (frame number).
	 */
	int page;

	/* Load this many pages.
	 */
	int n;

	/* The animation created by libnsgif.
	 */
	gif_animation *gif;

	/* The data/size pair we pass to libnsgif.
	 */
	size_t size;
	unsigned char *data;

} VipsForeignLoadGif;

typedef VipsForeignLoadClass VipsForeignLoadGifClass;

G_DEFINE_ABSTRACT_TYPE( VipsForeignLoadGif, vips_foreign_load_gif, 
	VIPS_TYPE_FOREIGN_LOAD );

static const char *
vips_foreign_load_gif_errstr( gif_result result )
{
	switch( result ) {
	case GIF_WORKING:
		return( _( "Working" ) ); 

	case GIF_OK:
		return( _( "OK" ) ); 

	case GIF_INSUFFICIENT_FRAME_DATA:
		return( _( "Insufficient data to complete frame" ) ); 

	case GIF_FRAME_DATA_ERROR:
		return( _( "GIF frame data error" ) ); 

	case GIF_INSUFFICIENT_DATA:
		return( _( "Insufficient data to do anything" ) ); 

	case GIF_DATA_ERROR:
		return( _( "GIF header data error" ) ); 

	case GIF_INSUFFICIENT_MEMORY:
		return( _( "Insuficient memory to process" ) ); 

	case GIF_FRAME_NO_DISPLAY:
		return( _( "No display" ) ); 

	case GIF_END_OF_FRAME:
		return( _( "At end of frame" ) ); 

	default:
		return( _( "Unknown error" ) ); 
	}
}

static void
vips_foreign_load_gif_dispose( GObject *gobject )
{
	VipsForeignLoadGif *gif = (VipsForeignLoadGif *) gobject;

	VIPS_FREEF( gif_finalise, gif->gif );

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

	if( vips__get_bytes( filename, buf, 4 ) == 4 &&
		vips_foreign_load_gif_is_a_buffer( buf, 4 ) )
		return( 1 );

	return( 0 );
}

static void *
vips_foreign_load_gif_bitmap_create( int width, int height )
{
        /* ensure a stupidly large bitmap is not created */

        return calloc(width * height, 4);
}

static void 
vips_foreign_load_gif_bitmap_set_opaque( void *bitmap, bool opaque )
{
        (void) opaque;  /* unused */
        (void) bitmap;  /* unused */
        g_assert(bitmap);
}

static bool 
vips_foreign_load_gif_bitmap_test_opaque( void *bitmap )
{
        (void) bitmap;  /* unused */
        g_assert(bitmap);
        return false;
}

static unsigned char *
vips_foreign_load_gif_bitmap_get_buffer( void *bitmap )
{
        g_assert(bitmap);
        return bitmap;
}

static void 
vips_foreign_load_gif_bitmap_destroy( void *bitmap )
{
        g_assert(bitmap);
        free(bitmap);
}

static void 
vips_foreign_load_gif_bitmap_modified( void *bitmap )
{
        (void) bitmap;  /* unused */
        g_assert(bitmap);
        return;
}

static gif_bitmap_callback_vt vips_foreign_load_gif_bitmap_callbacks = {
	vips_foreign_load_gif_bitmap_create,
	vips_foreign_load_gif_bitmap_destroy,
	vips_foreign_load_gif_bitmap_get_buffer,
	vips_foreign_load_gif_bitmap_set_opaque,
	vips_foreign_load_gif_bitmap_test_opaque,
	vips_foreign_load_gif_bitmap_modified
};

static int
vips_foreign_load_gif_load( VipsForeignLoad *load )
{
	VipsForeignLoadGif *gif = (VipsForeignLoadGif *) load;
	VipsImage **t = (VipsImage **) 
		vips_object_local_array( VIPS_OBJECT( load ), 4 );

	gif_result result;
	VipsImage *im;

	if( !(gif->gif = VIPS_NEW( load, gif_animation )) )
		return( -1 );
	gif_create( gif->gif, &vips_foreign_load_gif_bitmap_callbacks );

	/* Decode entire GIF.
	 *
	 * FIXME ... add progressive decode.
	 *
	 * FIXME ... only decode as far as we need for the selected page
	 *
	 */
        do {
                result = gif_initialise( gif->gif, gif->size, gif->data );
                if( result != GIF_OK && 
			result != GIF_WORKING ) 
                        return 1;
        } while( result != GIF_OK );

	/* Render from libnsgif memory areas into output image.
	 */

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
	object_class->description = _( "load GIF with libnsgif" );

	load_class->get_flags_filename = 
		vips_foreign_load_gif_get_flags_filename;
	load_class->get_flags = vips_foreign_load_gif_get_flags;

	VIPS_ARG_INT( class, "page", 10,
		_( "Page" ),
		_( "Load this page from the file" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignLoadGif, page ),
		0, 100000, 0 );

	VIPS_ARG_INT( class, "n", 6,
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

	/* mmap the file.
	 */
	        if( vips_rawload( filename, &t[0],
                        out->Xsize, out->Ysize, VIPS_IMAGE_SIZEOF_PEL( out ),
                        "offset", header_offset,
                        NULL ) ||


	if( vips_foreign_load_gif_open( gif, file->filename ) ) 
		return( -1 ); 

	VIPS_SETSTR( load->out->filename, file->filename );

	return( vips_foreign_load_gif_load( load ) );
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
	object_class->description = _( "load GIF with libnsgif" );

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
vips_giflib_buffer_read( GifFileType *file, GifByteType *buf, int n )
{
	VipsForeignLoadGifBuffer *buffer = 
		(VipsForeignLoadGifBuffer *) file->UserData;
	size_t will_read = VIPS_MIN( n, buffer->bytes_to_go );

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

	if( vips_foreign_load_gif_open_buffer( gif, vips_giflib_buffer_read ) ) 
		return( -1 ); 

	return( vips_foreign_load_gif_load( load ) );
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
	object_class->description = _( "load GIF with libnsgif" );

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

#endif /*HAVE_LIBNSGIF*/
