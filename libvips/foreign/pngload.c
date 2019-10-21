/* load png from a file
 *
 * 5/12/11
 * 	- from tiffload.c
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vips/vips.h>
#include <vips/buf.h>
#include <vips/internal.h>

#include "pforeign.h"

#ifdef HAVE_PNG

typedef struct _VipsForeignLoadPngStream {
	VipsForeignLoad parent_object;

	/* Load from a stream.
	 */
	VipsStreami *input;

} VipsForeignLoadPngStream;

typedef VipsForeignLoadClass VipsForeignLoadPngStreamClass;

G_DEFINE_TYPE( VipsForeignLoadPngStream, vips_foreign_load_png_stream, 
	VIPS_TYPE_FOREIGN_LOAD );

static VipsForeignFlags
vips_foreign_load_png_stream_get_flags( VipsForeignLoad *load )
{
	VipsForeignLoadPngStream *stream = (VipsForeignLoadPngStream *) load;

	VipsForeignFlags flags;

	flags = 0;
	if( vips__png_isinterlaced_stream( stream->input ) )
		flags |= VIPS_FOREIGN_PARTIAL;
	else
		flags |= VIPS_FOREIGN_SEQUENTIAL;

	return( flags );
}

static int
vips_foreign_load_png_stream_header( VipsForeignLoad *load )
{
	VipsForeignLoadPngStream *stream = (VipsForeignLoadPngStream *) load;

	if( vips__png_header_stream( stream->input, load->out ) )
		return( -1 );

	return( 0 );
}

static int
vips_foreign_load_png_stream_load( VipsForeignLoad *load )
{
	VipsForeignLoadPngStream *stream = (VipsForeignLoadPngStream *) load;

	if( vips__png_read_stream( stream->input, load->real, load->fail ) )
		return( -1 );

	return( 0 );
}

static void
vips_foreign_load_png_stream_class_init( VipsForeignLoadPngStreamClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "pngload_stream";
	object_class->description = _( "load png from stream" );

	load_class->is_a_stream = vips__png_ispng_stream;
	load_class->get_flags = vips_foreign_load_png_stream_get_flags;
	load_class->header = vips_foreign_load_png_stream_header;
	load_class->load = vips_foreign_load_png_stream_load;

	VIPS_ARG_OBJECT( class, "input", 1,
		_( "Input" ),
		_( "Stream to load from" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignLoadPngStream, input ),
		VIPS_TYPE_STREAM_INPUT );

}

static void
vips_foreign_load_png_stream_init( VipsForeignLoadPngStream *stream )
{
}

typedef struct _VipsForeignLoadPng {
	VipsForeignLoad parent_object;

	/* Filename for load.
	 */
	char *filename; 

} VipsForeignLoadPng;

typedef VipsForeignLoadClass VipsForeignLoadPngClass;

G_DEFINE_TYPE( VipsForeignLoadPng, vips_foreign_load_png, 
	VIPS_TYPE_FOREIGN_LOAD );

static gboolean
vips_foreign_load_png_is_a( const char *filename )
{
	VipsStreami *input;
	gboolean result;

	if( !(input = vips_stream_input_new_from_filename( filename )) )
		return( FALSE );
	result = vips__png_ispng_stream( input );
	VIPS_UNREF( input );

	return( result );
}

static VipsForeignFlags
vips_foreign_load_png_get_flags_filename( const char *filename )
{
	VipsStreami *input;
	VipsForeignFlags flags;

	if( !(input = vips_stream_input_new_from_filename( filename )) )
		return( 0 );

	flags = 0;
	if( vips__png_isinterlaced_stream( input ) )
		flags |= VIPS_FOREIGN_PARTIAL;
	else
		flags |= VIPS_FOREIGN_SEQUENTIAL;

	VIPS_UNREF( input );

	return( flags );
}

static VipsForeignFlags
vips_foreign_load_png_get_flags( VipsForeignLoad *load )
{
	VipsForeignLoadPng *png = (VipsForeignLoadPng *) load;

	return( vips_foreign_load_png_get_flags_filename( png->filename ) ); 
}

static int
vips_foreign_load_png_header( VipsForeignLoad *load )
{
	VipsForeignLoadPng *png = (VipsForeignLoadPng *) load;

	VipsStreami *input;

	if( !(input = vips_stream_input_new_from_filename( png->filename )) )
		return( -1 );
	if( vips__png_header_stream( input, load->out ) ) {
		VIPS_UNREF( input );
		return( -1 );
	}
	VIPS_UNREF( input );

	return( 0 );
}

static int
vips_foreign_load_png_load( VipsForeignLoad *load )
{
	VipsForeignLoadPng *png = (VipsForeignLoadPng *) load;

	VipsStreami *input;

	if( !(input = vips_stream_input_new_from_filename( png->filename )) )
		return( -1 );
	if( vips__png_read_stream( input, load->real, load->fail ) ) {
		VIPS_UNREF( input );
		return( -1 );
	}
	VIPS_UNREF( input );

	return( 0 );
}

static void
vips_foreign_load_png_class_init( VipsForeignLoadPngClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "pngload";
	object_class->description = _( "load png from file" );

	foreign_class->suffs = vips__png_suffs;

	/* We are fast at is_a(), so high priority.
	 */
	foreign_class->priority = 200;

	load_class->is_a = vips_foreign_load_png_is_a;
	load_class->get_flags_filename = 
		vips_foreign_load_png_get_flags_filename;
	load_class->get_flags = vips_foreign_load_png_get_flags;
	load_class->header = vips_foreign_load_png_header;
	load_class->load = vips_foreign_load_png_load;

	VIPS_ARG_STRING( class, "filename", 1, 
		_( "Filename" ),
		_( "Filename to load from" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignLoadPng, filename ),
		NULL );
}

static void
vips_foreign_load_png_init( VipsForeignLoadPng *png )
{
}

typedef struct _VipsForeignLoadPngBuffer {
	VipsForeignLoad parent_object;

	/* Load from a buffer.
	 */
	VipsArea *buf;

} VipsForeignLoadPngBuffer;

typedef VipsForeignLoadClass VipsForeignLoadPngBufferClass;

G_DEFINE_TYPE( VipsForeignLoadPngBuffer, vips_foreign_load_png_buffer, 
	VIPS_TYPE_FOREIGN_LOAD );

static gboolean
vips_foreign_load_png_buffer_is_a_buffer( const void *buf, size_t len )
{
	VipsStreami *input;
	gboolean result;

	if( !(input = vips_stream_input_new_from_memory( buf, len )) )
		return( FALSE );
	result = vips__png_ispng_stream( input );
	VIPS_UNREF( input );

	return( result );
}

static VipsForeignFlags
vips_foreign_load_png_buffer_get_flags( VipsForeignLoad *load )
{
	VipsForeignLoadPngBuffer *buffer = (VipsForeignLoadPngBuffer *) load;

	VipsStreami *input;
	VipsForeignFlags flags;

	if( !(input = vips_stream_input_new_from_memory( buffer->buf->data, 
		buffer->buf->length )) ) 
		return( 0 );

	flags = 0;
	if( vips__png_isinterlaced_stream( input ) )
		flags |= VIPS_FOREIGN_PARTIAL;
	else
		flags |= VIPS_FOREIGN_SEQUENTIAL;

	VIPS_UNREF( input );

	return( flags );
}

static int
vips_foreign_load_png_buffer_header( VipsForeignLoad *load )
{
	VipsForeignLoadPngBuffer *buffer = (VipsForeignLoadPngBuffer *) load;

	VipsStreami *input;

	if( !(input = vips_stream_input_new_from_memory( buffer->buf->data, 
		buffer->buf->length )) ) 
		return( -1 );
	if( vips__png_header_stream( input, load->out ) ) {
		VIPS_UNREF( input );
		return( -1 );
	}
	VIPS_UNREF( input );

	return( 0 );
}

static int
vips_foreign_load_png_buffer_load( VipsForeignLoad *load )
{
	VipsForeignLoadPngBuffer *buffer = (VipsForeignLoadPngBuffer *) load;

	VipsStreami *input;

	if( !(input = vips_stream_input_new_from_memory( buffer->buf->data, 
		buffer->buf->length )) ) 
		return( -1 );
	if( vips__png_read_stream( input, load->real, load->fail ) ) {
		VIPS_UNREF( input );
		return( -1 );
	}
	VIPS_UNREF( input );

	return( 0 );
}

static void
vips_foreign_load_png_buffer_class_init( VipsForeignLoadPngBufferClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "pngload_buffer";
	object_class->description = _( "load png from buffer" );

	load_class->is_a_buffer = vips_foreign_load_png_buffer_is_a_buffer;
	load_class->get_flags = vips_foreign_load_png_buffer_get_flags;
	load_class->header = vips_foreign_load_png_buffer_header;
	load_class->load = vips_foreign_load_png_buffer_load;

	VIPS_ARG_BOXED( class, "buffer", 1, 
		_( "Buffer" ),
		_( "Buffer to load from" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignLoadPngBuffer, buf ),
		VIPS_TYPE_BLOB );

}

static void
vips_foreign_load_png_buffer_init( VipsForeignLoadPngBuffer *buffer )
{
}

#endif /*HAVE_PNG*/

/**
 * vips_pngload:
 * @filename: file to load
 * @out: (out): decompressed image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Read a PNG file into a VIPS image. It can read all png images, including 8-
 * and 16-bit images, 1 and 3 channel, with and without an alpha channel.
 *
 * Any ICC profile is read and attached to the VIPS image. It also supports
 * XMP metadata.
 *
 * See also: vips_image_new_from_file().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_pngload( const char *filename, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "pngload", ap, filename, out );
	va_end( ap );

	return( result );
}

/**
 * vips_pngload_buffer:
 * @buf: (array length=len) (element-type guint8): memory area to load
 * @len: (type gsize): size of memory area
 * @out: (out): image to write
 * @...: %NULL-terminated list of optional named arguments
 *
 * Exactly as vips_pngload(), but read from a PNG-formatted memory block.
 *
 * You must not free the buffer while @out is active. The 
 * #VipsObject::postclose signal on @out is a good place to free. 
 *
 * See also: vips_pngload().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_pngload_buffer( void *buf, size_t len, VipsImage **out, ... )
{
	va_list ap;
	VipsBlob *blob;
	int result;

	/* We don't take a copy of the data or free it.
	 */
	blob = vips_blob_new( NULL, buf, len );

	va_start( ap, out );
	result = vips_call_split( "pngload_buffer", ap, blob, out );
	va_end( ap );

	vips_area_unref( VIPS_AREA( blob ) );

	return( result );
}

/**
 * vips_pngload_stream:
 * @input: stream to load from
 * @out: (out): image to write
 * @...: %NULL-terminated list of optional named arguments
 *
 * Exactly as vips_pngload(), but read from a stream. 
 *
 * See also: vips_pngload().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_pngload_stream( VipsStreami *input, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "pngload_stream", ap, input, out );
	va_end( ap );

	return( result );
}
