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

typedef struct _VipsForeignLoadPng {
	VipsForeignLoad parent_object;

	/* Set by subclasses.
	 */
	VipsStreami *streami;

} VipsForeignLoadPng;

typedef VipsForeignLoadClass VipsForeignLoadPngClass;

G_DEFINE_TYPE( VipsForeignLoadPng, vips_foreign_load_png, 
	VIPS_TYPE_FOREIGN_LOAD );

static void
vips_foreign_load_png_dispose( GObject *gobject )
{
	VipsForeignLoadPng *png = (VipsForeignLoadPng *) gobject;

	VIPS_UNREF( png->streami );

	G_OBJECT_CLASS( vips_foreign_load_png_parent_class )->
		dispose( gobject );
}

static VipsForeignFlags
vips_foreign_load_png_get_flags_stream( VipsStreami *streami )
{
	VipsForeignFlags flags;

	flags = 0;
	if( vips__png_isinterlaced_stream( streami ) )
		flags |= VIPS_FOREIGN_PARTIAL;
	else
		flags |= VIPS_FOREIGN_SEQUENTIAL;

	return( flags );
}

static VipsForeignFlags
vips_foreign_load_png_get_flags( VipsForeignLoad *load )
{
	VipsForeignLoadPng *png = (VipsForeignLoadPng *) load;

	return( vips_foreign_load_png_get_flags_stream( png->streami ) );
}

static VipsForeignFlags
vips_foreign_load_png_get_flags_filename( const char *filename )
{
	VipsStreami *streami;
	VipsForeignFlags flags;

	if( !(streami = vips_streami_new_from_file( filename )) )
		return( 0 );
	flags = vips_foreign_load_png_get_flags_stream( streami );
	VIPS_UNREF( streami );

	return( flags );
}

static int
vips_foreign_load_png_header( VipsForeignLoad *load )
{
	VipsForeignLoadPng *png = (VipsForeignLoadPng *) load;

	if( vips__png_header_stream( png->streami, load->out ) )
		return( -1 );

	return( 0 );
}

static int
vips_foreign_load_png_load( VipsForeignLoad *load )
{
	VipsForeignLoadPng *png = (VipsForeignLoadPng *) load;

	if( vips__png_read_stream( png->streami, load->real, load->fail ) )
		return( -1 );

	return( 0 );
}

static void
vips_foreign_load_png_class_init( VipsForeignLoadPngClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->dispose = vips_foreign_load_png_dispose;

	object_class->nickname = "pngload_base";
	object_class->description = _( "load png base class" );

	/* We are fast at is_a(), so high priority.
	 */
	foreign_class->priority = 200;

	load_class->get_flags_filename = 
		vips_foreign_load_png_get_flags_filename;
	load_class->get_flags = vips_foreign_load_png_get_flags;
	load_class->header = vips_foreign_load_png_header;
	load_class->load = vips_foreign_load_png_load;

}

static void
vips_foreign_load_png_init( VipsForeignLoadPng *png )
{
}

typedef struct _VipsForeignLoadPngStream {
	VipsForeignLoadPng parent_object;

	/* Load from a stream.
	 */
	VipsStreami *streami;

} VipsForeignLoadPngStream;

typedef VipsForeignLoadPngClass VipsForeignLoadPngStreamClass;

G_DEFINE_TYPE( VipsForeignLoadPngStream, vips_foreign_load_png_stream, 
	vips_foreign_load_png_get_type() );

static int
vips_foreign_load_png_stream_build( VipsObject *object )
{
	VipsForeignLoadPng *png = (VipsForeignLoadPng *) object;
	VipsForeignLoadPngStream *stream = (VipsForeignLoadPngStream *) object;

	if( stream->streami ) {
		png->streami = stream->streami;
		g_object_ref( png->streami );
	}

	if( VIPS_OBJECT_CLASS( vips_foreign_load_png_stream_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

static gboolean
vips_foreign_load_png_stream_is_a_stream( VipsStreami *streami )
{
	return( vips__png_ispng_stream( streami ) );
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
	object_class->build = vips_foreign_load_png_stream_build;

	load_class->is_a_stream = vips_foreign_load_png_stream_is_a_stream;

	VIPS_ARG_OBJECT( class, "streami", 1,
		_( "Streami" ),
		_( "Stream to load from" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignLoadPngStream, streami ),
		VIPS_TYPE_STREAMI );

}

static void
vips_foreign_load_png_stream_init( VipsForeignLoadPngStream *stream )
{
}

typedef struct _VipsForeignLoadPngFile {
	VipsForeignLoadPng parent_object;

	/* Filename for load.
	 */
	char *filename; 

} VipsForeignLoadPngFile;

typedef VipsForeignLoadPngClass VipsForeignLoadPngFileClass;

G_DEFINE_TYPE( VipsForeignLoadPngFile, vips_foreign_load_png_file, 
	vips_foreign_load_png_get_type() );

static int
vips_foreign_load_png_file_build( VipsObject *object )
{
	VipsForeignLoadPng *png = (VipsForeignLoadPng *) object;
	VipsForeignLoadPngFile *file = (VipsForeignLoadPngFile *) object;

	if( file->filename &&
		!(png->streami = vips_streami_new_from_file( file->filename )) )
		return( -1 );

	if( VIPS_OBJECT_CLASS( vips_foreign_load_png_file_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

static gboolean
vips_foreign_load_png_file_is_a( const char *filename )
{
	VipsStreami *streami;
	gboolean result;

	if( !(streami = vips_streami_new_from_file( filename )) )
		return( FALSE );
	result = vips_foreign_load_png_stream_is_a_stream( streami );
	VIPS_UNREF( streami );

	return( result );
}

static void
vips_foreign_load_png_file_class_init( VipsForeignLoadPngFileClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "pngload";
	object_class->description = _( "load png from file" );
	object_class->build = vips_foreign_load_png_file_build;

	foreign_class->suffs = vips__png_suffs;

	load_class->is_a = vips_foreign_load_png_file_is_a;

	VIPS_ARG_STRING( class, "filename", 1, 
		_( "Filename" ),
		_( "Filename to load from" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignLoadPngFile, filename ),
		NULL );
}

static void
vips_foreign_load_png_file_init( VipsForeignLoadPngFile *file )
{
}

typedef struct _VipsForeignLoadPngBuffer {
	VipsForeignLoadPng parent_object;

	/* Load from a buffer.
	 */
	VipsArea *buf;

} VipsForeignLoadPngBuffer;

typedef VipsForeignLoadPngClass VipsForeignLoadPngBufferClass;

G_DEFINE_TYPE( VipsForeignLoadPngBuffer, vips_foreign_load_png_buffer, 
	vips_foreign_load_png_get_type() );

static int
vips_foreign_load_png_buffer_build( VipsObject *object )
{
	VipsForeignLoadPng *png = (VipsForeignLoadPng *) object;
	VipsForeignLoadPngBuffer *buffer = (VipsForeignLoadPngBuffer *) object;

	if( buffer->buf &&
		!(png->streami = vips_streami_new_from_memory( 
			buffer->buf->data, buffer->buf->length )) )
		return( -1 );

	if( VIPS_OBJECT_CLASS( vips_foreign_load_png_buffer_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

static gboolean
vips_foreign_load_png_buffer_is_a_buffer( const void *buf, size_t len )
{
	VipsStreami *streami;
	gboolean result;

	if( !(streami = vips_streami_new_from_memory( buf, len )) )
		return( FALSE );
	result = vips_foreign_load_png_stream_is_a_stream( streami );
	VIPS_UNREF( streami );

	return( result );
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
	object_class->build = vips_foreign_load_png_buffer_build;

	load_class->is_a_buffer = vips_foreign_load_png_buffer_is_a_buffer;

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
 * @streami: stream to load from
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
vips_pngload_stream( VipsStreami *streami, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "pngload_stream", ap, streami, out );
	va_end( ap );

	return( result );
}
