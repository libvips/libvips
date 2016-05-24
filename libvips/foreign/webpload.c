/* load webp images
 *
 * 6/8/13
 * 	- from pngload.c
 * 28/2/16
 * 	- add @shrink
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
#define DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <string.h>

#include <vips/vips.h>

#ifdef HAVE_LIBWEBP

#include "webp.h"

typedef struct _VipsForeignLoadWebp {
	VipsForeignLoad parent_object;

	/* Shrink by this much during load.
	 */
	int shrink; 
} VipsForeignLoadWebp;

typedef VipsForeignLoadClass VipsForeignLoadWebpClass;

G_DEFINE_ABSTRACT_TYPE( VipsForeignLoadWebp, vips_foreign_load_webp, 
	VIPS_TYPE_FOREIGN_LOAD );

static VipsForeignFlags
vips_foreign_load_webp_get_flags( VipsForeignLoad *load )
{
	return( 0 );
}

static int
vips_foreign_load_webp_build( VipsObject *object )
{
	if( VIPS_OBJECT_CLASS( vips_foreign_load_webp_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

static void
vips_foreign_load_webp_class_init( VipsForeignLoadWebpClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "webpload_base";
	object_class->description = _( "load webp" );
	object_class->build = vips_foreign_load_webp_build;

	load_class->get_flags = vips_foreign_load_webp_get_flags;

	VIPS_ARG_INT( class, "shrink", 10, 
		_( "Shrink" ), 
		_( "Shrink factor on load" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignLoadWebp, shrink ),
		1, 1024, 1 );

}

static void
vips_foreign_load_webp_init( VipsForeignLoadWebp *webp )
{
	webp->shrink = 1;
}

typedef struct _VipsForeignLoadWebpFile {
	VipsForeignLoadWebp parent_object;

	/* Filename for load.
	 */
	char *filename; 

} VipsForeignLoadWebpFile;

typedef VipsForeignLoadWebpClass VipsForeignLoadWebpFileClass;

G_DEFINE_TYPE( VipsForeignLoadWebpFile, vips_foreign_load_webp_file, 
	vips_foreign_load_webp_get_type() );

static VipsForeignFlags
vips_foreign_load_webp_file_get_flags_filename( const char *filename )
{
	return( 0 );
}

static gboolean
vips_foreign_load_webp_file_is_a( const char *filename )
{
	return( vips__iswebp( filename ) );
}

static int
vips_foreign_load_webp_file_header( VipsForeignLoad *load )
{
	VipsForeignLoadWebp *webp = (VipsForeignLoadWebp *) load;
	VipsForeignLoadWebpFile *file = (VipsForeignLoadWebpFile *) load;

	if( vips__webp_read_file_header( file->filename, load->out, 
		webp->shrink ) )
		return( -1 );

	VIPS_SETSTR( load->out->filename, file->filename );

	return( 0 );
}

static int
vips_foreign_load_webp_file_load( VipsForeignLoad *load )
{
	VipsForeignLoadWebp *webp = (VipsForeignLoadWebp *) load;
	VipsForeignLoadWebpFile *file = (VipsForeignLoadWebpFile *) load;

	if( vips__webp_read_file( file->filename, load->real, webp->shrink ) )
		return( -1 );

	return( 0 );
}

const char *vips__webp_suffs[] = { ".webp", NULL };

static void
vips_foreign_load_webp_file_class_init( VipsForeignLoadWebpFileClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "webpload";
	object_class->description = _( "load webp from file" );

	foreign_class->suffs = vips__webp_suffs;

	load_class->get_flags_filename = 
		vips_foreign_load_webp_file_get_flags_filename;
	load_class->is_a = vips_foreign_load_webp_file_is_a;
	load_class->header = vips_foreign_load_webp_file_header;
	load_class->load = vips_foreign_load_webp_file_load;

	VIPS_ARG_STRING( class, "filename", 1, 
		_( "Filename" ),
		_( "Filename to load from" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignLoadWebpFile, filename ),
		NULL );
}

static void
vips_foreign_load_webp_file_init( VipsForeignLoadWebpFile *file )
{
}

typedef struct _VipsForeignLoadWebpBuffer {
	VipsForeignLoadWebp parent_object;

	/* Load from a buffer.
	 */
	VipsArea *buf;

} VipsForeignLoadWebpBuffer;

typedef VipsForeignLoadWebpClass VipsForeignLoadWebpBufferClass;

G_DEFINE_TYPE( VipsForeignLoadWebpBuffer, vips_foreign_load_webp_buffer, 
	vips_foreign_load_webp_get_type() );

static int
vips_foreign_load_webp_buffer_header( VipsForeignLoad *load )
{
	VipsForeignLoadWebp *webp = (VipsForeignLoadWebp *) load;
	VipsForeignLoadWebpBuffer *buffer = (VipsForeignLoadWebpBuffer *) load;

	if( vips__webp_read_buffer_header( buffer->buf->data, 
		buffer->buf->length, load->out, webp->shrink ) )
		return( -1 );

	return( 0 );
}

static int
vips_foreign_load_webp_buffer_load( VipsForeignLoad *load )
{
	VipsForeignLoadWebp *webp = (VipsForeignLoadWebp *) load;
	VipsForeignLoadWebpBuffer *buffer = (VipsForeignLoadWebpBuffer *) load;

	if( vips__webp_read_buffer( buffer->buf->data, buffer->buf->length, 
		load->real, webp->shrink ) )
		return( -1 );

	return( 0 );
}

static void
vips_foreign_load_webp_buffer_class_init( 
	VipsForeignLoadWebpBufferClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "webpload_buffer";
	object_class->description = _( "load webp from buffer" );

	/* is_a() is not that quick ... lower the priority.
	 */
	foreign_class->priority = -50;

	load_class->is_a_buffer = vips__iswebp_buffer; 
	load_class->header = vips_foreign_load_webp_buffer_header;
	load_class->load = vips_foreign_load_webp_buffer_load;

	VIPS_ARG_BOXED( class, "buffer", 1, 
		_( "Buffer" ),
		_( "Buffer to load from" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignLoadWebpBuffer, buf ),
		VIPS_TYPE_BLOB );
}

static void
vips_foreign_load_webp_buffer_init( VipsForeignLoadWebpBuffer *buffer )
{
}

#endif /*HAVE_LIBWEBP*/

/**
 * vips_webpload:
 * @filename: file to load
 * @out: decompressed image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @shrink: %gint, shrink by this much on load
 *
 * Read a WebP file into a VIPS image. 
 *
 * Use @shrink to specify a shrink-on-load factor.
 *
 * See also: vips_image_new_from_file().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_webpload( const char *filename, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "webpload", ap, filename, out );
	va_end( ap );

	return( result );
}

/**
 * vips_webpload_buffer:
 * @buf: memory area to load
 * @len: size of memory area
 * @out: image to write
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @shrink: %gint, shrink by this much on load
 *
 * Read a WebP-formatted memory block into a VIPS image. Exactly as
 * vips_webpload(), but read from a memory buffer. 
 *
 * You must not free the buffer while @out is active. The 
 * #VipsObject::postclose signal on @out is a good place to free. 
 *
 * See also: vips_webpload()
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_webpload_buffer( void *buf, size_t len, VipsImage **out, ... )
{
	va_list ap;
	VipsBlob *blob;
	int result;

	/* We don't take a copy of the data or free it.
	 */
	blob = vips_blob_new( NULL, buf, len );

	va_start( ap, out );
	result = vips_call_split( "webpload_buffer", ap, blob, out );
	va_end( ap );

	vips_area_unref( VIPS_AREA( blob ) );

	return( result );
}
