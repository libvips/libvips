/* load png from a file
 *
 * 5/12/11
 * 	- from tiffload.c
 * 29/8/21 joshuamsager
 *	-  add "unlimited" flag to png load
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
#include <glib/gi18n-lib.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vips/vips.h>
#include <vips/buf.h>
#include <vips/internal.h>

#include "pforeign.h"

#if defined(HAVE_PNG)

typedef struct _VipsForeignLoadPng {
	VipsForeignLoad parent_object;

	/* Set by subclasses.
	 */
	VipsSource *source;

	/* remove all denial of service limits.
	 */
	gboolean unlimited;

} VipsForeignLoadPng;

typedef VipsForeignLoadClass VipsForeignLoadPngClass;

G_DEFINE_ABSTRACT_TYPE( VipsForeignLoadPng, vips_foreign_load_png, 
	VIPS_TYPE_FOREIGN_LOAD );

static void
vips_foreign_load_png_dispose( GObject *gobject )
{
	VipsForeignLoadPng *png = (VipsForeignLoadPng *) gobject;

	VIPS_UNREF( png->source );

	G_OBJECT_CLASS( vips_foreign_load_png_parent_class )->
		dispose( gobject );
}

static VipsForeignFlags
vips_foreign_load_png_get_flags_source( VipsSource *source )
{
	VipsForeignFlags flags;

	flags = 0;
	if( vips__png_isinterlaced_source( source ) )
		flags |= VIPS_FOREIGN_PARTIAL;
	else
		flags |= VIPS_FOREIGN_SEQUENTIAL;

	return( flags );
}

static VipsForeignFlags
vips_foreign_load_png_get_flags( VipsForeignLoad *load )
{
	VipsForeignLoadPng *png = (VipsForeignLoadPng *) load;

	return( vips_foreign_load_png_get_flags_source( png->source ) );
}

static VipsForeignFlags
vips_foreign_load_png_get_flags_filename( const char *filename )
{
	VipsSource *source;
	VipsForeignFlags flags;

	if( !(source = vips_source_new_from_file( filename )) )
		return( 0 );
	flags = vips_foreign_load_png_get_flags_source( source );
	VIPS_UNREF( source );

	return( flags );
}

static int
vips_foreign_load_png_header( VipsForeignLoad *load )
{
	VipsForeignLoadPng *png = (VipsForeignLoadPng *) load;

	if( vips__png_header_source( png->source, load->out, png->unlimited ) )
		return( -1 );

	return( 0 );
}

static int
vips_foreign_load_png_load( VipsForeignLoad *load )
{
	VipsForeignLoadPng *png = (VipsForeignLoadPng *) load;

	if( vips__png_read_source( png->source, load->real, 
		load->fail_on, png->unlimited ) )
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
	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

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

	VIPS_ARG_BOOL( class, "unlimited", 23,
		_( "Unlimited" ),
		_( "Remove all denial of service limits" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignLoadPng, unlimited ),
		FALSE );
}

static void
vips_foreign_load_png_init( VipsForeignLoadPng *png )
{
}

typedef struct _VipsForeignLoadPngSource {
	VipsForeignLoadPng parent_object;

	/* Load from a source.
	 */
	VipsSource *source;

} VipsForeignLoadPngSource;

typedef VipsForeignLoadPngClass VipsForeignLoadPngSourceClass;

G_DEFINE_TYPE( VipsForeignLoadPngSource, vips_foreign_load_png_source, 
	vips_foreign_load_png_get_type() );

static int
vips_foreign_load_png_source_build( VipsObject *object )
{
	VipsForeignLoadPng *png = (VipsForeignLoadPng *) object;
	VipsForeignLoadPngSource *source = (VipsForeignLoadPngSource *) object;

	if( source->source ) {
		png->source = source->source;
		g_object_ref( png->source );
	}

	if( VIPS_OBJECT_CLASS( vips_foreign_load_png_source_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

static gboolean
vips_foreign_load_png_source_is_a_source( VipsSource *source )
{
	return( vips__png_ispng_source( source ) );
}

static void
vips_foreign_load_png_source_class_init( VipsForeignLoadPngSourceClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsOperationClass *operation_class = VIPS_OPERATION_CLASS( class );
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "pngload_source";
	object_class->description = _( "load png from source" );
	object_class->build = vips_foreign_load_png_source_build;

	operation_class->flags |= VIPS_OPERATION_NOCACHE;

	load_class->is_a_source = vips_foreign_load_png_source_is_a_source;

	VIPS_ARG_OBJECT( class, "source", 1,
		_( "Source" ),
		_( "Source to load from" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignLoadPngSource, source ),
		VIPS_TYPE_SOURCE );

}

static void
vips_foreign_load_png_source_init( VipsForeignLoadPngSource *source )
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
		!(png->source = vips_source_new_from_file( file->filename )) )
		return( -1 );

	if( VIPS_OBJECT_CLASS( vips_foreign_load_png_file_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

static gboolean
vips_foreign_load_png_file_is_a( const char *filename )
{
	VipsSource *source;
	gboolean result;

	if( !(source = vips_source_new_from_file( filename )) )
		return( FALSE );
	result = vips_foreign_load_png_source_is_a_source( source );
	VIPS_UNREF( source );

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
	VipsBlob *blob;

} VipsForeignLoadPngBuffer;

typedef VipsForeignLoadPngClass VipsForeignLoadPngBufferClass;

G_DEFINE_TYPE( VipsForeignLoadPngBuffer, vips_foreign_load_png_buffer, 
	vips_foreign_load_png_get_type() );

static int
vips_foreign_load_png_buffer_build( VipsObject *object )
{
	VipsForeignLoadPng *png = (VipsForeignLoadPng *) object;
	VipsForeignLoadPngBuffer *buffer = (VipsForeignLoadPngBuffer *) object;

	if( buffer->blob &&
		!(png->source = vips_source_new_from_memory( 
			VIPS_AREA( buffer->blob )->data, 
			VIPS_AREA( buffer->blob )->length )) )
		return( -1 );

	if( VIPS_OBJECT_CLASS( vips_foreign_load_png_buffer_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

static gboolean
vips_foreign_load_png_buffer_is_a_buffer( const void *buf, size_t len )
{
	VipsSource *source;
	gboolean result;

	if( !(source = vips_source_new_from_memory( buf, len )) )
		return( FALSE );
	result = vips_foreign_load_png_source_is_a_source( source );
	VIPS_UNREF( source );

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
		G_STRUCT_OFFSET( VipsForeignLoadPngBuffer, blob ),
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
 * Optional arguments:
 *
 * * @fail_on: #VipsFailOn, types of read error to fail on
 * * @unlimited: %gboolean, remove all denial of service limits
 *
 * Read a PNG file into a VIPS image. It can read all png images, including 8-
 * and 16-bit images, 1 and 3 channel, with and without an alpha channel.
 *
 * Any ICC profile is read and attached to the VIPS image. It also supports
 * XMP metadata.
 *
 * Use @fail_on to set the type of error that will cause load to fail. By
 * default, loaders are permissive, that is, #VIPS_FAIL_ON_NONE.
 *
 * By default, the PNG loader limits the number of text and data chunks to 
 * block some denial of service attacks. Set @unlimited to disable these 
 * limits.
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
 * Optional arguments:
 *
 * * @fail_on: #VipsFailOn, types of read error to fail on
 * * @unlimited: %gboolean, Remove all denial of service limits
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
 * vips_pngload_source:
 * @source: source to load from
 * @out: (out): image to write
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @fail_on: #VipsFailOn, types of read error to fail on
 * * @unlimited: %gboolean, Remove all denial of service limits
 *
 * Exactly as vips_pngload(), but read from a source. 
 *
 * See also: vips_pngload().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_pngload_source( VipsSource *source, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "pngload_source", ap, source, out );
	va_end( ap );

	return( result );
}
