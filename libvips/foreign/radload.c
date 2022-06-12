/* load radlab from a file
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
#include <glib/gi18n-lib.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vips/vips.h>
#include <vips/buf.h>
#include <vips/internal.h>

#include "pforeign.h"

#ifdef HAVE_RADIANCE

typedef struct _VipsForeignLoadRad {
	VipsForeignLoad parent_object;

	/* Set by subclasses.
	 */
	VipsSource *source;

} VipsForeignLoadRad;

typedef VipsForeignLoadClass VipsForeignLoadRadClass;

G_DEFINE_ABSTRACT_TYPE( VipsForeignLoadRad, vips_foreign_load_rad, 
	VIPS_TYPE_FOREIGN_LOAD );

static void
vips_foreign_load_rad_dispose( GObject *gobject )
{
	VipsForeignLoadRad *rad = (VipsForeignLoadRad *) gobject;

	VIPS_UNREF( rad->source );

	G_OBJECT_CLASS( vips_foreign_load_rad_parent_class )->
		dispose( gobject );
}

static VipsForeignFlags
vips_foreign_load_rad_get_flags( VipsForeignLoad *load )
{
	return( VIPS_FOREIGN_SEQUENTIAL );
}

static VipsForeignFlags
vips_foreign_load_rad_get_flags_filename( const char *filename )
{
	return( VIPS_FOREIGN_SEQUENTIAL );
}

static int
vips_foreign_load_rad_header( VipsForeignLoad *load )
{
	VipsForeignLoadRad *rad = (VipsForeignLoadRad *) load;

	if( vips__rad_header( rad->source, load->out ) )
		return( -1 );

	return( 0 );
}

static int
vips_foreign_load_rad_load( VipsForeignLoad *load )
{
	VipsForeignLoadRad *rad = (VipsForeignLoadRad *) load;

	if( vips__rad_load( rad->source, load->real ) )
		return( -1 );

	return( 0 );
}

static void
vips_foreign_load_rad_class_init( VipsForeignLoadRadClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsOperationClass *operation_class = VIPS_OPERATION_CLASS( class );
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->dispose = vips_foreign_load_rad_dispose;

	object_class->nickname = "radload_base";
	object_class->description = _( "load rad base class" );

	/* You're unlikely to want to use this on untrusted files.
	 */
	operation_class->flags |= VIPS_OPERATION_UNTRUSTED;

	/* is_a() is not that quick ... lower the priority.
	 */
	foreign_class->priority = -50;

	load_class->get_flags_filename = 
		vips_foreign_load_rad_get_flags_filename;
	load_class->get_flags = vips_foreign_load_rad_get_flags;
	load_class->header = vips_foreign_load_rad_header;
	load_class->load = vips_foreign_load_rad_load;

}

static void
vips_foreign_load_rad_init( VipsForeignLoadRad *rad )
{
}

typedef struct _VipsForeignLoadRadSource {
	VipsForeignLoadRad parent_object;

	/* Load from a source.
	 */
	VipsSource *source;

} VipsForeignLoadRadSource;

typedef VipsForeignLoadRadClass VipsForeignLoadRadSourceClass;

G_DEFINE_TYPE( VipsForeignLoadRadSource, vips_foreign_load_rad_source, 
	vips_foreign_load_rad_get_type() );

static int
vips_foreign_load_rad_source_build( VipsObject *object )
{
	VipsForeignLoadRad *rad = (VipsForeignLoadRad *) object;
	VipsForeignLoadRadSource *source = (VipsForeignLoadRadSource *) object;

	if( source->source ) {
		rad->source = source->source;
		g_object_ref( rad->source );
	}

	if( VIPS_OBJECT_CLASS( vips_foreign_load_rad_source_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

static gboolean
vips_foreign_load_rad_source_is_a_source( VipsSource *source )
{
	return( vips__rad_israd( source ) );
}

static void
vips_foreign_load_rad_source_class_init( VipsForeignLoadRadSourceClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsOperationClass *operation_class = VIPS_OPERATION_CLASS( class );
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "radload_source";
	object_class->description = _( "load rad from source" );
	object_class->build = vips_foreign_load_rad_source_build;

	operation_class->flags |= VIPS_OPERATION_NOCACHE;

	load_class->is_a_source = vips_foreign_load_rad_source_is_a_source;

	VIPS_ARG_OBJECT( class, "source", 1,
		_( "Source" ),
		_( "Source to load from" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignLoadRadSource, source ),
		VIPS_TYPE_SOURCE );

}

static void
vips_foreign_load_rad_source_init( VipsForeignLoadRadSource *source )
{
}

typedef struct _VipsForeignLoadRadFile {
	VipsForeignLoadRad parent_object;

	/* Filename for load.
	 */
	char *filename; 

} VipsForeignLoadRadFile;

typedef VipsForeignLoadRadClass VipsForeignLoadRadFileClass;

G_DEFINE_TYPE( VipsForeignLoadRadFile, vips_foreign_load_rad_file, 
	vips_foreign_load_rad_get_type() );

static int
vips_foreign_load_rad_file_build( VipsObject *object )
{
	VipsForeignLoadRad *rad = (VipsForeignLoadRad *) object;
	VipsForeignLoadRadFile *file = (VipsForeignLoadRadFile *) object;

	if( file->filename &&
		!(rad->source = vips_source_new_from_file( file->filename )) )
		return( -1 );

	if( VIPS_OBJECT_CLASS( vips_foreign_load_rad_file_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

static int
vips_foreign_load_rad_file_is_a( const char *filename )
{
	VipsSource *source;
	int result;

	if( !(source = vips_source_new_from_file( filename )) )
		return( -1 );
	result = vips_foreign_load_rad_source_is_a_source( source );
	VIPS_UNREF( source );

	return( result );
}

static void
vips_foreign_load_rad_file_class_init( VipsForeignLoadRadFileClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "radload";
	object_class->description = _( "load a Radiance image from a file" );
	object_class->build = vips_foreign_load_rad_file_build;

	foreign_class->suffs = vips__rad_suffs;

	load_class->is_a = vips_foreign_load_rad_file_is_a;

	VIPS_ARG_STRING( class, "filename", 1, 
		_( "Filename" ),
		_( "Filename to load from" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignLoadRadFile, filename ),
		NULL );
}

static void
vips_foreign_load_rad_file_init( VipsForeignLoadRadFile *file )
{
}

typedef struct _VipsForeignLoadRadBuffer {
	VipsForeignLoadRad parent_object;

	/* Load from a buffer.
	 */
	VipsBlob *blob;

} VipsForeignLoadRadBuffer;

typedef VipsForeignLoadRadClass VipsForeignLoadRadBufferClass;

G_DEFINE_TYPE( VipsForeignLoadRadBuffer, vips_foreign_load_rad_buffer, 
	vips_foreign_load_rad_get_type() );

static int
vips_foreign_load_rad_buffer_build( VipsObject *object )
{
	VipsForeignLoadRad *rad = (VipsForeignLoadRad *) object;
	VipsForeignLoadRadBuffer *buffer = (VipsForeignLoadRadBuffer *) object;

	if( buffer->blob &&
		!(rad->source = vips_source_new_from_memory( 
			VIPS_AREA( buffer->blob )->data, 
			VIPS_AREA( buffer->blob )->length )) )
		return( -1 );

	if( VIPS_OBJECT_CLASS( vips_foreign_load_rad_file_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

static gboolean
vips_foreign_load_rad_buffer_is_a_buffer( const void *buf, size_t len )
{
	VipsSource *source;
	gboolean result;

	if( !(source = vips_source_new_from_memory( buf, len )) )
		return( FALSE );
	result = vips_foreign_load_rad_source_is_a_source( source );
	VIPS_UNREF( source );

	return( result );
}

static void
vips_foreign_load_rad_buffer_class_init( VipsForeignLoadRadBufferClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "radload_buffer";
	object_class->description = _( "load rad from buffer" );
	object_class->build = vips_foreign_load_rad_buffer_build;

	load_class->is_a_buffer = vips_foreign_load_rad_buffer_is_a_buffer;

	VIPS_ARG_BOXED( class, "buffer", 1, 
		_( "Buffer" ),
		_( "Buffer to load from" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignLoadRadBuffer, blob ),
		VIPS_TYPE_BLOB );

}

static void
vips_foreign_load_rad_buffer_init( VipsForeignLoadRadBuffer *buffer )
{
}

#endif /*HAVE_RADIANCE*/

/**
 * vips_radload:
 * @filename: file to load
 * @out: (out): output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Read a Radiance (HDR) file into a VIPS image. 
 *
 * Radiance files are read as #VIPS_CODING_RAD. They have one byte for each of
 * red, green and blue, and one byte of shared exponent. Some operations (like
 * vips_extract_area()) can work directly with images in this format, but 
 * mmany (all the arithmetic operations, for example) will not. Unpack 
 * #VIPS_CODING_RAD images to 3 band float with vips_rad2float() if 
 * you want to do arithmetic on them.
 *
 * This operation ignores some header fields, like VIEW and DATE. It will not 
 * rotate/flip as the FORMAT string asks.
 *
 * Sections of this reader from Greg Ward and Radiance with kind permission. 
 *
 * See also: vips_image_new_from_file().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_radload( const char *filename, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "radload", ap, filename, out ); 
	va_end( ap );

	return( result );
}

/**
 * vips_radload_buffer:
 * @buf: (array length=len) (element-type guint8): memory area to load
 * @len: (type gsize): size of memory area
 * @out: (out): image to write
 * @...: %NULL-terminated list of optional named arguments
 *
 * Exactly as vips_radload(), but read from a HDR-formatted memory block.
 *
 * You must not free the buffer while @out is active. The 
 * #VipsObject::postclose signal on @out is a good place to free. 
 *
 * See also: vips_radload().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_radload_buffer( void *buf, size_t len, VipsImage **out, ... )
{
	va_list ap;
	VipsBlob *blob;
	int result;

	/* We don't take a copy of the data or free it.
	 */
	blob = vips_blob_new( NULL, buf, len );

	va_start( ap, out );
	result = vips_call_split( "radload_buffer", ap, blob, out );
	va_end( ap );

	vips_area_unref( VIPS_AREA( blob ) );

	return( result );
}

/**
 * vips_radload_source:
 * @source: source to load from
 * @out: (out): output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Exactly as vips_radload(), but read from a source. 
 *
 * See also: vips_radload().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_radload_source( VipsSource *source, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "radload_source", ap, source, out );
	va_end( ap );

	return( result );
}

