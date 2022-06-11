/* load fits from a file
 *
 * 5/12/11
 * 	- from openslideload.c
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

#ifdef HAVE_CFITSIO

#include "pforeign.h"

typedef struct _VipsForeignLoadFits {
	VipsForeignLoad parent_object;

	/* Set by subclasses.
	 */
	VipsSource *source;

	/* Filename from source.
	 */
	const char *filename;

} VipsForeignLoadFits;

typedef VipsForeignLoadClass VipsForeignLoadFitsClass;

G_DEFINE_ABSTRACT_TYPE( VipsForeignLoadFits, vips_foreign_load_fits, 
	VIPS_TYPE_FOREIGN_LOAD );

static void
vips_foreign_load_fits_dispose( GObject *gobject )
{
	VipsForeignLoadFits *fits = (VipsForeignLoadFits *) gobject;

	VIPS_UNREF( fits->source );

	G_OBJECT_CLASS( vips_foreign_load_fits_parent_class )->
		dispose( gobject );
}

static int
vips_foreign_load_fits_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsForeignLoadFits *fits = 
		(VipsForeignLoadFits *) object;

	/* We can only open sources which have an associated filename, since
	 * the fits library works in terms of filenames.
	 */
	if( fits->source ) {
		VipsConnection *connection = VIPS_CONNECTION( fits->source );

		const char *filename;

		if( !vips_source_is_file( fits->source ) ||
			!(filename = vips_connection_filename( connection )) ) {
			vips_error( class->nickname, "%s", 
				_( "no filename available" ) );
			return( -1 );
		}

		fits->filename = filename;
	}

	if( VIPS_OBJECT_CLASS( vips_foreign_load_fits_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

static VipsForeignFlags
vips_foreign_load_fits_get_flags_source( VipsSource *source )
{
	return( VIPS_FOREIGN_PARTIAL );
}

static VipsForeignFlags
vips_foreign_load_fits_get_flags( VipsForeignLoad *load )
{
	return( VIPS_FOREIGN_PARTIAL );
}

static VipsForeignFlags
vips_foreign_load_fits_get_flags_filename( const char *filename )
{
	VipsSource *source;
	VipsForeignFlags flags;

	if( !(source = vips_source_new_from_file( filename )) )
		return( 0 );
	flags = vips_foreign_load_fits_get_flags_source( source );
	VIPS_UNREF( source );

	return( flags );
}

static int
vips_foreign_load_fits_header( VipsForeignLoad *load )
{
	VipsForeignLoadFits *fits = (VipsForeignLoadFits *) load;

	if( vips__fits_read_header( fits->filename, load->out ) ) 
		return( -1 );

	VIPS_SETSTR( load->out->filename, fits->filename );

	return( 0 );
}

static int
vips_foreign_load_fits_load( VipsForeignLoad *load )
{
	VipsForeignLoadFits *fits = (VipsForeignLoadFits *) load;
	VipsImage **t = (VipsImage **) 
		vips_object_local_array( VIPS_OBJECT( fits ), 2 );

	t[0] = vips_image_new();
	if( vips__fits_read( fits->filename, t[0] ) || 
		vips_flip( t[0], &t[1], VIPS_DIRECTION_VERTICAL, NULL ) ||
		vips_image_write( t[1], load->real ) )
		return( -1 );

	return( 0 );
}

static void
vips_foreign_load_fits_class_init( VipsForeignLoadFitsClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsOperationClass *operation_class = VIPS_OPERATION_CLASS( class );
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->dispose = vips_foreign_load_fits_dispose;
	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "fitsload_base";
	object_class->description = _( "FITS loader base class" );
	object_class->build = vips_foreign_load_fits_build;

	/* cfitsio has not been fuzzed, so should not be used with
	 * untrusted input unless you are very careful.
	 */
	operation_class->flags |= VIPS_OPERATION_UNTRUSTED;

	/* is_a() is not that quick ... lower the priority.
	 */
	foreign_class->priority = -50;

	load_class->get_flags_filename = 
		vips_foreign_load_fits_get_flags_filename;
	load_class->get_flags = vips_foreign_load_fits_get_flags;
	load_class->is_a = vips__fits_isfits;
	load_class->header = vips_foreign_load_fits_header;
	load_class->load = vips_foreign_load_fits_load;

}

static void
vips_foreign_load_fits_init( VipsForeignLoadFits *fits )
{
}

typedef struct _VipsForeignLoadFitsFile {
	VipsForeignLoadFits parent_object;

	/* Filename for load.
	 */
	char *filename; 

} VipsForeignLoadFitsFile;

typedef VipsForeignLoadFitsClass VipsForeignLoadFitsFileClass;

G_DEFINE_TYPE( VipsForeignLoadFitsFile, vips_foreign_load_fits_file, 
	vips_foreign_load_fits_get_type() );

static int
vips_foreign_load_fits_file_build( VipsObject *object )
{
	VipsForeignLoadFits *fits = (VipsForeignLoadFits *) object;
	VipsForeignLoadFitsFile *file = (VipsForeignLoadFitsFile *) object;

	if( file->filename &&
		!(fits->source = vips_source_new_from_file( file->filename )) )
		return( -1 );

	if( VIPS_OBJECT_CLASS( vips_foreign_load_fits_file_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

static void
vips_foreign_load_fits_file_class_init( VipsForeignLoadFitsFileClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "fitsload";
	object_class->description = _( "load a FITS image" );
	object_class->build = vips_foreign_load_fits_file_build;

	foreign_class->suffs = vips__fits_suffs;

	load_class->is_a = vips__fits_isfits;

	VIPS_ARG_STRING( class, "filename", 1, 
		_( "Filename" ),
		_( "Filename to load from" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignLoadFitsFile, filename ),
		NULL );
}

static void
vips_foreign_load_fits_file_init( VipsForeignLoadFitsFile *file )
{
}

typedef struct _VipsForeignLoadFitsSource {
	VipsForeignLoadFits parent_object;

	/* Load from a source.
	 */
	VipsSource *source;

} VipsForeignLoadFitsSource;

typedef VipsForeignLoadFitsClass VipsForeignLoadFitsSourceClass;

G_DEFINE_TYPE( VipsForeignLoadFitsSource, vips_foreign_load_fits_source, 
	vips_foreign_load_fits_get_type() );

static int
vips_foreign_load_fits_source_build( VipsObject *object )
{
	VipsForeignLoadFits *fits = (VipsForeignLoadFits *) object;
	VipsForeignLoadFitsSource *source = 
		(VipsForeignLoadFitsSource *) object;

	if( source->source ) {
		fits->source = source->source;
		g_object_ref( fits->source );
	}

	if( VIPS_OBJECT_CLASS( vips_foreign_load_fits_source_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

static gboolean
vips_foreign_load_fits_source_is_a_source( VipsSource *source )
{
	VipsConnection *connection = VIPS_CONNECTION( source );

	const char *filename;

	return( vips_source_is_file( source ) &&
		(filename = vips_connection_filename( connection )) &&
		vips__fits_isfits( filename ) );
}

static void
vips_foreign_load_fits_source_class_init( 
	VipsForeignLoadFitsSourceClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsOperationClass *operation_class = VIPS_OPERATION_CLASS( class );
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "fitsload_source";
	object_class->description = _( "load FITS from a source" );
	object_class->build = vips_foreign_load_fits_source_build;

	operation_class->flags |= VIPS_OPERATION_NOCACHE;

	load_class->is_a_source = 
		vips_foreign_load_fits_source_is_a_source;

	VIPS_ARG_OBJECT( class, "source", 1,
		_( "Source" ),
		_( "Source to load from" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignLoadFitsSource, source ),
		VIPS_TYPE_SOURCE );

}

static void
vips_foreign_load_fits_source_init( VipsForeignLoadFitsSource *fits )
{
}

#endif /*HAVE_CFITSIO*/

/**
 * vips_fitsload:
 * @filename: file to load
 * @out: (out): decompressed image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Read a FITS image file into a VIPS image. 
 *
 * This operation can read images with up to three dimensions. Any higher
 * dimensions must be empty. 
 *
 * It can read 8, 16 and 32-bit integer images, signed and unsigned, float and 
 * double. 
 *
 * FITS metadata is attached with the "fits-" prefix.
 *
 * See also: vips_image_new_from_file().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_fitsload( const char *filename, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "fitsload", ap, filename, out );
	va_end( ap );

	return( result );
}

/**
 * vips_fitsload_source:
 * @source: source to load from
 * @out: (out): decompressed image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Exactly as vips_fitsload(), but read from a source. 
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_fitsload_source( VipsSource *source, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "fitsload_source", ap, source, out );
	va_end( ap );

	return( result );
}
