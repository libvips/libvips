/* load vips from a file
 *
 * 24/11/11
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

#include <vips/vips.h>
#include <vips/internal.h>

typedef struct _VipsForeignLoadVips {
	VipsForeignLoad parent_object;

	/* Source to load from (set by subclasses).
	 */
	VipsSource *source;

} VipsForeignLoadVips;

typedef VipsForeignLoadClass VipsForeignLoadVipsClass;

G_DEFINE_ABSTRACT_TYPE( VipsForeignLoadVips, vips_foreign_load_vips, 
	VIPS_TYPE_FOREIGN_LOAD );

static void
vips_foreign_load_vips_dispose( GObject *gobject )
{
	VipsForeignLoadVips *vips = (VipsForeignLoadVips *) gobject;

	VIPS_UNREF( vips->source );

	G_OBJECT_CLASS( vips_foreign_load_vips_parent_class )->
		dispose( gobject );
}

static VipsForeignFlags
vips_foreign_load_vips_get_flags_source( VipsSource *source )
{
	unsigned char *data;
	VipsForeignFlags flags;

	flags = VIPS_FOREIGN_PARTIAL;

	if( vips_source_sniff_at_most( source, &data, 4 ) == 4 &&
		*((guint32 *) data) == VIPS_MAGIC_SPARC ) 
		flags |= VIPS_FOREIGN_BIGENDIAN;

	return( flags );
}

static VipsForeignFlags
vips_foreign_load_vips_get_flags( VipsForeignLoad *load )
{
	VipsForeignLoadVips *vips = (VipsForeignLoadVips *) load;

	return( vips_foreign_load_vips_get_flags_source( vips->source ) );
}

static VipsForeignFlags
vips_foreign_load_vips_get_flags_filename( const char *filename )
{
	VipsSource *source;
	VipsForeignFlags flags;

	if( !(source = vips_source_new_from_file( filename )) )
		return( 0 );
	flags = vips_foreign_load_vips_get_flags_source( source );
	VIPS_UNREF( source );

	return( flags );
}

static int
vips_foreign_load_vips_header( VipsForeignLoad *load )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( load );
	VipsForeignLoadVips *vips = (VipsForeignLoadVips *) load;
	VipsConnection *connection = VIPS_CONNECTION( vips->source );

	const char *filename;
	VipsImage *image;
	VipsImage *x;

	if( !vips_source_is_file( vips->source ) ||
		!(filename = vips_connection_filename( connection )) ) {
		vips_error( class->nickname, 
			"%s", _( "no filename associated with source" ) );
		return( -1 );
	}

	if( !(image = vips_image_new_mode( filename, "r" )) )
		return( -1 );

	/* What a hack. Remove the @out that's there now and replace it with
	 * our image. 
	 */
	g_object_get( load, "out", &x, NULL );
	g_object_unref( x );
	g_object_unref( x );

	g_object_set( load, "out", image, NULL );

	return( 0 );
}

static void
vips_foreign_load_vips_class_init( VipsForeignLoadVipsClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsOperationClass *operation_class = VIPS_OPERATION_CLASS( class );
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->dispose = vips_foreign_load_vips_dispose;

	object_class->nickname = "vipsload_base";
	object_class->description = _( "load vips base class" );

	/* You're unlikely to want to use this on untrusted files.
	 */
	operation_class->flags |= VIPS_OPERATION_UNTRUSTED;

	/* We are fast at is_a(), so high priority.
	 */
	foreign_class->priority = 200;

	load_class->get_flags = vips_foreign_load_vips_get_flags;
	load_class->get_flags_filename = 
		vips_foreign_load_vips_get_flags_filename;
	load_class->header = vips_foreign_load_vips_header;
	load_class->load = NULL;

}

static void
vips_foreign_load_vips_init( VipsForeignLoadVips *vips )
{
}

typedef struct _VipsForeignLoadVipsFile {
	VipsForeignLoadVips parent_object;

	char *filename;

} VipsForeignLoadVipsFile;

typedef VipsForeignLoadVipsClass VipsForeignLoadVipsFileClass;

G_DEFINE_TYPE( VipsForeignLoadVipsFile, vips_foreign_load_vips_file, 
	vips_foreign_load_vips_get_type() );

static int
vips_foreign_load_vips_file_build( VipsObject *object )
{
	VipsForeignLoadVips *vips = (VipsForeignLoadVips *) object;
	VipsForeignLoadVipsFile *file = (VipsForeignLoadVipsFile *) object;

	if( file->filename &&
		!(vips->source = vips_source_new_from_file( file->filename )) )
		return( -1 );

	if( VIPS_OBJECT_CLASS( vips_foreign_load_vips_file_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

const char *vips__suffs[] = { ".v", ".vips", NULL };

static gboolean
vips_foreign_load_vips_file_is_a( const char *filename )
{
	return( vips__file_magic( filename ) );
}

static void
vips_foreign_load_vips_file_class_init( VipsForeignLoadVipsClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "vipsload";
	object_class->description = _( "load vips from file" );
	object_class->build = vips_foreign_load_vips_file_build;

	foreign_class->suffs = vips__suffs;

	load_class->is_a = vips_foreign_load_vips_file_is_a;

	VIPS_ARG_STRING( class, "filename", 1, 
		_( "Filename" ),
		_( "Filename to load from" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignLoadVipsFile, filename ),
		NULL );
}

static void
vips_foreign_load_vips_file_init( VipsForeignLoadVipsFile *file )
{
}

typedef struct _VipsForeignLoadVipsSource {
	VipsForeignLoadVips parent_object;

	VipsSource *source;

} VipsForeignLoadVipsSource;

typedef VipsForeignLoadVipsClass VipsForeignLoadVipsSourceClass;

G_DEFINE_TYPE( VipsForeignLoadVipsSource, vips_foreign_load_vips_source, 
	vips_foreign_load_vips_get_type() );

static int
vips_foreign_load_vips_source_build( VipsObject *object )
{
	VipsForeignLoadVips *vips = (VipsForeignLoadVips *) object;
	VipsForeignLoadVipsSource *source = 
		(VipsForeignLoadVipsSource *) object;

	if( source->source ) {
		vips->source = source->source;
		g_object_ref( vips->source );
	}

	if( VIPS_OBJECT_CLASS( vips_foreign_load_vips_source_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

static gboolean
vips_foreign_load_vips_source_is_a_source( VipsSource *source )
{
	VipsConnection *connection = VIPS_CONNECTION( source );

	const char *filename;

	return( vips_source_is_file( source ) &&
		(filename = vips_connection_filename( connection )) &&
		vips__file_magic( filename ) );
}

static void
vips_foreign_load_vips_source_class_init( VipsForeignLoadVipsClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsOperationClass *operation_class = VIPS_OPERATION_CLASS( class );
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "vipsload_source";
	object_class->description = _( "load vips from source" );
	object_class->build = vips_foreign_load_vips_source_build;

	operation_class->flags |= VIPS_OPERATION_NOCACHE;

	load_class->is_a_source = 
		vips_foreign_load_vips_source_is_a_source;

	VIPS_ARG_OBJECT( class, "source", 1,
		_( "Source" ),
		_( "Source to load from" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignLoadVipsSource, source ),
		VIPS_TYPE_SOURCE );

}

static void
vips_foreign_load_vips_source_init( VipsForeignLoadVipsSource *source )
{
}

/**
 * vips_vipsload:
 * @filename: file to load
 * @out: (out): decompressed image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Read in a vips image. 
 *
 * See also: vips_vipssave().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_vipsload( const char *filename, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "vipsload", ap, filename, out );
	va_end( ap );

	return( result );
}

/**
 * vips_vipsload_source:
 * @source: source to load from
 * @out: (out): decompressed image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Exactly as vips_vipsload(), but read from a source. 
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_vipsload_source( VipsSource *source, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "vipsload_source", ap, source, out );
	va_end( ap );

	return( result );
}
