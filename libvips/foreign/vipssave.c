/* save to vips
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
#define DEBUG_VERBOSE
#define DEBUG
#define VIPS_DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <glib/gi18n-lib.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vips/vips.h>
#include <vips/internal.h>

typedef struct _VipsForeignSaveVips {
	VipsForeignSave parent_object;

	VipsTarget *target;

} VipsForeignSaveVips;

typedef VipsForeignSaveClass VipsForeignSaveVipsClass;

G_DEFINE_ABSTRACT_TYPE( VipsForeignSaveVips, vips_foreign_save_vips, 
	VIPS_TYPE_FOREIGN_SAVE );

static void
vips_foreign_save_vips_dispose( GObject *gobject )
{
	VipsForeignSaveVips *vips = (VipsForeignSaveVips *) gobject;

	VIPS_UNREF( vips->target );

	G_OBJECT_CLASS( vips_foreign_save_vips_parent_class )->
		dispose( gobject );
}

static int
vips_foreign_save_vips_build( VipsObject *object )
{
	VipsForeignSaveVips *vips = (VipsForeignSaveVips *) object;

	const char *filename;

	if( VIPS_OBJECT_CLASS( vips_foreign_save_vips_parent_class )->
		build( object ) )
		return( -1 );

	if( (filename = 
		vips_connection_filename( VIPS_CONNECTION( vips->target ) )) ) {
		VipsForeignSave *save = (VipsForeignSave *) object;

		VipsImage *x;

		/* vips_image_build() has some magic for "w"
		 * preventing recursion and sending this directly to the
		 * saver built into iofuncs.
		 */
		if( !(x = vips_image_new_mode( filename, "w" )) )
			return( -1 );
		if( vips_image_write( save->ready, x ) ) {
			g_object_unref( x );
			return( -1 ); 
		}
		g_object_unref( x );
	}
	else {
		VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );

		/* We could add load vips from memory, fd, via mmap etc. here.
		 * We should perhaps move iofuncs/vips.c into this file.
		 *
		 * For now, just fail unless there's a filename associated
		 * with this source.
		 */
		vips_error( class->nickname, 
			"%s", _( "no filename associated with target" ) );
		return( -1 );
	}

	if( vips_target_end( vips->target ) )
		return( -1 );

	return( 0 );
}

/* From vipsload.c.
 */
extern const char *vips__suffs[];

static void
vips_foreign_save_vips_class_init( VipsForeignSaveVipsClass *class )
{
	int i;

	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;
	VipsForeignSaveClass *save_class = (VipsForeignSaveClass *) class;

	gobject_class->dispose = vips_foreign_save_vips_dispose;

	object_class->nickname = "vipssave_base";
	object_class->description = _( "save vips base class" );
	object_class->build = vips_foreign_save_vips_build;

	foreign_class->suffs = vips__suffs;

	save_class->saveable = VIPS_SAVEABLE_ANY;
	for( i = 0; i < VIPS_CODING_LAST; i++ )
		save_class->coding[i] = TRUE;
}

static void
vips_foreign_save_vips_init( VipsForeignSaveVips *vips )
{
}

typedef struct _VipsForeignSaveVipsFile {
	VipsForeignSaveVips parent_object;

	char *filename;
} VipsForeignSaveVipsFile;

typedef VipsForeignSaveVipsClass VipsForeignSaveVipsFileClass;

G_DEFINE_TYPE( VipsForeignSaveVipsFile, vips_foreign_save_vips_file, 
	vips_foreign_save_vips_get_type() );

static int
vips_foreign_save_vips_file_build( VipsObject *object )
{
	VipsForeignSaveVips *vips = (VipsForeignSaveVips *) object;
	VipsForeignSaveVipsFile *file = (VipsForeignSaveVipsFile *) object;

	if( !(vips->target = vips_target_new_to_file( file->filename )) )
		return( -1 );

	if( VIPS_OBJECT_CLASS( vips_foreign_save_vips_file_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

static void
vips_foreign_save_vips_file_class_init( VipsForeignSaveVipsFileClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "vipssave";
	object_class->description = _( "save image to file in vips format" );
	object_class->build = vips_foreign_save_vips_file_build;

	VIPS_ARG_STRING( class, "filename", 1, 
		_( "Filename" ),
		_( "Filename to save to" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignSaveVipsFile, filename ),
		NULL );
}

static void
vips_foreign_save_vips_file_init( VipsForeignSaveVipsFile *file )
{
}

typedef struct _VipsForeignSaveVipsTarget {
	VipsForeignSaveVips parent_object;

	VipsTarget *target;

} VipsForeignSaveVipsTarget;

typedef VipsForeignSaveVipsClass VipsForeignSaveVipsTargetClass;

G_DEFINE_TYPE( VipsForeignSaveVipsTarget, vips_foreign_save_vips_target, 
	vips_foreign_save_vips_get_type() );

static int
vips_foreign_save_vips_target_build( VipsObject *object )
{
	VipsForeignSaveVips *vips = (VipsForeignSaveVips *) object;
	VipsForeignSaveVipsTarget *target = 
		(VipsForeignSaveVipsTarget *) object;

	vips->target = target->target;
	g_object_ref( vips->target );

	if( VIPS_OBJECT_CLASS( vips_foreign_save_vips_target_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

static void
vips_foreign_save_vips_target_class_init( 
	VipsForeignSaveVipsTargetClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "vipssave_target";
	object_class->description = _( "save image to target in vips format" );
	object_class->build = vips_foreign_save_vips_target_build;

	VIPS_ARG_OBJECT( class, "target", 1,
		_( "Target" ),
		_( "Target to save to" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignSaveVipsTarget, target ),
		VIPS_TYPE_TARGET );

}

static void
vips_foreign_save_vips_target_init( VipsForeignSaveVipsTarget *target )
{
}

/**
 * vips_vipssave: (method)
 * @in: image to save 
 * @filename: file to write to 
 * @...: %NULL-terminated list of optional named arguments
 *
 * Write @in to @filename in VIPS format.
 *
 * See also: vips_vipsload().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_vipssave( VipsImage *in, const char *filename, ... )
{
	va_list ap;
	int result;

	va_start( ap, filename );
	result = vips_call_split( "vipssave", ap, in, filename );
	va_end( ap );

	return( result );
}

/**
 * vips_vipssave_target: (method)
 * @in: image to save 
 * @target: save image to this target
 * @...: %NULL-terminated list of optional named arguments
 *
 * As vips_vipssave(), but save to a target.
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_vipssave_target( VipsImage *in, VipsTarget *target, ... )
{
	va_list ap;
	int result;

	va_start( ap, target );
	result = vips_call_split( "vipssave_target", ap, in, target );
	va_end( ap );

	return( result );
}
