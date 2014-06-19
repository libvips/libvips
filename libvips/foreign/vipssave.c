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
#include <vips/intl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vips/vips.h>
#include <vips/internal.h>

typedef struct _VipsForeignSaveVips {
	VipsForeignSave parent_object;

	char *filename;

} VipsForeignSaveVips;

typedef VipsForeignSaveClass VipsForeignSaveVipsClass;

G_DEFINE_TYPE( VipsForeignSaveVips, vips_foreign_save_vips, 
	VIPS_TYPE_FOREIGN_SAVE );

static int
vips_foreign_save_vips_build( VipsObject *object )
{
	VipsForeignSave *save = (VipsForeignSave *) object;
	VipsForeignSaveVips *vips = (VipsForeignSaveVips *) object;

	VipsImage *x;

	if( VIPS_OBJECT_CLASS( vips_foreign_save_vips_parent_class )->
		build( object ) )
		return( -1 );

	if( !(x = vips_image_new_mode( vips->filename, "w" )) )
		return( -1 );
	if( vips_image_write( save->ready, x ) ) {
		g_object_unref( x );
		return( -1 ); 
	}
	g_object_unref( x );

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

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "vipssave";
	object_class->description = _( "save image to vips file" );
	object_class->build = vips_foreign_save_vips_build;

	foreign_class->suffs = vips__suffs;

	save_class->saveable = VIPS_SAVEABLE_ANY;
	for( i = 0; i < VIPS_CODING_LAST; i++ )
		save_class->coding[i] = TRUE;

	VIPS_ARG_STRING( class, "filename", 1, 
		_( "Filename" ),
		_( "Filename to save to" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignSaveVips, filename ),
		NULL );
}

static void
vips_foreign_save_vips_init( VipsForeignSaveVips *vips )
{
}

