/* wrap a vips7 operation as a vips8 class
 * 
 * 12/7/11
 * 	- quick hack
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
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

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

#include <vips/vips.h>
#include <vips/internal.h>
#include <vips/debug.h>
#include <vips/vector.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

#define VIPS7_PREFIX "Vips7_"

static GHashTable *vips7_types = NULL;

typedef VipsOperation VipsVips7;
typedef VipsOperationClass VipsVips7Class;

static int
vips_vips7_build( VipsObject *object )
{
	VipsVips7 *vips7 = VIPS_VIPS7( object );

	if( VIPS_OBJECT_CLASS( parent_class )->build( object ) )
		return( -1 );

	return( 0 );
}

static void
vips_vips7_class_init( VipsVips7Class *class )
{
	/* The name of the vips operation we wrap is hidden in our class name.
	 */
	const char *name = G_OBJECT_CLASS_NAME( class ) + 
		strlen( VIPS7_PREFIX );

	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsOperationClass *oclass = VIPS_OPERATION_CLASS( class );

	im_function *fn = im_find_function( name );

	int i;

	g_assert( fn );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->build = vips_vips7_build;

	object_class->nickname = name;
	object_class->description = fn->desc;

	for( i = 0; i < fn->argc; i++ ) {
		GParamSpec *pspec;

		pspec = g_param_spec_object( "out", "Output", 
			_( "Output image" ),
			VIPS_TYPE_IMAGE,
			G_PARAM_READWRITE );
		g_object_class_install_property( gobject_class, 
			PROP_OUTPUT, pspec );
		vips_object_class_install_argument( vobject_class, pspec,
			VIPS_ARGUMENT_REQUIRED_OUTPUT, 
			G_STRUCT_OFFSET( VipsArithmetic, output ) );
	}
}

static void
vips_vips7_init( VipsVips7 *vips7 )
{
}

static GType
vips_get_type( im_function *fn )
{
	static const GTypeInfo info = {
		sizeof( VipsVips7Class ),
		NULL,           /* base_init */
		NULL,           /* base_finalize */
		(GClassInitFunc) vips_vips7_class_init,
		NULL,           /* class_finalize */
		NULL,           /* class_data */
		sizeof( VipsVips7 ),
		32,             /* n_preallocs */
		(GInstanceInitFunc) vips_vips7_init,
	};

	char name[256];
	GType type;

	if( !vips7_types )
		vips7_types = g_hash_table_new( g_direct_hash, g_direct_equal );

	if( (type = g_hash_table_lookup( vips7_types, fn )) )
		return( type );

	im_snprintf( name, 256, VIPS7_PREFIX "%s", fn->name );
	type = g_type_register_static( VIPS_OPERATION, name, &info, 0 );
	g_hash_table_insert( vips7_types, fn, type );

	return( type );
}

