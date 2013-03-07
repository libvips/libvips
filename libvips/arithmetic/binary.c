/* base class for all binary operations
 *
 * 13/3/11
 * 	- argh, forgot to make a private array for the inputs
 * 16/5/11
 * 	- added sizealike
 * 30/10/11
 * 	- moe most functionality into arithmetic.c
 */

/*

    Copyright (C) 1991-2005 The National Gallery

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License as published by the Free Software Foundation; either
    version 2.1 of the License, or (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU 
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this library; if not, write to the Free Software
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
#include <math.h>

#include <vips/vips.h>

#include "binary.h"

G_DEFINE_ABSTRACT_TYPE( VipsBinary, vips_binary, VIPS_TYPE_ARITHMETIC );

static int
vips_binary_build( VipsObject *object )
{
	VipsArithmetic *arithmetic = VIPS_ARITHMETIC( object );
	VipsBinary *binary = VIPS_BINARY( object );

	arithmetic->n = 2;
	arithmetic->in = (VipsImage **) vips_object_local_array( object, 2 );
	arithmetic->in[0] = binary->left;
	arithmetic->in[1] = binary->right;

	if( arithmetic->in[0] )
		g_object_ref( arithmetic->in[0] );
	if( arithmetic->in[1] )
		g_object_ref( arithmetic->in[1] );

	if( VIPS_OBJECT_CLASS( vips_binary_parent_class )->build( object ) )
		return( -1 );

	return( 0 );
}

static void
vips_binary_class_init( VipsBinaryClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "binary";
	vobject_class->description = _( "binary operations" );
	vobject_class->build = vips_binary_build;

	/* Create properties.
	 */

	VIPS_ARG_IMAGE( class, "left", 1, 
		_( "Left" ), 
		_( "Left-hand image argument" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsBinary, left ) );

	VIPS_ARG_IMAGE( class, "right", 2,
		_( "Right" ), 
		_( "Right-hand image argument" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsBinary, right ) );

}

static void
vips_binary_init( VipsBinary *binary )
{
	/* Init our instance fields.
	 */
}
