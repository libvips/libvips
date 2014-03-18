/* base class for all nary operations
 *
 * 18/3/14
 * 	- from binary.c
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

#include "nary.h"

G_DEFINE_ABSTRACT_TYPE( VipsNary, vips_nary, VIPS_TYPE_ARITHMETIC );

static int
vips_nary_build( VipsObject *object )
{
	VipsArithmetic *arithmetic = VIPS_ARITHMETIC( object );
	VipsNary *nary = VIPS_NARY( object );

	if( nary->in ) {
		arithmetic->in = nary->in->data;
		arithmetic->n = nary->in->n;
	}

	if( VIPS_OBJECT_CLASS( vips_nary_parent_class )->build( object ) )
		return( -1 );

	return( 0 );
}

static void
vips_nary_class_init( VipsNaryClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "nary";
	vobject_class->description = _( "nary operations" );
	vobject_class->build = vips_nary_build;

	/* Create properties.
	 */

	VIPS_ARG_BOXED( class, "in", 0, 
		_( "Input" ), 
		_( "Array of input images" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsNary, in ),
		VIPS_TYPE_ARRAY_IMAGE );

}

static void
vips_nary_init( VipsNary *nary )
{
	/* Init our instance fields.
	 */
}
