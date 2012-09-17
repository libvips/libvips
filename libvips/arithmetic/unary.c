/* base class for all unary operations
 *
 * 30/10/11
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
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

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

#include "unary.h"

G_DEFINE_ABSTRACT_TYPE( VipsUnary, vips_unary, VIPS_TYPE_ARITHMETIC );

static int
vips_unary_build( VipsObject *object )
{
	VipsArithmetic *arithmetic = VIPS_ARITHMETIC( object );
	VipsUnary *unary = VIPS_UNARY( object );

	arithmetic->n = 1;
	arithmetic->in = (VipsImage **) vips_object_local_array( object, 1 );
	arithmetic->in[0] = unary->in;
	if( arithmetic->in[0] )
		g_object_ref( arithmetic->in[0] );

	if( VIPS_OBJECT_CLASS( vips_unary_parent_class )->build( object ) )
		return( -1 );

	return( 0 );
}

static void
vips_unary_class_init( VipsUnaryClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "unary";
	vobject_class->description = _( "unary operations" );
	vobject_class->build = vips_unary_build;

	/* Create properties.
	 */

	VIPS_ARG_IMAGE( class, "in", 1, 
		_( "Input" ), 
		_( "Input image argument" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsUnary, in ) );

}

static void
vips_unary_init( VipsUnary *unary )
{
	/* Init our instance fields.
	 */
}

/* Call this before chaining up in _build() to make the operation fall back to
 * copy.
 */
int
vips_unary_copy( VipsUnary *unary )
{
	VipsArithmetic *arithmetic = VIPS_ARITHMETIC( unary );

	/* This isn't set by arith until build(), so we have to set
	 * again here.
	 *
	 * Should arith set out in _init()?
	 */
	g_object_set( unary, "out", vips_image_new(), NULL ); 

	return( vips_image_write( unary->in, arithmetic->out ) );
}
