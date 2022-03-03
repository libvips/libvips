/* an image plus a constant
 *
 * 11/11/11
 * 	- from arith_binary_const
 * 21/8/19
 * 	- revise to fix out of range comparisons
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
#include <glib/gi18n-lib.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vips/vips.h>

#include "unaryconst.h"

G_DEFINE_ABSTRACT_TYPE( VipsUnaryConst, vips_unary_const, VIPS_TYPE_UNARY );

static int
vips_unary_const_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsArithmetic *arithmetic = VIPS_ARITHMETIC( object );
	VipsUnary *unary = (VipsUnary *) object;
	VipsUnaryConst *uconst = (VipsUnaryConst *) object;

	/* If we have a three-element vector we need to bandup the image to
	 * match.
	 */
	uconst->n = 1;
	if( uconst->c )
		uconst->n = VIPS_MAX( uconst->n, uconst->c->n );
	if( unary->in )
		uconst->n = VIPS_MAX( uconst->n, unary->in->Bands );
	arithmetic->base_bands = uconst->n;

	if( unary->in && 
		uconst->c ) {
		if( vips_check_vector( class->nickname, 
			uconst->c->n, unary->in ) )
		return( -1 );
	}

	/* Some operations need int constants, for example boolean AND, SHIFT
	 * etc.
	 *
	 * Some can use int constants as an optimisation, for example (x <
	 * 12). It depends on the value though: obviously (x < 12.5) should
	 * not use the int form.
	 *
	 * For complex images, we double the vector length and set the
	 * imaginary part to 0.
	 */
	if( uconst->c ) {
		gboolean is_complex = 
			vips_band_format_iscomplex( unary->in->BandFmt );
		int step = is_complex ? 2 : 1;
		int n = step * uconst->n;
		double *c = (double *) uconst->c->data;

		int i;

		uconst->c_int = VIPS_ARRAY( object, n, int );
		uconst->c_double = VIPS_ARRAY( object, n, double );
		if( !uconst->c_int ||
			!uconst->c_double )
			return( -1 );
		memset( uconst->c_int, 0, n * sizeof( int ) );
		memset( uconst->c_double, 0, n * sizeof( double ) );

		for( i = 0; i < n; i += step )
			uconst->c_double[i] = 
				c[VIPS_MIN( i / step, uconst->c->n - 1)];

		for( i = 0; i < n; i += step )
			uconst->c_int[i] = uconst->c_double[i];
		
		uconst->is_int = TRUE;
		for( i = 0; i < n; i += step )
			if( uconst->c_int[i] != uconst->c_double[i] ) {
				uconst->is_int = FALSE;
				break;
			}
	}

	if( VIPS_OBJECT_CLASS( vips_unary_const_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

static void
vips_unary_const_class_init( VipsUnaryConstClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "unary_const";
	object_class->description = _( "unary operations with a constant" );
	object_class->build = vips_unary_const_build;

	VIPS_ARG_BOXED( class, "c", 201, 
		_( "c" ), 
		_( "Array of constants" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsUnaryConst, c ),
		VIPS_TYPE_ARRAY_DOUBLE );
}

static void
vips_unary_const_init( VipsUnaryConst *uconst )
{
}
