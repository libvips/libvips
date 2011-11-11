/* im_lintra.c -- linear transform 
 *
 * Copyright: 1990, N. Dessipris, based on im_powtra()
 * Author: Nicos Dessipris
 * Written on: 02/05/1990
 * Modified on: 
 * 23/4/93 JC
 *	- adapted to work with partial images
 * 1/7/93 JC
 *	- adapted for partial v2
 * 7/10/94 JC
 *	- new IM_NEW()
 *	- more typedefs 
 * 9/2/95 JC
 *	- adapted for im_wrap...
 *	- operations on complex images now just transform the real channel
 * 29/9/95 JC
 *	- complex was broken
 * 15/4/97 JC
 *	- return(0) missing from generate, arrgh!
 * 1/7/98 JC
 *	- im_lintra_vec added
 * 3/8/02 JC
 *	- fall back to im_copy() for a == 1, b == 0
 * 10/10/02 JC
 *	- auug, failing to multiply imag for complex! (thanks matt)
 * 10/12/02 JC
 *	- removed im_copy() fallback ... meant that output format could change
 *	  with value :-( very confusing
 * 30/6/04
 *	- added 1 band image * n band vector case
 * 8/12/06
 * 	- add liboil support
 * 9/9/09
 * 	- gtkdoc comment, minor reformat
 * 31/7/10
 * 	- remove liboil
 * 31/10/11
 * 	- rework as a class
 * 	- removed the 1-ary constant path, no faster
 */

/*

    Copyright (C) 1991-2005 The National Gallery

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
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

#include "arithmetic.h"
#include "unary.h"

/**
 * VipsLinear:
 * @in: image to transform
 * @out: output image
 * @a: array of constants for multiplication
 * @b: array of constants for addition
 *
 * Pass an image through a linear transform, ie. (@out = @in * @a + @b). Output
 * is always float for integer input, double for double input, complex for
 * complex input and double complex for double complex input.
 *
 * If the arrays of constants have just one element, that constant is used for 
 * all image bands. If the arrays have more than one element and they have 
 * the same number of elements as there are bands in the image, then 
 * one array element is used for each band. If the arrays have more than one
 * element and the image only has a single band, the result is a many-band
 * image where each band corresponds to one array element.
 *
 * See also: #VipsAdd.
 *
 * Returns: 0 on success, -1 on error
 */

typedef struct _VipsLinear {
	VipsUnary parent_instance;

	/* Our constants: multiply by a, add b.
	 */
	VipsArea *a;
	VipsArea *b;

	/* Our constants expanded to match arith->ready in size.
	 */
	int n;
	double *a_ready;
	double *b_ready;

} VipsLinear;

typedef VipsUnaryClass VipsLinearClass;

G_DEFINE_TYPE( VipsLinear, vips_linear, VIPS_TYPE_UNARY );

static int
vips_linear_build( VipsObject *object )
{
	VipsArithmetic *arithmetic = VIPS_ARITHMETIC( object );
	VipsUnary *unary = (VipsUnary *) object;
	VipsLinear *linear = (VipsLinear *) object;
	int i;

	/* If we have a three-element vector we need to bandup the image to
	 * match.
	 */
	linear->n = 1;
	if( linear->a )
		linear->n = VIPS_MAX( linear->n, linear->b->n );
	if( linear->b )
		linear->n = VIPS_MAX( linear->n, linear->b->n );
	if( unary->in )
		linear->n = VIPS_MAX( linear->n, unary->in->Bands );
	arithmetic->base_bands = linear->n;

	if( unary->in && linear->a && linear->b ) {
		if( vips_check_vector( "VipsLinear", 
			linear->a->n, unary->in ) ||
			vips_check_vector( "VipsLinear", 
				linear->b->n, unary->in ) )
		return( -1 );
	}

	/* Make up-banded versions of our constants.
	 */
	linear->a_ready = g_new( double, linear->n );
	linear->b_ready = g_new( double, linear->n );

	for( i = 0; i < linear->n; i++ ) {
		if( linear->a ) {
			double *ary = (double *) linear->a->data;
			int j = VIPS_MIN( i, linear->a->n - 1 );

			linear->a_ready[i] = ary[j];
		}

		if( linear->b ) {
			double *ary = (double *) linear->b->data;
			int j = VIPS_MIN( i, linear->b->n - 1 );

			linear->b_ready[i] = ary[j];
		}
	}

	if( VIPS_OBJECT_CLASS( vips_linear_parent_class )->build( object ) )
		return( -1 );

	return( 0 );
}

/* Non-complex input, any output.
 */
#define LOOPN( IN, OUT ) { \
	IN *p = (IN *) in[0]; \
	OUT *q = (OUT *) out; \
	\
	for( i = 0, x = 0; x < width; x++ ) \
		for( k = 0; k < nb; k++, i++ ) \
			q[i] = a[k] * (OUT) p[i] + b[k]; \
}

/* Complex input, complex output. 
 */
#define LOOPCMPLXN( IN, OUT ) { \
	IN *p = (IN *) in[0]; \
	OUT *q = (OUT *) out; \
	\
	for( x = 0; x < width; x++ ) \
		for( k = 0; k < nb; k++ ) { \
			q[0] = a[k] * p[0] + b[k]; \
			q[1] = a[k] * p[1]; \
			q += 2; \
			p += 2; \
		} \
}

/* Lintra a buffer, n set of scale/offset.
 */
static void
vips_linear_buffer( VipsArithmetic *arithmetic, PEL *out, PEL **in, int width )
{
	VipsImage *im = arithmetic->ready[0];
	VipsLinear *linear = (VipsLinear *) arithmetic;
	double *a = linear->a_ready;
	double *b = linear->b_ready;
	int nb = im->Bands;

	int i, x, k;

	switch( vips_image_get_format( im ) ) {
        case VIPS_FORMAT_UCHAR: 	LOOPN( unsigned char, float ); break;
        case VIPS_FORMAT_CHAR: 		LOOPN( signed char, float ); break; 
        case VIPS_FORMAT_USHORT: 	LOOPN( unsigned short, float ); break; 
        case VIPS_FORMAT_SHORT: 	LOOPN( signed short, float ); break; 
        case VIPS_FORMAT_UINT: 		LOOPN( unsigned int, float ); break; 
        case VIPS_FORMAT_INT: 		LOOPN( signed int, float );  break; 
        case VIPS_FORMAT_FLOAT: 	LOOPN( float, float ); break; 
        case VIPS_FORMAT_DOUBLE:	LOOPN( double, double ); break; 
        case VIPS_FORMAT_COMPLEX:	LOOPCMPLXN( float, float ); break; 
        case VIPS_FORMAT_DPCOMPLEX:	LOOPCMPLXN( double, double ); break;

        default:
		g_assert( 0 );
        }
}

/* Save a bit of typing.
 */
#define UC VIPS_FORMAT_UCHAR
#define C VIPS_FORMAT_CHAR
#define US VIPS_FORMAT_USHORT
#define S VIPS_FORMAT_SHORT
#define UI VIPS_FORMAT_UINT
#define I VIPS_FORMAT_INT
#define F VIPS_FORMAT_FLOAT
#define X VIPS_FORMAT_COMPLEX
#define D VIPS_FORMAT_DOUBLE
#define DX VIPS_FORMAT_DPCOMPLEX

/* Format doesn't change with linear.
 */
static const VipsBandFormat vips_bandfmt_linear[10] = {
/* UC  C   US  S   UI  I   F   X   D   DX */
   F,  F,  F,  F,  F,  F,  F,  X,  D,  DX 
};

static void
vips_linear_class_init( VipsLinearClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsArithmeticClass *aclass = VIPS_ARITHMETIC_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "linear";
	object_class->description = _( "calculate (a * in + b)" );
	object_class->build = vips_linear_build;

	vips_arithmetic_set_format_table( aclass, vips_bandfmt_linear );

	aclass->process_line = vips_linear_buffer;

	VIPS_ARG_BOXED( class, "a", 110, 
		_( "a" ), 
		_( "Multiply by this" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsLinear, a ),
		VIPS_TYPE_ARRAY_DOUBLE );

	VIPS_ARG_BOXED( class, "b", 111, 
		_( "b" ), 
		_( "Add this" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsLinear, b ),
		VIPS_TYPE_ARRAY_DOUBLE );

}

static void
vips_linear_init( VipsLinear *linear )
{
}

int
vips_linear( VipsImage *in, VipsImage **out, double *a, double *b, int n, ... )
{
	va_list ap;
	VipsArea *area_a;
	VipsArea *area_b;
	double *array; 
	int result;
	int i;

	area_a = vips_area_new_array( G_TYPE_DOUBLE, sizeof( double ), n ); 
	array = (double *) area_a->data;
	for( i = 0; i < n; i++ ) 
		array[i] = a[i];

	area_b = vips_area_new_array( G_TYPE_DOUBLE, sizeof( double ), n ); 
	array = (double *) area_b->data;
	for( i = 0; i < n; i++ ) 
		array[i] = b[i];

	va_start( ap, n );
	result = vips_call_split( "linear", ap, in, out, area_a, area_b );
	va_end( ap );

	vips_area_unref( area_a );
	vips_area_unref( area_b );

	return( result );
}

int
vips_linear1( VipsImage *in, VipsImage **out, double a, double b, ... )
{
	va_list ap;
	VipsArea *area_a;
	VipsArea *area_b;
	double *array; 
	int result;

	area_a = vips_area_new_array( G_TYPE_DOUBLE, sizeof( double ), 1 ); 
	array = (double *) area_a->data;
	array[0] = a;

	area_b = vips_area_new_array( G_TYPE_DOUBLE, sizeof( double ), 1 ); 
	array = (double *) area_b->data;
	array[0] = b;

	va_start( ap, b );
	result = vips_call_split( "linear", ap, in, out, area_a, area_b );
	va_end( ap );

	vips_area_unref( area_a );
	vips_area_unref( area_b );

	return( result );
}
