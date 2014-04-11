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
 * 30/11/13
 * 	- 1ary is back, faster with gcc 4.8
 * 3/12/13
 * 	- try an ORC path with the band loop unrolled
 * 14/1/14
 * 	- add uchar output option
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

#include "unary.h"

typedef struct _VipsLinear {
	VipsUnary parent_instance;

	/* Our constants: multiply by a, add b.
	 */
	VipsArrayComp *a;
	VipsArrayComp *b;

	/* uchar output.
	 */
	gboolean uchar;

	/* Our constants expanded to match arith->ready in size.
	 */
	int n;
	double *a_real_ready;
	double *b_real_ready;
	double *a_imag_ready;
	double *b_imag_ready;

} VipsLinear;

typedef VipsUnaryClass VipsLinearClass;

G_DEFINE_TYPE( VipsLinear, vips_linear, VIPS_TYPE_UNARY );

/* Is there an imaginary component to a constant?
 */
static gboolean
vips_comp_array_has_imaginary( VipsCompArray *comp )
{
	VipsComp *ary = (VipsComp *) comp->data;

	int i;

	for( i = 0; i < comp->n; i++ )
		if( ary[i].imag != 0.0 ) 
			return( TRUE ); 

	return( FALSE );
}

static int
vips_linear_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsArithmetic *arithmetic = VIPS_ARITHMETIC( object );
	VipsUnary *unary = (VipsUnary *) object;
	VipsLinear *linear = (VipsLinear *) object;

	int bands;
	int i;

	/* How many bands will our input image have after decoding?
	 */
	switch( unary->in->Coding ) {
	case VIPS_CODING_RAD:
	case VIPS_CODING_LABQ:
		bands = 3;
		break;

	default:
		bands = unary->in->Bands;
		break;
	}

	/* If we have a three-element vector we need to bandup the image to
	 * match.
	 */
	linear->n = 1;
	if( linear->a )
		linear->n = VIPS_MAX( linear->n, linear->b->n );
	if( linear->b )
		linear->n = VIPS_MAX( linear->n, linear->b->n );
	if( unary->in )
		linear->n = VIPS_MAX( linear->n, bands );
	arithmetic->base_bands = linear->n;

	if( unary->in && 
		linear->a && 
		linear->b ) {
		if( vips_check_vector( class->nickname, 
			linear->a->n, unary->in ) ||
			vips_check_vector( class->nickname, 
				linear->b->n, unary->in ) )
		return( -1 );
	}

	/* Make up-banded versions of our constants.
	 */
	linear->a_real_ready = VIPS_ARRAY( linear, linear->n, double );
	linear->b_real_ready = VIPS_ARRAY( linear, linear->n, double );

	if( (linear->a && vips_comp_array_has_imaginary( linear->a )) ||
		(linear->b && vips_comp_array_has_imaginary( linear->b )) ) {
		linear->a_imag_ready = VIPS_ARRAY( linear, linear->n, double );
		linear->b_imag_ready = VIPS_ARRAY( linear, linear->n, double );
	}

	for( i = 0; i < linear->n; i++ ) {
		if( linear->a ) {
			VipsComp *ary = (VipsComp *) linear->a->data;
			int j = VIPS_MIN( i, linear->a->n - 1 );

			linear->a_real_ready[i] = ary[j].real;

			if( linear->a_imag_ready )
				linear->a_imag_ready[i] = ary[j].imag;
		}

		if( linear->b ) {
			VipsComp *ary = (VipsComp *) linear->b->data;
			int j = VIPS_MIN( i, linear->b->n - 1 );

			linear->b_ready[i] = ary[j].real;

			if( linear->b_imag_ready )
				linear->b_imag_ready[i] = ary[j].imag;
		}
	}

	/* Complex constants mean we need complex output.
	 */
	if( unary->in &&
		linear->a_imag_ready &&
		!vips_band_format_iscomplex( unary->in->BandFmt ) ) {
		if( unary->in->BandFmt == VIPS_FORMAT_DOUBLE )
			arithmetic->format = VIPS_FORMAT_DPCOMPLEX;
		else
			arithmetic->format = VIPS_FORMAT_COMPLEX;
	}

	if( linear->uchar )
		arithmetic->format = VIPS_FORMAT_UCHAR;

	if( VIPS_OBJECT_CLASS( vips_linear_parent_class )->build( object ) )
		return( -1 );

	return( 0 );
}

/* Non-complex input, any output, all bands of the constant equal.
 */
#define LOOP1( IN, OUT ) { \
	IN * restrict p = (IN *) in[0]; \
	OUT * restrict q = (OUT *) out; \
	OUT a1 = a[0]; \
	OUT b1 = b[0]; \
	int sz = width * nb; \
	\
	for( x = 0; x < sz; x++ ) \
		q[x] = a1 * (OUT) p[x] + b1; \
}

/* Non-complex input, any output.
 */
#define LOOPN( IN, OUT ) { \
	IN * restrict p = (IN *) in[0]; \
	OUT * restrict q = (OUT *) out; \
	\
	for( i = 0, x = 0; x < width; x++ ) \
		for( k = 0; k < nb; k++, i++ ) \
			q[i] = a[k] * (OUT) p[i] + b[k]; \
}

#define LOOP( IN, OUT ) { \
	if( linear->a->n == 1 && linear->b->n == 1 ) { \
		LOOP1( IN, OUT ); \
	} \
	else { \
		LOOPN( IN, OUT ); \
	} \
}

/* Complex input, complex output. 
 */
#define LOOPCMPLXN( IN, OUT ) { \
	IN * restrict p = (IN *) in[0]; \
	OUT * restrict q = (OUT *) out; \
	\
	for( x = 0; x < width; x++ ) \
		for( k = 0; k < nb; k++ ) { \
			q[0] = a[k] * p[0] + b[k]; \
			q[1] = p[1]; \
			q += 2; \
			p += 2; \
		} \
}

/* Non-complex input, any output, all bands of the constant equal, uchar
 * output.
 */
#define LOOP1uc( IN ) { \
	IN * restrict p = (IN *) in[0]; \
	VipsPel * restrict q = (VipsPel *) out; \
	float a1 = a[0]; \
	float b1 = b[0]; \
	int sz = width * nb; \
	\
	for( x = 0; x < sz; x++ ) { \
		float t = a1 * p[x] + b1; \
		\
		q[x] = VIPS_CLIP( 0, t, 255 ); \
	} \
}

/* Non-complex input, uchar output.
 */
#define LOOPNuc( IN ) { \
	IN * restrict p = (IN *) in[0]; \
	VipsPel * restrict q = (VipsPel *) out; \
	\
	for( i = 0, x = 0; x < width; x++ ) \
		for( k = 0; k < nb; k++, i++ ) { \
			double t = a[k] * p[i] + b[k]; \
			\
			q[i] = VIPS_CLIP( 0, t, 255 ); \
		} \
}

#define LOOPuc( IN ) { \
	if( linear->a->n == 1 && linear->b->n == 1 ) { \
		LOOP1uc( IN ); \
	} \
	else { \
		LOOPNuc( IN ); \
	} \
}

/* Complex input, uchar output. 
 */
#define LOOPCMPLXNuc( IN ) { \
	IN * restrict p = (IN *) in[0]; \
	VipsPel * restrict q = (VipsPel *) out; \
	\
	for( i = 0, x = 0; x < width; x++ ) \
		for( k = 0; k < nb; k++, i++ ) { \
			double t = a[k] * p[0] + b[k]; \
			\
			q[i] = VIPS_CLIP( 0, t, 255 ); \
			p += 2; \
		} \
}

/* Lintra a buffer, n set of scale/offset.
 */
static void
vips_linear_buffer( VipsArithmetic *arithmetic, 
	VipsPel *out, VipsPel **in, int width )
{
	VipsImage *im = arithmetic->ready[0];
	VipsLinear *linear = (VipsLinear *) arithmetic;
	double * restrict a = linear->a_ready;
	double * restrict b = linear->b_ready;
	int nb = im->Bands;

	int i, x, k;

	if( linear->uchar )
		switch( vips_image_get_format( im ) ) {
		case VIPS_FORMAT_UCHAR: 	
			LOOPuc( unsigned char ); break;
		case VIPS_FORMAT_CHAR: 		
			LOOPuc( signed char ); break; 
		case VIPS_FORMAT_USHORT: 	
			LOOPuc( unsigned short ); break; 
		case VIPS_FORMAT_SHORT: 	
			LOOPuc( signed short ); break; 
		case VIPS_FORMAT_UINT: 		
			LOOPuc( unsigned int ); break; 
		case VIPS_FORMAT_INT: 		
			LOOPuc( signed int );  break; 
		case VIPS_FORMAT_FLOAT: 	
			LOOPuc( float ); break; 
		case VIPS_FORMAT_DOUBLE:	
			LOOPuc( double ); break; 
		case VIPS_FORMAT_COMPLEX:	
			LOOPCMPLXNuc( float ); break; 
		case VIPS_FORMAT_DPCOMPLEX:	
			LOOPCMPLXNuc( double ); break;

		default:
			g_assert( 0 );
		}
	else
		switch( vips_image_get_format( im ) ) {
		case VIPS_FORMAT_UCHAR: 	
			LOOP( unsigned char, float ); break;
		case VIPS_FORMAT_CHAR: 		
			LOOP( signed char, float ); break; 
		case VIPS_FORMAT_USHORT: 	
			LOOP( unsigned short, float ); break; 
		case VIPS_FORMAT_SHORT: 	
			LOOP( signed short, float ); break; 
		case VIPS_FORMAT_UINT: 		
			LOOP( unsigned int, float ); break; 
		case VIPS_FORMAT_INT: 		
			LOOP( signed int, float );  break; 
		case VIPS_FORMAT_FLOAT: 	
			LOOP( float, float ); break; 
		case VIPS_FORMAT_DOUBLE:	
			LOOP( double, double ); break; 
		case VIPS_FORMAT_COMPLEX:	
			LOOPCMPLXN( float, float ); break; 
		case VIPS_FORMAT_DPCOMPLEX:	
			LOOPCMPLXN( double, double ); break;

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
static const VipsBandFormat vips_linear_format_table[10] = {
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

	aclass->process_line = vips_linear_buffer;

	vips_arithmetic_set_format_table( aclass, vips_linear_format_table ); 

	VIPS_ARG_BOXED( class, "a", 110, 
		_( "a" ), 
		_( "Multiply by this" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsLinear, a ),
		VIPS_TYPE_ARRAY_COMP );

	VIPS_ARG_BOXED( class, "b", 111, 
		_( "b" ), 
		_( "Add this" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsLinear, b ),
		VIPS_TYPE_ARRAY_COMP );

	VIPS_ARG_BOOL( class, "uchar", 112, 
		_( "uchar" ), 
		_( "Output should be uchar" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsLinear, uchar ),
		FALSE );

}

static void
vips_linear_init( VipsLinear *linear )
{
}

static int
vips_linearv( VipsImage *in, VipsImage **out, 
	double *a, double *b, int n, va_list ap )
{
	VipsArea *area_a;
	VipsArea *area_b;
	int result;

	area_a = (VipsArea *) vips_array_double_new( a, n );
	area_b = (VipsArea *) vips_array_double_new( b, n );

	result = vips_call_split( "linear", ap, in, out, area_a, area_b );

	vips_area_unref( area_a );
	vips_area_unref( area_b );

	return( result );
}

/**
 * vips_linear:
 * @in: image to transform
 * @out: output image
 * @a: (array length=n): array of constants for multiplication
 * @b: (array length=n): array of constants for addition
 * @n: length of constant arrays
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * @uchar: output uchar pixels
 *
 * Pass an image through a linear transform, ie. (@out = @in * @a + @b). Output
 * is float for integer input, double for double input, complex for
 * complex input and double complex for double complex input. Set @uchar to
 * output uchar pixels. 
 *
 * If the arrays of constants have just one element, that constant is used for 
 * all image bands. If the arrays have more than one element and they have 
 * the same number of elements as there are bands in the image, then 
 * one array element is used for each band. If the arrays have more than one
 * element and the image only has a single band, the result is a many-band
 * image where each band corresponds to one array element.
 *
 * See also: vips_linear1(), vips_add().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_linear( VipsImage *in, VipsImage **out, double *a, double *b, int n, ... )
{
	va_list ap;
	int result;

	va_start( ap, n );
	result = vips_linearv( in, out, a, b, n, ap );
	va_end( ap );

	return( result );
}

/**
 * vips_linear1:
 * @in: image to transform
 * @out: output image
 * @a: constant for multiplication
 * @b: constant for addition
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * @uchar: output uchar pixels
 *
 * Run vips_linear() with a single constant. 
 *
 * See also: vips_linear().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_linear1( VipsImage *in, VipsImage **out, double a, double b, ... )
{
	va_list ap;
	int result;

	va_start( ap, b );
	result = vips_linearv( in, out, &a, &b, 1, ap );
	va_end( ap );

	return( result );
}
