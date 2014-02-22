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
 * 21/2/14
 * 	- add imaginary components
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
#include <string.h>
#include <math.h>

#include <vips/vips.h>

#include "unary.h"

typedef struct _VipsLinear {
	VipsUnary parent_instance;

	/* Our constants: multiply by a, add b.
	 */
	VipsArea *a;
	VipsArea *b;

	/* Optional imaginary part. Zero if not set. 
	 */
	VipsArea *a_imag;
	VipsArea *b_imag;

	/* uchar output.
	 */
	gboolean uchar;

	/* Our constants expanded to match arith->ready in size.
	 */
	int n;
	double *a_ready;
	double *b_ready;
	double *a_imag_ready;
	double *b_imag_ready;

} VipsLinear;

typedef VipsUnaryClass VipsLinearClass;

G_DEFINE_TYPE( VipsLinear, vips_linear, VIPS_TYPE_UNARY );

static int
vips_linear_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsArithmetic *arithmetic = VIPS_ARITHMETIC( object );
	VipsUnary *unary = (VipsUnary *) object;
	VipsLinear *linear = (VipsLinear *) object;

	int bands;
	VipsBandFormat format;
	int i;

	/* How many bands will our input image have after decoding? Need
	 * format too.
	 */
	switch( unary->in->Coding ) {
	case VIPS_CODING_RAD:
		bands = 3;
		format = VIPS_FORMAT_FLOAT;
		break;

	case VIPS_CODING_LABQ:
		bands = 3;
		format = VIPS_FORMAT_SHORT;
		break;

	default:
		bands = unary->in->Bands;
		format = unary->in->BandFmt;
		break;
	}

	/* If we have a many-element vector, we need to bandup the image to
	 * match.
	 */

	linear->n = 1;
	if( linear->a )
		linear->n = VIPS_MAX( linear->n, linear->a->n );
	if( linear->b )
		linear->n = VIPS_MAX( linear->n, linear->b->n );
	if( linear->a_imag )
		linear->n = VIPS_MAX( linear->n, linear->a_imag->n );
	if( linear->b_imag )
		linear->n = VIPS_MAX( linear->n, linear->b_imag->n );
	if( unary->in )
		linear->n = VIPS_MAX( linear->n, bands );
	arithmetic->base_bands = linear->n;

	if( unary->in && 
		linear->a &&
		vips_check_vector( class->nickname, linear->a->n, unary->in ) )
		return( -1 );
	if( linear->b &&
		linear->a &&
		vips_check_vector_length( class->nickname, 
			linear->b->n, linear->a->n ) )
		return( -1 );
	if( linear->a_imag &&
		linear->a &&
		vips_check_vector_length( class->nickname, 
			linear->a_imag->n, linear->a->n ) )
		return( -1 );
	if( linear->b_imag &&
		linear->a &&
		vips_check_vector_length( class->nickname, 
			linear->b_imag->n, linear->a->n ) )
		return( -1 );

	/* Make up-banded versions of our constants.
	 */
	linear->a_ready = VIPS_ARRAY( linear, linear->n, double );
	linear->b_ready = VIPS_ARRAY( linear, linear->n, double );

	/* Either complex constant can be missing, we need to default to zero.
	 */
	if( linear->a_imag ||
		linear->b_imag ) {
		linear->a_imag_ready = VIPS_ARRAY( linear, linear->n, double );
		linear->b_imag_ready = VIPS_ARRAY( linear, linear->n, double );
		memset( linear->a_imag_ready, 0, linear->n * sizeof( double ) );
		memset( linear->b_imag_ready, 0, linear->n * sizeof( double ) );
	}

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

		if( linear->a_imag ) {
			double *ary = (double *) linear->a_imag->data;
			int j = VIPS_MIN( i, linear->a_imag->n - 1 );

			linear->a_imag_ready[i] = ary[j];
		}

		if( linear->b_imag ) {
			double *ary = (double *) linear->b_imag->data;
			int j = VIPS_MIN( i, linear->b_imag->n - 1 );

			linear->b_imag_ready[i] = ary[j];
		}
	}

	if( linear->uchar )
		arithmetic->format = VIPS_FORMAT_UCHAR;
	else if( linear->a_imag ||
		linear->b_imag ) {
		if( format == VIPS_FORMAT_DOUBLE )
			arithmetic->format = VIPS_FORMAT_DPCOMPLEX;
		else
			arithmetic->format = VIPS_FORMAT_COMPLEX;
	}

	if( VIPS_OBJECT_CLASS( vips_linear_parent_class )->build( object ) )
		return( -1 );

	return( 0 );
}

/* Non-complex input, non-complex constant, all bands of the constant equal.
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

/* Non-complex input, non-complex constant, many-band constant.
 */
#define LOOPN( IN, OUT ) { \
	IN * restrict p = (IN *) in[0]; \
	OUT * restrict q = (OUT *) out; \
	\
	for( i = 0, x = 0; x < width; x++ ) \
		for( k = 0; k < nb; k++, i++ ) \
			q[i] = a[k] * (OUT) p[i] + b[k]; \
}

/* Non-complex input, complex constant, many-band constant.
 */
#define LOOPNC( IN, OUT ) { \
	IN * restrict p = (IN *) in[0]; \
	OUT * restrict q = (OUT *) out; \
	\
	for( i = 0, x = 0; x < width; x++ ) \
		for( k = 0; k < nb; k++, i++ ) { \
			q[0] = p[i] * a[k] + b[k]; \
			q[1] = p[i] * a_imag[k] + b_imag[k]; \
			q += 2; \
		} \
}

#define LOOP( IN, OUT ) { \
	if( linear->a_imag_ready ) { \
		LOOPNC( IN, OUT ); \
	} \
	else if( linear->a->n == 1 && linear->b->n == 1 ) { \
		LOOP1( IN, OUT ); \
	} \
	else { \
		LOOPN( IN, OUT ); \
	} \
}

/* Complex input, non-complex constant. 
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

/* Complex input, complex constant. 
 */
#define LOOPCMPLXNC( IN, OUT ) { \
	IN * restrict p = (IN *) in[0]; \
	OUT * restrict q = (OUT *) out; \
	\
	for( x = 0; x < width; x++ ) \
		for( k = 0; k < nb; k++ ) { \
			double x1 = p[0]; \
			double y1 = p[1]; \
			double x2 = a[k]; \
			double y2 = a_imag[k]; \
			\
			q[0] = x1 * x2 - y1 * y2 + b[k]; \
			q[1] = x1 * y2 + x2 * y1 + b_imag[k]; \
			\
			q += 2; \
			p += 2; \
		} \
}

#define LOOPCMPLX( IN, OUT ) { \
	if( linear->a_imag_ready ) { \
		LOOPCMPLXNC( IN, OUT ); \
	} \
	else { \
		LOOPCMPLXN( IN, OUT ); \
	} \
}

/* Non-complex input, all bands of the constant equal, uchar output. Since we
 * don't look at the imaginary component of the constant since we don't
 * generate the imaginary component of the output, we work for a complex
 * constant too. 
 */
#define LOOP1uc( IN, DUMMY ) { \
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

/* Non-complex input, non-complex constant, uchar output. Since we are
 * outputting non-complex, we will work for a complex constant too. 
 */
#define LOOPNuc( IN, DUMMY ) { \
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

#define LOOPuc( IN, DUMMY ) { \
	if( linear->a->n == 1 && linear->b->n == 1 ) { \
		LOOP1uc( IN, DUMMY ); \
	} \
	else { \
		LOOPNuc( IN, DUMMY ); \
	} \
}

/* Complex input, non-complex constant, uchar output. 
 */
#define LOOPCMPLXNuc( IN, DUMMY ) { \
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

/* Complex input, complex constant, uchar output. 
 */
#define LOOPCMPLXNCuc( IN, DUMMY ) { \
	IN * restrict p = (IN *) in[0]; \
	VipsPel * restrict q = (VipsPel *) out; \
	\
	for( i = 0, x = 0; x < width; x++ ) \
		for( k = 0; k < nb; k++, i++ ) { \
			double x1 = p[0]; \
			double y1 = p[1]; \
			double x2 = a[k]; \
			double y2 = a_imag[k]; \
			double t = x1 * x2 - y1 * y2 + b[k]; \
			\
			q[i] = VIPS_CLIP( 0, t, 255 ); \
			p += 2; \
		} \
}

#define LOOPCMPLXuc( IN, OUT ) { \
	if( linear->a_imag_ready ) { \
		LOOPCMPLXNCuc( IN, OUT ); \
	} \
	else { \
		LOOPCMPLXNuc( IN, OUT ); \
	} \
}

#define SWITCH( REAL, CMPLX ) { \
	switch( vips_image_get_format( im ) ) { \
	case VIPS_FORMAT_UCHAR: \
		REAL( unsigned char, float ); break; \
	case VIPS_FORMAT_CHAR: \
		REAL( signed char, float ); break; \
	case VIPS_FORMAT_USHORT: \
		REAL( unsigned short, float ); break; \
	case VIPS_FORMAT_SHORT: \
		REAL( signed short, float ); break; \
	case VIPS_FORMAT_UINT: \
		REAL( unsigned int, float ); break; \
	case VIPS_FORMAT_INT: \
		REAL( signed int, float );  break; \
	case VIPS_FORMAT_FLOAT: \
		REAL( float, float ); break; \
	case VIPS_FORMAT_DOUBLE: \
		REAL( double, double ); break; \
	case VIPS_FORMAT_COMPLEX: \
		CMPLX( float, float ); break; \
	case VIPS_FORMAT_DPCOMPLEX: \
		CMPLX( double, double ); break; \
	\
	default: \
		g_assert( 0 ); \
	} \
}

static void
vips_linear_buffer( VipsArithmetic *arithmetic, 
	VipsPel *out, VipsPel **in, int width )
{
	VipsImage *im = arithmetic->ready[0];
	VipsLinear *linear = (VipsLinear *) arithmetic;
	double * restrict a = linear->a_ready;
	double * restrict b = linear->b_ready;
	double * restrict a_imag = linear->a_imag_ready;
	double * restrict b_imag = linear->b_imag_ready;
	int nb = im->Bands;

	int i, x, k;

	if( linear->uchar ) {
		SWITCH( LOOPuc, LOOPCMPLXuc ); 
	}
	else {
		SWITCH( LOOP, LOOPCMPLX ); 
	}
}

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
		VIPS_TYPE_ARRAY_DOUBLE );

	VIPS_ARG_BOXED( class, "b", 111, 
		_( "b" ), 
		_( "Add this" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsLinear, b ),
		VIPS_TYPE_ARRAY_DOUBLE );

	VIPS_ARG_BOXED( class, "a_imag", 112, 
		_( "a_imag" ), 
		_( "Multiply by this (imaginary component)" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsLinear, a_imag ),
		VIPS_TYPE_ARRAY_DOUBLE );

	VIPS_ARG_BOXED( class, "b_imag", 113, 
		_( "b_imag" ), 
		_( "Add this (imaginary component)" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsLinear, b_imag ),
		VIPS_TYPE_ARRAY_DOUBLE );

	VIPS_ARG_BOOL( class, "uchar", 114, 
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
	double *a, double *a_imag, double *b, double *b_imag, int n, 
	va_list ap )
{
	VipsOperation *operation;
	VipsArea *area_a;
	VipsArea *area_b;

	if( !(operation = vips_operation_new( "linear" )) )
		return( -1 ); 

	area_a = (VipsArea *) vips_array_double_new( a, n );
	area_b = (VipsArea *) vips_array_double_new( b, n );

	g_object_set( operation,
		"in", in,
		"a", area_a,
		"b", area_b,
		NULL ); 

	vips_area_unref( area_a );
	vips_area_unref( area_b );

	if( a_imag ) { 
		VipsArea *area_a_imag;

		area_a_imag = (VipsArea *) vips_array_double_new( a_imag, n );
		g_object_set( operation, 
			"a_imag", area_a_imag,
			NULL );
		vips_area_unref( area_a_imag );
	}

	if( b_imag ) { 
		VipsArea *area_b_imag;

		area_b_imag = (VipsArea *) vips_array_double_new( b_imag, n );
		g_object_set( operation, 
			"b_imag", area_b_imag,
			NULL );
		vips_area_unref( area_b_imag );
	}

	(void) vips_object_set_valist( VIPS_OBJECT( operation ), ap );

	if( vips_cache_operation_buildp( &operation ) ) {
		vips_object_unref_outputs( VIPS_OBJECT( operation ) );
		g_object_unref( operation );

		return( -1 );
	}

	g_object_get( operation,
		"out", out,
		NULL );

	g_object_unref( operation );

	return( 0 );
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
 * @a_imag: #VipsArrayDouble of imaginary constants for multiplication
 * @b_imag: #VipsArrayDouble of imaginary constants for addition
 *
 * Pass an image through a linear transform, ie. (@out = @in * @a + @b). Output
 * is float for integer input, double for double input, complex for
 * complex input and double complex for double complex input. If complex
 * constants are specified, the output is complex, see below.
 *
 * Set @uchar to output uchar pixels. This is much faster than vips_linear()
 * followed by vips_cast().
 *
 * If the arrays of constants have just one element, that constant is used for 
 * all image bands. If the arrays have more than one element and they have 
 * the same number of elements as there are bands in the image, then 
 * one array element is used for each band. If the arrays have more than one
 * element and the image only has a single band, the result is a many-band
 * image where each band corresponds to one array element.
 *
 * Set @a_imag and @b_imag to set imagiary constants for multiplication and
 * addition. If imaginary components are specified, the output is complex for
 * non-double-complex inputs and double-complex for double-complex inputs.
 *
 * See also: vips_linear1(), vips_linear_complex(), vips_linear_complex1(),
 * vips_add().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_linear( VipsImage *in, VipsImage **out, double *a, double *b, int n, ... )
{
	va_list ap;
	int result;

	va_start( ap, n );
	result = vips_linearv( in, out, a, NULL, b, NULL, n, ap );
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
 * @a_imag: #VipsArrayDouble of imaginary constants for multiplication
 * @b_imag: #VipsArrayDouble of imaginary constants for addition
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
	result = vips_linearv( in, out, &a, NULL, &b, NULL, 1, ap );
	va_end( ap );

	return( result );
}

/**
 * vips_linear_complex:
 * @in: image to transform
 * @out: output image
 * @a: (array length=n): array of real constants for multiplication
 * @a_imag: (array length=n): array of imaginary constants for multiplication
 * @b: (array length=n): array of real constants for addition
 * @b_imag: (array length=n): array of imaginary constants for addition
 * @n: length of constant arrays
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * @uchar: output uchar pixels
 *
 * Run vips_linear() with a set of complex constants.
 *
 * See also: vips_linear().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_linear_complex( VipsImage *in, VipsImage **out, 
	double *a, double *a_imag, double *b, double *b_imag, int n, ... )
{
	va_list ap;
	int result;

	va_start( ap, n );
	result = vips_linearv( in, out, a, a_imag, b, b_imag, n, ap );
	va_end( ap );

	return( result );
}

/**
 * vips_linear_complex1:
 * @in: image to transform
 * @out: output image
 * @a: real constant for multiplication
 * @a_imag: imaginary constant for multiplication
 * @b: real constant for addition
 * @b_imag: imaginary constant for addition
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * @uchar: output uchar pixels
 *
 * Run vips_linear() with a single complex constant.
 *
 * See also: vips_linear().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_linear_complex1( VipsImage *in, VipsImage **out, 
	double a, double a_imag, double b, double b_imag, ... )
{
	va_list ap;
	int result;

	va_start( ap, b_imag );
	result = vips_linearv( in, out, &a, &a_imag, &b, &b_imag, 1, ap );
	va_end( ap );

	return( result );
}
