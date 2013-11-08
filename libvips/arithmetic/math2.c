/* math2.c --- 2ary math funcs
 *
 * Copyright: 1990, N. Dessipris
 *
 * Author: Nicos Dessipris
 * Written on: 02/05/1990
 * Modified on: 
 * 10/12/93 JC
 *	- now reports total number of x/0, rather than each one.
 * 1/2/95 JC
 *	- rewritten for PIO with im_wrapone()
 *	- incorrect complex code removed
 *	- /0 reporting removed for ease of programming
 * 15/4/97 JC
 *	- return( 0 ) missing, oops!
 * 6/7/98 JC
 *	- _vec form added
 * 30/8/09
 * 	- gtkdoc
 * 	- tiny cleanups
 * 20/9/09
 * 	- im_powtra() adapated to make math2.c
 * 12/11/11
 * 	- redone as a class
 * 17/7/12
 * 	- wopconst was broken
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
#include "unaryconst.h"

typedef struct _VipsMath2 {
	VipsBinary parent_instance;

	VipsOperationMath2 math2;

} VipsMath2;

typedef VipsBinaryClass VipsMath2Class;

G_DEFINE_TYPE( VipsMath2, vips_math2, VIPS_TYPE_BINARY );

static int
vips_math2_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsBinary *binary = (VipsBinary *) object;

	if( binary->left &&
		vips_check_noncomplex( class->nickname, binary->left ) )
		return( -1 );
	if( binary->right &&
		vips_check_noncomplex( class->nickname, binary->right ) )
		return( -1 );

	if( VIPS_OBJECT_CLASS( vips_math2_parent_class )->build( object ) )
		return( -1 );

	return( 0 );
}

#define LOOP( IN, OUT, OP ) { \
	IN *p1 = (IN *) in[0]; \
	IN *p2 = (IN *) in[1]; \
	OUT *q = (OUT *) out; \
	\
	for( x = 0; x < sz; x++ ) \
		OP( q[x], p1[x], p2[x] ); \
}

#define SWITCH( L, OP ) \
	switch( vips_image_get_format( im ) ) { \
	case VIPS_FORMAT_UCHAR: \
		L( unsigned char, float, OP ); break; \
	case VIPS_FORMAT_CHAR: \
		L( signed char, float, OP ); break; \
	case VIPS_FORMAT_USHORT: \
		L( unsigned short, float, OP ); break; \
	case VIPS_FORMAT_SHORT: \
		L( signed short, float, OP ); break; \
	case VIPS_FORMAT_UINT: \
		L( unsigned int, float, OP ); break; \
	case VIPS_FORMAT_INT: \
		L( signed int, float, OP ); break; \
	case VIPS_FORMAT_FLOAT: \
		L( float, float, OP ); break; \
	case VIPS_FORMAT_DOUBLE: \
		L( double, double, OP ); break;\
 	\
	default: \
		g_assert( 0 ); \
	} 

#define POW( Y, X, E ) { \
	double left = (double) (X); \
	double right = (double) (E); \
	\
	if( left == 0.0 && right < 0.0 ) \
		/* Division by zero! Difficult to report tho' \
		 */ \
		(Y) = 0.0; \
	else \
		(Y) = pow( left, right ); \
}

#define WOP( Y, X, E ) POW( Y, E, X )

static void
vips_math2_buffer( VipsArithmetic *arithmetic, 
	VipsPel *out, VipsPel **in, int width )
{
	VipsMath2 *math2 = (VipsMath2 *) arithmetic;
	VipsImage *im = arithmetic->ready[0];
	const int sz = width * vips_image_get_bands( im );

	int x;

	switch( math2->math2 ) {
	case VIPS_OPERATION_MATH2_POW: 	SWITCH( LOOP, POW ); break;
	case VIPS_OPERATION_MATH2_WOP: 	SWITCH( LOOP, WOP ); break;

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

/* Type promotion for math2. Keep in sync with math2_buffer() above.
 */
static int vips_bandfmt_math2[10] = {
/* UC  C   US  S   UI  I   F   X   D   DX */
   F,  F,  F,  F,  F,  F,  F,  X,  D,  DX 
};

static void
vips_math2_class_init( VipsMath2Class *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsArithmeticClass *aclass = VIPS_ARITHMETIC_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "math2";
	object_class->description = _( "binary math operations" );
	object_class->build = vips_math2_build;

	vips_arithmetic_set_format_table( aclass, vips_bandfmt_math2 );

	aclass->process_line = vips_math2_buffer;

	VIPS_ARG_ENUM( class, "math2", 200, 
		_( "Operation" ), 
		_( "math to perform" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsMath2, math2 ),
		VIPS_TYPE_OPERATION_MATH2, VIPS_OPERATION_MATH2_POW ); 
}

static void
vips_math2_init( VipsMath2 *math2 )
{
}

static int
vips_math2v( VipsImage *left, VipsImage *right, VipsImage **out, 
	VipsOperationMath2 math2, va_list ap )
{
	return( vips_call_split( "math2", ap, left, right, out, math2 ) );
}

/**
 * vips_math2:
 * @left: left-hand input #VipsImage
 * @right: right-hand input #VipsImage
 * @out: output #VipsImage
 * @math2: math operation to perform
 * @...: %NULL-terminated list of optional named arguments
 *
 * This operation calculates a 2-ary maths operation on a pair of images
 * and writes the result to @out. The images may have any 
 * non-complex format. @out is float except in the case that either of @left
 * or @right are double, in which case @out is also double.
 *
 * It detects division by zero, setting those pixels to zero in the output. 
 * Beware: it does this silently!
 *
 * If the images differ in size, the smaller image is enlarged to match the
 * larger by adding zero pixels along the bottom and right.
 *
 * If the number of bands differs, one of the images 
 * must have one band. In this case, an n-band image is formed from the 
 * one-band image by joining n copies of the one-band image together, and then
 * the two n-band images are operated upon.
 *
 * The two input images are cast up to the smallest common format (see table 
 * Smallest common format in 
 * <link linkend="VIPS-arithmetic">arithmetic</link>), and that format is the
 * result type.
 *
 * See also: vips_math2_const().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_math2( VipsImage *left, VipsImage *right, VipsImage **out, 
	VipsOperationMath2 math2, ... )
{
	va_list ap;
	int result;

	va_start( ap, math2 );
	result = vips_math2v( left, right, out, math2, ap );
	va_end( ap );

	return( result );
}

/**
 * vips_pow:
 * @left: left-hand input #VipsImage
 * @right: right-hand input #VipsImage
 * @out: output #VipsImage
 * @...: %NULL-terminated list of optional named arguments
 *
 * Perform #VIPS_OPERATION_MATH2_POW on a pair of images. See
 * vips_math2().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_pow( VipsImage *left, VipsImage *right, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_math2v( left, right, out, VIPS_OPERATION_MATH2_POW, ap );
	va_end( ap );

	return( result );
}

/**
 * vips_wop:
 * @left: left-hand input #VipsImage
 * @right: right-hand input #VipsImage
 * @out: output #VipsImage
 * @...: %NULL-terminated list of optional named arguments
 *
 * Perform #VIPS_OPERATION_MATH2_WOP on a pair of images. See
 * vips_math2().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_wop( VipsImage *left, VipsImage *right, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_math2v( left, right, out, VIPS_OPERATION_MATH2_WOP, ap );
	va_end( ap );

	return( result );
}


typedef struct _VipsMath2Const {
	VipsUnaryConst parent_instance;

	VipsOperationMath2 math2;

} VipsMath2Const;

typedef VipsUnaryConstClass VipsMath2ConstClass;

G_DEFINE_TYPE( VipsMath2Const, 
	vips_math2_const, VIPS_TYPE_UNARY_CONST );

static int
vips_math2_const_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsUnary *unary = (VipsUnary *) object;
	VipsUnaryConst *uconst = (VipsUnaryConst *) object;

	if( unary->in &&
		vips_check_noncomplex( class->nickname, unary->in ) )
		return( -1 );

	uconst->const_format = VIPS_FORMAT_DOUBLE;

	if( VIPS_OBJECT_CLASS( vips_math2_const_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

#define LOOPC( IN, OUT, OP ) { \
	IN *p = (IN *) in[0]; \
	OUT *q = (OUT *) out; \
	double *c = (double *) uconst->c_ready; \
	\
	for( i = 0, x = 0; x < width; x++ ) \
		for( b = 0; b < bands; b++, i++ ) \
			OP( q[i], p[i], c[b] ); \
}

static void
vips_math2_const_buffer( VipsArithmetic *arithmetic, 
	VipsPel *out, VipsPel **in, int width )
{
	VipsUnaryConst *uconst = (VipsUnaryConst *) arithmetic;
	VipsMath2Const *math2 = (VipsMath2Const *) arithmetic;
	VipsImage *im = arithmetic->ready[0];
	int bands = im->Bands;

	int i, x, b;

	switch( math2->math2 ) {
	case VIPS_OPERATION_MATH2_POW: 	SWITCH( LOOPC, POW ); break;
	case VIPS_OPERATION_MATH2_WOP: 	SWITCH( LOOPC, WOP ); break;

        default:
		g_assert( 0 );
        }
}

static void
vips_math2_const_class_init( VipsMath2ConstClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsArithmeticClass *aclass = VIPS_ARITHMETIC_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "math2_const";
	object_class->description = _( "pow( @in, @c )" );
	object_class->build = vips_math2_const_build;

	vips_arithmetic_set_format_table( aclass, vips_bandfmt_math2 );

	aclass->process_line = vips_math2_const_buffer;

	VIPS_ARG_ENUM( class, "math2", 200, 
		_( "Operation" ), 
		_( "math to perform" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsMath2Const, math2 ),
		VIPS_TYPE_OPERATION_MATH2, VIPS_OPERATION_MATH2_POW ); 
}

static void
vips_math2_const_init( VipsMath2Const *math2_const )
{
}

static int
vips_math2_constv( VipsImage *in, VipsImage **out, 
	VipsOperationMath2 math2, double *c, int n, va_list ap )
{
	VipsArea *area_c;
	double *array; 
	int result;
	int i;

	area_c = vips_area_new_array( G_TYPE_DOUBLE, sizeof( double ), n ); 
	array = (double *) area_c->data;
	for( i = 0; i < n; i++ ) 
		array[i] = c[i];

	result = vips_call_split( "math2_const", ap, in, out, math2, area_c );

	vips_area_unref( area_c );

	return( result );
}

/**
 * vips_math2_const:
 * @in: input image
 * @out: output image
 * @math2: math operation to perform
 * @c: array of constants 
 * @n: number of constants in @c
 * @...: %NULL-terminated list of optional named arguments
 *
 * This operation calculates various 2-ary maths operations on an image and 
 * an array of constants and writes the result to @out. 
 * The image may have any 
 * non-complex format. @out is float except in the case that @in
 * is double, in which case @out is also double.
 *
 * It detects division by zero, setting those pixels to zero in the output. 
 * Beware: it does this silently!
 *
 * If the array of constants has just one element, that constant is used for 
 * all image bands. If the array has more than one element and they have 
 * the same number of elements as there are bands in the image, then 
 * one array element is used for each band. If the arrays have more than one
 * element and the image only has a single band, the result is a many-band
 * image where each band corresponds to one array element.
 *
 * See also: vips_math2(), vips_math().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_math2_const( VipsImage *in, VipsImage **out, 
	VipsOperationMath2 math2, double *c, int n, ... )
{
	va_list ap;
	int result;

	va_start( ap, n );
	result = vips_math2_constv( in, out, math2, c, n, ap ); 
	va_end( ap );

	return( result );
}

/**
 * vips_pow_const:
 * @in: left-hand input #VipsImage
 * @out: output #VipsImage
 * @c: array of constants 
 * @n: number of constants in @c
 * @...: %NULL-terminated list of optional named arguments
 *
 * Perform #VIPS_OPERATION_MATH2_POW on an image and a constant. See
 * vips_math2_const().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_pow_const( VipsImage *in, VipsImage **out, double *c, int n, ... )
{
	va_list ap;
	int result;

	va_start( ap, n );
	result = vips_math2_constv( in, out, 
		VIPS_OPERATION_MATH2_POW, c, n, ap );
	va_end( ap );

	return( result );
}

/**
 * vips_wop_const:
 * @in: left-hand input #VipsImage
 * @out: output #VipsImage
 * @c: array of constants 
 * @n: number of constants in @c
 * @...: %NULL-terminated list of optional named arguments
 *
 * Perform #VIPS_OPERATION_MATH2_WOP on an image and a constant. See
 * vips_math2_const().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_wop_const( VipsImage *in, VipsImage **out, double *c, int n, ... )
{
	va_list ap;
	int result;

	va_start( ap, n );
	result = vips_math2_constv( in, out, 
		VIPS_OPERATION_MATH2_WOP, c, n, ap );
	va_end( ap );

	return( result );
}

/**
 * vips_math2_const1:
 * @in: input image
 * @out: output image
 * @math2: math operation to perform
 * @c: constant 
 * @...: %NULL-terminated list of optional named arguments
 *
 * This operation calculates various 2-ary maths operations on an image and 
 * a constant. See vips_math2_const().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_math2_const1( VipsImage *in, VipsImage **out, 
	VipsOperationMath2 math2, double c, ... )
{
	va_list ap;
	int result;

	va_start( ap, c );
	result = vips_math2_constv( in, out, math2, &c, 1, ap ); 
	va_end( ap );

	return( result );
}

/**
 * vips_pow_const1:
 * @in: left-hand input #VipsImage
 * @out: output #VipsImage
 * @c: constant 
 * @...: %NULL-terminated list of optional named arguments
 *
 * Perform #VIPS_OPERATION_MATH2_POW on an image and a constant. See
 * vips_math2_const().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_pow_const1( VipsImage *in, VipsImage **out, double c, ... )
{
	va_list ap;
	int result;

	va_start( ap, c );
	result = vips_math2_constv( in, out, 
		VIPS_OPERATION_MATH2_POW, &c, 1, ap );
	va_end( ap );

	return( result );
}

/**
 * vips_wop_const1:
 * @in: left-hand input #VipsImage
 * @out: output #VipsImage
 * @c: constant 
 * @...: %NULL-terminated list of optional named arguments
 *
 * Perform #VIPS_OPERATION_MATH2_WOP on an image and a constant. See
 * vips_math2_const().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_wop_const1( VipsImage *in, VipsImage **out, double c, ... )
{
	va_list ap;
	int result;

	va_start( ap, c );
	result = vips_math2_constv( in, out, 
		VIPS_OPERATION_MATH2_WOP, &c, 1, ap );
	va_end( ap );

	return( result );
}
