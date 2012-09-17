/* remainder.c
 *
 * 2/8/99 JC
 *	- im_divide adapted to make im_remainder
 * 8/5/02 JC
 *	- im_remainderconst added
 *	- im_remainderconst_vec added
 * 27/9/04
 *	- updated for 1 band $op n band image -> n band image case
 * 26/2/07
 * 	- oop, broken for _vec case :-(
 * 14/5/08
 * 	- better /0 test
 * 27/8/08
 * 	- revise upcasting system
 * 	- add gtkdoc comments
 * 23/6/10
 * 	- constant ops clip to target range
 * 12/11/11
 * 	- redone as a class
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

#include "binary.h"
#include "unaryconst.h"

typedef VipsBinary VipsRemainder;
typedef VipsBinaryClass VipsRemainderClass;

G_DEFINE_TYPE( VipsRemainder, vips_remainder, VIPS_TYPE_BINARY );

static int
vips_remainder_build( VipsObject *object )
{
	VipsBinary *binary = (VipsBinary *) object;

	if( binary->left &&
		vips_check_noncomplex( "VipsRemainder", binary->left ) )
		return( -1 );
	if( binary->right &&
		vips_check_noncomplex( "VipsRemainder", binary->right ) )
		return( -1 );

	if( VIPS_OBJECT_CLASS( vips_remainder_parent_class )->build( object ) )
		return( -1 );

	return( 0 );
}

/* Integer remainder-after-division.
 */
#define IREMAINDER( TYPE ) { \
	TYPE *p1 = (TYPE *) in[0]; \
	TYPE *p2 = (TYPE *) in[1]; \
	TYPE *q = (TYPE *) out; \
	\
	for( x = 0; x < sz; x++ ) \
		if( p2[x] ) \
			q[x] = p1[x] % p2[x]; \
		else \
			q[x] = -1; \
}

/* Float remainder-after-division.
 */
#define FREMAINDER( TYPE ) { \
	TYPE *p1 = (TYPE *) in[0]; \
	TYPE *p2 = (TYPE *) in[1]; \
	TYPE *q = (TYPE *) out; \
	\
	for( x = 0; x < sz; x++ ) { \
		double a = p1[x]; \
		double b = p2[x]; \
		\
		if( b ) \
			q[x] = a - b * floor (a / b); \
		else \
			q[x] = -1; \
	} \
}

static void
vips_remainder_buffer( VipsArithmetic *arithmetic, 
	VipsPel *out, VipsPel **in, int width )
{
	VipsImage *im = arithmetic->ready[0];
	const int sz = width * vips_image_get_bands( im );

	int x;

        switch( vips_image_get_format( im ) ) {
        case VIPS_FORMAT_CHAR: 	IREMAINDER( signed char ); break; 
        case VIPS_FORMAT_UCHAR: IREMAINDER( unsigned char ); break; 
        case VIPS_FORMAT_SHORT: IREMAINDER( signed short ); break; 
        case VIPS_FORMAT_USHORT:IREMAINDER( unsigned short ); break; 
        case VIPS_FORMAT_INT: 	IREMAINDER( signed int ); break; 
        case VIPS_FORMAT_UINT: 	IREMAINDER( unsigned int ); break; 
        case VIPS_FORMAT_FLOAT: FREMAINDER( float ); break; 
        case VIPS_FORMAT_DOUBLE:FREMAINDER( double ); break;

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

/* Type promotion for remainder. Keep in sync with remainder_buffer() above.
 */
static int vips_bandfmt_remainder[10] = {
/* UC  C   US  S   UI  I  F  X  D  DX */
   UC, C,  US, S,  UI, I, F, X, D, DX
};

static void
vips_remainder_class_init( VipsRemainderClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsArithmeticClass *aclass = VIPS_ARITHMETIC_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "remainder";
	object_class->description = 
		_( "remainder after integer division of two images" );
	object_class->build = vips_remainder_build;

	vips_arithmetic_set_format_table( aclass, vips_bandfmt_remainder );

	aclass->process_line = vips_remainder_buffer;
}

static void
vips_remainder_init( VipsRemainder *remainder )
{
}

/**
 * vips_remainder:
 * @left: left-hand input #VipsImage
 * @right: right-hand input #VipsImage
 * @out: output #VipsImage
 * @...: %NULL-terminated list of optional named arguments
 *
 * This operation calculates @left % @right (remainder after integer division) 
 * and writes the result to @out. The images may have any 
 * non-complex format. For float formats, vips_remainder() calculates @in1 -
 * @in2 * floor (@in1 / @in2).
 *
 * If the images differ in size, the smaller image is enlarged to match the
 * larger by adding zero pixels along the bottom and right.
 *
 * If the number of bands differs, one of the images 
 * must have one band. In this case, an n-band image is formed from the 
 * one-band image by joining n copies of the one-band image together, and then
 * the two n-band images are operated upon.
 *
 * The two input images are cast up to the smallest common type (see table 
 * Smallest common format in 
 * <link linkend="VIPS-arithmetic">arithmetic</link>), and that format is the
 * result type.
 *
 * See also: vips_remainder_const(), vips_divide(), vips_round().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_remainder( VipsImage *left, VipsImage *right, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "remainder", ap, left, right, out );
	va_end( ap );

	return( result );
}

typedef VipsUnaryConst VipsRemainderConst;
typedef VipsUnaryConstClass VipsRemainderConstClass;

G_DEFINE_TYPE( VipsRemainderConst, 
	vips_remainder_const, VIPS_TYPE_UNARY_CONST );

static int
vips_remainder_const_build( VipsObject *object )
{
	VipsUnary *unary = (VipsUnary *) object;
	VipsUnaryConst *uconst = (VipsUnaryConst *) object;

	if( unary->in &&
		vips_check_noncomplex( "VipsRemainder", unary->in ) )
		return( -1 );

	if( unary->in )
		uconst->const_format = unary->in->BandFmt;

	if( VIPS_OBJECT_CLASS( vips_remainder_const_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

/* Integer remainder-after-divide, per-band constant.
 */
#define IREMAINDERCONST( TYPE ) { \
	TYPE *p = (TYPE *) in[0]; \
	TYPE *q = (TYPE *) out; \
	TYPE *c = (TYPE *) uconst->c_ready; \
	\
	for( i = 0, x = 0; x < width; x++ ) \
		for( b = 0; b < bands; b++, i++ ) \
			q[i] = p[i] % c[b]; \
}

/* Float remainder-after-divide, per-band constant.
 */
#define FREMAINDERCONST( TYPE ) { \
	TYPE *p = (TYPE *) in[0]; \
	TYPE *q = (TYPE *) out; \
	TYPE *c = (TYPE *) uconst->c_ready; \
	\
	for( i = 0, x = 0; x < width; x++ ) \
		for( b = 0; b < bands; b++, i++ ) { \
			double left = p[i]; \
			double right = c[b]; \
			\
			if( right ) \
				q[i] = left - right * floor( left / right ); \
			else \
				q[i] = -1; \
		} \
}

static void
vips_remainder_const_buffer( VipsArithmetic *arithmetic, 
	VipsPel *out, VipsPel **in, int width )
{
	VipsUnaryConst *uconst = (VipsUnaryConst *) arithmetic;
	VipsImage *im = arithmetic->ready[0];
	int bands = im->Bands;

	int i, x, b;

        switch( vips_image_get_format( im ) ) {
        case VIPS_FORMAT_CHAR: 	IREMAINDERCONST( signed char ); break; 
        case VIPS_FORMAT_UCHAR: IREMAINDERCONST( unsigned char ); break; 
        case VIPS_FORMAT_SHORT: IREMAINDERCONST( signed short ); break; 
        case VIPS_FORMAT_USHORT:IREMAINDERCONST( unsigned short ); break; 
        case VIPS_FORMAT_INT: 	IREMAINDERCONST( signed int ); break; 
        case VIPS_FORMAT_UINT: 	IREMAINDERCONST( unsigned int ); break; 
        case VIPS_FORMAT_FLOAT: FREMAINDERCONST( float ); break; 
        case VIPS_FORMAT_DOUBLE:FREMAINDERCONST( double ); break;

        default:
		g_assert( 0 );
        }
}

static void
vips_remainder_const_class_init( VipsRemainderConstClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsArithmeticClass *aclass = VIPS_ARITHMETIC_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "remainder_const";
	object_class->description = 
		_( "remainder after integer division of an image " 
		"and a constant" );
	object_class->build = vips_remainder_const_build;

	vips_arithmetic_set_format_table( aclass, vips_bandfmt_remainder );

	aclass->process_line = vips_remainder_const_buffer;
}

static void
vips_remainder_const_init( VipsRemainderConst *remainder_const )
{
}

static int
vips_remainder_constv( VipsImage *in, VipsImage **out, 
	double *c, int n, va_list ap )
{
	VipsArea *area_c;
	double *array; 
	int result;
	int i;

	area_c = vips_area_new_array( G_TYPE_DOUBLE, sizeof( double ), n ); 
	array = (double *) area_c->data;
	for( i = 0; i < n; i++ ) 
		array[i] = c[i];

	result = vips_call_split( "remainder_const", ap, in, out, area_c );

	vips_area_unref( area_c );

	return( result );
}

/**
 * vips_remainder_const:
 * @in: input image
 * @out: output image
 * @c: array of constants 
 * @n: number of constants in @c
 * @...: %NULL-terminated list of optional named arguments
 *
 * This operation calculates @in % @c (remainder after division by an 
 * array of constants) 
 * and writes the result to @out. 
 * The image may have any 
 * non-complex format. For float formats, vips_remainder_const() calculates 
 * @in - @c * floor (@in / @c).
 *
 * If the array of constants has just one element, that constant is used for 
 * all image bands. If the array has more than one element and they have 
 * the same number of elements as there are bands in the image, then 
 * one array element is used for each band. If the arrays have more than one
 * element and the image only has a single band, the result is a many-band
 * image where each band corresponds to one array element.
 *
 * See also: vips_remainder(), vips_divide(), vips_round().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_remainder_const( VipsImage *in, VipsImage **out, double *c, int n, ... )
{
	va_list ap;
	int result;

	va_start( ap, n );
	result = vips_remainder_constv( in, out, c, n, ap ); 
	va_end( ap );

	return( result );
}

/**
 * vips_remainder_const1:
 * @in: input image
 * @out: output image
 * @c: constant 
 * @...: %NULL-terminated list of optional named arguments
 *
 * This operation calculates @in % @c (remainder after division by a 
 * constant) 
 * and writes the result to @out. 
 * The image may have any 
 * non-complex format. For float formats, vips_remainder_const() calculates 
 * @in - @c * floor (@in / @c).
 *
 * If the array of constants has just one element, that constant is used for 
 * all image bands. If the array has more than one element and they have 
 * the same number of elements as there are bands in the image, then 
 * one array element is used for each band. If the arrays have more than one
 * element and the image only has a single band, the result is a many-band
 * image where each band corresponds to one array element.
 *
 * See also: vips_remainder(), vips_divide(), vips_round().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_remainder_const1( VipsImage *in, VipsImage **out, double c, ... )
{
	va_list ap;
	int result;

	va_start( ap, c );
	result = vips_remainder_constv( in, out, &c, 1, ap ); 
	va_end( ap );

	return( result );
}

