/* Divide two images
 *
 * Copyright: 1990, N. Dessipris.
 *
 * Author: Nicos Dessipris
 * Written on: 02/05/1990
 * Modified on: 
 * 29/4/93 JC
 *	- now works for partial images
 * 1/7/93 JC
 *	- adapted for partial v2
 *	- ANSIfied
 * 19/10/93 JC
 *	- coredump-inducing bug in complex*complex fixed
 * 13/12/93
 *	- char*short bug fixed
 * 12/6/95 JC
 *	- new im_multiply adapted to make new im_divide
 * 27/9/04
 *	- updated for 1 band $op n band image -> n band image case
 * 8/12/06
 * 	- add liboil support
 * 18/8/08
 * 	- revise upcasting system
 * 	- add gtkdoc comments
 * 31/7/10
 * 	- remove liboil support
 * 	- avoid /0 
 * 6/11/11
 * 	- rewrite as a class 
 * 22/2/12
 * 	- avoid /0 for complex as well
 * 6/4/12
 * 	- fixed switch cases
 *	- fixed int operands with <1 result
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

typedef VipsBinary VipsDivide;
typedef VipsBinaryClass VipsDivideClass;

G_DEFINE_TYPE( VipsDivide, vips_divide, VIPS_TYPE_BINARY );

/* Complex divide.
 */
#ifdef USE_MODARG_DIV

/* This is going to be much slower */
#define CLOOP( TYPE ) { \
	TYPE * __restrict__ left = (TYPE *) in[0]; \
	TYPE * __restrict__ right = (TYPE *) in[1]; \
	TYPE * __restrict__ q = (TYPE *) out; \
	int i; \
        \
	for( i = 0; i < sz; i++ ) { \
		if( right[0] == 0.0 && \
			right[1] == 0.0 ) { \
			q[0] = 0.0; \
			q[1] = 0.0; \
		} \
		else { \
			double arg = atan2( left[1], left[0] ) - \
				atan2( right[1], right[0] ); \
			double mod = hypot( left[1], left[0] ) / \
				hypot( right[1], right[0] ); \
			\
			q[0] = mod * cos( arg ); \
			q[1] = mod * sin( arg ); \
		} \
		\
		left += 2; \
		right += 2; \
		q += 2; \
	} \
}

#else /* USE_MODARG_DIV */

#define CLOOP( TYPE ) {                                     \
	TYPE * __restrict__ left = (TYPE *) in[0]; \
	TYPE * __restrict__ right = (TYPE *) in[1]; \
	TYPE * __restrict__ q = (TYPE *) out; \
	int i; \
        \
	for( i = 0; i < sz; i++ ) { \
		if( right[0] == 0.0 && \
			right[1] == 0.0 ) { \
			q[0] = 0.0; \
			q[1] = 0.0; \
		} \
		else if( fabs( right[0] ) > fabs( right[1] ) ) { \
			double a = right[1] / right[0]; \
			double b = right[0] + right[1] * a; \
			\
			q[0] = (left[0] + left[1] * a) / b; \
			q[1] = (left[1] - left[0] * a) / b; \
		} \
		else { \
			double a = right[0] / right[1]; \
			double b = right[1] + right[0] * a; \
			\
			q[0] = (left[0] * a + left[1]) / b; \
			q[1] = (left[1] * a - left[0]) / b; \
		} \
		\
		left += 2; \
		right += 2; \
		q += 2; \
	} \
}

#endif /* USE_MODARG_DIV */

/* Real divide. Cast in to OUT before divide so we work for float output.
 */
#define RLOOP( IN, OUT ) { \
	IN * __restrict__ left = (IN *) in[0]; \
	IN * __restrict__ right = (IN *) in[1]; \
	OUT * __restrict__ q = (OUT *) out; \
	\
	for( x = 0; x < sz; x++ ) \
		q[x] = right[x] == 0 ? q[x] : (OUT) left[x] / (OUT) right[x]; \
}

static void
vips_divide_buffer( VipsArithmetic *arithmetic, 
	VipsPel *out, VipsPel **in, int width )
{
	VipsImage *im = arithmetic->ready[0];
	const int sz = width * vips_image_get_bands( im );

	int x;

	/* Keep types here in sync with bandfmt_divide[] 
	 * below.
         */
        switch( vips_image_get_format( im ) ) {
        case VIPS_FORMAT_CHAR: 	RLOOP( signed char, float ); break; 
        case VIPS_FORMAT_UCHAR:	RLOOP( unsigned char, float ); break; 
        case VIPS_FORMAT_SHORT:	RLOOP( signed short, float ); break; 
        case VIPS_FORMAT_USHORT: RLOOP( unsigned short, float ); break; 
        case VIPS_FORMAT_INT: 	RLOOP( signed int, float ); break; 
        case VIPS_FORMAT_UINT: 	RLOOP( unsigned int, float ); break; 
        case VIPS_FORMAT_FLOAT:	RLOOP( float, float ); break; 
        case VIPS_FORMAT_DOUBLE: RLOOP( double, double ); break;

        case VIPS_FORMAT_COMPLEX: CLOOP( float ); break;
        case VIPS_FORMAT_DPCOMPLEX: CLOOP( double ); break;

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

/* Type promotion for division. Sign and value preserving. Make sure 
 * these match the case statement in divide_buffer() above.
 */
static int vips_divide_format_table[10] = {
/* UC  C   US  S   UI  I  F  X  D  DX */
   F,  F,  F,  F,  F,  F, F, X, D, DX
};

static void
vips_divide_class_init( VipsDivideClass *class )
{
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsArithmeticClass *aclass = VIPS_ARITHMETIC_CLASS( class );

	object_class->nickname = "divide";
	object_class->description = _( "divide two images" );

	aclass->format_table = vips_divide_format_table;

	aclass->process_line = vips_divide_buffer;
}

static void
vips_divide_init( VipsDivide *divide )
{
}

/**
 * vips_divide:
 * @in1: input image 1
 * @in2: input image 2
 * @out: output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * This operation calculates @in1 / @in2 and writes the result to @out. If any
 * pixels in @in2 are zero, the corresponding pixel in @out is also zero.
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
 * <link linkend="VIPS-arithmetic">arithmetic</link>), then the 
 * following table is used to determine the output type:
 *
 * <table>
 *   <title>im_divide() type promotion</title>
 *   <tgroup cols='2' align='left' colsep='1' rowsep='1'>
 *     <thead>
 *       <row>
 *         <entry>input type</entry>
 *         <entry>output type</entry>
 *       </row>
 *     </thead>
 *     <tbody>
 *       <row>
 *         <entry>uchar</entry>
 *         <entry>float</entry>
 *       </row>
 *       <row>
 *         <entry>char</entry>
 *         <entry>float</entry>
 *       </row>
 *       <row>
 *         <entry>ushort</entry>
 *         <entry>float</entry>
 *       </row>
 *       <row>
 *         <entry>short</entry>
 *         <entry>float</entry>
 *       </row>
 *       <row>
 *         <entry>uint</entry>
 *         <entry>float</entry>
 *       </row>
 *       <row>
 *         <entry>int</entry>
 *         <entry>float</entry>
 *       </row>
 *       <row>
 *         <entry>float</entry>
 *         <entry>float</entry>
 *       </row>
 *       <row>
 *         <entry>double</entry>
 *         <entry>double</entry>
 *       </row>
 *       <row>
 *         <entry>complex</entry>
 *         <entry>complex</entry>
 *       </row>
 *       <row>
 *         <entry>double complex</entry>
 *         <entry>double complex</entry>
 *       </row>
 *     </tbody>
 *   </tgroup>
 * </table>
 *
 * In other words, the output type is just large enough to hold the whole
 * range of possible values.
 *
 * See also: vips_multiply(), vips_linear(), vips_power().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_divide( VipsImage *left, VipsImage *right, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "divide", ap, left, right, out );
	va_end( ap );

	return( result );
}
