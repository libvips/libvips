/* im_multiply.c
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
 *	- new im_add adapted to make new im_multiply
 * 27/9/04
 *	- updated for 1 band $op n band image -> n band image case
 * 8/12/06
 * 	- add liboil support
 * 18/8/08
 * 	- revise upcasting system
 * 	- add gtkdoc comments
 * 31/7/10
 * 	- remove liboil
 * 7/11/11
 * 	- redo as a class
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

typedef VipsBinary VipsMultiply;
typedef VipsBinaryClass VipsMultiplyClass;

G_DEFINE_TYPE( VipsMultiply, vips_multiply, VIPS_TYPE_BINARY );

/* Complex multiply.
 */
#define CLOOP( TYPE ) { \
	TYPE *left = (TYPE *) in[0]; \
	TYPE *right = (TYPE *) in[1]; \
	TYPE *q = (TYPE *) out; \
	\
	for( x = 0; x < sz; x++ ) { \
		double x1 = left[0]; \
		double y1 = left[1]; \
		double x2 = right[0]; \
		double y2 = right[1]; \
		\
		left += 2; \
		right += 2; \
		\
		q[0] = x1 * x2 - y1 * y2; \
		q[1] = x1 * y2 + x2 * y1; \
		\
		q += 2; \
	} \
}

/* Real multiply.
 */
#define RLOOP( IN, OUT ) { \
	IN *left = (IN *) in[0]; \
	IN *right = (IN *) in[1]; \
	OUT *q = (OUT *) out; \
	\
	for( x = 0; x < sz; x++ ) \
		q[x] = left[x] * right[x]; \
}

static void
vips_multiply_buffer( VipsArithmetic *arithmetic, 
	VipsPel *out, VipsPel **in, int width )
{
	VipsImage *im = arithmetic->ready[0];
	const int sz = width * vips_image_get_bands( im );

	int x;

	/* Keep types here in sync with vips_bandfmt_multiply[] 
	 * below.
         */
        switch( vips_image_get_format( im ) ) {
        case VIPS_FORMAT_CHAR: 	RLOOP( signed char, signed short ); break; 
        case VIPS_FORMAT_UCHAR:	RLOOP( unsigned char, signed short ); break; 
        case VIPS_FORMAT_SHORT:	RLOOP( signed short, signed int ); break; 
        case VIPS_FORMAT_USHORT:RLOOP( unsigned short, signed int ); break; 
        case VIPS_FORMAT_INT: 	RLOOP( signed int, signed int ); break; 
        case VIPS_FORMAT_UINT: 	RLOOP( unsigned int, signed int ); break; 
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

/* Type promotion for multiplication. Sign and value preserving. Make sure 
 * these match the case statement in multiply_buffer() above.
 */
static int vips_bandfmt_multiply[10] = {
/* UC  C   US  S   UI  I  F  X  D  DX */
   US, S,  UI, I,  UI, I, F, X, D, DX
};

static void
vips_multiply_class_init( VipsMultiplyClass *class )
{
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsArithmeticClass *aclass = VIPS_ARITHMETIC_CLASS( class );

	object_class->nickname = "multiply";
	object_class->description = _( "multiply two images" );

	vips_arithmetic_set_format_table( aclass, vips_bandfmt_multiply );

	aclass->process_line = vips_multiply_buffer;
}

static void
vips_multiply_init( VipsMultiply *multiply )
{
}

/**
 * vips_multiply:
 * @left: left-hand image
 * @right: right-hand image
 * @out: output image
 *
 * This operation calculates @left * @right and writes the result to @out. 
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
 * <link linkend="VIPS-arithmetic">arithmetic</link>), then the 
 * following table is used to determine the output type:
 *
 * <table>
 *   <title>VipsMultiply type promotion</title>
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
 *         <entry>ushort</entry>
 *       </row>
 *       <row>
 *         <entry>char</entry>
 *         <entry>short</entry>
 *       </row>
 *       <row>
 *         <entry>ushort</entry>
 *         <entry>uint</entry>
 *       </row>
 *       <row>
 *         <entry>short</entry>
 *         <entry>int</entry>
 *       </row>
 *       <row>
 *         <entry>uint</entry>
 *         <entry>uint</entry>
 *       </row>
 *       <row>
 *         <entry>int</entry>
 *         <entry>int</entry>
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
 * See also: vips_add(), vips_linear().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_multiply( VipsImage *left, VipsImage *right, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "multiply", ap, left, right, out );
	va_end( ap );

	return( result );
}
