/* sum an array of images
 *
 * 18/3/14
 * 	- from add.c
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

typedef VipsNary VipsSum;
typedef VipsNaryClass VipsSumClass;

G_DEFINE_TYPE( VipsSum, vips_sum, VIPS_TYPE_NARY );

#define LOOP( IN, OUT ) { \
	IN ** restrict p = (IN **) in; \
	OUT * restrict q = (OUT *) out; \
	\
	for( x = 0; x < sz; x++ ) { \
		OUT sum; \
		\
		sum = p[0][x]; \
		for( i = 1; i < n; i++ ) \
			sum += p[i][x]; \
		q[x] = sum; \
	} \
}

static void
sum_buffer( VipsArithmetic *arithmetic, VipsPel *out, VipsPel **in, int width )
{
	VipsImage *im = arithmetic->ready[0];
	int n = arithmetic->n; 

	/* Complex just doubles the size.
	 */
	const int sz = width * vips_image_get_bands( im ) * 
		(vips_band_format_iscomplex( vips_image_get_format( im ) ) ? 
		 	2 : 1);

	int x;
	int i;

	/* Sum all input types. Keep types here in sync with 
	 * vips_sum_format_table[] below.
	 */
	switch( vips_image_get_format( im ) ) {
	case VIPS_FORMAT_UCHAR: 	
		LOOP( unsigned char, unsigned int ); break; 
	case VIPS_FORMAT_CHAR: 	
		LOOP( signed char, signed int ); break; 
	case VIPS_FORMAT_USHORT: 
		LOOP( unsigned short, unsigned int ); break; 
	case VIPS_FORMAT_SHORT: 	
		LOOP( signed short, signed int ); break; 
	case VIPS_FORMAT_UINT: 	
		LOOP( unsigned int, unsigned int ); break; 
	case VIPS_FORMAT_INT: 	
		LOOP( signed int, signed int ); break; 

	case VIPS_FORMAT_FLOAT: 		
	case VIPS_FORMAT_COMPLEX: 
		LOOP( float, float ); break; 

	case VIPS_FORMAT_DOUBLE:	
	case VIPS_FORMAT_DPCOMPLEX: 
		LOOP( double, double ); break;

	default:
		g_assert( 0 );
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

/* Type promotion for addition. Sign and value preserving. Make sure these
 * match the case statement in sum_buffer() above.
 */
static const VipsBandFormat vips_sum_format_table[10] = {
/* UC  C   US  S   UI  I  F  X  D  DX */
   UI, I,  UI, I,  UI, I, F, X, D, DX
};

static void
vips_sum_class_init( VipsSumClass *class )
{
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsArithmeticClass *aclass = VIPS_ARITHMETIC_CLASS( class );

	object_class->nickname = "sum";
	object_class->description = _( "sum an array of images" );

	aclass->process_line = sum_buffer;

	vips_arithmetic_set_format_table( aclass, vips_sum_format_table ); 
}

static void
vips_sum_init( VipsSum *sum )
{
}

static int
vips_sumv( VipsImage **in, VipsImage **out, int n, va_list ap )
{
	VipsArea *area;
	VipsImage **array; 
	int i;
	int result;

	area = vips_area_new_array_object( n );
	array = (VipsImage **) area->data;
	for( i = 0; i < n; i++ ) {
		array[i] = in[i];
		g_object_ref( array[i] );
	}

	result = vips_call_split( "sum", ap, area, out );

	vips_area_unref( area );

	return( result );
}

/**
 * vips_sum:
 * @in: array of input images
 * @out: output image
 * @n: number of input images
 * @...: %NULL-terminated list of optional named arguments
 *
 * This operation sums @in1 + @in2 and writes the result to @out. 
 *
 * If the images differ in size, the smaller images are enlarged to match the
 * largest by adding zero pixels along the bottom and right.
 *
 * If the number of bands differs, all but one of the images
 * must have one band. In this case, n-band images are formed from the 
 * one-band images by joining n copies of the one-band images together, and then
 * the n-band images are operated upon.
 *
 * The input images are cast up to the smallest common format (see table 
 * Smallest common format in 
 * <link linkend="VIPS-arithmetic">arithmetic</link>), then the 
 * following table is used to determine the output type:
 *
 * <table>
 *   <title>VipsSum type promotion</title>
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
 *         <entry>uint</entry>
 *       </row>
 *       <row>
 *         <entry>char</entry>
 *         <entry>int</entry>
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
 * See also: vips_add().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_sum( VipsImage **in, VipsImage **out, int n, ... )
{
	va_list ap;
	int result;

	va_start( ap, n );
	result = vips_sumv( in, out, n, ap );
	va_end( ap );

	return( result );
}
