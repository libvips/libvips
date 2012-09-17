/* add operation
 *
 * Copyright: 1990, N. Dessipris.
 *
 * Author: Nicos Dessipris
 * Written on: 02/05/1990
 * Modified on: 
 * 29/4/93 J.Cupitt
 *	- now works for partial images
 * 1/7/93 JC
 * 	- adapted for partial v2
 * 9/5/95 JC
 *	- simplified: now just handles 10 cases (instead of 50), using
 *	  im_clip2*() to help
 *	- now uses im_wrapmany() rather than im_generate()
 * 31/5/96 JC
 *	- SWAP() removed, *p++ removed
 * 27/9/04
 *	- im__cast_and_call() now matches bands as well
 *	- ... so 1 band + 4 band image -> 4 band image
 * 8/12/06
 * 	- add liboil support
 * 18/8/08
 * 	- revise upcasting system
 * 	- im__cast_and_call() no longer sets bbits for you
 * 	- add gtkdoc comments
 * 	- remove separate complex case, just double size
 * 11/9/09
 * 	- im__cast_and_call() becomes im__arith_binary()
 * 	- more of operation scaffold moved inside
 * 25/7/10
 * 	- remove oil support again ... we'll try Orc instead
 * 29/10/10
 * 	- move to VipsVector for Orc support
 * 28/2/11
 * 	- argh vector int/uint was broken
 * 4/4/11
 * 	- rewrite as a class
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

typedef VipsBinary VipsAdd;
typedef VipsBinaryClass VipsAddClass;

G_DEFINE_TYPE( VipsAdd, vips_add, VIPS_TYPE_BINARY );

#define LOOP( IN, OUT ) { \
	IN *left = (IN *) in[0]; \
	IN *right = (IN *) in[1]; \
	OUT *q = (OUT *) out; \
	\
	for( x = 0; x < sz; x++ ) \
		q[x] = left[x] + right[x]; \
}

static void
add_buffer( VipsArithmetic *arithmetic, VipsPel *out, VipsPel **in, int width )
{
	VipsArithmeticClass *class = VIPS_ARITHMETIC_GET_CLASS( arithmetic );
	VipsImage *im = arithmetic->ready[0];

	/* Complex just doubles the size.
	 */
	const int sz = width * vips_image_get_bands( im ) * 
		(vips_band_format_iscomplex( vips_image_get_format( im ) ) ? 
		 	2 : 1);

	VipsVector *v;

	if( (v = vips_arithmetic_get_vector( class, 
		vips_image_get_format( im ) )) ) {
		VipsExecutor ex;

		vips_executor_set_program( &ex, v, sz );
		vips_executor_set_array( &ex, v->s[0], in[0] );
		vips_executor_set_array( &ex, v->s[1], in[1] );
		vips_executor_set_destination( &ex, out );

		vips_executor_run( &ex );
	}
	else {
		int x;

		/* Add all input types. Keep types here in sync with 
		 * bandfmt_add[] below.
		 */
		switch( vips_image_get_format( im ) ) {
		case VIPS_FORMAT_UCHAR: 	
			LOOP( unsigned char, unsigned short ); break; 
		case VIPS_FORMAT_CHAR: 	
			LOOP( signed char, signed short ); break; 
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

/* Type promotion for addition. Sign and value preserving. Make sure these
 * match the case statement in add_buffer() above.
 */
static const VipsBandFormat bandfmt_add[10] = {
/* UC  C   US  S   UI  I  F  X  D  DX */
   US, S,  UI, I,  UI, I, F, X, D, DX
};

static void
vips_add_class_init( VipsAddClass *class )
{
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsArithmeticClass *aclass = VIPS_ARITHMETIC_CLASS( class );
	VipsVector *v;

	object_class->nickname = "add";
	object_class->description = _( "add two images" );

	vips_arithmetic_set_format_table( aclass, bandfmt_add );

	v = vips_arithmetic_get_program( aclass, VIPS_FORMAT_UCHAR );
	vips_vector_asm2( v, "convubw", "t1", "s1" );
	vips_vector_asm2( v, "convubw", "t2", "s2" );
	vips_vector_asm3( v, "addw", "d1", "t1", "t2" ); 

	v = vips_arithmetic_get_program( aclass, VIPS_FORMAT_CHAR );
	vips_vector_asm2( v, "convsbw", "t1", "s1" );
	vips_vector_asm2( v, "convsbw", "t2", "s2" );
	vips_vector_asm3( v, "addw", "d1", "t1", "t2" ); 

	v = vips_arithmetic_get_program( aclass, VIPS_FORMAT_USHORT );
	vips_vector_asm2( v, "convuwl", "t1", "s1" );
	vips_vector_asm2( v, "convuwl", "t2", "s2" );
	vips_vector_asm3( v, "addl", "d1", "t1", "t2" );

	v = vips_arithmetic_get_program( aclass, VIPS_FORMAT_SHORT );
	vips_vector_asm2( v, "convswl", "t1", "s1" );
	vips_vector_asm2( v, "convswl", "t2", "s2" );
	vips_vector_asm3( v, "addl", "d1", "t1", "t2" );

	/*

	   uint/int are a little slower than C, on a c2d anyway

	   float/double/complex are not handled well

	v = vips_arithmetic_get_vector( aclass, VIPS_FORMAT_UINT );
	vips_vector_asm3( v, "addl", "d1", "s1", "s2" );

	v = vips_arithmetic_get_vector( aclass, VIPS_FORMAT_INT );
	vips_vector_asm3( v, "addl", "d1", "s1", "s2" );

	 */

	vips_arithmetic_compile( aclass );

	aclass->process_line = add_buffer;
}

static void
vips_add_init( VipsAdd *add )
{
}

/**
 * vips_add:
 * @left: input image 
 * @right: input image 
 * @out: output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * This operation calculates @in1 + @in2 and writes the result to @out. 
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
 *   <title>VipsAdd type promotion</title>
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
 * Operations on integer images are performed using the processor's vector unit,
 * if possible. Disable this with --vips-novector or IM_NOVECTOR.
 *
 * See also: vips_subtract(), vips_linear().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_add( VipsImage *left, VipsImage *right, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "add", ap, left, right, out );
	va_end( ap );

	return( result );
}
