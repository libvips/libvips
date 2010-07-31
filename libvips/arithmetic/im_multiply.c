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
 */

/*

    This file is part of VIPS.
    
    VIPS is free software; you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

 */

/*

    These files are distributed with VIPS - http://www.vips.ecs.soton.ac.uk

 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <stdlib.h>
#include <math.h>

#include <vips/vips.h>
#include <vips/internal.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* Complex multiply.
 */
#define CLOOP( TYPE ) { \
	TYPE *p1 = (TYPE *) in[0]; \
	TYPE *p2 = (TYPE *) in[1]; \
	TYPE *q = (TYPE *) out; \
	\
	for( x = 0; x < sz; x++ ) { \
		double x1 = p1[0]; \
		double y1 = p1[1]; \
		double x2 = p2[0]; \
		double y2 = p2[1]; \
		\
		p1 += 2; \
		p2 += 2; \
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
	IN *p1 = (IN *) in[0]; \
	IN *p2 = (IN *) in[1]; \
	OUT *q = (OUT *) out; \
	\
	for( x = 0; x < sz; x++ ) \
		q[x] = p1[x] * p2[x]; \
}

static void
multiply_buffer( PEL **in, PEL *out, int width, IMAGE *im )
{
	const int sz = width * im->Bands;

	int x;

	/* Multiply all input types. Keep types here in sync with 
	 * bandfmt_multiply[] below.
         */
        switch( im->BandFmt ) {
        case IM_BANDFMT_CHAR: 	RLOOP( signed char, signed short ); break; 
        case IM_BANDFMT_UCHAR: 	RLOOP( unsigned char, unsigned short ); break; 
        case IM_BANDFMT_SHORT: 	RLOOP( signed short, signed int ); break; 
        case IM_BANDFMT_USHORT:	RLOOP( unsigned short, unsigned int ); break; 
        case IM_BANDFMT_INT: 	RLOOP( signed int, signed int ); break; 
        case IM_BANDFMT_UINT: 	RLOOP( unsigned int, unsigned int ); break; 
        case IM_BANDFMT_FLOAT: 	RLOOP( float, float ); break; 
        case IM_BANDFMT_COMPLEX: CLOOP( float ); break; 
        case IM_BANDFMT_DOUBLE:	RLOOP( double, double ); break;
        case IM_BANDFMT_DPCOMPLEX: CLOOP( double ); break;

        default:
		g_assert( 0 );
        }
}

/* Save a bit of typing.
 */
#define UC IM_BANDFMT_UCHAR
#define C IM_BANDFMT_CHAR
#define US IM_BANDFMT_USHORT
#define S IM_BANDFMT_SHORT
#define UI IM_BANDFMT_UINT
#define I IM_BANDFMT_INT
#define F IM_BANDFMT_FLOAT
#define X IM_BANDFMT_COMPLEX
#define D IM_BANDFMT_DOUBLE
#define DX IM_BANDFMT_DPCOMPLEX

/* Type promotion for multiplication. Sign and value preserving. Make sure 
 * these match the case statement in multiply_buffer() above.
 */
static int bandfmt_multiply[10] = {
/* UC  C   US  S   UI  I  F  X  D  DX */
   US, S,  UI, I,  UI, I, F, X, D, DX
};

/**
 * im_multiply:
 * @in1: input #IMAGE 1
 * @in2: input #IMAGE 2
 * @out: output #IMAGE
 *
 * This operation calculates @in1 * @in2 and writes the result to @out. 
 * The images must be the same size. They may have any format. 
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
 *   <title>im_multiply() type promotion</title>
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
 * See also: im_divide(), im_lintra().
 *
 * Returns: 0 on success, -1 on error
 */
int 
im_multiply( IMAGE *in1, IMAGE *in2, IMAGE *out )
{	
	return( im__arith_binary( "im_multiply",
		in1, in2, out, 
		bandfmt_multiply,
		(im_wrapmany_fn) multiply_buffer, NULL ) );
}
