/* @(#) Subtract two images
 * @(#) Images must have the same no of bands and can be of any type
 * @(#) No check for overflow is carried out.
 * @(#)
 * @(#) int 
 * @(#) im_subtract( in1, in2, out)
 * @(#) IMAGE *in1, *in2, *out;
 * @(#)
 * @(#) Returns 0 on success and -1 on error
 * @(#)
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
 * 12/6/95 JC
 * 	- new im_add() adapted to make this
 * 31/5/96 JC
 *	- what was this SWAP() stuff? failed for small - big!
 * 22/8/03 JC
 *	- cast up more quickly to help accuracy
 * 27/9/04
 *	- updated for 1 band $op n band image -> n band image case
 * 8/12/06
 * 	- add liboil support
 * 18/8/08
 * 	- revise upcasting system
 * 	- add gtkdoc comments
 * 	- remove separate complex case, just double size
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
#include <assert.h>

#include <vips/vips.h>
#include <vips/internal.h>

#ifdef HAVE_LIBOIL
#include <liboil/liboil.h>
#endif /*HAVE_LIBOIL*/

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

#define LOOP( IN, OUT ) { \
	IN *p1 = (IN *) in[0]; \
	IN *p2 = (IN *) in[1]; \
	OUT *q = (OUT *) out; \
	\
	for( x = 0; x < sz; x++ ) \
		q[x] = p1[x] - p2[x]; \
}

static void
subtract_buffer( PEL **in, PEL *out, int width, IMAGE *im )
{
	/* Complex just doubles the size.
	 */
	const int sz = width * im->Bands * (im_iscomplex( im ) ? 2 : 1);

	int x;

	/* Add all input types. Keep types here in sync with bandfmt_subtract[] 
	 * below.
         */
        switch( im->BandFmt ) {
        case IM_BANDFMT_CHAR: 	LOOP( signed char, signed short ); break; 
        case IM_BANDFMT_UCHAR: 	LOOP( unsigned char, signed short ); break; 
        case IM_BANDFMT_SHORT: 	LOOP( signed short, signed int ); break; 
        case IM_BANDFMT_USHORT: LOOP( unsigned short, signed int ); break; 
        case IM_BANDFMT_INT: 	LOOP( signed int, signed int ); break; 
        case IM_BANDFMT_UINT: 	LOOP( unsigned int, signed int ); break; 

        case IM_BANDFMT_FLOAT: 		
        case IM_BANDFMT_COMPLEX:
#ifdef HAVE_LIBOIL
		oil_subtract_f32( (float *) out, 
			(float *) in[0], (float *) in[1], sz );
#else /*!HAVE_LIBOIL*/
		LOOP( float, float ); 
#endif /*HAVE_LIBOIL*/
		break; 

        case IM_BANDFMT_DOUBLE:	
        case IM_BANDFMT_DPCOMPLEX:
		LOOP( double, double ); 
		break;

        default:
		assert( 0 );
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

/* Type promotion for subtraction. Sign and value preserving. Make sure these
 * match the case statement in subtract_buffer() above.
 */
static int bandfmt_subtract[10] = {
/* UC  C   US  S   UI  I  F  X  D  DX */
   S,  S,  I,  I,  I,  I, F, X, D, DX
};

/**
 * im_subtract:
 * @in1: input image 1
 * @in2: input image 2
 * @out: output image
 *
 * This operation calculates @in1 - @in2 and writes the result to @out. 
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
 *   <title>im_subtract() type promotion</title>
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
 *         <entry>short</entry>
 *       </row>
 *       <row>
 *         <entry>char</entry>
 *         <entry>short</entry>
 *       </row>
 *       <row>
 *         <entry>ushort</entry>
 *         <entry>int</entry>
 *       </row>
 *       <row>
 *         <entry>short</entry>
 *         <entry>int</entry>
 *       </row>
 *       <row>
 *         <entry>uint</entry>
 *         <entry>int</entry>
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
 * See also: im_add(), im_lintra().
 *
 * Returns: 0 on success, -1 on error
 */
int 
im_subtract( IMAGE *in1, IMAGE *in2, IMAGE *out )
{	
	return( im__arith_binary( "im_subtract", 
		in1, in2, out, 
		bandfmt_subtract,
		(im_wrapmany_fn) subtract_buffer, NULL ) );
}
