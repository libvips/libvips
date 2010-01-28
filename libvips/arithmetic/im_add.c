/* im_add.c
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
		q[x] = p1[x] + p2[x]; \
}

static void
add_buffer( PEL **in, PEL *out, int width, IMAGE *im )
{
	/* Complex just doubles the size.
	 */
	const int sz = width * im->Bands * 
		(vips_bandfmt_iscomplex( im->BandFmt ) ? 2 : 1);

	int x;

	/* Add all input types. Keep types here in sync with bandfmt_add[] 
	 * below.
         */
        switch( im->BandFmt ) {
        case IM_BANDFMT_UCHAR: 	LOOP( unsigned char, unsigned short ); break; 
        case IM_BANDFMT_CHAR: 	LOOP( signed char, signed short ); break; 
        case IM_BANDFMT_USHORT: LOOP( unsigned short, unsigned int ); break; 
        case IM_BANDFMT_SHORT: 	LOOP( signed short, signed int ); break; 
        case IM_BANDFMT_UINT: 	LOOP( unsigned int, unsigned int ); break; 
        case IM_BANDFMT_INT: 	LOOP( signed int, signed int ); break; 

        case IM_BANDFMT_FLOAT: 		
        case IM_BANDFMT_COMPLEX:
#ifdef HAVE_LIBOIL
		oil_add_f32( (float *) out, 
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

/* For two integer types, the "largest", ie. one which can represent the
 * full range of both.
 */
static int bandfmt_largest[6][6] = {
        /* UC  C   US  S   UI  I */
/* UC */ { UC, S,  US, S,  UI, I },
/* C */  { S,  C,  I,  S,  I,  I },
/* US */ { US, I,  US, I,  UI, I },
/* S */  { S,  S,  I,  S,  I,  I },
/* UI */ { UI, I,  UI, I,  UI, I },
/* I */  { I,  I,  I,  I,  I,  I }
};

/* For two formats, find one which can represent the full range of both.
 */
static VipsBandFmt
im__format_common( VipsBandFmt in1, VipsBandFmt in2 )
{
	if( vips_bandfmt_iscomplex( in1 ) || 
		vips_bandfmt_iscomplex( in2 ) ) {
		/* What kind of complex?
		 */
		if( in1 == IM_BANDFMT_DPCOMPLEX || in2 == IM_BANDFMT_DPCOMPLEX )
			/* Output will be DPCOMPLEX. 
			 */
			return( IM_BANDFMT_DPCOMPLEX );
		else
			return( IM_BANDFMT_COMPLEX );

	}
	else if( vips_bandfmt_isfloat( in1 ) || 
		vips_bandfmt_isfloat( in2 ) ) {
		/* What kind of float?
		 */
		if( in1 == IM_BANDFMT_DOUBLE || in2 == IM_BANDFMT_DOUBLE )
			return( IM_BANDFMT_DOUBLE );
		else
			return( IM_BANDFMT_FLOAT );
	}
	else 
		/* Must be int+int -> int.
		 */
		return( bandfmt_largest[in1][in2] );
}

int
im__formatalike_vec( IMAGE **in, IMAGE **out, int n )
{
	int i;
	VipsBandFmt fmt;

	g_assert( n >= 1 );

	fmt = in[0]->BandFmt;
	for( i = 1; i < n; i++ )
		fmt = im__format_common( fmt, in[i]->BandFmt );

	for( i = 0; i < n; i++ )
		if( im_clip2fmt( in[i], out[i], fmt ) )
			return( -1 );

	return( 0 );
}

int
im__formatalike( IMAGE *in1, IMAGE *in2, IMAGE *out1, IMAGE *out2 )
{
	IMAGE *in[2];
	IMAGE *out[2];

	in[0] = in1;
	in[1] = in2;
	out[0] = out1;
	out[1] = out2;

	return( im__formatalike_vec( in, out, 2 ) );
}

/* Make an n-band image. Input 1 or n bands.
 */
int
im__bandup( IMAGE *in, IMAGE *out, int n )
{
	IMAGE *bands[256];
	int i;

	if( in->Bands == n ) 
		return( im_copy( in, out ) );
	if( in->Bands != 1 ) {
		im_error( "im__bandup", _( "not one band or %d bands" ), n );
		return( -1 );
	}
	if( n > 256 || n < 1 ) {
		im_error( "im__bandup", "%s", _( "bad bands" ) );
		return( -1 );
	}

	for( i = 0; i < n; i++ )
		bands[i] = in;

	return( im_gbandjoin( bands, out, n ) );
}

int
im__bandalike( IMAGE *in1, IMAGE *in2, IMAGE *out1, IMAGE *out2 )
{
	if( im_check_bands_1orn( "im__bandalike", in1, in2 ) )
		return( -1 );
	if( im__bandup( in1, out1, IM_MAX( in1->Bands, in2->Bands ) ) ||
		im__bandup( in2, out2, IM_MAX( in1->Bands, in2->Bands ) ) )
		return( -1 );

	return( 0 );
}

/* The common part of most binary arithmetic, relational and boolean
 * operators. We:
 *
 * - check in and out
 * - cast in1 and in2 up to a common format
 * - cast the common format to the output format with the supplied table
 * - equalise bands 
 * - run the supplied buffer operation passing one of the up-banded,
 *   up-casted and up-sized inputs as the first param
 */
int
im__arith_binary( const char *domain, 
	IMAGE *in1, IMAGE *in2, IMAGE *out, 
	int format_table[10], 
	im_wrapmany_fn fn, void *b )
{
	IMAGE *t[5];

	if( im_piocheck( in1, out ) || 
		im_pincheck( in2 ) ||
		im_check_bands_1orn( domain, in1, in2 ) ||
		im_check_same_size( domain, in1, in2 ) ||
		im_check_uncoded( domain, in1 ) ||
		im_check_uncoded( domain, in2 ) )
		return( -1 );

	/* Cast our input images up to a common format and bands.
	 */
	if( im_open_local_array( out, t, 4, domain, "p" ) ||
		im__formatalike( in1, in2, t[0], t[1] ) ||
		im__bandalike( t[0], t[1], t[2], t[3] ) )
		return( -1 );

	/* Generate the output.
	 */
	if( im_cp_descv( out, t[2], t[3], NULL ) )
		return( -1 );

	/* What number of bands will we write? Same as up-banded input.
	 */
	out->Bands = t[2]->Bands;

	/* What output type will we write? 
	 */
	out->BandFmt = format_table[t[2]->BandFmt];

	/* And process! The buffer function gets one of the input images as a
	 * sample.
	 */
	t[4] = NULL;
	if( im_wrapmany( t + 2, out, fn, t[2], b ) )	
		return( -1 );

	return( 0 );
}

/* Type promotion for addition. Sign and value preserving. Make sure these
 * match the case statement in add_buffer() above.
 */
static int bandfmt_add[10] = {
/* UC  C   US  S   UI  I  F  X  D  DX */
   US, S,  UI, I,  UI, I, F, X, D, DX
};

/**
 * im_add:
 * @in1: input image 1
 * @in2: input image 2
 * @out: output image
 *
 * This operation calculates @in1 + @in2 and writes the result to @out. 
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
 *   <title>im_add() type promotion</title>
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
 * See also: im_subtract(), im_lintra().
 *
 * Returns: 0 on success, -1 on error
 */
int 
im_add( IMAGE *in1, IMAGE *in2, IMAGE *out )
{
	return( im__arith_binary( "im_add",
		in1, in2, out, 
		bandfmt_add,
		(im_wrapmany_fn) add_buffer, NULL ) );
}
