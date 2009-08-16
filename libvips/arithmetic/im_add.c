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

/* Complex add.
 */
#define cloop(TYPE) { \
	TYPE *p1 = (TYPE *) in[0]; \
	TYPE *p2 = (TYPE *) in[1]; \
	TYPE *q = (TYPE *) out; \
	\
	for( x = 0; x < sz; x++ ) { \
		double rp1 = p1[0]; \
		double ip1 = p1[1]; \
		\
		double rp2 = p2[0]; \
		double ip2 = p2[1]; \
		\
		p1 += 2; \
		p2 += 2; \
		\
		q[0] = rp1 + rp2; \
		q[1] = ip1 + ip2; \
		\
		q += 2; \
	} \
}

/* Real add.
 */
#define rloop(IN, OUT) { \
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
	int x;
	int sz = width * im->Bands;

	/* Add all input types. Kep types here in sync with bandfmt_add[] below.
         */
        switch( im->BandFmt ) {
        case IM_BANDFMT_UCHAR: 	rloop( unsigned char, unsigned short ); break; 
        case IM_BANDFMT_CHAR: 	rloop( signed char, signed short ); break; 
        case IM_BANDFMT_USHORT: rloop( unsigned short, unsigned int ); break; 
        case IM_BANDFMT_SHORT: 	rloop( signed short, signed int ); break; 
        case IM_BANDFMT_UINT: 	rloop( unsigned int, unsigned int ); break; 
        case IM_BANDFMT_INT: 	rloop( signed int, signed int ); break; 

        case IM_BANDFMT_FLOAT: 		
#ifdef HAVE_LIBOIL
		oil_add_f32( (float *) out, 
			(float *) in[0], (float *) in[1], sz );
#else /*!HAVE_LIBOIL*/
		rloop( float, float ); 
#endif /*HAVE_LIBOIL*/
		break; 

        case IM_BANDFMT_DOUBLE:	rloop( double, double ); break; 
        case IM_BANDFMT_COMPLEX:cloop( float ); break;
        case IM_BANDFMT_DPCOMPLEX:cloop( double ); break;

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
#define M IM_BANDFMT_COMPLEX
#define D IM_BANDFMT_DOUBLE
#define DM IM_BANDFMT_DPCOMPLEX

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
im__format_common( IMAGE *in1, IMAGE *in2 )
{
	if( im_iscomplex( in1 ) || im_iscomplex( in2 ) ) {
		/* What kind of complex?
		 */
		if( in1->BandFmt == IM_BANDFMT_DPCOMPLEX || 
			in2->BandFmt == IM_BANDFMT_DPCOMPLEX )
			/* Output will be DPCOMPLEX. 
			 */
			return( IM_BANDFMT_DPCOMPLEX );
		else
			return( IM_BANDFMT_COMPLEX );

	}
	else if( im_isfloat( in1 ) || im_isfloat( in2 ) ) {
		/* What kind of float?
		 */
		if( in1->BandFmt == IM_BANDFMT_DOUBLE || 
			in2->BandFmt == IM_BANDFMT_DOUBLE )
			return( IM_BANDFMT_DOUBLE );
		else
			return( IM_BANDFMT_FLOAT );
	}
	else 
		/* Must be int+int -> int.
		 */
		return( bandfmt_largest[in1->BandFmt][in2->BandFmt] );
}

/* Make an n-band image. Input 1 or n bands.
 */
static int
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

/* Cast in1 and in2 up to a common type and number of bands, then call the
 * function. Also used by subtract, multiply, divide, etc.
 */
int
im__cast_and_call( IMAGE *in1, IMAGE *in2, IMAGE *out, 
	im_wrapmany_fn fn, void *a )
{
	VipsBandFmt fmt;
	IMAGE *t[5];

	if( im_open_local_array( out, t, 4, "type cast:1", "p" ) )
		return( -1 );

	/* Cast our input images up to a common type.
	 */
	fmt = im__format_common( in1, in2 );
	if( im_clip2fmt( in1, t[0], fmt ) ||
		im_clip2fmt( in2, t[1], fmt ) )
		return( -1 );

	/* Force bands up to the same as out.
	 */
	if( im__bandup( t[0], t[2], out->Bands ) ||
		im__bandup( t[1], t[3], out->Bands ) )
		return( -1 );

	/* And process!
	 */
	t[4] = NULL;
	if( im_wrapmany( t + 2, out, fn, out, a ) )	
		return( -1 );

	return( 0 );
}

/* Type promotion for addition. Sign and value preserving. Make sure these
 * match the case statement in add_buffer() above.
 */
static int bandfmt_add[10] = {
/* UC  C   US  S   UI  I  F  M  D  DM */
   US, S,  UI, I,  UI, I, F, M, D, DM
};

/**
 * im_add:
 * @in1: input image 1
 * @in2: input image 2
 * @out: output image
 *
 * This operation adds corresponding pixels in images @in1 and 
 * @in2 and writes the result to the image descriptor @out. The images must be
 * the same size, but may have any type. If one of the images has a single
 * band, it is added to every band of the other image.
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
	/* Basic checks.
	 */
	if( im_piocheck( in1, out ) || im_pincheck( in2 ) )
		return( -1 );
	if( in1->Bands != in2->Bands &&
		(in1->Bands != 1 && in2->Bands != 1) ) {
		im_error( "im_add", "%s", _( "not same number of bands" ) );
		return( -1 );
	}
	if( in1->Coding != IM_CODING_NONE || in2->Coding != IM_CODING_NONE ) {
		im_error( "im_add", "%s", _( "not uncoded" ) );
		return( -1 );
	}
	if( im_cp_descv( out, in1, in2, NULL ) )
		return( -1 );

	/* What number of bands will we write?
	 */
	out->Bands = IM_MAX( in1->Bands, in2->Bands );

	/* What output type will we write? int, float or complex.
	 */
	out->BandFmt = bandfmt_add[im__format_common( in1, in2 )];
	out->Bbits = im_bits_of_fmt( out->BandFmt );

	/* And process!
	 */
	if( im__cast_and_call( in1, in2, out, 
		(im_wrapmany_fn) add_buffer, NULL ) )
		return( -1 );

	/* Success!
	 */
	return( 0 );
}
