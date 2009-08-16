/* @(#) Multiply two images
 * @(#) Images must have the same no of bands and can be of any type
 * @(#) No check for overflow is carried out.
 * @(#)
 * @(#) int 
 * @(#) im_multiply(in1, in2, out)
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

/* Swap two IMAGE pointers.
 */
#define SWAP(A,B) { \
	IMAGE *t; \
	t = (A); (A) = (B); (B) = t; \
}

/* Complex multiply.
 */
#define cloop(TYPE) \
{\
	TYPE *p1 = (TYPE *) in[0];\
	TYPE *p2 = (TYPE *) in[1];\
	TYPE *q = (TYPE *) out;\
	\
	for( x = 0; x < sz; x++ ) {\
		double x1 = p1[0];\
		double y1 = p1[1];\
		double x2 = p2[0];\
		double y2 = p2[1];\
		\
		p1 += 2;\
		p2 += 2;\
		\
		q[0] = x1 * x2 - y1 * y2;\
		q[1] = x1 * y2 + x2 * y1;\
		\
		q += 2;\
	}\
}

/* Real multiply.
 */
#define rloop(TYPE) \
{\
	TYPE *p1 = (TYPE *) in[0];\
	TYPE *p2 = (TYPE *) in[1];\
	TYPE *q = (TYPE *) out;\
	\
	for( x = 0; x < sz; x++ )\
		q[x] = p1[x] * p2[x];\
}

static void
multiply_buffer( PEL **in, PEL *out, int width, IMAGE *im )
{
	int x;
	int sz = width * im->Bands;

	/* Multiply all input types.
         */
        switch( im->BandFmt ) {
        case IM_BANDFMT_CHAR: 		rloop( signed char ); break; 
        case IM_BANDFMT_UCHAR: 		rloop( unsigned char ); break; 
        case IM_BANDFMT_SHORT: 		rloop( signed short ); break; 
        case IM_BANDFMT_USHORT: 	rloop( unsigned short ); break; 
        case IM_BANDFMT_INT: 		rloop( signed int ); break; 
        case IM_BANDFMT_UINT: 		rloop( unsigned int ); break; 

        case IM_BANDFMT_FLOAT: 	
#ifdef HAVE_LIBOIL
		oil_multiply_f32( (float *) out, 
			(float *) in[0], (float *) in[1], sz );
#else /*!HAVE_LIBOIL*/
		rloop( float ); 
#endif /*HAVE_LIBOIL*/
		break; 

        case IM_BANDFMT_DOUBLE:		rloop( double ); break; 
        case IM_BANDFMT_COMPLEX:	cloop( float ); break;
        case IM_BANDFMT_DPCOMPLEX:	cloop( double ); break;

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

/* Type conversions for two integer inputs. Rules for float and complex 
 * encoded with ifs. We are sign and value preserving. 
 */
static int iformat[6][6] = {
        /* UC  C   US  S   UI  I */
/* UC */ { US, S,  UI, I,  UI, I },
/* C */  { S,  S,  I,  I,  I,  I },
/* US */ { UI, I,  UI, I,  UI, I },
/* S */  { I,  I,  I,  I,  I,  I },
/* UI */ { UI, I,  UI, I,  UI, I },
/* I */  { I,  I,  I,  I,  I,  I }
};

int 
im_multiply( IMAGE *in1, IMAGE *in2, IMAGE *out )
{	
	/* Basic checks.
	 */
	if( im_piocheck( in1, out ) || im_pincheck( in2 ) )
		return( -1 );

	if( in1->Xsize != in2->Xsize || in1->Ysize != in2->Ysize ) {
		im_error( "im_multiply", "%s", _( "not same size" ) );
		return( -1 );
	}
	if( in1->Bands != in2->Bands &&
		(in1->Bands != 1 && in2->Bands != 1) ) {
		im_error( "im_multiply", 
			"%s", _( "not same number of bands" ) );
		return( -1 );
	}
	if( in1->Coding != IM_CODING_NONE || in2->Coding != IM_CODING_NONE ) {
		im_error( "im_multiply", "%s", _( "not uncoded" ) );
		return( -1 );
	}
	if( im_cp_descv( out, in1, in2, NULL ) )
		return( -1 );

	/* What number of bands will we write?
	 */
	out->Bands = IM_MAX( in1->Bands, in2->Bands );

	/* Swap arguments to get the largest on the left. 
	 */
	if( in1->Bbits < in2->Bbits )
		SWAP( in1, in2 );

	/* What output type will we write? int, float or complex.
	 */
	if( im_iscomplex( in1 ) || im_iscomplex( in2 ) ) {
		/* Make sure we have complex on the left. 
		 */
		if( !im_iscomplex( in1 ) )
			SWAP( in1, in2 );

		/* What kind of complex?
		 */
		if( in1->BandFmt == IM_BANDFMT_DPCOMPLEX )
			/* Output will be DPCOMPLEX. 
			 */
			out->BandFmt = IM_BANDFMT_DPCOMPLEX;
		else
			out->BandFmt = IM_BANDFMT_COMPLEX;
	}
	else if( im_isfloat( in1 ) || im_isfloat( in2 ) ) {
		/* Make sure we have float on the left. 
		 */
		if( !im_isfloat( in1 ) )
			SWAP( in1, in2 );
		
		/* What kind of float?
		 */
		if( in1->BandFmt == IM_BANDFMT_DOUBLE )
			out->BandFmt = IM_BANDFMT_DOUBLE;
		else
			out->BandFmt = IM_BANDFMT_FLOAT;
	}
	else 
		/* Must be int+int = int.
		 */
		out->BandFmt = iformat[in2->BandFmt][in1->BandFmt];

	/* And process!
	 */
	if( im__cast_and_call( in1, in2, out, 
		(im_wrapmany_fn) multiply_buffer, NULL ) )
		return( -1 );

	/* Success!
	 */
	return( 0 );
}
