/* @(#) Divide two images
 * @(#) Images must have the same no of bands and can be of any type
 * @(#) No check for overflow is carried out.
 * @(#)
 * @(#) int 
 * @(#) im_divide(in1, in2, out)
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
 *	- new im_multiply adapted to make new im_divide
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

/* Complex divide.
 */
#ifdef USE_MODARG_DIV
/* This is going to be much slower */

#define cloop(TYPE)                                         \
{                                                           \
  TYPE *X= (TYPE*) in[0];                                   \
  TYPE *Y= (TYPE*) in[1];                                   \
  TYPE *Z= (TYPE*) out;                                     \
  TYPE *Z_stop= Z + sz * 2;                                 \
                                                            \
  for( ; Z < Z_stop; X+= 2, Y+=2 ){                         \
    double arg= atan2( X[1], X[0] ) - atan2( Y[1], Y[0] );  \
    double mod= hypot( X[1], X[0] ) / hypot( Y[1], Y[0] );  \
    *Z++= mod * cos( arg );                                 \
    *Z++= mod * sin( arg );                                 \
  }                                                         \
}

#else /* USE_MODARG_DIV */

#define cloop(TYPE)                   \
{                                     \
  TYPE *X= (TYPE*) in[0];             \
  TYPE *Y= (TYPE*) in[1];             \
  TYPE *Z= (TYPE*) out;               \
  TYPE *Z_stop= Z + sz * 2;           \
                                      \
  for( ; Z < Z_stop; X+= 2, Y+=2 )    \
    if( fabs( Y[0] ) > fabs( Y[1] )){ \
      double a= Y[1] / Y[0];          \
      double b= Y[0] + Y[1] * a;      \
      *Z++= ( X[0] + X[1] * a ) / b;  \
      *Z++= ( X[1] - X[0] * a ) / b;  \
    }                                 \
    else {                            \
      double a= Y[0] / Y[1];          \
      double b= Y[1] + Y[0] * a;      \
      *Z++= ( X[0] * a + X[1] ) / b;  \
      *Z++= ( X[1] * a - X[0] ) / b;  \
    }                                 \
}

#endif /* USE_MODARG_DIV */

/* Real divide.
 */
#define rloop(TYPE) \
{\
	TYPE *p1 = (TYPE *) in[0];\
	TYPE *p2 = (TYPE *) in[1];\
	TYPE *q = (TYPE *) out;\
	\
	for( x = 0; x < sz; x++ )\
		q[x] = p1[x] / p2[x];\
}

static void
divide_buffer( PEL **in, PEL *out, int width, IMAGE *im )
{
	int x;
	int sz = width * im->Bands;

	/* Divide all input types.
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
		oil_divide_f32( (float *) out, 
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

int 
im_divide( IMAGE *in1, IMAGE *in2, IMAGE *out )
{	
	/* Basic checks.
	 */
	if( im_piocheck( in1, out ) || im_pincheck( in2 ) )
		return( -1 );
	if( in1->Bands != in2->Bands &&
		(in1->Bands != 1 && in2->Bands != 1) ) {
		im_error( "im_divide", "%s", _( "not same number of bands" ) );
		return( -1 );
	}
	if( in1->Coding != IM_CODING_NONE || in2->Coding != IM_CODING_NONE ) {
		im_error( "im_divide", "%s", _( "not uncoded" ) );
		return( -1 );
	}
	if( im_cp_descv( out, in1, in2, NULL ) )
		return( -1 );

	/* What number of bands will we write?
	 */
	out->Bands = IM_MAX( in1->Bands, in2->Bands );

	/* What output type will we write? float, double or complex.
	 */
	if( im_iscomplex( in1 ) || im_iscomplex( in2 ) ) {
		/* What kind of complex?
		 */
		if( in1->BandFmt == IM_BANDFMT_DPCOMPLEX || 
			in2->BandFmt == IM_BANDFMT_DPCOMPLEX )
			/* Output will be DPCOMPLEX. 
			 */
			out->BandFmt = IM_BANDFMT_DPCOMPLEX;
		else
			out->BandFmt = IM_BANDFMT_COMPLEX;

	}
	else if( im_isfloat( in1 ) || im_isfloat( in2 ) ) {
		/* What kind of float?
		 */
		if( in1->BandFmt == IM_BANDFMT_DOUBLE || 
			in2->BandFmt ==  IM_BANDFMT_DOUBLE )
			out->BandFmt = IM_BANDFMT_DOUBLE;
		else
			out->BandFmt = IM_BANDFMT_FLOAT;
	}
	else {
		/* An int type -- output must be just float.
		 */
		out->BandFmt = IM_BANDFMT_FLOAT;
	}

	/* And process!
	 */
	if( im__cast_and_call( in1, in2, out, 
		(im_wrapmany_fn) divide_buffer, NULL ) )
		return( -1 );

	/* Success!
	 */
	return( 0 );
}
