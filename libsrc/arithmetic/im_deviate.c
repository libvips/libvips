/* @(#) Find the standard deviation of an image. Takes any non-complex image 
 * @(#) format, returns a double. Finds the deviation of all bands.
 * @(#)
 * @(#) int 
 * @(#) im_deviate( im, out )
 * @(#) IMAGE *im;
 * @(#) double *out;
 * @(#)
 * @(#) Returns 0 on success and -1 on error.
 *
 * Copyright: 1990, J. Cupitt
 *
 * Author: J. Cupitt
 * Written on: 02/08/1990
 * Modified on: 
 * 5/5/93 JC
 *	- now does partial images
 *	- less likely to overflow
 *	- adapted from im_avg
 * 1/7/93 JC
 *	- adapted for partial v2
 *	- ANSIfied
 * 21/2/95 JC
 *	- modernised again
 * 11/5/95 JC
 * 	- oops! return( NULL ) in im_avg(), instead of return( -1 )
 * 20/6/95 JC
 *	- now returns double, not float
 * 13/1/05
 *	- use 64 bit arithmetic 
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

/* Start function: allocate space for a pair of doubles in which we can 
 * accumulate the sum and the sum of squares.
 */
static void *
start_fn( IMAGE *out, void *a, void *b )
{
	double *tmp;

	if( !(tmp = IM_ARRAY( out, 2, double )) )
		return( NULL );
	tmp[0] = 0.0;
	tmp[1] = 0.0;

	return( (void *) tmp );
}

/* Stop function. Add this little sum to the main sum.
 */
static int
stop_fn( void *seq, void *a, void *b )
{
	double *tmp = (double *) seq;
	double *sum = (double *) a;

	sum[0] += tmp[0];
	sum[1] += tmp[1];

	return( 0 );
}

/* Loop over region, adding information to the appropriate fields of tmp.
 */
static int
scan_fn( REGION *reg, void *seq, void *a, void *b )
{	
	double *tmp = (double *) seq;
	Rect *r = &reg->valid;
	IMAGE *im = reg->im;
	int le = r->left;
	int to = r->top;
	int bo = IM_RECT_BOTTOM(r);
	int sz = IM_REGION_N_ELEMENTS( reg );
	double s = 0.0;
	double s2 = 0.0;
	int x, y;

/* Sum pels in this section.
 */
#define loop(TYPE) \
	{	TYPE *p; \
 		\
		for( y = to; y < bo; y++ ) { \
			p = (TYPE *) IM_REGION_ADDR( reg, le, y ); \
			\
			for( x = 0; x < sz; x++ ) { \
				TYPE v = p[x]; \
				\
				s += v; \
				s2 += (double) v * (double) v; \
			}\
		}\
	}

	/* Now generate code for all types. 
	 */
	switch( im->BandFmt ) {
	case IM_BANDFMT_UCHAR:		loop(unsigned char); break; 
	case IM_BANDFMT_CHAR:		loop(signed char); break; 
	case IM_BANDFMT_USHORT:		loop(unsigned short); break; 
	case IM_BANDFMT_SHORT:		loop(signed short); break; 
	case IM_BANDFMT_UINT:		loop(unsigned int); break; 
	case IM_BANDFMT_INT:		loop(signed int); break; 
	case IM_BANDFMT_FLOAT:		loop(float); break; 

	case IM_BANDFMT_DOUBLE:	
#ifdef HAVE_LIBOIL
		for( y = to; y < bo; y++ ) { 
			double *p = (double *) IM_REGION_ADDR( reg, le, y ); 
			double t;
			double t2;

			oil_sum_f64( &t, p, sizeof( double ), sz );
			oil_squaresum_f64( &t2, p, sz );

			s += t;
			s2 += t2;
		}
#else /*!HAVE_LIBOIL*/
		loop(double); 
#endif /*HAVE_LIBOIL*/
		break; 

	default: 
		assert( 0 );
	}

	/* Add to sum for this sequence.
	 */
	tmp[0] += s;
	tmp[1] += s2;

	return( 0 );
}

/* Find the average of an image.
 */
int
im_deviate( IMAGE *in, double *out )
{	
	double sum[2] = { 0.0, 0.0 };
	gint64 N;

	/* Check our args. 
	 */
	if( im_pincheck( in ) ||
		im_check_uncoded( "im_deviate", in ) ||
		im_check_noncomplex( "im_deviate", in ) )
		return( -1 );

	/* Loop over input, summing pixels.
	 */
	if( im_iterate( in, start_fn, scan_fn, stop_fn, &sum, NULL ) )
		return( -1 );

	/*
	  
	    NOTE: NR suggests a two-pass algorithm to minimise roundoff. 
	    But that's too expensive for us :-( so do it the old one-pass 
	    way.

	 */

	/* Calculate and return deviation. Add a fabs to stop sqrt(<=0).
	 */
	N = (gint64) in->Xsize * in->Ysize * in->Bands;
	*out = sqrt( fabs( sum[1] - (sum[0] * sum[0] / N) ) / (N - 1) );

	return( 0 );
}
