/* im_avg.c
 *
 * Copyright: 1990, J. Cupitt
 *
 * Author: J. Cupitt
 * Written on: 02/08/1990
 * Modified on: 
 * 5/5/93 JC
 *	- now does partial images
 *	- less likely to overflow
 * 1/7/93 JC
 *	- adapted for partial v2
 *	- ANSI C
 * 21/2/95 JC
 *	- modernised again
 * 11/5/95 JC
 * 	- oops! return( NULL ) in im_avg(), instead of return( -1 )
 * 20/6/95 JC
 *	- now returns double
 * 13/1/05
 *	- use 64 bit arithmetic 
 * 8/12/06
 * 	- add liboil support
 * 18/8/09
 * 	- gtkdoc, minor reformatting
 * 7/9/09
 * 	- rewrite for im__wrapiter()
 * 	- add complex case (needed for im_max())
 * 8/9/09
 * 	- wrapscan stuff moved here
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

#ifdef HAVE_LIBOIL
#include <liboil/liboil.h>
#endif /*HAVE_LIBOIL*/

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

typedef struct _Wrapscan {
	IMAGE *in;
	im_start_fn start; 
	im__wrapscan_fn scan; 
	im_stop_fn stop;
	void *a; 
	void *b;
} Wrapscan;

static void *
wrapscan_start( IMAGE *in, void *a, void *b )
{
	Wrapscan *wrapscan = (Wrapscan *) a;

	return( wrapscan->start( in, wrapscan->a, wrapscan->b ) );
}

static int
wrapscan_stop( void *seq, void *a, void *b )
{
	Wrapscan *wrapscan = (Wrapscan *) a;

	return( wrapscan->stop( seq, wrapscan->a, wrapscan->b ) );
}

static int
wrapscan_scan( REGION *reg, void *seq, void *a, void *b )
{
	Wrapscan *wrapscan = (Wrapscan *) a;
	Rect *r = &reg->valid;
	int lsk = IM_REGION_LSKIP( reg );

	int y;
	PEL *p;

	p = (PEL *) IM_REGION_ADDR( reg, r->left, r->top ); 
	for( y = 0; y < r->height; y++ ) { 
		if( wrapscan->scan( p, r->width, seq, 
			wrapscan->a, wrapscan->b ) )
			return( -1 );
		p += lsk;
	} 

	return( 0 );
}

/* Like im_iterate(), but the scan function works a line at a time, like
 * im_wrap*(). Shared with im_min(), im_deviate() etc.
 */
int
im__wrapscan( IMAGE *in, 
	im_start_fn start, im__wrapscan_fn scan, im_stop_fn stop,
	void *a, void *b )
{
	Wrapscan wrapscan;

	wrapscan.in = in;
	wrapscan.start = start;
	wrapscan.scan = scan;
	wrapscan.stop = stop;
	wrapscan.a = a;
	wrapscan.b = b;

	return( im_iterate( in, 
		wrapscan_start, wrapscan_scan, wrapscan_stop, 
		&wrapscan, NULL ) );
}

/* Start function: allocate space for a double in which we can accumulate the
 * sum.
 */
static void *
avg_start( IMAGE *out, void *a, void *b )
{
	double *sum;

	if( !(sum = IM_NEW( NULL, double )) ) 
		return( NULL );
	*sum = 0.0;

	return( (void *) sum );
}

/* Stop function. Add this little sum to the main sum.
 */
static int
avg_stop( void *seq, void *a, void *b )
{
	double *sum = (double *) seq;
	double *global_sum = (double *) b;

	*global_sum += *sum;

	im_free( seq );

	return( 0 );
}

/* Sum pels in this section.
 */
#define LOOP( TYPE ) { \
	TYPE *p = (TYPE *) in; \
	\
	for( x = 0; x < sz; x++ ) \
		m += p[x]; \
}

#define CLOOP( TYPE ) { \
	TYPE *p = (TYPE *) in; \
	\
	for( x = 0; x < sz; x++ ) { \
		double mod, re, im; \
		\
		re = p[0]; \
		im = p[1]; \
		p += 2; \
		mod = re * re + im * im; \
		\
		m += mod; \
	} \
} 

/* Loop over region, accumulating a sum in *tmp.
 */
static int
avg_scan( void *in, int n, void *seq, void *a, void *b )
{
	const IMAGE *im = (IMAGE *) a;
	const int sz = n * im->Bands;

	double *sum = (double *) seq;

	int x;
	double m;

	m = *sum;

	/* Now generate code for all types. 
	 */
	switch( im->BandFmt ) {
	case IM_BANDFMT_UCHAR:		LOOP( unsigned char ); break; 
	case IM_BANDFMT_CHAR:		LOOP( signed char ); break; 
	case IM_BANDFMT_USHORT:		LOOP( unsigned short ); break; 
	case IM_BANDFMT_SHORT:		LOOP( signed short ); break; 
	case IM_BANDFMT_UINT:		LOOP( unsigned int ); break;
	case IM_BANDFMT_INT:		LOOP( signed int ); break; 
	case IM_BANDFMT_FLOAT:		LOOP( float ); break; 

	case IM_BANDFMT_DOUBLE:	
#ifdef HAVE_LIBOIL
{ 
		double *p = (double *) in;
		double t;

		oil_sum_f64( &t, p, sizeof( double ), sz );

		m += t;
}
#else /*!HAVE_LIBOIL*/
		LOOP( double ); 
#endif /*HAVE_LIBOIL*/
		break; 

	case IM_BANDFMT_COMPLEX:	CLOOP( float ); break; 
	case IM_BANDFMT_DPCOMPLEX:	CLOOP( double ); break; 

	default: 
		g_assert( 0 );
	}

	*sum = m;

	return( 0 );
}

/**
 * im_avg:
 * @in: input #IMAGE
 * @out: output pixel average
 *
 * This operation finds the average value in an image. It operates on all 
 * bands of the input image: use im_stats() if you need to calculate an 
 * average for each band. For complex images, return the average modulus.
 *
 * See also: im_stats(), im_bandmean(), im_deviate(), im_rank()
 *
 * Returns: 0 on success, -1 on error
 */
int
im_avg( IMAGE *in, double *out )
{
	double global_sum;
	gint64 vals, pels;

	/* Check our args. 
	 */
	if( im_pincheck( in ) ||
		im_check_noncomplex( "im_avg", in ) ||
		im_check_uncoded( "im_avg", in ) ) 
		return( -1 );

	/* Loop over input, summing pixels.
	 */
	global_sum = 0.0;
	if( im__wrapscan( in, 
		avg_start, avg_scan, avg_stop, in, &global_sum ) ) 
		return( -1 );

	/* Calculate and return average. For complex, we accumulate re*re +
	 * im*im, so we need to sqrt.
	 */
	pels = (gint64) in->Xsize * in->Ysize;
	vals = pels * in->Bands;
	*out = global_sum / vals;
	if( im_iscomplex( in ) )
		*out = sqrt( *out );

	return( 0 );
}

/* Get the value of pixel (0, 0). Use this to init the min/max value for
 * im_max()/im_stats()/etc. 
 */
int
im__value( IMAGE *im, double *value )
{
	IMAGE *t;

	if( !(t = im_open_local( im, "im__value", "p" )) ||
		im_extract_areabands( im, t, 0, 0, 1, 1, 0, 1 ) ||
		im_avg( t, value ) )
		return( -1 );

	return( 0 );
}
