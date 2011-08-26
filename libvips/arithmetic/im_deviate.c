/* im_deviate.c
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
 * 2/9/09
 * 	- gtk-doc comment
 * 	- minor reformatting
 * 4/9/09
 * 	- use im__wrapscan()
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

typedef struct _Wrapscan {
	IMAGE *in;
	im_start_fn start; 
	im__wrapscan_fn scan; 
	im_stop_fn stop;
	void *a; 
	void *b;
} Wrapscan;

static void *
wrapscan_start( VipsImage *in, void *a, void *b )
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

/* Like vips_sink(), but the scan function works a line at a time, like
 * im_wrap*(). Shared with im_min(), im_deviate() etc.
 */
int
im__wrapscan( VipsImage *in, 
	VipsStart start, im__wrapscan_fn scan, VipsStop stop,
	void *a, void *b )
{
	Wrapscan wrapscan;

	wrapscan.in = in;
	wrapscan.start = start;
	wrapscan.scan = scan;
	wrapscan.stop = stop;
	wrapscan.a = a;
	wrapscan.b = b;

	return( vips_sink( in, 
		wrapscan_start, wrapscan_scan, wrapscan_stop, 
		&wrapscan, NULL ) );
}

/* Start function: allocate space for a pair of doubles in which we can 
 * accumulate the sum and the sum of squares.
 */
static void *
deviate_start( IMAGE *out, void *a, void *b )
{
	double *ss2;

	if( !(ss2 = IM_ARRAY( NULL, 2, double )) )
		return( NULL );
	ss2[0] = 0.0;
	ss2[1] = 0.0;

	return( (void *) ss2 );
}

/* Stop function. Add this little sum to the main sum.
 */
static int
deviate_stop( void *seq, void *a, void *b )
{
	double *ss2 = (double *) seq;
	double *global_ss2 = (double *) b;

	global_ss2[0] += ss2[0];
	global_ss2[1] += ss2[1];

	im_free( seq );

	return( 0 );
}

/* Sum pels in this section.
 */
#define LOOP( TYPE ) { \
	TYPE *p = (TYPE *) in; \
	\
	for( x = 0; x < sz; x++ ) { \
		TYPE v = p[x]; \
		\
		s += v; \
		s2 += (double) v * (double) v; \
	} \
}

/* Loop over region, accumulating a sum in *tmp.
 */
static int
deviate_scan( void *in, int n, void *seq, void *a, void *b )
{
	const IMAGE *im = (IMAGE *) a;
	const int sz = n * im->Bands;

	double *ss2 = (double *) seq;

	int x;
	double s, s2;

	s = ss2[0];
	s2 = ss2[1];

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
	case IM_BANDFMT_DOUBLE:		LOOP( double ); break; 

	default: 
		g_assert( 0 );
	}

	ss2[0] = s;
	ss2[1] = s2;

	return( 0 );
}

/**
 * im_deviate:
 * @in: input #IMAGE
 * @out: output pixel standard deviation
 *
 * This operation finds the standard deviation of all pixels in @in. It 
 * operates on all bands of the input image: use im_stats() if you need 
 * to calculate an average for each band. 
 *
 * Non-complex images only.
 *
 * See also: im_stats(), im_bandmean(), im_avg(), im_rank()
 *
 * Returns: 0 on success, -1 on error
 */
int
im_deviate( IMAGE *in, double *out )
{
	double global_ss2[2];
	double s, s2;
	gint64 vals;

	/* Check our args. 
	 */
	if( im_pincheck( in ) ||
		im_check_uncoded( "im_deviate", in ) ||
		im_check_noncomplex( "im_deviate", in ) )
		return( -1 );

	/* Loop over input, summing pixels.
	 */
	global_ss2[0] = 0.0;
	global_ss2[1] = 0.0;
	if( im__wrapscan( in, 
		deviate_start, deviate_scan, deviate_stop, in, global_ss2 ) ) 
		return( -1 );

	/*
	  
		NOTE: NR suggests a two-pass algorithm to minimise roundoff. 
		But that's too expensive for us :-( so do it the old one-pass 
		way.

	 */

	/* Calculate and return deviation. Add a fabs to stop sqrt(<=0).
	 */
	vals = (gint64) in->Xsize * (gint64) in->Ysize * (gint64) in->Bands;
	s = global_ss2[0];
	s2 = global_ss2[1];
	*out = sqrt( fabs( s2 - (s * s / vals) ) / (vals - 1) );

	return( 0 );
}
