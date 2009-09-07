/* im_max.c
 *
 * Copyright: 1990, J. Cupitt
 *
 * Author: J. Cupitt
 * Written on: 02/05/1990
 * Modified on : 18/03/1991, N. Dessipris
 * 7/7/93 JC
 *	- complex case fixed
 *	- im_incheck() call added
 * 20/6/95 JC
 *	- now returns double
 *	- modernised a little
 *	- now returns max square amplitude rather than amplitude for complex
 * 9/5/02 JC
 *	- partialed
 * 3/4/02 JC
 *	- random wrong result for >1 thread :-( (thanks Joe)
 * 15/10/07
 * 	- oh, heh, seq->inf was not being set correctly, not that it mattered
 * 4/9/09
 * 	- rewrite with im__value(), much simpler and fixes a race condition
 * 	- gtkdoc comment
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

/* New sequence value.
 */
static void *
max_start( IMAGE *in, void *a, void *b )
{
	double *global_max = (double *) b;
	double *max;

	if( !(max = IM_NEW( NULL, double )) ) 
		return( NULL );
	*max = *global_max;

	return( (void *) max );
}

/* Merge the sequence value back into the per-call state.
 */
static int
max_stop( void *seq, void *a, void *b )
{
	double *max = (double *) seq;
	double *global_max = (double *) b;

	/* Merge.
	 */
	*global_max = IM_MAX( *global_max, *max );

	im_free( seq );

	return( 0 );
}

#define LOOP( TYPE ) { \
	TYPE *p = (TYPE *) in; \
	\
	for( x = 0; x < sz; x++ ) { \
		double v = p[x]; \
		\
		if( v > m ) \
			m = v; \
	} \
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
		if( mod > m ) \
			m = mod; \
	} \
} 

/* Loop over region, adding to seq.
 */
static int
max_scan( void *in, int n, void *seq, void *a, void *b )
{
	const IMAGE *im = (IMAGE *) a;
	const int sz = n * im->Bands;

	double *max = (double *) seq;

	int x;
	double m;

	m = *max;

	switch( im->BandFmt ) {
	case IM_BANDFMT_UCHAR:		LOOP( unsigned char ); break; 
	case IM_BANDFMT_CHAR:		LOOP( signed char ); break; 
	case IM_BANDFMT_USHORT:		LOOP( unsigned short ); break; 
	case IM_BANDFMT_SHORT:		LOOP( signed short ); break; 
	case IM_BANDFMT_UINT:		LOOP( unsigned int ); break;
	case IM_BANDFMT_INT:		LOOP( signed int ); break; 
	case IM_BANDFMT_FLOAT:		LOOP( float ); break; 
	case IM_BANDFMT_DOUBLE:		LOOP( double ); break; 
	case IM_BANDFMT_COMPLEX:	CLOOP( float ); break; 
	case IM_BANDFMT_DPCOMPLEX:	CLOOP( double ); break; 

	default:  
		g_assert( 0 );
	}

	*max = m; 

	return( 0 );
}

/** 
 * im_max:
 * @in: input #IMAGE
 * @out: output double
 *
 * Finds the the maximum value of image #in and returns it at the
 * location pointed by out.  If input is complex, the max modulus
 * is returned. im_max() finds the maximum of all bands: if you
 * want to find the maximum of each band separately, use im_stats().
 *
 * See also: im_maxpos(), im_min(), im_stats().
 *
 * Returns: 0 on success, -1 on error
 */
int
im_max( IMAGE *in, double *out )
{
	double global_max;

	if( im_pincheck( in ) ||
		im_check_uncoded( "im_max", in ) )
		return( -1 );

	if( im__value( in, &global_max ) )
		return( -1 );
	/* We use square mod for scanning, for speed.
	 */
	if( im_iscomplex( in ) )
		global_max *= global_max;

	if( im__wrapscan( in, max_start, max_scan, max_stop, 
		in, &global_max ) ) 
		return( -1 );

	/* Back to modulus.
	 */
	if( im_iscomplex( in ) )
		global_max = sqrt( global_max );

	*out = global_max;

	return( 0 );
}
