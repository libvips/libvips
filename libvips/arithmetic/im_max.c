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

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* New sequence value.
 */
static void *
max_start( IMAGE *in, void *a, void *b )
{
	double *value = (double *) a;
	double *seq = IM_NEW( NULL, double );

	*seq = *value;

	return( (void *) seq );
}

/* Merge the sequence value back into the per-call state.
 */
static int
max_stop( void *vseq, void *a, void *b )
{
	double *seq = (double *) vseq;
	double *value = (double *) a;

	/* Merge.
	 */
	*value = IM_MAX( *value, *seq );

	im_free( seq );

	return( 0 );
}

#define LOOP( TYPE ) { \
	for( y = to; y < bo; y++ ) { \
		TYPE *p = (TYPE *) IM_REGION_ADDR( reg, le, y ); \
		\
		for( x = 0; x < nel; x++ ) { \
			double v = p[x]; \
			\
			if( v > m ) \
				m = v; \
		} \
	} \
} 

#define CLOOP( TYPE ) { \
	for( y = to; y < bo; y++ ) { \
		TYPE *p = (TYPE *) IM_REGION_ADDR( reg, le, y ); \
		\
		for( x = 0; x < nel; x++ ) { \
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
	} \
} 

/* Loop over region, adding to seq.
 */
static int
max_scan( REGION *reg, void *vseq, void *a, void *b )
{
	double *seq = (double *) vseq;
	Rect *r = &reg->valid;
	IMAGE *im = reg->im;
	int le = r->left;
	int to = r->top;
	int bo = IM_RECT_BOTTOM(r);
	int nel = IM_REGION_N_ELEMENTS( reg );

	int x, y;
	double m;

	m = *seq;

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

	*seq = m; 

#ifdef DEBUG
        printf( "im_max: left = %d, top = %d, width = %d, height = %d\n",
		r->left, r->top, r->width, r->height );
	printf( "   (max = %g)\n", *seq );
#endif /*DEBUG*/

	return( 0 );
}

/* Get the value of pixel (0, 0). Use this to init the min/max value for
 * threads. Shared with im_min(), im_stats() etc. This will return mod for
 * complex.
 */
int
im__value( IMAGE *im, double *value )
{
	IMAGE *t;

	if( !(t = im_open_local( im, "im__value", "p" )) ||
		im_extract_area( im, t, 0, 0, 1, 1 ) ||
		im_avg( t, value ) )
		return( -1 );

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
	double value;

	if( im_pincheck( in ) ||
		im_check_uncoded( "im_max", in ) )
		return( -1 );

	if( im__value( in, &value ) )
		return( -1 );
	/* We use square mod for scanning, for speed.
	 */
	if( im_iscomplex( in ) )
		value *= value;

	if( im_iterate( in, max_start, max_scan, max_stop, &value, NULL ) ) 
		return( -1 );

	/* Back to modulus.
	 */
	if( im_iscomplex( in ) )
		value = sqrt( value );

	*out = value;

	return( 0 );
}
