/* im_min.c
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
 *	- now returns min square amplitude rather than amplitude for complex
 * 9/5/02 JC
 *	- partialed, based in im_max()
 * 3/4/02 JC
 *	- random wrong result for >1 thread :-( (thanks Joe)
 * 4/9/09
 * 	- rewrite from im_max()
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

/* New sequence value.
 */
static void *
min_start( IMAGE *in, void *a, void *b )
{
	double *global_min = (double *) b;
	double *min;

	if( !(min = IM_NEW( NULL, double )) ) 
		return( NULL );
	*min = *global_min;

	return( (void *) min );
}

/* Merge the sequence value back into the per-call state.
 */
static int
min_stop( void *seq, void *a, void *b )
{
	double *min = (double *) seq;
	double *global_min = (double *) b;

	/* Merge.
	 */
	*global_min = IM_MIN( *global_min, *min );

	im_free( seq );

	return( 0 );
}

#define LOOP( TYPE ) { \
	TYPE *p = (TYPE *) in; \
	\
	for( x = 0; x < sz; x++ ) { \
		double v = p[x]; \
		\
		if( v < m ) \
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
		if( mod < m ) \
			m = mod; \
	} \
} 

/* Loop over region, adding to seq.
 */
static int
min_scan( void *in, int n, void *seq, void *a, void *b )
{
	const IMAGE *im = (IMAGE *) a;
	const int sz = n * im->Bands;

	double *min = (double *) seq;

	int x;
	double m;

	m = *min;

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

	*min = m; 

	return( 0 );
}

/** 
 * im_min:
 * @in: input #IMAGE
 * @out: output double
 *
 * Finds the the minimum value of image #in and returns it at the
 * location pointed by out.  If input is complex, the min modulus
 * is returned. im_min() finds the minimum of all bands: if you
 * want to find the minimum of each band separately, use im_stats().
 *
 * See also: im_minpos(), im_max(), im_stats().
 *
 * Returns: 0 on success, -1 on error
 */
int
im_min( IMAGE *in, double *out )
{
	double global_min;

	if( im_pincheck( in ) ||
		im_check_uncoded( "im_min", in ) )
		return( -1 );

	if( im__value( in, &global_min ) )
		return( -1 );
	/* We use square mod for scanning, for speed.
	 */
	if( im_iscomplex( in ) )
		global_min *= global_min;

	if( im__wrapscan( in, min_start, min_scan, min_stop, 
		in, &global_min ) ) 
		return( -1 );

	/* Back to modulus.
	 */
	if( im_iscomplex( in ) )
		global_min = sqrt( global_min );

	*out = global_min;

	return( 0 );
}
