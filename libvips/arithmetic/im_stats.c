/* @(#) im_stats: find general image statistics for all bands separately
(C) Kirk Martinez 1993
23/4/93 J.Cupitt
	- adapted to partial images
	- special struct abandoned; now returns DOUBLEMASK.
1/7/93 JC
	- adapted for partial v2
	- ANSIfied
27/7/93 JC
	- init of mask changed to use actual values, not IM_MAXDOUBLE and
	  (-IM_MAXDOUBLE). These caused problems when assigned to floats.
	  funny business with offset==42, yuk!
31/8/93 JC
	- forgot to init global max/min properly! sorry.
21/6/95 JC
	- still did not init max and min correctly --- now fixed for good

 * 13/1/05
 *	- use 64 bit arithmetic 
 * 1/9/09
 *	- argh nope min/max was broken again for >1CPU in short pipelines on 
 *  	  some architectures
 * 7/9/09
 * 	- rework based on new im__wrapscan() / im_max() ideas for a proper fix
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

/* Track min/max/sum/sum-of-squares for each thread during a scan.
 */
static void *
stats_start( IMAGE *im, void *a, void *b )
{
	double *global_stats = (double *) b;

	double *stats;
	int i;

	if( !(stats = IM_ARRAY( NULL, 4 * im->Bands, double )) )
		return( NULL );

	for( i = 0; i < 4 * im->Bands; i++ )
		stats[i] = global_stats[i];

	return( stats );
}

/* Merge a thread's output back into the global stats.
 */
static int
stats_stop( void *seq, void *a, void *b )
{
	const IMAGE *im = (IMAGE *) a;
	double *global_stats = (double *) b;
	double *stats = (double *) seq;

	int i;

	for( i = 0; i < 4 * im->Bands; i += 4 ) {
		global_stats[0] = IM_MIN( global_stats[0], stats[0] );
		global_stats[1] = IM_MAX( global_stats[1], stats[1] );
		global_stats[2] += stats[2];
		global_stats[3] += stats[3];

		global_stats += 4;
		stats += 4;
	}

	im_free( seq );

	return( 0 );
}

/* We scan lines bands times to avoid repeating band loops.
 * Use temp variables of same type for min/max for faster comparisons.
 */
#define LOOP( TYPE ) { \
	for( z = 0; z < im->Bands; z++ ) { \
		TYPE *q = (TYPE *) in + z; \
		double *row = stats + z * 4; \
		TYPE small, big; \
		double sum, sum2; \
		\
		small = row[0]; \
		big = row[1]; \
		sum = row[2]; \
		sum2 = row[3]; \
		\
		for( x = 0; x < n; x++ ) { \
			TYPE value = *q; \
			\
			sum += value;\
			sum2 += (double) value * (double) value;\
			if( value > big ) \
				big = value; \
			else if( value < small ) \
				small = value;\
			\
			q += im->Bands; \
		}\
		\
		row[0] = small; \
		row[1] = big; \
		row[2] = sum; \
		row[3] = sum2; \
	}\
} 

/* Loop over region, adding to seq.
 */
static int
stats_scan( void *in, int n, void *seq, void *a, void *b )
{
	const IMAGE *im = (IMAGE *) a;

	double *stats = (double *) seq;

	int x, z;

	/* Now generate code for all types. 
	 */
	switch( im->BandFmt ) {
	case IM_BANDFMT_UCHAR:	LOOP( unsigned char ); break; 
	case IM_BANDFMT_CHAR:	LOOP( signed char ); break; 
	case IM_BANDFMT_USHORT:	LOOP( unsigned short ); break; 
	case IM_BANDFMT_SHORT:	LOOP( signed short ); break; 
	case IM_BANDFMT_UINT:	LOOP( unsigned int ); break; 
	case IM_BANDFMT_INT:	LOOP( signed int ); break; 
	case IM_BANDFMT_DOUBLE:	LOOP( double ); break;
	case IM_BANDFMT_FLOAT:	LOOP( float ); break; 

	default: 
		g_assert( 0 );
	}

	return( 0 );
}

/* Find the statistics of an image. Take any non-complex format. Write the
 * stats to a DOUBLEMASK of size 6 by (in->Bands+1). We hold a row for each 
 * band, plus one row for all bands. Row n has 6 elements, which are, in 
 * order, (minimum, maximum, sum, sum^2, mean, deviation) for band n. Row 0 has 
 * the figures for all bands together.
 */
DOUBLEMASK *
im_stats( IMAGE *im )
{	
	DOUBLEMASK *out;
	double *row;
	gint64 pels, vals, z;
	double *global_stats;
	int i, j;
	double value;

	if( im_pincheck( im ) ||
		im_check_noncomplex( "im_stats", im ) ||
		im_check_uncoded( "im_stats", im ) )
		return( NULL );

	if( !(global_stats = IM_ARRAY( im, 4 * im->Bands, double )) )
		return( NULL );
	if( im__value( im, &value ) )
		return( NULL );
	for( i = 0; i < 4 * im->Bands; i += 4 ) {
		global_stats[i + 0] = value;
		global_stats[i + 1] = value;
		global_stats[i + 2] = 0.0;
		global_stats[i + 3] = 0.0;
	}

	/* Loop over input, calculating min, max, sum, sum^2 for each band
	 * separately.
	 */
	if( im__wrapscan( im, stats_start, stats_scan, stats_stop, 
		im, &global_stats ) ) 
		return( NULL );

	/* Calculate mean, deviation, plus overall stats.
	 */
	if( !(out = im_create_dmask( "stats", 6, im->Bands + 1 )) )
		return( NULL );

	/* Init global max/min/sum/sum2.
	 */
	out->coeff[0] = value;
	out->coeff[1] = value;
	out->coeff[2] = 0.0;
	out->coeff[3] = 0.0;

	pels = (gint64) im->Xsize * im->Ysize;
	vals = pels * im->Bands;

	for( i = 0; i < im->Bands; i++ ) {
		row = out->coeff + (z + 1) * 6;
		for( j = 0; j < 4; j++ )
			row[j] = global_stats[i * 4 + j];

		out->coeff[0] = IM_MIN( out->coeff[0], row[0] );
		out->coeff[1] = IM_MAX( out->coeff[1], row[1] );
		out->coeff[2] += row[2];
		out->coeff[3] += row[3];
		row[4] = row[2] / pels;
		row[5] = sqrt( fabs( row[3] - (row[2] * row[2] / pels) ) / 
			(pels - 1) );
	} 
	out->coeff[4] = out->coeff[2] / vals;
	out->coeff[5] = sqrt( fabs( out->coeff[3] - 
		(out->coeff[2] * out->coeff[2] / vals) ) / (vals - 1) );

#ifdef DEBUG
	printf( "im_stats:\n" );
	im_print_dmask( out );
#endif /*DEBUG*/

	return( out );
}
