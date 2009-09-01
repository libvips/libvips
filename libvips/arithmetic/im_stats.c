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

1/9/09
	- argh nope min/max was broken again for >1CPU in short pipelines on 
	  some architectures

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
#include <assert.h>

#include <vips/vips.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* Make and initialise a DOUBLEMASK suitable for grabbing statistics.
 */
static void *
make_mask( IMAGE *im, void *a, void *b )
{
	DOUBLEMASK *out;

	/* Make temp output.
	 */
	if( !(out = im_create_dmask( "stats", 6, im->Bands + 1 )) )
		return( NULL );
	
	/* Set offset to magic value: 42 indicates we have not yet initialised
	 * max and min for this mask.
	 */
	out->offset = 42;

#ifdef DEBUG
	printf( "make_mask: created %p\n", out );
#endif /*DEBUG*/

	return( out );
}

/* Merge a temp DOUBLEMASK into the real DOUBLEMASK. Row 0 is unused, row 1
 * has the stats for band 1. These are: (minimum, maximum, sum, sum^2). If the
 * offset of out is 42, then it has not been inited yet and we just copy.
 */
static int
merge_mask( void *seq, void *a, void *b )
{
	DOUBLEMASK *tmp = (DOUBLEMASK *) seq;
	DOUBLEMASK *out = (DOUBLEMASK *) a;
	double *rowi, *rowo;
	int z;

#ifdef DEBUG
	printf( "merge_mask: tmp = %p, out = %p\n", tmp, out );
	im_print_dmask( tmp );
	im_print_dmask( out );
#endif /*DEBUG*/

	/* Merge, or just copy? Also, tmp might be uninited, so allow for that
	 * too.
	 */
	if( out->offset == 42 && tmp->offset != 42 ) {
#ifdef DEBUG
		printf( "merge_mask: copying\n", tmp );
#endif /*DEBUG*/

		/* Copy info from tmp.
		 */
		for( z = 1; z < tmp->ysize; z++ ) {
			rowi = tmp->coeff + z * 6;
			rowo = out->coeff + z * 6;

			rowo[0] = rowi[0];
			rowo[1] = rowi[1];
			rowo[2] = rowi[2];
			rowo[3] = rowi[3];
		}

		out->offset = 0;
	}
	else if( out->offset != 42 && tmp->offset != 42 ) {
#ifdef DEBUG
		printf( "merge_mask: merging\n" );
#endif /*DEBUG*/

		/* Add info from tmp.
		 */
		for( z = 1; z < tmp->ysize; z++ ) {
			rowi = tmp->coeff + z * 6;
			rowo = out->coeff + z * 6;

			rowo[0] = IM_MIN( rowi[0], rowo[0] );
			rowo[1] = IM_MAX( rowi[1], rowo[1] );
			rowo[2] += rowi[2];
			rowo[3] += rowi[3];
		}
	}

	/* Can now free tmp.
	 */
	im_free_dmask( tmp );

	return( 0 );
}

/* Loop over region, adding information to the appropriate fields of tmp.
 * We set max, min, sum, sum of squares. Our caller fills in the rest.
 */
static int
scan_fn( REGION *reg, void *seq, void *a, void *b )
{
	DOUBLEMASK *tmp = (DOUBLEMASK *) seq;
	Rect *r = &reg->valid;
	IMAGE *im = reg->im;
	int bands = im->Bands;
	int le = r->left;
	int ri = IM_RECT_RIGHT(r);
	int to = r->top;
	int bo = IM_RECT_BOTTOM(r);
	int x, y, z;

/* What type? First define the loop we want to perform for all types.
 * We scan lines bands times to avoid repeating band loops.
 * Use temp variables of same type for min/max for faster comparisons.
 * Use double to sum bands.
 */
#define non_complex_loop(TYPE) \
	{	TYPE *p, *q; \
		TYPE value, small, big; \
		double *row; \
 		\
		/* Have min and max been initialised? \
		 */ \
		if( tmp->offset == 42 ) { \
			/* Init min and max for each band. \
			 */ \
			p = (TYPE *) IM_REGION_ADDR( reg, le, to ); \
			for( z = 0; z < bands; z++ ) { \
				row = tmp->coeff + (z + 1) * 6; \
				row[0] = p[z]; \
				row[1] = p[z]; \
			} \
			tmp->offset = 0; \
		} \
		\
		for( y = to; y < bo; y++ ) { \
			p = (TYPE *) IM_REGION_ADDR( reg, le, y ); \
 			\
			for( z = 0; z < bands; z++ ) { \
				q = p + z; \
				row = tmp->coeff + (z + 1)*6; \
				small = row[0]; \
				big = row[1]; \
				\
				for( x = le; x < ri; x++ ) { \
					value = *q; \
					q += bands; \
					row[2] += value;\
					row[3] += (double)value*(double)value;\
					if( value > big ) \
						big = value; \
					else if( value < small ) \
						small = value;\
				}\
 				\
				row[0] = small; \
				row[1] = big; \
			}\
		}\
	} 

	/* Now generate code for all types. 
	 */
	switch( im->BandFmt ) {
	case IM_BANDFMT_UCHAR:	non_complex_loop(unsigned char); break; 
	case IM_BANDFMT_CHAR:	non_complex_loop(signed char); break; 
	case IM_BANDFMT_USHORT:	non_complex_loop(unsigned short); break; 
	case IM_BANDFMT_SHORT:	non_complex_loop(signed short); break; 
	case IM_BANDFMT_UINT:	non_complex_loop(unsigned int); break; 
	case IM_BANDFMT_INT:	non_complex_loop(signed int); break; 
	case IM_BANDFMT_DOUBLE:	non_complex_loop(double); break;
	case IM_BANDFMT_FLOAT:	non_complex_loop(float); break; 

	default: 
		assert( 0 );
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
im_stats( IMAGE *in )
{	
	DOUBLEMASK *out;
	double *row, *base;
	gint64 pels, vals, z;

	/* Check our args. 
	 */
	if( im_pincheck( in ) )
		return( NULL );
	if( im_iscomplex( in ) ) {
		im_error( "im_stats", "%s", _( "bad input type" ) );
		return( NULL );
	}
	if( in->Coding != IM_CODING_NONE ) {
		im_error( "im_stats", "%s", _( "not uncoded" ) );
		return( NULL );
	}

	/* Make output.
	 */
	pels = (gint64) in->Xsize * in->Ysize;
	vals = pels * in->Bands;
	if( !(out = make_mask( in, NULL, NULL )) )
		return( NULL );

	/* Loop over input, calculating min, max, sum, sum^2 for each band
	 * separately.
	 */
	if( im_iterate( in, make_mask, scan_fn, merge_mask, out, NULL ) ) {
		im_free_dmask( out );
		return( NULL );
	}

	/* Calculate mean, deviation, plus overall stats.
	 */
	base = out->coeff;
	base[0] = base[6];	/* Init global max/min */
	base[1] = base[7];
	for( z = 0; z < in->Bands; z++ ) {
		row = base + (z + 1) * 6;
		base[0] = IM_MIN( base[0], row[0] );
		base[1] = IM_MAX( base[1], row[1] );
		base[2] += row[2];
		base[3] += row[3];
		row[4] = row[2] / pels;
		row[5] = sqrt( fabs( row[3] - (row[2] * row[2] / pels) ) / 
			(pels - 1) );
	} 
	base[4] = base[2] / vals;
	base[5] = sqrt( fabs( base[3] - (base[2] * base[2] / vals) ) / 
		(vals - 1) );

#ifdef DEBUG
	printf( "im_stats:\n" );
	im_print_dmask( out );
#endif /*DEBUG*/

	return( out );
}
