/* Rank filter.
 *
 * Author: JC
 * Written on: 19/8/96
 * Modified on: 
 * JC 20/8/96
 *	- now uses insert-sort rather than bubble-sort
 *	- now works for any non-complex type
 * JC 22/6/01 
 *	- oops, sanity check on n wrong
 * JC 28/8/03
 *	- cleanups
 *	- better selection algorithm ... same speed for 3x3, about 3x faster
 *	  for 5x5, faster still for larger windows
 *	- index from zero for consistency with other parts of vips
 * 7/4/04 
 *	- now uses im_embed() with edge stretching on the input, not
 *	  the output
 *	- sets Xoffset / Yoffset
 * 7/10/04
 *	- oops, im_embed() size was wrong
 * 10/11/10
 * 	- cleanups
 * 	- gtk-doc
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
#include <assert.h>

#include <vips/vips.h>

/* Global state: save our parameters here.
 */
typedef struct {
	IMAGE *in, *out;	/* Images we run */
	int xsize, ysize;	/* Window size */
	int index;		/* Element select */
	int n;			/* xsize * ysize */
} RankInfo;

/* Sequence value: just the array we sort in.
 */
typedef struct {
	REGION *ir;
	PEL *sort;
} SeqInfo;

/* Free a sequence value.
 */
static int
rank_stop( void *vseq, void *a, void *b )
{
	SeqInfo *seq = (SeqInfo *) vseq;

	IM_FREEF( im_region_free, seq->ir );

	return( 0 );
}

/* Rank start function.
 */
static void *
rank_start( IMAGE *out, void *a, void *b )
{
	IMAGE *in = (IMAGE *) a;
	RankInfo *rnk = (RankInfo *) b;
	SeqInfo *seq;

	if( !(seq = IM_NEW( out, SeqInfo )) )
		return( NULL );

	/* Init!
	 */
	seq->ir = NULL;
	seq->sort = NULL;

	/* Attach region and arrays.
	 */
	seq->ir = im_region_create( in );
	seq->sort = IM_ARRAY( out, 
		IM_IMAGE_SIZEOF_ELEMENT( in ) * rnk->n, PEL );
	if( !seq->ir || !seq->sort ) {
		rank_stop( seq, in, rnk );
		return( NULL );
	}

	return( (void *) seq );
}

/* Inner loop for select-sorting TYPE.
 */
#define LOOP_SELECT( TYPE ) { \
	TYPE *q = (TYPE *) IM_REGION_ADDR( or, le, y ); \
	TYPE *p = (TYPE *) IM_REGION_ADDR( ir, le, y ); \
	TYPE *sort = (TYPE *) seq->sort; \
	TYPE a; \
	\
	for( x = 0; x < sz; x++ ) { \
		TYPE *d = p + x; \
		\
		/* Copy window into sort[].
		 */ \
		for( k = 0, j = 0; j < rnk->ysize; j++ ) { \
			for( i = 0; i < eaw; i += bands, k++ ) \
				sort[k] = d[i]; \
			d += ls; \
		} \
		\
		/* Rearrange sort[] to make the index-th element the index-th 
		 * smallest, adapted from Numerical Recipes in C.
		 */ \
		lower = 0;	/* Range we know the result lies in */ \
		upper = rnk->n - 1; \
		for(;;) { \
			if( upper - lower < 2 ) { \
				/* 1 or 2 elements left. 
				 */ \
				if( upper - lower == 1 &&  \
					sort[lower] > sort[upper] ) \
					IM_SWAP( TYPE, \
						sort[lower], sort[upper] ); \
				break; \
			} \
			else { \
				/* Pick mid-point of remaining elements. 
				 */ \
				mid = (lower + upper) >> 1; \
				\
				/* Sort lower/mid/upper elements, hold 
				 * midpoint in sort[lower + 1] for 
				 * partitioning. 
				 */  \
				IM_SWAP( TYPE, sort[lower + 1], sort[mid] ); \
				if( sort[lower] > sort[upper] ) \
					IM_SWAP( TYPE, \
						sort[lower], sort[upper] ); \
				if( sort[lower + 1] > sort[upper] ) \
					IM_SWAP( TYPE, \
						sort[lower + 1], sort[upper] );\
				if( sort[lower] > sort[lower + 1] ) \
					IM_SWAP( TYPE, \
						sort[lower], sort[lower + 1] );\
				\
				i = lower + 1; \
				j = upper; \
				a = sort[lower + 1]; \
				\
				for(;;) { \
					/* Search for out of order elements. 
					 */ \
					do \
						i++; \
					while( sort[i] < a ); \
					do \
						j--; \
					while( sort[j] > a ); \
					if( j < i ) \
						break; \
					IM_SWAP( TYPE, sort[i], sort[j] ); \
				} \
				\
				/* Replace mid element. 
				 */ \
				sort[lower + 1] = sort[j]; \
				sort[j] = a; \
				\
				/* Move to partition with the kth element. 
				 */ \
				if( j >= rnk->index ) \
					upper = j - 1; \
				if( j <= rnk->index ) \
					lower = i; \
			} \
		} \
		\
		q[x] = sort[rnk->index]; \
	} \
}

/* Loop for find max of window.
 */
#define LOOP_MAX( TYPE ) { \
	TYPE *q = (TYPE *) IM_REGION_ADDR( or, le, y ); \
	TYPE *p = (TYPE *) IM_REGION_ADDR( ir, le, y ); \
	\
	for( x = 0; x < sz; x++ ) { \
		TYPE *d = &p[x]; \
		TYPE max; \
		\
		max = *d; \
		for( j = 0; j < rnk->ysize; j++ ) { \
			TYPE *e = d; \
			\
			for( i = 0; i < rnk->xsize; i++ ) { \
				if( *e > max ) \
					max = *e; \
				\
				e += bands; \
			} \
			\
			d += ls; \
		} \
		\
		q[x] = max; \
	} \
}

/* Loop for find min of window.
 */
#define LOOP_MIN( TYPE ) { \
	TYPE *q = (TYPE *) IM_REGION_ADDR( or, le, y ); \
	TYPE *p = (TYPE *) IM_REGION_ADDR( ir, le, y ); \
	\
	for( x = 0; x < sz; x++ ) { \
		TYPE *d = &p[x]; \
		TYPE min; \
		\
		min = *d; \
		for( j = 0; j < rnk->ysize; j++ ) { \
			TYPE *e = d; \
			\
			for( i = 0; i < rnk->xsize; i++ ) { \
				if( *e < min ) \
					min = *e; \
				\
				e += bands; \
			} \
			\
			d += ls; \
		} \
		\
		q[x] = min; \
	} \
}

#define SWITCH( OPERATION ) \
	switch( rnk->out->BandFmt ) { \
	case IM_BANDFMT_UCHAR: 	OPERATION( unsigned char ); break; \
	case IM_BANDFMT_CHAR:   OPERATION( signed char ); break; \
	case IM_BANDFMT_USHORT: OPERATION( unsigned short ); break; \
	case IM_BANDFMT_SHORT:  OPERATION( signed short ); break; \
	case IM_BANDFMT_UINT:   OPERATION( unsigned int ); break; \
	case IM_BANDFMT_INT:    OPERATION( signed int ); break; \
	case IM_BANDFMT_FLOAT:  OPERATION( float ); break; \
	case IM_BANDFMT_DOUBLE: OPERATION( double ); break; \
 	\
	default: \
		assert( 0 ); \
	} 

/* Rank of a REGION.
 */
static int
rank_gen( REGION *or, void *vseq, void *a, void *b )
{
	SeqInfo *seq = (SeqInfo *) vseq;
	IMAGE *in = (IMAGE *) a;
	RankInfo *rnk = (RankInfo *) b;
	REGION *ir = seq->ir;

	Rect *r = &or->valid;
	Rect s;
	int le = r->left;
	int to = r->top;
	int bo = IM_RECT_BOTTOM(r);
	int sz = IM_REGION_N_ELEMENTS( or );

	int ls;
	int bands = in->Bands;
	int eaw = rnk->xsize * bands;		/* elements across window */

	int x, y;
	int i, j, k;
	int upper, lower, mid;

	/* Prepare the section of the input image we need. A little larger
	 * than the section of the output image we are producing.
	 */
	s = *r;
	s.width += rnk->xsize - 1;
	s.height += rnk->ysize - 1;
	if( im_prepare( ir, &s ) )
		return( -1 );
	ls = IM_REGION_LSKIP( ir ) / IM_IMAGE_SIZEOF_ELEMENT( in );

	for( y = to; y < bo; y++ ) { 
		if( rnk->index == 0 )
			SWITCH( LOOP_MIN )
		else if( rnk->index == rnk->n - 1 ) 
			SWITCH( LOOP_MAX )
		else 
			SWITCH( LOOP_SELECT ) }

	return( 0 );
}

/* Rank filter.
 */
int
im_rank_raw( IMAGE *in, IMAGE *out, int xsize, int ysize, int index )
{
	RankInfo *rnk;

	if( im_piocheck( in, out ) ||
		im_check_uncoded( "im_rank", in ) ||
		im_check_noncomplex( "im_rank", in ) )
		return( -1 );
	if( xsize > 1000 || ysize > 1000 || xsize <= 0 || ysize <= 0 || 
		index < 0 || index > xsize * ysize - 1 ) {
		im_error( "im_rank", "%s", _( "bad parameters" ) );
		return( -1 );
	}

	/* Save parameters.
	 */
	if( !(rnk = IM_NEW( out, RankInfo )) )
		return( -1 );
	rnk->in = in;
	rnk->out = out;
	rnk->xsize = xsize;
	rnk->ysize = ysize;
	rnk->index = index;
	rnk->n = xsize * ysize;

	/* Prepare output. Consider a 7x7 window and a 7x7 image --- the output
	 * would be 1x1.
	 */
	if( im_cp_desc( out, in ) )
		return( -1 );
	out->Xsize -= xsize - 1;
	out->Ysize -= ysize - 1;
	if( out->Xsize <= 0 || out->Ysize <= 0 ) {
		im_error( "im_rank", "%s", _( "image too small for window" ) );
		return( -1 );
	}

	/* Set demand hints. FATSTRIP is good for us, as THINSTRIP will cause
	 * too many recalculations on overlaps.
	 */
	if( im_demand_hint( out, IM_FATSTRIP, in, NULL ) )
		return( -1 );

	/* Generate! 
	 */
	if( im_generate( out, rank_start, rank_gen, rank_stop, in, rnk ) )
		return( -1 );

	out->Xoffset = -xsize / 2;
	out->Yoffset = -ysize / 2;

	return( 0 );
}


/**
 * im_rank:
 * @in: input image
 * @out: output image
 * @width: window width
 * @height: window height
 * @index: select pixel
 *
 * im_rank() does rank filtering on an image. A window of size @width by
 * @height is passed over the image. At each position, the pixels inside the 
 * window are sorted into ascending order and the pixel at position @index is 
 * output. @index numbers from 0.
 *
 * It works for any non-complex image type, with any number of bands. 
 * The input is expanded by copying edge pixels before performing the 
 * operation so that the output image has the same size as the input. 
 * Edge pixels in the output image are therefore only approximate.
 *
 * For a median filter with mask size m (3 for 3x3, 5 for 5x5, etc.) use
 *
 *  im_rank( in, out, m, m, m * m / 2 );
 *
 * The special cases n == 0 and n == m * m - 1 are useful dilate and 
 * expand operators.
 *
 * See also: im_conv(), im_fastcor().
 *
 * Returns: 0 on success, -1 on error
 */
int 
im_rank( IMAGE *in, IMAGE *out, int width, int height, int index )
{
	IMAGE *t1;

	if( !(t1 = im_open_local( out, "im_rank", "p" )) ||
		im_embed( in, t1, 1, 
			width / 2, height / 2, 
			in->Xsize + width - 1, in->Ysize + height - 1 ) ||
		im_rank_raw( t1, out, width, height, index ) )
		return( -1 );

	out->Xoffset = 0;
	out->Yoffset = 0;

	return( 0 );
}
