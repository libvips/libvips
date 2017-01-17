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
 * 17/1/14
 * 	- redone as a class
 * 12/11/16
 * 	- oop, allow index == 0, thanks Rob
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
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
    02110-1301  USA

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
#include <string.h>
#include <math.h>

#include <vips/vips.h>
#include <vips/internal.h>

#include "pmorphology.h"

typedef struct _VipsRank {
	VipsMorphology parent_instance;

	VipsImage *out;

	int width;
	int height;
	int index;

	int n; 

} VipsRank;

typedef VipsMorphologyClass VipsRankClass;

G_DEFINE_TYPE( VipsRank, vips_rank, VIPS_TYPE_MORPHOLOGY );

/* Sequence value: just the array we sort in.
 */
typedef struct {
	VipsRegion *ir;
	VipsPel *sort;
} VipsRankSequence;

static int
vips_rank_stop( void *vseq, void *a, void *b )
{
	VipsRankSequence *seq = (VipsRankSequence *) vseq;

	VIPS_FREEF( g_object_unref, seq->ir );

	return( 0 );
}

static void *
vips_rank_start( IMAGE *out, void *a, void *b )
{
	VipsImage *in = (VipsImage *) a;
	VipsRank *rank = (VipsRank *) b;
	VipsRankSequence *seq;

	if( !(seq = VIPS_NEW( out, VipsRankSequence )) )
		return( NULL );
	seq->ir = NULL;
	seq->sort = NULL;

	seq->ir = vips_region_new( in );
	if( !(seq->sort = VIPS_ARRAY( out, 
		VIPS_IMAGE_SIZEOF_ELEMENT( in ) * rank->n, VipsPel )) ) { 
		vips_rank_stop( seq, in, rank );
		return( NULL );
	}

	return( (void *) seq );
}

/* Inner loop for select-sorting TYPE.
 */
#define LOOP_SELECT( TYPE ) { \
	TYPE *q = (TYPE *) VIPS_REGION_ADDR( or, r->left, r->top + y ); \
	TYPE *p = (TYPE *) VIPS_REGION_ADDR( ir, r->left, r->top + y ); \
	TYPE *sort = (TYPE *) seq->sort; \
	TYPE a; \
	\
	for( x = 0; x < sz; x++ ) { \
		TYPE *d = p + x; \
		\
		/* Copy window into sort[].
		 */ \
		for( k = 0, j = 0; j < rank->height; j++ ) { \
			for( i = 0; i < eaw; i += bands, k++ ) \
				sort[k] = d[i]; \
			d += ls; \
		} \
		\
		/* Rearrange sort[] to make the index-th element the index-th 
		 * smallest, adapted from Numerical Recipes in C.
		 */ \
		lower = 0;	/* Range we know the result lies in */ \
		upper = rank->n - 1; \
		for(;;) { \
			if( upper - lower < 2 ) { \
				/* 1 or 2 elements left. 
				 */ \
				if( upper - lower == 1 &&  \
					sort[lower] > sort[upper] ) \
					VIPS_SWAP( TYPE, \
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
				VIPS_SWAP( TYPE, sort[lower + 1], sort[mid] ); \
				if( sort[lower] > sort[upper] ) \
					VIPS_SWAP( TYPE, \
						sort[lower], sort[upper] ); \
				if( sort[lower + 1] > sort[upper] ) \
					VIPS_SWAP( TYPE, \
						sort[lower + 1], sort[upper] );\
				if( sort[lower] > sort[lower + 1] ) \
					VIPS_SWAP( TYPE, \
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
					VIPS_SWAP( TYPE, sort[i], sort[j] ); \
				} \
				\
				/* Replace mid element. 
				 */ \
				sort[lower + 1] = sort[j]; \
				sort[j] = a; \
				\
				/* Move to partition with the kth element. 
				 */ \
				if( j >= rank->index ) \
					upper = j - 1; \
				if( j <= rank->index ) \
					lower = i; \
			} \
		} \
		\
		q[x] = sort[rank->index]; \
	} \
}

/* Loop for find max of window.
 */
#define LOOP_MAX( TYPE ) { \
	TYPE *q = (TYPE *) VIPS_REGION_ADDR( or, r->left, r->top + y ); \
	TYPE *p = (TYPE *) VIPS_REGION_ADDR( ir, r->left, r->top + y ); \
	\
	for( x = 0; x < sz; x++ ) { \
		TYPE *d = &p[x]; \
		TYPE max; \
		\
		max = *d; \
		for( j = 0; j < rank->height; j++ ) { \
			TYPE *e = d; \
			\
			for( i = 0; i < rank->width; i++ ) { \
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
	TYPE *q = (TYPE *) VIPS_REGION_ADDR( or, r->left, r->top + y ); \
	TYPE *p = (TYPE *) VIPS_REGION_ADDR( ir, r->left, r->top + y ); \
	\
	for( x = 0; x < sz; x++ ) { \
		TYPE *d = &p[x]; \
		TYPE min; \
		\
		min = *d; \
		for( j = 0; j < rank->height; j++ ) { \
			TYPE *e = d; \
			\
			for( i = 0; i < rank->width; i++ ) { \
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
	switch( rank->out->BandFmt ) { \
	case VIPS_FORMAT_UCHAR: 	OPERATION( unsigned char ); break; \
	case VIPS_FORMAT_CHAR:   	OPERATION( signed char ); break; \
	case VIPS_FORMAT_USHORT: 	OPERATION( unsigned short ); break; \
	case VIPS_FORMAT_SHORT:  	OPERATION( signed short ); break; \
	case VIPS_FORMAT_UINT:   	OPERATION( unsigned int ); break; \
	case VIPS_FORMAT_INT:    	OPERATION( signed int ); break; \
	case VIPS_FORMAT_FLOAT:  	OPERATION( float ); break; \
	case VIPS_FORMAT_DOUBLE: 	OPERATION( double ); break; \
 	\
	default: \
		g_assert_not_reached(); \
	} 

static int
vips_rank_generate( VipsRegion *or, 
	void *vseq, void *a, void *b, gboolean *stop )
{
	VipsRect *r = &or->valid;
	VipsRankSequence *seq = (VipsRankSequence *) vseq;
	VipsRegion *ir = seq->ir;
	VipsImage *in = (VipsImage *) a;
	VipsRank *rank = (VipsRank *) b;
	int bands = in->Bands;
	int eaw = rank->width * bands;		/* elements across window */
	int sz = VIPS_REGION_N_ELEMENTS( or );

	VipsRect s;
	int ls;

	int x, y;
	int i, j, k;
	int upper, lower, mid;

	/* Prepare the section of the input image we need. A little larger
	 * than the section of the output image we are producing.
	 */
	s = *r;
	s.width += rank->width - 1;
	s.height += rank->height - 1;
	if( vips_region_prepare( ir, &s ) )
		return( -1 );
	ls = VIPS_REGION_LSKIP( ir ) / VIPS_IMAGE_SIZEOF_ELEMENT( in );

	for( y = 0; y < r->height; y++ ) { 
		if( rank->index == 0 )
			SWITCH( LOOP_MIN )
		else if( rank->index == rank->n - 1 ) 
			SWITCH( LOOP_MAX )
		else 
			SWITCH( LOOP_SELECT ) }

	return( 0 );
}

static int
vips_rank_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsMorphology *morphology = VIPS_MORPHOLOGY( object );
	VipsRank *rank = (VipsRank *) object;
	VipsImage **t = (VipsImage **) vips_object_local_array( object, 3 );

	VipsImage *in;

	if( VIPS_OBJECT_CLASS( vips_rank_parent_class )->build( object ) )
		return( -1 );

	in = morphology->in; 

	if( vips_image_decode( in, &t[0] ) )
		return( -1 );
	in = t[0];

	if( vips_check_noncomplex( class->nickname, in ) )
		return( -1 );
	if( rank->width > in->Xsize || 
		rank->height > in->Ysize ) {
		vips_error( class->nickname, "%s", _( "window too large" ) );
		return( -1 );
	}
	rank->n = rank->width * rank->height;
	if( rank->index < 0 || rank->index > rank->n - 1 ) {
		vips_error( class->nickname, "%s", _( "index out of range" ) );
		return( -1 );
	}

	/* Expand the input. 
	 */
	if( vips_embed( in, &t[1], 
		rank->width / 2, rank->height / 2, 
		in->Xsize + rank->width - 1, in->Ysize + rank->height - 1,
		"extend", VIPS_EXTEND_COPY,
		NULL ) )
		return( -1 );
	in = t[1];

	g_object_set( object, "out", vips_image_new(), NULL ); 

	/* Set demand hints. FATSTRIP is good for us, as THINSTRIP will cause
	 * too many recalculations on overlaps.
	 */
	if( vips_image_pipelinev( rank->out, 
		VIPS_DEMAND_STYLE_FATSTRIP, in, NULL ) )
		return( -1 );
	rank->out->Xsize -= rank->width - 1;
	rank->out->Ysize -= rank->height - 1;

	if( vips_image_generate( rank->out, 
		vips_rank_start, 
		vips_rank_generate, 
		vips_rank_stop, 
		in, rank ) )
		return( -1 );

	rank->out->Xoffset = 0;
	rank->out->Yoffset = 0;

	vips_reorder_margin_hint( rank->out, rank->width * rank->height ); 

	return( 0 );
}

static void
vips_rank_class_init( VipsRankClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "rank";
	object_class->description = _( "rank filter" );
	object_class->build = vips_rank_build;

	VIPS_ARG_IMAGE( class, "out", 2, 
		_( "Output" ), 
		_( "Output image" ),
		VIPS_ARGUMENT_REQUIRED_OUTPUT, 
		G_STRUCT_OFFSET( VipsRank, out ) );

	VIPS_ARG_INT( class, "width", 4, 
		_( "Width" ), 
		_( "Window width in pixels" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsRank, width ),
		1, 100000, 11 );

	VIPS_ARG_INT( class, "height", 5, 
		_( "Height" ), 
		_( "Window height in pixels" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsRank, height ),
		1, 100000, 11 );

	VIPS_ARG_INT( class, "index", 6, 
		_( "index" ), 
		_( "Select pixel at index" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsRank, index ),
		0, 100000000, 50 );

}

static void
vips_rank_init( VipsRank *rank )
{
	rank->width = 11;
	rank->height = 11;
	rank->index = 50;
}

/**
 * vips_rank:
 * @in: input image
 * @out: output image
 * @width: width of region
 * @height: height of region
 * @index: select pixel
 * @...: %NULL-terminated list of optional named arguments
 *
 * vips_rank() does rank filtering on an image. A window of size @width by
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
 *  vips_rank( in, out, m, m, m * m / 2 );
 *
 * The special cases n == 0 and n == m * m - 1 are useful dilate and 
 * expand operators.
 *
 * See also: vips_conv(), vips_median(), vips_spcor().
 *
 * Returns: 0 on success, -1 on error
 */
int 
vips_rank( VipsImage *in, VipsImage **out, 
	int width, int height, int index, ... )
{
	va_list ap;
	int result;

	va_start( ap, index );
	result = vips_call_split( "rank", ap, in, out, width, height, index );
	va_end( ap );

	return( result );
}

/**
 * vips_median:
 * @in: input image
 * @out: output image
 * @size: size of region
 * @...: %NULL-terminated list of optional named arguments
 *
 * A convenience function equivalent to:
 *
 *  vips_rank( in, out, size, size, (size * size) / 2 );
 *
 * See also: vips_rank().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_median( VipsImage *in, VipsImage **out, int size, ... )
{
	va_list ap;
	int result;

	va_start( ap, size );
	result = vips_call_split( "rank", ap, in, out, 
		size, size, (size * size) / 2 );
	va_end( ap );

	return( result );
}
