/* Sort a set of images, pixelwise, and pick out the index at each point.
 *
 * 19/8/03
 *	- from im_maxvalue(), via im_gbandjoin()
 * 10/11/10
 * 	- gtkdoc
 * 	- cleanups
 * 	- any mix of formats and bands
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
#include <assert.h>

#include <vips/vips.h>
#include <vips/internal.h>

/* Parameters.
 */
typedef struct Rank {
	IMAGE **in;		/* Array of input images, NULL-terminated */
	IMAGE *out;
	int n;			/* Number of input images */
	int index;		/* Pick out this one */
} Rank;

/* Make a Rank struct.
 */
static Rank *
rank_new( IMAGE **in, IMAGE *out, int n, int index )
{
	Rank *rank;
	IMAGE **t;

	if( !(rank = IM_NEW( out, Rank )) )
		return( NULL );

	rank->n = n;
	rank->index = index;
	rank->out = out;
	if( !(t = IM_ARRAY( out, n, IMAGE * )) || 
		!(rank->in = IM_ARRAY( out, n + 1, IMAGE * )) ) 
		return( NULL );

	/* Cast inputs up to a common format, common bands.
	 */
	if( im_open_local_array( out, t, n, "im_rank_image", "p" ) ||
		im_open_local_array( out, rank->in, n, "im_rank_image", "p" ) ||
		im__bandalike_vec( "im_rank_image", in, t, n ) ||
		im__formatalike_vec( t, rank->in, n ) )
		return( NULL );
	rank->in[n] = NULL;

	return( rank );
}

/* Our sequence value.
 */
typedef struct {
	Rank *rank;

	REGION **ir;		/* Input regions */
	VipsPel **pts;		/* Per-input region data pointer */
	VipsPel *sort;		/* Sort pixels here */
} RankSequence;

/* Free a sequence value.
 */
static int
rank_stop( void *vseq, void *a, void *b )
{
	RankSequence *seq = (RankSequence *) vseq;
	Rank *rank = (Rank *) b;

	int i;

	if( seq->ir )
		for( i = 0; i < rank->n; i++ ) 
			IM_FREEF( im_region_free, seq->ir[i] );

	return( 0 );
}

/* Make a sequence value.
 */
static void *
rank_start( IMAGE *out, void *a, void *b )
{
	IMAGE **in = (IMAGE **) a;
	Rank *rank = (Rank *) b;

	RankSequence *seq;
	int i;

	if( !(seq = IM_NEW( out, RankSequence )) )
		return( NULL );

	/* Init!
	 */
	seq->rank = rank;
	seq->ir = NULL;
	seq->pts = NULL;

	/* Attach regions and arrays.
	 */
	seq->ir = IM_ARRAY( out, rank->n + 1, REGION * );
	seq->pts = IM_ARRAY( out, rank->n + 1, VipsPel * );
	seq->sort = IM_ARRAY( out, 
		rank->n * IM_IMAGE_SIZEOF_ELEMENT( in[0] ), VipsPel );
	if( !seq->ir || !seq->pts || !seq->sort ) {
		rank_stop( seq, in, rank );
		return( NULL );
	}

	for( i = 0; i < rank->n; i++ )
		if( !(seq->ir[i] = im_region_create( in[i] )) ) {
			rank_stop( seq, in, rank );
			return( NULL );
		}
	seq->ir[i] = NULL;

	return( (void *) seq );
}

/* Special-case max and min (rather common).
 */
#define FIND_IM_MAX( TYPE ) { \
	for( x = 0; x < sz; x++ ) { \
		TYPE top = ((TYPE *) seq->pts[0])[x]; \
 		\
		for( i = 1; i < rank->n; i++ ) { \
			TYPE v = ((TYPE *) seq->pts[i])[x]; \
 			\
			if( v > top ) \
				top = v; \
		} \
 		\
		((TYPE *) q)[x] = top; \
	} \
}

#define FIND_IM_MIN( TYPE ) { \
	for( x = 0; x < sz; x++ ) { \
		TYPE bot = ((TYPE *) seq->pts[0])[x]; \
 		\
		for( i = 1; i < rank->n; i++ ) { \
			TYPE v = ((TYPE *) seq->pts[i])[x]; \
 			\
			if( v < bot ) \
				bot = v; \
		} \
 		\
		((TYPE *) q)[x] = bot; \
	} \
}

/* Inner loop for sorting.
 */
#define FIND_IM_RANK( TYPE ) { \
	TYPE *sort = (TYPE *) seq->sort; \
	\
	for( x = 0; x < sz; x++ ) { \
		for( i = 0; i < rank->n; i++ ) { \
			TYPE v = ((TYPE *) seq->pts[i])[x]; \
			\
			/* Search for element >v. 
			 */\
			for( j = 0; j < i; j++ ) \
				if( sort[j] > v ) \
					break; \
			\
			/* Move remaining elements down. 
			 */ \
			for( k = i; k > j; k-- ) \
				sort[k] = sort[k - 1]; \
			\
			/* Insert this element. 
			 */ \
			sort[j] = v; \
		} \
		\
		((TYPE *) q)[x] = sort[rank->index]; \
	} \
} 

#define SWITCH( OPERATION ) \
	switch( rank->out->BandFmt ) { \
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

static int
rank_gen( REGION *or, void *vseq, void *a, void *b )
{
	RankSequence *seq = (RankSequence *) vseq;
	Rank *rank = (Rank *) b;
	Rect *r = &or->valid;
        int le = r->left;
        int to = r->top;
        int bo = IM_RECT_BOTTOM(r);
	int sz = IM_REGION_N_ELEMENTS( or );

	int x, y, i, j, k;

	/* Prepare each input area.
	 */
	for( i = 0; i < rank->n; i++ )
		if( im_prepare( seq->ir[i], r ) )
			return( -1 );

	/* Loop over output!
	 */
	for( y = to; y < bo; y++ ) {
		VipsPel *q = IM_REGION_ADDR( or, le, y );

		for( i = 0; i < rank->n; i++ )
			seq->pts[i] = IM_REGION_ADDR( seq->ir[i], le, y );

		/* Special-case max and min.
		 */
		if( rank->index == 0 ) 
			SWITCH( FIND_IM_MIN )
		else if( rank->index == rank->n - 1 )
			SWITCH( FIND_IM_MAX )
		else
			SWITCH( FIND_IM_RANK )
	}

	return( 0 );
}

/**
 * im_rank_image:
 * @in: input image array
 * @out: output image
 * @n: number of input images
 * @index: select pixel
 *
 * im_rank_image() sorts the images @in pixel-wise, then outputs an 
 * image in which each pixel is selected from the sorted list by the 
 * @index parameter. For example, if @index
 * is zero, then each output pixel will be the minimum of all the 
 * corresponding input pixels. 
 *
 * It works for any uncoded, non-complex image type. Images are cast up to the
 * smallest common-format.
 *
 * Any image can have either 1 band or n bands, where n is the same for all
 * the non-1-band images. Single band images are then effectively copied to 
 * make n-band images.
 *
 * See also: im_rank(), im_maxvalue().
 *
 * Returns: 0 on success, -1 on error
 */
int
im_rank_image( IMAGE **in, IMAGE *out, int n, int index )
{
	int i;
	Rank *rank;

	if( n < 1 ) {
		im_error( "im_rank_image", "%s", _( "zero input images!" ) );
		return( -1 );
	}
	if( index < 0 || index > n - 1 ) {
		im_error( "im_rank_image", 
			_( "index should be in range 0 - %d" ), n - 1 );
		return( -1 );
	}
	if( im_poutcheck( out ) )
		return( -1 );
	for( i = 0; i < n; i++ ) 
		if( im_pincheck( in[i] ) ||
			im_check_uncoded( "im_rank_image", in[i] ) ||
			im_check_noncomplex( "im_rank_image", in[i] ) ||
			im_check_size_same( "im_rank_image", in[i], in[0] ) )
			return( -1 );

	if( !(rank = rank_new( in, out, n, index )) ||
		im_cp_desc_array( out, rank->in ) ||
		im_demand_hint_array( out, IM_THINSTRIP, rank->in )  ||
		im_generate( out, 
			rank_start, rank_gen, rank_stop, rank->in, rank ) )
		return( -1 );
	
	return( 0 );
}

/**
 * im_maxvalue:
 * @in: input image array
 * @out: output image
 * @n: number of input images
 *
 * im_maxvalue() is a convenience function over im_rank_image(). It sorts the 
 * input images pixel-wise, then outputs an image 
 * in which each pixel is the maximum  of all the corresponding input images. 
 * It works for any uncoded, non-complex image type. Images are cast up to the
 * smallest common-format.
 *
 * Any image can have either 1 band or n bands, where n is the same for all
 * the non-1-band images. Single band images are then effectively copied to 
 * make n-band images.
 *
 * See also: im_rank_image().
 *
 * Returns: 0 on success, -1 on error
 */
int
im_maxvalue( IMAGE **in, IMAGE *out, int n )
{
	return( im_rank_image( in, out, n, n - 1 ) );
}
