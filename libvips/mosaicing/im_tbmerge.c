/* Merge two images top-bottom. dx, dy is the offset needed to get from sec 
 * (secondary image) to ref (reference image). 
 *
 * Usage:
 *
 *   int 
 *   im_tbmerge( ref, sec, out, dx, dy )
 *   IMAGE *ref, *sec, *out;
 *   int dx, dy;
 *   
 * Returns 0 on success and -1 on error
 *
 * Copyright: 1990, 1991 N. Dessipris 
 * Author: N. Dessipris
 * Written on: 20/09/1990
 * Updated on: 17/04/1991
 * 1/6/92: J. Cupitt
 *      - check for difference bug fixed
 *      - geometry calculations improved and simplified
 *      - small speedups
 * 30/6/93 K.Martinez : coped with IM_CODING_LABQ images
 * 7/7/93 JC
 *	- ANSIfied
 *	- proper freeing on errors, ready for partial
 * 8/11/93 JC
 *	- now propogates both input histories
 *	- adds magic lines for global mosaic optimisation
 *
 *
 *  16/May/1994 Ahmed. Abbood
 *      - Modified to use partials on all IO
 *
 *  June/1995 Ahmed Abbood
 *
 *      - Modified to work with different types of images.
 *
 *
 * 16/6/95 JC
 *	- added to VIPS!
 * 7/9/95 JC
 *	- split into two parts: im_tbmerge() and im__tbmerge()
 *	- latter called by im_tbmosaic()
 *	- just the same as public im_tbmerge(), but adds no history
 *	- necessary for im_global_balance()
 *	- small bugs fixed
 * 10/10/95 JC
 *	- better checks that parameters are sensible
 * 11/10/95 JC
 *	- Kirk spotted what a load of rubbish Ahmed's code is
 *	- rewritten - many, many bugs fixed
 * 28/7/97 JC
 *	- new non-rectangular im_lrmerge adapted to make this
 *	- small tidies
 * 18/2/98 JC
 *	- im_demand_hint() call added
 * 19/2/98 JC
 *	- now works for any dx/dy by calling im_insert() for bizarre cases
 * 2/2/01 JC
 *	- added tunable max blend width
 * 8/3/01 JC
 *	- switched to integer arithmetic for integer blends
 * 23/3/01 JC
 *	- oops, iblend was broken
 * 7/11/01 JC
 *	- more sophisticated transparency handling
 * 15/8/02 JC
 *	- records Xoffset/Yoffset
 * 20/6/05
 *	- now requires all bands == 0 for transparency (used to just check
 *	  band 0)
 * 24/1/11
 * 	- gtk-doc
 * 	- match formats and bands automatically
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
#include <math.h>

#include <vips/vips.h>
#include <vips/thread.h>
#include <vips/transform.h>
#include <vips/internal.h>

#include "mosaic.h"

/* Return the position of the first non-zero pel from the top.
 */
static int
find_top( REGION *ir, int *pos, int x, int y, int h )
{
	VipsPel *pr = IM_REGION_ADDR( ir, x, y );
	IMAGE *im = ir->im;
	int ls = IM_REGION_LSKIP( ir ) / IM_IMAGE_SIZEOF_ELEMENT( im );
	int b = im->Bands;
	int i, j;

	/* Double the number of bands in a complex.
	 */
	if( vips_bandfmt_iscomplex( im->BandFmt ) )
		b *= 2;

/* Search for the first non-zero band element from the top edge of the image.
 */
#define tsearch( TYPE ) { \
	TYPE *p = (TYPE *) pr; \
	\
	for( i = 0; i < h; i++ ) { \
		for( j = 0; j < b; j++ ) \
			if( p[j] ) \
				break; \
		if( j < b ) \
			break; \
		\
		p += ls; \
	} \
}

	switch( im->BandFmt ) {
	case IM_BANDFMT_UCHAR: 	tsearch( unsigned char ); break; 
	case IM_BANDFMT_CHAR: 	tsearch( signed char ); break; 
	case IM_BANDFMT_USHORT: tsearch( unsigned short ); break; 
	case IM_BANDFMT_SHORT: 	tsearch( signed short ); break; 
	case IM_BANDFMT_UINT: 	tsearch( unsigned int ); break; 
	case IM_BANDFMT_INT: 	tsearch( signed int );  break; 
	case IM_BANDFMT_FLOAT: 	tsearch( float ); break; 
	case IM_BANDFMT_DOUBLE:	tsearch( double ); break; 
	case IM_BANDFMT_COMPLEX:tsearch( float ); break; 
	case IM_BANDFMT_DPCOMPLEX:tsearch( double ); break;

	default:
		im_error( "im_tbmerge", "%s", _( "internal error" ) );
		return( -1 );
	}

	*pos = y + i;

	return( 0 );
}

/* Return the position of the first non-zero pel from the bottom.
 */
static int
find_bot( REGION *ir, int *pos, int x, int y, int h )
{
	VipsPel *pr = IM_REGION_ADDR( ir, x, y );
	IMAGE *im = ir->im;
	int ls = IM_REGION_LSKIP( ir ) / IM_IMAGE_SIZEOF_ELEMENT( ir->im );
	int b = im->Bands;
	int i, j;

	/* Double the number of bands in a complex.
	 */
	if( vips_bandfmt_iscomplex( im->BandFmt ) )
		b *= 2;

/* Search for the first non-zero band element from the top edge of the image.
 */
#define rsearch( TYPE ) { \
	TYPE *p = (TYPE *) pr + (h - 1) * ls; \
	\
	for( i = h - 1; i >= 0; i-- ) { \
		for( j = 0; j < b; j++ ) \
			if( p[j] ) \
				break; \
		if( j < b ) \
			break; \
		\
		p -= ls; \
	} \
}

	switch( im->BandFmt ) {
	case IM_BANDFMT_UCHAR: 	rsearch( unsigned char ); break; 
	case IM_BANDFMT_CHAR: 	rsearch( signed char ); break; 
	case IM_BANDFMT_USHORT: rsearch( unsigned short ); break; 
	case IM_BANDFMT_SHORT: 	rsearch( signed short ); break; 
	case IM_BANDFMT_UINT: 	rsearch( unsigned int ); break; 
	case IM_BANDFMT_INT: 	rsearch( signed int );  break; 
	case IM_BANDFMT_FLOAT: 	rsearch( float ); break; 
	case IM_BANDFMT_DOUBLE:	rsearch( double ); break; 
	case IM_BANDFMT_COMPLEX:rsearch( float ); break; 
	case IM_BANDFMT_DPCOMPLEX:rsearch( double ); break;

	default:
		im_error( "im_tbmerge", "%s", _( "internal error" ) );
		return( -1 );
	}

	*pos = y + i;

	return( 0 );
}

/* Make first/last for oreg.
 */
static int
make_firstlast( MergeInfo *inf, Overlapping *ovlap, Rect *oreg )
{
	REGION *rir = inf->rir;
	REGION *sir = inf->sir;
	Rect rr, sr;
	int x;
	int missing;

	/* We're going to build first/last ... lock it from other generate
	 * threads. In fact it's harmless if we do get two writers, but we may
	 * avoid duplicating work.
	 */
	g_mutex_lock( ovlap->fl_lock );

	/* Do we already have first/last for this area? Bail out if we do.
	 */
	missing = 0;
	for( x = oreg->left; x < IM_RECT_RIGHT( oreg ); x++ ) {
		const int j = x - ovlap->overlap.left;
		const int first = ovlap->first[j];

		if( first < 0 ) {
			missing = 1;
			break;
		}
	}
	if( !missing ) {
		/* No work to do!
		 */
		g_mutex_unlock( ovlap->fl_lock );
		return( 0 );
	}

	/* Entire height of overlap in ref for oreg ... we know oreg is inside
	 * overlap.
	 */
	rr.left = oreg->left;
	rr.top = ovlap->overlap.top;
	rr.width = oreg->width;
	rr.height = ovlap->overlap.height;
	rr.left -= ovlap->rarea.left;
	rr.top -= ovlap->rarea.top;

	/* Same in sec.
	 */
	sr.left = oreg->left;
	sr.top = ovlap->overlap.top;
	sr.width = oreg->width;
	sr.height = ovlap->overlap.height;
	sr.left -= ovlap->sarea.left;
	sr.top -= ovlap->sarea.top;

	/* Make pixels.
	 */
	if( im_prepare( rir, &rr ) || im_prepare( sir, &sr ) ) {
		g_mutex_unlock( ovlap->fl_lock );
		return( -1 );
	}

	/* Make first/last cache.
	 */
	for( x = 0; x < oreg->width; x++ ) {
		const int j = (x + oreg->left) - ovlap->overlap.left;
		int *first = &ovlap->first[j];
		int *last = &ovlap->last[j];

		/* Done this line already?
		 */
		if( *first < 0 ) {
			/* Search for top/bottom of overlap on this scan-line.
			 */
			if( find_top( sir, first, 
				x + sr.left, sr.top, sr.height ) ||
				find_bot( rir, last, 
					x + rr.left, rr.top, rr.height ) ) {
				g_mutex_unlock( ovlap->fl_lock );
				return( -1 );
			}

			/* Translate to output space.
			 */
			*first += ovlap->sarea.top;
			*last += ovlap->rarea.top;

			/* Clip to maximum blend width, if necessary.
			 */
			if( ovlap->mwidth >= 0 && 
				*last - *first > ovlap->mwidth ) {
				int shrinkby = (*last - *first) - ovlap->mwidth;

				*first += shrinkby / 2;
				*last -= shrinkby / 2;
			}
		}
	}

	g_mutex_unlock( ovlap->fl_lock );

	return( 0 );
}

/* Test pixel == 0.
 */
#define TEST_ZERO( TYPE, T, RESULT ) { \
	TYPE *tt = (T); \
	int ii; \
	\
	for( ii = 0; ii < cb; ii++ ) \
		if( tt[i] ) \
			break; \
	if( ii == cb )  \
		(RESULT) = 1; \
}

/* Blend two integer images ... one scan-line.
 */
#define iblend( TYPE, B, IN1, IN2, OUT ) { \
	TYPE *tr = (TYPE *) (IN1); \
	TYPE *ts = (TYPE *) (IN2); \
	TYPE *tq = (TYPE *) (OUT); \
	const int cb = (B); \
	int ref_zero; \
	int sec_zero; \
	int x, b; \
	int i; \
	\
	for( i = 0, x = 0; x < oreg->width; x++ ) { \
		ref_zero = 0; \
		sec_zero = 0; \
		TEST_ZERO( TYPE, tr, ref_zero ); \
		TEST_ZERO( TYPE, ts, sec_zero ); \
		\
		/* Above the bottom image? \
		 */ \
		if( y < first[x] ) { \
			if( !ref_zero ) \
				for( b = 0; b < cb; b++, i++ )  \
					tq[i] = tr[i]; \
			else \
				for( b = 0; b < cb; b++, i++ )  \
					tq[i] = ts[i]; \
		} \
		/* To the right? \
		 */ \
		else if( y >= last[x] ) { \
			if( !sec_zero ) \
				for( b = 0; b < cb; b++, i++ )  \
					tq[i] = ts[i]; \
			else \
				for( b = 0; b < cb; b++, i++ )  \
					tq[i] = tr[i]; \
		} \
		/* In blend area. \
		 */ \
		else { \
			if( !ref_zero && !sec_zero ) { \
				const int bheight = last[x] - first[x]; \
				const int inx = ((y - first[x]) << \
					BLEND_SHIFT) / bheight; \
				int c1 = im__icoef1[inx];  \
				int c2 = im__icoef2[inx];  \
				\
				for( b = 0; b < cb; b++, i++ ) \
					tq[i] = c1*tr[i] / BLEND_SCALE + \
						c2*ts[i] / BLEND_SCALE; \
			} \
			else if( !ref_zero ) \
				for( b = 0; b < cb; b++, i++ )  \
					tq[i] = tr[i]; \
			else \
				for( b = 0; b < cb; b++, i++ )  \
					tq[i] = ts[i]; \
		}  \
	} \
}

/* Blend two float images.
 */
#define fblend( TYPE, B, IN1, IN2, OUT ) { \
	TYPE *tr = (TYPE *) (IN1); \
	TYPE *ts = (TYPE *) (IN2); \
	TYPE *tq = (TYPE *) (OUT); \
	int ref_zero; \
	int sec_zero; \
	const int cb = (B); \
	int x, b; \
	int i; \
	\
	for( i = 0, x = 0; x < oreg->width; x++ ) { \
		ref_zero = 0; \
		sec_zero = 0; \
		TEST_ZERO( TYPE, tr, ref_zero ); \
		TEST_ZERO( TYPE, ts, sec_zero ); \
		\
		/* Above the bottom image? \
		 */ \
		if( y < first[x] )  \
			if( !ref_zero ) \
				for( b = 0; b < cb; b++, i++ )  \
					tq[i] = tr[i]; \
			else \
				for( b = 0; b < cb; b++, i++ )  \
					tq[i] = tr[i]; \
		/* To the right? \
		 */ \
		else if( y >= last[x] )  \
			if( !sec_zero ) \
				for( b = 0; b < cb; b++, i++ )  \
					tq[i] = ts[i]; \
			else \
				for( b = 0; b < cb; b++, i++ )  \
					tq[i] = tr[i]; \
		/* In blend area. \
		 */ \
		else { \
			if( !ref_zero && !sec_zero ) { \
				const int bheight = last[x] - first[x]; \
				const int inx = ((y - first[x]) << \
					BLEND_SHIFT) / bheight; \
				double c1 = im__coef1[inx];  \
				double c2 = im__coef2[inx];  \
				\
				for( b = 0; b < cb; b++, i++ ) \
					tq[i] = c1 * tr[i] + c2 * ts[i]; \
			} \
			else if( !ref_zero ) \
				for( b = 0; b < cb; b++, i++ )  \
					tq[i] = tr[i]; \
			else \
				for( b = 0; b < cb; b++, i++ )  \
					tq[i] = ts[i]; \
		}  \
	} \
}

/* Top-bottom blend function for non-labpack images.
 */
static int
tb_blend( REGION *or, MergeInfo *inf, Overlapping *ovlap, Rect *oreg )
{
	REGION *rir = inf->rir;
	REGION *sir = inf->sir;
	IMAGE *im = or->im;

	Rect prr, psr;
	int y, yr, ys;

	/* Make sure we have a complete first/last set for this area.
	 */
	if( make_firstlast( inf, ovlap, oreg ) )
		return( -1 );

	/* Part of rr which we will output.
	 */
	prr = *oreg;
	prr.left -= ovlap->rarea.left;
	prr.top -= ovlap->rarea.top;

	/* Part of sr which we will output.
	 */
	psr = *oreg;
	psr.left -= ovlap->sarea.left;
	psr.top -= ovlap->sarea.top;

	/* Make pixels.
	 */
	if( im_prepare( rir, &prr ) )
		return( -1 );
	if( im_prepare( sir, &psr ) )
		return( -1 );

	/* Loop down overlap area.
	 */
	for( y = oreg->top, yr = prr.top, ys = psr.top; 
		y < IM_RECT_BOTTOM( oreg ); y++, yr++, ys++ ) { 
		VipsPel *pr = IM_REGION_ADDR( rir, prr.left, yr );
		VipsPel *ps = IM_REGION_ADDR( sir, psr.left, ys );
		VipsPel *q = IM_REGION_ADDR( or, oreg->left, y );

		const int j = oreg->left - ovlap->overlap.left;
		const int *first = ovlap->first + j;
		const int *last = ovlap->last + j;

		switch( im->BandFmt ) {
		case IM_BANDFMT_UCHAR: 	
			iblend( unsigned char, im->Bands, pr, ps, q ); break; 
		case IM_BANDFMT_CHAR: 	
			iblend( signed char, im->Bands, pr, ps, q ); break; 
		case IM_BANDFMT_USHORT: 
			iblend( unsigned short, im->Bands, pr, ps, q ); break; 
		case IM_BANDFMT_SHORT: 	
			iblend( signed short, im->Bands, pr, ps, q ); break; 
		case IM_BANDFMT_UINT: 	
			iblend( unsigned int, im->Bands, pr, ps, q ); break; 
		case IM_BANDFMT_INT: 	
			iblend( signed int, im->Bands, pr, ps, q );  break; 
		case IM_BANDFMT_FLOAT: 	
			fblend( float, im->Bands, pr, ps, q ); break; 
		case IM_BANDFMT_DOUBLE:	
			fblend( double, im->Bands, pr, ps, q ); break; 
		case IM_BANDFMT_COMPLEX:
			fblend( float, im->Bands*2, pr, ps, q ); break; 
		case IM_BANDFMT_DPCOMPLEX:
			fblend( double, im->Bands*2, pr, ps, q ); break;

		default:
			im_error( "im_tbmerge", "%s", _( "internal error" ) );
			return( -1 );
		}
	}

	return( 0 );
}

/* Top-bottom blend function for IM_CODING_LABQ images.
 */
static int
tb_blend_labpack( REGION *or, MergeInfo *inf, Overlapping *ovlap, Rect *oreg )
{
	REGION *rir = inf->rir;
	REGION *sir = inf->sir;
	Rect prr, psr;
	int y, yr, ys;

	/* Make sure we have a complete first/last set for this area. This
	 * will just look at the top 8 bits of L, not all 10, but should be OK.
	 */
	if( make_firstlast( inf, ovlap, oreg ) )
		return( -1 );

	/* Part of rr which we will output.
	 */
	prr = *oreg;
	prr.left -= ovlap->rarea.left;
	prr.top -= ovlap->rarea.top;

	/* Part of sr which we will output.
	 */
	psr = *oreg;
	psr.left -= ovlap->sarea.left;
	psr.top -= ovlap->sarea.top;

	/* Make pixels.
	 */
	if( im_prepare( rir, &prr ) )
		return( -1 );
	if( im_prepare( sir, &psr ) )
		return( -1 );

	/* Loop down overlap area.
	 */
	for( y = oreg->top, yr = prr.top, ys = psr.top; 
		y < IM_RECT_BOTTOM( oreg ); y++, yr++, ys++ ) { 
		VipsPel *pr = IM_REGION_ADDR( rir, prr.left, yr );
		VipsPel *ps = IM_REGION_ADDR( sir, psr.left, ys );
		VipsPel *q = IM_REGION_ADDR( or, oreg->left, y );

		const int j = oreg->left - ovlap->overlap.left;
		const int *first = ovlap->first + j;
		const int *last = ovlap->last + j;

		float *fq = inf->merge;
		float *r = inf->from1;
		float *s = inf->from2;

		/* Unpack two bits we want.
		 */
		vips__LabQ2Lab_vec( r, pr, oreg->width );
		vips__LabQ2Lab_vec( s, ps, oreg->width );

		/* Blend as floats.
		 */
		fblend( float, 3, r, s, fq ); 

		/* Re-pack to output buffer.
		 */
		vips__Lab2LabQ_vec( q, inf->merge, oreg->width );
	}

	return( 0 );
}

/* Build per-call state.
 */
static Overlapping *
build_tbstate( IMAGE *ref, IMAGE *sec, IMAGE *out, int dx, int dy, int mwidth )
{
   	Overlapping *ovlap;

	if( !(ovlap = im__build_mergestate( "im_tbmerge", 
		ref, sec, out, dx, dy, mwidth )) )
		return( NULL );

	/* Select blender.
	 */
	switch( ovlap->ref->Coding ) {
	case IM_CODING_LABQ:
		ovlap->blend = tb_blend_labpack;
		break;

	case IM_CODING_NONE:
		ovlap->blend = tb_blend;
		break;

	default:
		im_error( "im_tbmerge", "%s", _( "unknown coding type" ) );
		return( NULL );
	}

	/* Find the parts of output which come just from ref and just from sec.
	 */
	ovlap->rpart = ovlap->rarea;
	ovlap->spart = ovlap->sarea;
	ovlap->rpart.height -= ovlap->overlap.height;
	ovlap->spart.top += ovlap->overlap.height;
	ovlap->spart.height -= ovlap->overlap.height;

	/* Is there too much overlap? ie. bottom edge of ref image is greater
	 * than bottom edge of sec image, or top edge of ref > top edge of
	 * sec.
	 */
	if( IM_RECT_BOTTOM( &ovlap->rarea ) > IM_RECT_BOTTOM( &ovlap->sarea ) ||
		ovlap->rarea.top > ovlap->sarea.top ) {
		im_error( "im_tbmerge", "%s", _( "too much overlap" ) );
		return( NULL );
	}

	/* Max number of pixels we may have to blend together.
	 */
	ovlap->blsize = ovlap->overlap.width;

	return( ovlap );
}

int
im__tbmerge( IMAGE *ref, IMAGE *sec, IMAGE *out, int dx, int dy, int mwidth )
{  
	Overlapping *ovlap;

	if( dy > 0 || dy < 1 - ref->Ysize ) {
		/* No overlap, use insert instead.
		 */
  		if( im_insert( ref, sec, out, -dx, -dy ) )
			return( -1 );
		out->Xoffset = -dx;
		out->Yoffset = -dy;

		return( 0 );
	}

	/* Build state for this join.
	 */
	if( !(ovlap = build_tbstate( ref, sec, out, dx, dy, mwidth )) )
		return( -1 );

	/* Prepare the output IMAGE.
	 */ 
	if( im_cp_descv( out, ref, sec, NULL ) )
		return( -1 );
	out->Xsize = ovlap->oarea.width;
	out->Ysize = ovlap->oarea.height;
	out->Xoffset = ovlap->sarea.left;
	out->Yoffset = ovlap->sarea.top;

	/* Set demand hints. 
	 */
	if( im_demand_hint( out, IM_THINSTRIP, ref, sec, NULL ) )
		return( -1 );

	/* Generate!
	 */
	if( im_generate( out,
		im__start_merge, im__merge_gen, im__stop_merge, ovlap, NULL ) )
		return( -1 );

	return ( 0 );
}

/**
 * im_tbmerge:
 * @ref: reference image
 * @sec: secondary image
 * @out: output image
 * @dx: displacement of ref from sec
 * @dy: displacement of ref from sec
 * @mwidth: maximum seam width
 *
 * This operation joins two images top-bottom (with @ref on the top) with a 
 * smooth seam.
 *
 * If the number of bands differs, one of the images 
 * must have one band. In this case, an n-band image is formed from the 
 * one-band image by joining n copies of the one-band image together, and then
 * the two n-band images are operated upon.
 *
 * The two input images are cast up to the smallest common type (see table 
 * Smallest common format in 
 * <link linkend="VIPS-arithmetic">arithmetic</link>).
 *
 * @dx and @dy give the displacement of @sec relative to @ref, in other words,
 * the vector to get from the origin of @sec to the origin of @ref, in other
 * words, @dx will generally be a negative number. 
 *
 * @mwidth limits  the  maximum height of the
 * blend area.  A value of "-1" means "unlimited". The two images are blended 
 * with a raised cosine. 
 *
 * Pixels with all bands equal to zero are "transparent", that
 * is, zero pixels in the overlap area do not  contribute  to  the  merge.
 * This makes it possible to join non-rectangular images.
 *
 * See also: im_lrmosaic(), im_lrmerge(), im_match_linear(), im_insert().
 *
 * Returns: 0 on success, -1 on error
 */
int
im_tbmerge( IMAGE *ref, IMAGE *sec, IMAGE *out, int dx, int dy, int mwidth )
{ 
	if( im__tbmerge( ref, sec, out, dx, dy, mwidth ) )
		return( -1 );

	if( im_histlin( out, "#TBJOIN <%s> <%s> <%s> <%d> <%d> <%d>", 
		ref->filename, sec->filename, out->filename, 
		-dx, -dy, mwidth ) )
		return( -1 );

	return( 0 );
}
