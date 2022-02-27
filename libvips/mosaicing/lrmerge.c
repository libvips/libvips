/* Merge two images left-right. 
 *
 * Copyright: 1990, 1991 N. Dessipris 
 * Author: N. Dessipris
 * Written on: 20/09/1990
 * Updated on: 17/04/1991
 * 1/6/92: JC
 * 	- check for difference bug fixed
 *	- geometry calculations improved and simplified
 *	- small speedups
 Kirk Martinez for Sys5 29/4/93
 * 7/8/93 JC
 *	- ANSIfied
 *	- memory leaks fixed, ready for partial v2
 *	- now does IM_CODING_LABQ too
 * 8/11/93 JC
 *	- now propogates both input histories
 *	- adds magic lines for global mosaic optimisation
 *
 *
 *
 May/1994 Ahmed Abbood
 *
 *	- Modified to use partials on all IO
 *
 June/1995 Ahmed Abbood
 *
 *	- Modified to work with different types of images.
 *
 * 16/6/95 JC
 *	- tidied up a little
 *	- added to VIPS!
 * 7/9/95 JC
 *	- split into two parts: im_lrmerge() and im__lrmerge()
 *	- latter called by im_lrmosaic()
 *	- just the same as public im_lrmerge(), but adds no history
 *	- necessary for im_global_balance()
 *	- small bugs fixed
 * 10/10/95 JC
 *	- better checks that parameters are sensible
 * 11/10/95 JC
 *	- Kirk spotted what a load of rubbish Ahmed's code is
 *	- rewritten - many, many bugs fixed
 * 24/1/97 JC
 *	- now outputs bounding area of input images, rather than clipping
 *	- ignores 0 pixels in blend
 *	- small tidies
 * 7/2/97 JC
 *	- new blend, caching
 * 25/2/97 JC
 *	- old blend back, much simpler
 *	- speed this up at some point if you think of an easy way to do it
 * 29/7/97 JC
 *	- IM_CODING_LABQ blend now works, was bug in im_wrapone()
 *	- small tidies
 * 10/1/98 JC
 *	- merge LUTs now shared between all running mergers
 *	- frees memory explicitly in im__stop_merge, for much better memory
 *	  use in large mosaics, huge improvement!
 * 18/2/98 JC
 *	- im_demand_hint() call added
 * 19/2/98 JC
 *	- now works for any dx/dy by calling im_insert() for bizarre cases
 * 26/9/99 JC
 *	- ooops, blend lut was wrong! wonder how long that's been broken,
 *	  since feb97 I guess
 * 2/2/01 JC
 *	- added tunable max blend width
 * 8/3/01 JC
 *	- switched to integer arithmetic for integer blends
 * 7/11/01 JC
 *	- more sophisticated transparency handling
 *	- tiny blend speed up
 * 19/3/02 JC
 * 	- move fl cache to main state for better sharing
 * 15/8/02 JC
 *	- records Xoffset/Yoffset
 * 20/6/05
 *	- now requires all bands == 0 for transparency (used to just check
 *	  band 0)
 * 24/1/11
 * 	- gtk-doc
 * 	- match formats and bands automatically
 * 22/5/14
 * 	- wrap as a class
 * 18/6/20 kleisauke
 * 	- convert to vips8
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
#include <glib/gi18n-lib.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <limits.h>

/* Define for debug output.
#define DEBUG
 */

#include <vips/vips.h>
#include <vips/thread.h>
#include <vips/transform.h>
#include <vips/internal.h>

#include "pmosaicing.h"

/* Blend luts. Shared between all lr and tb blends.
 */
double *vips__coef1 = NULL;
double *vips__coef2 = NULL;
int *vips__icoef1 = NULL;
int *vips__icoef2 = NULL;

/* Create a lut for the merging area. Always BLEND_SIZE entries, we 
 * scale later when we index it.
 */
int
vips__make_blend_luts( void )
{
	int x;

	/* Already done?
	 */
	if( vips__coef1 && vips__coef2 )
		return( 0 );

	/* Allocate and fill.
	 */
	vips__coef1 = VIPS_ARRAY( NULL, BLEND_SIZE, double );
	vips__coef2 = VIPS_ARRAY( NULL, BLEND_SIZE, double );
	vips__icoef1 = VIPS_ARRAY( NULL, BLEND_SIZE, int );
	vips__icoef2 = VIPS_ARRAY( NULL, BLEND_SIZE, int );
	if( !vips__coef1 || !vips__coef2 || !vips__icoef1 || !vips__icoef2 ) 
		return( -1 ); 

	for( x = 0; x < BLEND_SIZE; x++ ) {
		double a = VIPS_PI * x / (BLEND_SIZE - 1.0);

		vips__coef1[x] = (cos( a ) + 1.0) / 2.0;
		vips__coef2[x] = 1.0 - vips__coef1[x];
		vips__icoef1[x] = vips__coef1[x] * BLEND_SCALE;
		vips__icoef2[x] = vips__coef2[x] * BLEND_SCALE;
	}

	return( 0 );
}

/* Return the position of the first non-zero pel from the left.
 */
static int
find_first( VipsRegion *ir, int *pos, int x, int y, int w )
{
	VipsPel *pr = VIPS_REGION_ADDR( ir, x, y );
	VipsImage *im = ir->im;
	int ne = w * im->Bands;
	int i;

	/* Double the number of bands in a complex.
	 */
	if( vips_band_format_iscomplex( im->BandFmt ) )
		ne *= 2;

/* Search for the first non-zero band element from the left edge of the image.
 */
#define lsearch( TYPE ) { \
	TYPE *p = (TYPE *) pr; \
	\
	for( i = 0; i < ne; i++ ) \
		if( p[i] )\
			break;\
}

	switch( im->BandFmt ) {
	case VIPS_FORMAT_UCHAR:		lsearch( unsigned char ); break; 
	case VIPS_FORMAT_CHAR:		lsearch( signed char ); break; 
	case VIPS_FORMAT_USHORT:	lsearch( unsigned short ); break; 
	case VIPS_FORMAT_SHORT:		lsearch( signed short ); break; 
	case VIPS_FORMAT_UINT:		lsearch( unsigned int ); break; 
	case VIPS_FORMAT_INT:		lsearch( signed int );  break; 
	case VIPS_FORMAT_FLOAT:		lsearch( float ); break; 
	case VIPS_FORMAT_DOUBLE:	lsearch( double ); break; 
	case VIPS_FORMAT_COMPLEX:	lsearch( float ); break; 
	case VIPS_FORMAT_DPCOMPLEX:	lsearch( double ); break;

	default:
		g_assert_not_reached(); 
		return( -1 );
	}

	/* i is first non-zero band element, we want first non-zero pixel.
	 */
	*pos = x + i / im->Bands;

	return( 0 );
}

/* Return the position of the first non-zero pel from the right.
 */
static int
find_last( VipsRegion *ir, int *pos, int x, int y, int w )
{
	VipsPel *pr = VIPS_REGION_ADDR( ir, x, y );
	VipsImage *im = ir->im;
	int ne = w * im->Bands;
	int i;

	/* Double the number of bands in a complex.
	 */
	if( vips_band_format_iscomplex( im->BandFmt ) )
		ne *= 2;

/* Search for the first non-zero band element from the right.
 */
#define rsearch( TYPE ) { \
	TYPE *p = (TYPE *) pr; \
	\
	for( i = ne - 1; i >= 0; i-- )\
		if( p[i] )\
			break;\
}

	switch( im->BandFmt ) {
	case VIPS_FORMAT_UCHAR:		rsearch( unsigned char ); break; 
	case VIPS_FORMAT_CHAR:		rsearch( signed char ); break; 
	case VIPS_FORMAT_USHORT:	rsearch( unsigned short ); break; 
	case VIPS_FORMAT_SHORT:		rsearch( signed short ); break; 
	case VIPS_FORMAT_UINT:		rsearch( unsigned int ); break; 
	case VIPS_FORMAT_INT:		rsearch( signed int );  break; 
	case VIPS_FORMAT_FLOAT:		rsearch( float ); break; 
	case VIPS_FORMAT_DOUBLE:	rsearch( double ); break; 
	case VIPS_FORMAT_COMPLEX:	rsearch( float ); break; 
	case VIPS_FORMAT_DPCOMPLEX:	rsearch( double ); break;

	default:
		vips_error( "lrmerge", "%s", _( "internal error" ) );
		return( -1 );
	}

	/* i is first non-zero band element, we want first non-zero pixel.
	 */
	*pos = x + i / im->Bands;

	return( 0 );
}

/* Make sure we have first/last for this area.
 */
static int
make_firstlast( MergeInfo *inf, Overlapping *ovlap, VipsRect *oreg )
{
	VipsRegion *rir = inf->rir;
	VipsRegion *sir = inf->sir;
	VipsRect rr, sr;
	int y, yr, ys;
	int missing;

	/* We're going to build first/last ... lock it from other generate
	 * threads. In fact it's harmless if we do get two writers, but we may
	 * avoid duplicating work.
	 */
	g_mutex_lock( ovlap->fl_lock );

	/* Do we already have first/last for this area? Bail out if we do.
	 */
	missing = 0;
	for( y = oreg->top; y < VIPS_RECT_BOTTOM( oreg ); y++ ) {
		const int j = y - ovlap->overlap.top;
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

	/* Entire width of overlap in ref for scan-lines we want.
	 */
	rr.left = ovlap->overlap.left;
	rr.top = oreg->top;
	rr.width = ovlap->overlap.width;
	rr.height = oreg->height;
	rr.left -= ovlap->rarea.left;
	rr.top -= ovlap->rarea.top;

	/* Entire width of overlap in sec for scan-lines we want.
	 */
	sr.left = ovlap->overlap.left;
	sr.top = oreg->top;
	sr.width = ovlap->overlap.width;
	sr.height = oreg->height;
	sr.left -= ovlap->sarea.left;
	sr.top -= ovlap->sarea.top;

#ifdef DEBUG
	printf( "lrmerge: making first/last for areas:\n" );
	printf( "ref: left = %d, top = %d, width = %d, height = %d\n",
		rr.left, rr.top, rr.width, rr.height );
	printf( "sec: left = %d, top = %d, width = %d, height = %d\n",
		sr.left, sr.top, sr.width, sr.height );
#endif

	/* Make pixels.
	 */
	if( vips_region_prepare( rir, &rr ) ||
		vips_region_prepare( sir, &sr ) ) {
		g_mutex_unlock( ovlap->fl_lock );
		return( -1 );
	}

	/* Make first/last cache.
	 */
	for( y = oreg->top, yr = rr.top, ys = sr.top; 
		y < VIPS_RECT_BOTTOM( oreg ); y++, yr++, ys++ ) {
		const int j = y - ovlap->overlap.top;
		int *first = &ovlap->first[j];
		int *last = &ovlap->last[j];

		/* Done this line already?
		 */
		if( *first < 0 ) {
			/* Search for start/end of overlap on this scan-line.
			 */
			if( find_first( sir, first, 
				sr.left, ys, sr.width ) ||
				find_last( rir, last, 
					rr.left, yr, rr.width ) ) {
				g_mutex_unlock( ovlap->fl_lock );
				return( -1 );
			}

			/* Translate to output space.
			 */
			*first += ovlap->sarea.left;
			*last += ovlap->rarea.left;

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
		if( tt[i + ii] ) \
			break; \
	if( ii == cb )  \
		(RESULT) = 1; \
}

/* Blend two integer images.
 */
#define iblend( TYPE, B, IN1, IN2, OUT ) { \
	TYPE *tr = (TYPE *) (IN1); \
	TYPE *ts = (TYPE *) (IN2); \
	TYPE *tq = (TYPE *) (OUT); \
	const int cb = (B); \
	const int left = VIPS_CLIP( 0, first - oreg->left, oreg->width ); \
	const int right = VIPS_CLIP( left, last - oreg->left, oreg->width ); \
	int ref_zero; \
	int sec_zero; \
	int x, b; \
	int i; \
	\
	/* Left of the blend area. \
	 */ \
	for( i = 0, x = 0; x < left; x++ ) { \
		ref_zero = 0; \
		TEST_ZERO( TYPE, tr, ref_zero ); \
		if( !ref_zero ) \
			for( b = 0; b < cb; b++, i++ ) \
				tq[i] = tr[i]; \
		else \
			for( b = 0; b < cb; b++, i++ ) \
				tq[i] = ts[i]; \
	} \
	\
	/* In blend area. \
	 */ \
	for( x = left; x < right; x++ ) { \
		ref_zero = 0; \
		sec_zero = 0; \
		TEST_ZERO( TYPE, tr, ref_zero ); \
		TEST_ZERO( TYPE, ts, sec_zero ); \
		\
		if( !ref_zero && !sec_zero ) { \
			int inx = ((x + oreg->left - first) <<  \
				BLEND_SHIFT) / bwidth; \
			int c1 = vips__icoef1[inx]; \
			int c2 = vips__icoef2[inx]; \
			\
			for( b = 0; b < cb; b++, i++ ) \
				tq[i] = c1 * tr[i] / BLEND_SCALE + \
					c2 * ts[i] / BLEND_SCALE; \
		} \
		else if( !ref_zero ) \
			for( b = 0; b < cb; b++, i++ ) \
				tq[i] = tr[i]; \
		else \
			for( b = 0; b < cb; b++, i++ ) \
				tq[i] = ts[i]; \
	} \
	\
	/* Right of blend.
	 */ \
	for( x = right; x < oreg->width; x++ ) { \
		sec_zero = 0; \
		TEST_ZERO( TYPE, ts, sec_zero ); \
		if( !sec_zero ) \
			for( b = 0; b < cb; b++, i++ )  \
				tq[i] = ts[i]; \
		else \
			for( b = 0; b < cb; b++, i++ )  \
				tq[i] = tr[i]; \
	} \
}

/* Blend two float images.
 */
#define fblend( TYPE, B, IN1, IN2, OUT ) { \
	TYPE *tr = (TYPE *) (IN1); \
	TYPE *ts = (TYPE *) (IN2); \
	TYPE *tq = (TYPE *) (OUT); \
	const int cb = (B); \
	const int left = VIPS_CLIP( 0, first - oreg->left, oreg->width ); \
	const int right = VIPS_CLIP( left, last - oreg->left, oreg->width ); \
	int ref_zero; \
	int sec_zero; \
	int x, b; \
	int i; \
	\
	/* Left of the blend area. \
	 */ \
	for( i = 0, x = 0; x < left; x++ ) { \
		ref_zero = 0; \
		TEST_ZERO( TYPE, tr, ref_zero ); \
		if( !ref_zero ) \
			for( b = 0; b < cb; b++, i++ ) \
				tq[i] = tr[i]; \
		else \
			for( b = 0; b < cb; b++, i++ ) \
				tq[i] = ts[i]; \
	} \
	\
	/* In blend area. \
	 */ \
	for( x = left; x < right; x++ ) { \
		ref_zero = 0; \
		sec_zero = 0; \
		TEST_ZERO( TYPE, tr, ref_zero ); \
		TEST_ZERO( TYPE, ts, sec_zero ); \
		\
		if( !ref_zero && !sec_zero ) { \
			int inx = ((x + oreg->left - first) <<  \
				BLEND_SHIFT) / bwidth; \
			double c1 = vips__coef1[inx];  \
			double c2 = vips__coef2[inx];  \
			\
			for( b = 0; b < cb; b++, i++ ) \
				tq[i] = c1 * tr[i] + c2 * ts[i]; \
		} \
		else if( !ref_zero ) \
			for( b = 0; b < cb; b++, i++ ) \
				tq[i] = tr[i]; \
		else \
			for( b = 0; b < cb; b++, i++ ) \
				tq[i] = ts[i]; \
	} \
	\
	/* Right of blend.
	 */ \
	for( x = right; x < oreg->width; x++ ) { \
		sec_zero = 0; \
		TEST_ZERO( TYPE, ts, sec_zero ); \
		if( !sec_zero ) \
			for( b = 0; b < cb; b++, i++ )  \
				tq[i] = ts[i]; \
		else \
			for( b = 0; b < cb; b++, i++ )  \
				tq[i] = tr[i]; \
	} \
}

/* Left-right blend function for non-labpack images.
 */
static int
lr_blend( VipsRegion *or, MergeInfo *inf, Overlapping *ovlap, VipsRect *oreg )
{
	VipsRegion *rir = inf->rir;
	VipsRegion *sir = inf->sir;
	VipsImage *im = or->im;

	VipsRect prr, psr;
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
	if( vips_region_prepare( rir, &prr ) || 
		vips_region_prepare( sir, &psr ) )
		return( -1 );

	/* Loop down overlap area.
	 */
	for( y = oreg->top, yr = prr.top, ys = psr.top; 
		y < VIPS_RECT_BOTTOM( oreg ); y++, yr++, ys++ ) { 
		VipsPel *pr = VIPS_REGION_ADDR( rir, prr.left, yr );
		VipsPel *ps = VIPS_REGION_ADDR( sir, psr.left, ys );
		VipsPel *q = VIPS_REGION_ADDR( or, oreg->left, y );

		const int j = y - ovlap->overlap.top;
		const int first = ovlap->first[j];
		const int last = ovlap->last[j];
		const int bwidth = last - first;

		switch( im->BandFmt ) {
		case VIPS_FORMAT_UCHAR: 	
			iblend( unsigned char, im->Bands, pr, ps, q ); break; 
		case VIPS_FORMAT_CHAR: 	
			iblend( signed char, im->Bands, pr, ps, q ); break; 
		case VIPS_FORMAT_USHORT: 
			iblend( unsigned short, im->Bands, pr, ps, q ); break; 
		case VIPS_FORMAT_SHORT: 	
			iblend( signed short, im->Bands, pr, ps, q ); break; 
		case VIPS_FORMAT_UINT: 	
			iblend( unsigned int, im->Bands, pr, ps, q ); break; 
		case VIPS_FORMAT_INT: 	
			iblend( signed int, im->Bands, pr, ps, q );  break; 
		case VIPS_FORMAT_FLOAT: 	
			fblend( float, im->Bands, pr, ps, q ); break; 
		case VIPS_FORMAT_DOUBLE:	
			fblend( double, im->Bands, pr, ps, q ); break; 
		case VIPS_FORMAT_COMPLEX:
			fblend( float, im->Bands * 2, pr, ps, q ); break; 
		case VIPS_FORMAT_DPCOMPLEX:
			fblend( double, im->Bands * 2, pr, ps, q ); break;

		default:
			g_assert_not_reached();
			return( -1 );
		}
	}

	return( 0 );
}

/* Left-right blend function for VIPS_CODING_LABQ images.
 */
static int
lr_blend_labpack( VipsRegion *or, MergeInfo *inf, Overlapping *ovlap, 
	VipsRect *oreg )
{
	VipsRegion *rir = inf->rir;
	VipsRegion *sir = inf->sir;
	VipsRect prr, psr;
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
	if( vips_region_prepare( rir, &prr ) || 
		vips_region_prepare( sir, &psr ) )
		return( -1 );

	/* Loop down overlap area.
	 */
	for( y = oreg->top, yr = prr.top, ys = psr.top; 
		y < VIPS_RECT_BOTTOM( oreg ); y++, yr++, ys++ ) { 
		VipsPel *pr = VIPS_REGION_ADDR( rir, prr.left, yr );
		VipsPel *ps = VIPS_REGION_ADDR( sir, psr.left, ys );
		VipsPel *q = VIPS_REGION_ADDR( or, oreg->left, y );

		const int j = y - ovlap->overlap.top;
		const int first = ovlap->first[j];
		const int last = ovlap->last[j];
		const int bwidth = last - first;

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

static void
lock_free( VipsImage *image, GMutex *lock )
{
	VIPS_FREEF( vips_g_mutex_free, lock );
}

/* Build basic per-call state and do some geometry calculations. Shared with
 * tbmerge, so not static.
 */
Overlapping *
vips__build_mergestate( const char *domain,
	VipsImage *ref, VipsImage *sec, VipsImage *out, 
	int dx, int dy, int mwidth )
{
	VipsImage **t = (VipsImage **)
		vips_object_local_array( VIPS_OBJECT( out ), 4 );

	VipsImage **arry;
   	Overlapping *ovlap;
	int x;

	/* TODO(kleisauke): Copied from vips_insert, perhaps we
	 * need a separate function for this?
	 * (just like im__insert_base)
	 */
	if( vips_image_pio_input( ref ) ||
		vips_image_pio_input( sec ) ||
		vips_check_bands_1orn( domain, ref, sec ) ||
		vips_check_coding_known( domain, ref ) ||
		vips_check_coding_same( domain, ref, sec ) )
		return( NULL );

	/* Cast our input images up to a common format and bands.
	 */
	if( vips__formatalike( ref, sec, &t[0], &t[1] ) ||
		vips__bandalike( domain, t[0], t[1], &t[2], &t[3] ) )
		return( NULL );
	
	if( !(arry = vips_allocate_input_array( out,
		t[2], t[3], NULL )) )
		return( NULL );

	if( vips_image_pipeline_array( out,
		VIPS_DEMAND_STYLE_SMALLTILE, arry ) )
		return( NULL );

	if( mwidth < -1 ) {
		vips_error( domain, "%s", _( "mwidth must be -1 or >= 0" ) );
		return( NULL );
	}

	if( !(ovlap = VIPS_NEW( out, Overlapping )) )
		return( NULL );

	ovlap->ref = arry[0];
	ovlap->sec = arry[1];
	ovlap->out = out;
	ovlap->dx = dx;
	ovlap->dy = dy;
	ovlap->mwidth = mwidth;

	/* Area occupied by ref image. Place at (0,0) to start with.
	 */
   	ovlap->rarea.left = 0;
   	ovlap->rarea.top = 0;
   	ovlap->rarea.width = ovlap->ref->Xsize;
   	ovlap->rarea.height = ovlap->ref->Ysize;

	/* Area occupied by sec image. 
	 */
   	ovlap->sarea.left = -dx;
   	ovlap->sarea.top = -dy;
   	ovlap->sarea.width = ovlap->sec->Xsize;
   	ovlap->sarea.height = ovlap->sec->Ysize;

	/* Compute overlap. 
	 */
	vips_rect_intersectrect( &ovlap->rarea, &ovlap->sarea, &ovlap->overlap );
	if( vips_rect_isempty( &ovlap->overlap ) ) {
		vips_error( domain, "%s", _( "no overlap" ) );
		return( NULL );
	}

	/* Find position and size of output image.
	 */
	vips_rect_unionrect( &ovlap->rarea, &ovlap->sarea, &ovlap->oarea );

	/* Now: translate everything, so that the output image, not the left
	 * image, is at (0,0).
	 */
	ovlap->rarea.left -= ovlap->oarea.left;
	ovlap->rarea.top -= ovlap->oarea.top;
	ovlap->sarea.left -= ovlap->oarea.left;
	ovlap->sarea.top -= ovlap->oarea.top;
	ovlap->overlap.left -= ovlap->oarea.left;
	ovlap->overlap.top -= ovlap->oarea.top;
	ovlap->oarea.left = 0;
	ovlap->oarea.top = 0;

	/* Make sure blend luts are built.
	 */
	vips__make_blend_luts();
	
	/* Size of first/last cache. Could be either of these ... just pick
	 * the larger.
	 */
	ovlap->flsize = VIPS_MAX( ovlap->overlap.width, ovlap->overlap.height );

	/* Build first/last cache.
	 */
	ovlap->first = VIPS_ARRAY( out, ovlap->flsize, int );
	ovlap->last = VIPS_ARRAY( out, ovlap->flsize, int );
	if( !ovlap->first || !ovlap->last ) 
		return( NULL ); 
	for( x = 0; x < ovlap->flsize; x++ )
		ovlap->first[x] = -1;

	ovlap->fl_lock = vips_g_mutex_new();

	g_signal_connect( out, "close",
		G_CALLBACK( lock_free ), ovlap->fl_lock );

	return( ovlap );
}

/* Build per-call state.
 */
static Overlapping *
build_lrstate( VipsImage *ref, VipsImage *sec, VipsImage *out, 
	int dx, int dy, int mwidth )
{
   	Overlapping *ovlap;

	if( !(ovlap = vips__build_mergestate( "lrmerge", 
		ref, sec, out, dx, dy, mwidth )) )
		return( NULL );

	/* Select blender.
	 */
	switch( ovlap->ref->Coding ) {
	case VIPS_CODING_LABQ:
		ovlap->blend = lr_blend_labpack;
		break;

	case VIPS_CODING_NONE:
		ovlap->blend = lr_blend;
		break;

	default:
		vips_error( "lrmerge", "%s", _( "unknown coding type" ) );
		return( NULL );
	}

	/* Find the parts of output which come just from ref and just from sec.
	 */
	ovlap->rpart = ovlap->rarea;
	ovlap->spart = ovlap->sarea;
	ovlap->rpart.width -= ovlap->overlap.width;
	ovlap->spart.left += ovlap->overlap.width;
	ovlap->spart.width -= ovlap->overlap.width;

	/* Is there too much overlap? ie. right edge of ref image is greater
	 * than right edge of sec image, or left > left.
	 */
	if( VIPS_RECT_RIGHT( &ovlap->rarea ) > 
		VIPS_RECT_RIGHT( &ovlap->sarea ) ||
		ovlap->rarea.left > ovlap->sarea.left ) {
		vips_error( "lrmerge", "%s", _( "too much overlap" ) );
		return( NULL );
	}

	/* Max number of pixels we may have to blend over.
	 */
	ovlap->blsize = ovlap->overlap.width;

	return( ovlap );
}

/* The area being demanded can be filled using only pels from either the ref 
 * or the sec images. Attach output to the appropriate part of the input image. 
 * area is the position that ir->im occupies in the output image.
 *
 * Shared with tbmerge, so not static.
 */
int
vips__attach_input( VipsRegion *or, VipsRegion *ir, VipsRect *area )
{
	VipsRect r = or->valid;

	/* Translate to source coordinate space.
	 */
	r.left -= area->left;
	r.top -= area->top;

	/* Demand input.
	 */
	if( vips_region_prepare( ir, &r ) )
		return( -1 );

	/* Attach or to ir.
	 */
	if( vips_region_region( or, ir, &or->valid, r.left, r.top ) )
		 return( -1 );

	return( 0 );
}

/* The area being demanded requires pixels from the ref and sec images. As 
 * above, but just do a sub-area of the output, and make sure we copy rather 
 * than just pointer-fiddling. reg is the sub-area of or->valid we should do.
 *
 * Shared with tbmerge, so not static.
 */
int
vips__copy_input( VipsRegion *or, VipsRegion *ir, 
	VipsRect *area, VipsRect *reg )
{
	VipsRect r = *reg;

	/* Translate to source coordinate space.
	 */
	r.left -= area->left;
	r.top -= area->top;

	/* Paint this area of ir into or.
	 */
	if( vips_region_prepare_to( ir, or, &r, reg->left, reg->top ) )
		return( -1 );

	return( 0 );
}

/* Generate function for merge. This is shared between lrmerge and
 * tbmerge.
 */
int
vips__merge_gen( VipsRegion *or, void *seq, void *a, void *b, 
	gboolean *stop )
{
	MergeInfo *inf = (MergeInfo *) seq;
	Overlapping *ovlap = (Overlapping *) a;
	VipsRect *r = &or->valid;
	VipsRect rreg, sreg, oreg;

	/* Find intersection with overlap, ref and sec parts. 
	 */
	vips_rect_intersectrect( r, &ovlap->rpart, &rreg );
	vips_rect_intersectrect( r, &ovlap->spart, &sreg );

	/* Do easy cases first: can we satisfy this demand with pixels just 
	 * from ref, or just from sec.
	 */
	if( vips_rect_equalsrect( r, &rreg ) ) {
		if( vips__attach_input( or, inf->rir, &ovlap->rarea ) )
			return( -1 );
	}
	else if( vips_rect_equalsrect( r, &sreg ) ) {
		if( vips__attach_input( or, inf->sir, &ovlap->sarea ) )
			return( -1 );
	}
	else {
		/* Difficult case - do in three stages: black out whole area, 
		 * copy in parts of ref and sec we touch, write blend area. 
		 * This could be sped up somewhat ... we will usually black 
		 * out far too much, and write to the blend area three times. 
		 * Upgrade in the future!
		 */

		/* Need intersections with whole of left & right, and overlap
		 * too.
		 */
		vips_rect_intersectrect( r, &ovlap->rarea, &rreg );
		vips_rect_intersectrect( r, &ovlap->sarea, &sreg );
		vips_rect_intersectrect( r, &ovlap->overlap, &oreg );

		vips_region_black( or );
		if( !vips_rect_isempty( &rreg ) ) 
			if( vips__copy_input( or, 
				inf->rir, &ovlap->rarea, &rreg ) )
				return( -1 );
		if( !vips_rect_isempty( &sreg ) )
			if( vips__copy_input( or, 
				inf->sir, &ovlap->sarea, &sreg ) )
				return( -1 );

		/* Nasty: inf->rir and inf->sir now point to the same bit of
		 * memory (part of or), and we've written twice. We need to
		 * make sure we get fresh pixels for the blend, so we must
		 * invalidate them both. Should maybe add a call to the API
		 * for this.
		 */
		inf->rir->valid.width = inf->sir->valid.width = 0;

		/* Now blat in the blended area.
		 */
		if( !vips_rect_isempty( &oreg ) )
			if( ovlap->blend( or, inf, ovlap, &oreg ) )
				return( -1 );
	}

	return( 0 );
}

/* Stop function. Shared with tbmerge. Free explicitly to reduce mem
 * requirements quickly for large mosaics.
 */
int
vips__stop_merge( void *seq, void *a, void *b )
{
	MergeInfo *inf = (MergeInfo *) seq;

	VIPS_UNREF( inf->rir );
	VIPS_UNREF( inf->sir );
	VIPS_FREE( inf->from1 );
	VIPS_FREE( inf->from2 );
	VIPS_FREE( inf->merge );
	g_free( inf );

	return( 0 );
}

/* Start function. Shared with tbmerge.
 */
void *
vips__start_merge( VipsImage *out, void *a, void *b )
{
	Overlapping *ovlap = (Overlapping *) a;
	MergeInfo *inf;

	if( !(inf = VIPS_NEW( NULL, MergeInfo )) )
		return( NULL );

	inf->rir = NULL;
	inf->sir = NULL;
	inf->from1 = NULL;
	inf->from2 = NULL;
	inf->merge = NULL;

	/* If this is going to be a VIPS_CODING_LABQ, we need VIPS_CODING_LABQ 
	 * blend buffers.
	 */
	if( out->Coding == VIPS_CODING_LABQ ) {
		inf->from1 = VIPS_ARRAY( NULL, ovlap->blsize * 3, float );
		inf->from2 = VIPS_ARRAY( NULL, ovlap->blsize * 3, float );
		inf->merge = VIPS_ARRAY( NULL, ovlap->blsize * 3, float );
		if( !inf->from1 || !inf->from2 || !inf->merge ) {
			vips__stop_merge( inf, NULL, NULL );
			return( NULL ); 
		}
	}

	inf->rir = vips_region_new( ovlap->ref );
	inf->sir = vips_region_new( ovlap->sec );

	if( !inf->rir || !inf->sir ) {
		vips__stop_merge( inf, NULL, NULL );
		return( NULL );
	}

	return( inf );
}

int
vips__lrmerge( VipsImage *ref, VipsImage *sec, VipsImage *out, 
	int dx, int dy, int mwidth )
{
	Overlapping *ovlap;

#ifdef DEBUG
	printf( "lrmerge %s %s %s %d %d %d\n", 
		ref->filename, sec->filename, out->filename, 
		dx, dy, mwidth );
	printf( "ref is %d x %d pixels\n", ref->Xsize, ref->Ysize );
	printf( "sec is %d x %d pixels\n", sec->Xsize, sec->Ysize );
#endif

	if( dx > 0 || dx < 1 - ref->Xsize ) {
		VipsImage *x;

#ifdef DEBUG
		printf( "lrmerge: no overlap, using insert\n" ); 
#endif

		/* No overlap, use insert instead.
		 */
  		if( vips_insert( ref, sec, &x, -dx, -dy,
  			"expand", TRUE,
			NULL ) )
			return( -1 );
		if( vips_image_write( x, out ) ) {
			g_object_unref( x );
			return( -1 );
		}
		g_object_unref( x );

		out->Xoffset = -dx;
		out->Yoffset = -dy;

		return( 0 );
	}

	if( !(ovlap = build_lrstate( ref, sec, out, dx, dy, mwidth )) )
		return( -1 );

	if( vips_image_pipelinev( out,
		VIPS_DEMAND_STYLE_THINSTRIP, ovlap->ref, ovlap->sec, NULL ) )
		return( -1 );

	out->Xsize = ovlap->oarea.width;
	out->Ysize = ovlap->oarea.height;
	out->Xoffset = -dx;
	out->Yoffset = -dy;

	if( vips_image_generate( out,
		vips__start_merge, vips__merge_gen, vips__stop_merge, 
		ovlap, NULL ) )
		return( -1 );

	return ( 0 );
}

const char *
vips__get_mosaic_name( VipsImage *image )
{
	const char *name;

	if( vips_image_get_typeof( image, "mosaic-name" ) ) {
		if( vips_image_get_string( image, "mosaic-name", &name ) )
			return( NULL );
	}
	else 
		name = image->filename;

	return( name ); 
}

void
vips__add_mosaic_name( VipsImage *image )
{
	static int global_serial = 0;

	/* TODO(kleisauke): Could we call vips_image_temp_name instead?
	 */
	int serial = g_atomic_int_add( &global_serial, 1 );

	char name[256];

	/* We must override any inherited name, so don't test for doesn't
	 * exist before setting.
	 */
	vips_snprintf( name, 256, "mosaic-temp-%d", serial );
	vips_image_set_string( image, "mosaic-name", name );
}

