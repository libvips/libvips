/* im_spcor
 *
 * Copyright: 1990, N. Dessipris; 2006, 2007 Nottingham Trent University.
 *
 *
 * Author: Nicos Dessipris
 * Written on: 02/05/1990
 * Modified on : 
 * 20/2/95 JC
 *	- updated
 *	- ANSIfied, a little
 * 21/2/95 JC
 *	- rewritten
 *	- partialed 
 *	- speed-ups
 *	- new correlation coefficient (see above), from Niblack "An
 *	  Introduction to Digital Image Processing", Prentice/Hall, pp 138.
 * 4/9/97 JC
 *	- now does short/ushort as well
 * 13/2/03 JC
 *	- oops, could segv for short images
 * 14/4/04 JC
 *	- sets Xoffset / Yoffset
 * 8/3/06 JC
 *	- use im_embed() with edge stretching on the input, not the output
 *
 * 2006-10-24 tcv
 *      - add im_spcor2
 *
 * 2007-11-12 tcv
 *      - make im_spcor a wrapper selecting either im__spcor or im__spcor2
 * 2008-09-09 JC
 * 	- roll back the windowed version for now, it has some tile edge effects
 * 3/2/10
 * 	- gtkdoc
 * 	- cleanups
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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <math.h>

#include <vips/vips.h>

/* Hold per-call state here.
 */
typedef struct {
	IMAGE *ref;		/* Image we are searching for */
	double rmean;		/* Mean of search window */
	double c1;		/* sqrt(sumij (ref(i,j)-mean(ref))^2) */
} Spcor;

#define LOOP( IN ) { \
	IN *a = (IN *) p; \
	IN *b = (IN *) ref->data; \
	int in_lsk = lsk / sizeof( IN ); \
	IN *a1; \
	IN *b1; \
 	\
	/* For each pel in or, loop over ref. First, \
	 * calculate mean of area in ir corresponding to ref. \
	 */ \
	a1 = a; \
	sum1 = 0; \
	for( j = 0; j < ref->Ysize; j++ ) { \
		for( i = 0; i < ref->Xsize; i++ ) \
			sum1 += a1[i]; \
		a1 += in_lsk;  \
	} \
	imean = sum1 / VIPS_IMAGE_N_PELS( ref ); \
 	\
	/* Loop over ir again, this time calculating  \
	 * sum-of-squares-of-differences for this window on \
	 * ir, and also sum-of-products-of-differences from mean. \
	 */ \
	a1 = a; \
	b1 = b; \
	sum2 = 0.0; \
	sum3 = 0.0; \
	for( j = 0; j < ref->Ysize; j++ ) { \
		for( i = 0; i < ref->Xsize; i++ ) { \
			/* Reference pel, and input pel. \
			 */ \
			IN rp = b1[i]; \
			IN ip = a1[i]; \
			\
			/* Accumulate sum-of-squares-of- \
			 * differences for input image. \
			 */ \
			double t = ip - imean; \
			sum2 += t * t; \
			\
			/* Accumulate product-of-difference from mean. \
			 */ \
			sum3 += (rp - spcor->rmean) * (ip - imean); \
		} \
		a1 += in_lsk; \
		b1 += ref->Xsize; \
	} \
}

/* spcor generate function.
 */
static int
spcor_gen( REGION *or, void *vseq, void *a, void *b )
{
	REGION *ir = (REGION *) vseq;
	Spcor *spcor = (Spcor *) b;
	IMAGE *ref = spcor->ref;
	Rect irect;
	Rect *r = &or->valid;
	int le = r->left;
	int to = r->top;
	int bo = IM_RECT_BOTTOM( r );
	int ri = IM_RECT_RIGHT( r );

	int x, y, i, j;
	int lsk;

	double imean;
	double sum1;
	double sum2, sum3;
	double c2, cc;

	/* What part of ir do we need?
	 */
	irect.left = or->valid.left;
	irect.top = or->valid.top;
	irect.width = or->valid.width + ref->Xsize - 1;
	irect.height = or->valid.height + ref->Ysize - 1;

	if( im_prepare( ir, &irect ) )
		return( -1 );
	lsk = IM_REGION_LSKIP( ir );

	/* Loop over or.
	 */
	for( y = to; y < bo; y++ ) {
		float *q = (float *) IM_REGION_ADDR( or, le, y );

		for( x = le; x < ri; x++ ) {
			VipsPel *p = IM_REGION_ADDR( ir, x, y );

			/* Find sums for this position.
			 */
			switch( ref->BandFmt ) {
			case IM_BANDFMT_UCHAR:	LOOP(unsigned char); break;
			case IM_BANDFMT_CHAR:	LOOP(signed char); break;
			case IM_BANDFMT_USHORT: LOOP(unsigned short); break;
			case IM_BANDFMT_SHORT:	LOOP(signed short); break;
			default:
				g_assert( 0 );
			}

			/* Now: calculate correlation coefficient!
			 */
			c2 = sqrt( sum2 );
			cc = sum3 / (spcor->c1 * c2);

			*q++ = cc;
		}
	}

	return( 0 );
}

/* Pre-calculate stuff for our reference image.
 */
static Spcor *
spcor_new( IMAGE *out, IMAGE *ref )
{
	Spcor *spcor;
	guint64 sz = VIPS_IMAGE_N_PELS( ref );
	VipsPel *p = ref->data;
	double s;
	size_t i;

	if( !(spcor = IM_NEW( out, Spcor )) )
		return( NULL );

	/* Pre-calculate stuff on our reference image.
	 */
	spcor->ref = ref;
	if( im_avg( spcor->ref, &spcor->rmean ) )
		return( NULL );

	/* Find sqrt-of-sum-of-squares-of-differences.
	 */
	s = 0.0;
	for( i = 0; i < sz; i++ ) {
		double t = (int) p[i] - spcor->rmean;
		s += t * t;
	}
	spcor->c1 = sqrt( s );

	return( spcor );
}

int 
im_spcor_raw( IMAGE *in, IMAGE *ref, IMAGE *out )
{
	Spcor *spcor;

	/* PIO between in and out; WIO from ref, since it's probably tiny.
	 */
	if( im_piocheck( in, out ) || 
		im_incheck( ref ) )
		return( -1 );

	/* Check sizes.
	 */
	if( in->Xsize < ref->Xsize || 
		in->Ysize < ref->Ysize ) {
		im_error( "im_spcor_raw", 
			"%s", _( "ref not smaller than or equal to in" ) );
		return( -1 );
	}

	/* Check types.
	 */
	if( im_check_uncoded( "im_spcor", in ) ||
		im_check_mono( "im_spcor", in ) || 
		im_check_8or16( "im_spcor", in ) ||
		im_check_coding_same( "im_spcor", in, ref ) ||
		im_check_bands_same( "im_spcor", in, ref ) || 
		im_check_format_same( "im_spcor", in, ref ) )
		return( -1 );

	/* Prepare the output image. 
	 */
	if( im_cp_descv( out, in, ref, NULL ) )
		return( -1 );
	out->BandFmt = IM_BANDFMT_FLOAT;
	out->Xsize = in->Xsize - ref->Xsize + 1;
	out->Ysize = in->Ysize - ref->Ysize + 1;

	/* Pre-calculate some stuff.
	 */
	if( !(spcor = spcor_new( out, ref )) )
		return( -1 );

	/* Set demand hints. FATSTRIP is good for us, as THINSTRIP will cause
	 * too many recalculations on overlaps.
	 */
	if( im_demand_hint( out, IM_FATSTRIP, in, NULL ) )
		return( -1 );

	/* Write the correlation.
	 */
	if( im_generate( out,
		im_start_one, spcor_gen, im_stop_one, in, spcor ) )
		return( -1 );

	out->Xoffset = -ref->Xsize / 2;
	out->Yoffset = -ref->Ysize / 2;

	return( 0 );
}

/**
 * im_spcor:
 * @in: input image
 * @ref: reference image
 * @out: output image
 *
 * Calculate a correlation surface.
 *
 * @ref is placed at every position in @in and the correlation coefficient
 * calculated. One-band, 8 or 16-bit images only. @in and @ref must have the
 * same #VipsBandFmt. The output
 * image is always %IM_BANDFMT_FLOAT. @ref must be smaller than or equal to 
 * @in. The output
 * image is the same size as the input. 
 *
 * The correlation coefficient is calculated as:
 *
 * |[
 *          sumij (ref(i,j)-mean(ref))(inkl(i,j)-mean(inkl))
 * c(k,l) = ------------------------------------------------
 *          sqrt(sumij (ref(i,j)-mean(ref))^2) *
 *                      sqrt(sumij (inkl(i,j)-mean(inkl))^2)
 * ]|
 *
 * where inkl is the area of @in centred at position (k,l).
 *
 * from Niblack "An Introduction to Digital Image Processing", 
 * Prentice/Hall, pp 138.
 *
 * See also: im_gradcor(), im_fastcor().
 *
 * Returns: 0 on success, -1 on error
 */
int
im_spcor( IMAGE *in, IMAGE *ref, IMAGE *out )
{
	IMAGE *t1 = im_open_local( out, "im_spcor intermediate", "p" );

	if( !t1 ||
		im_embed( in, t1, 1, 
			ref->Xsize / 2, ref->Ysize / 2, 
			in->Xsize + ref->Xsize - 1, 
			in->Ysize + ref->Ysize - 1 ) ||
		im_spcor_raw( t1, ref, out ) ) 
		return( -1 );

	out->Xoffset = 0;
	out->Yoffset = 0;

	return( 0 );
}

