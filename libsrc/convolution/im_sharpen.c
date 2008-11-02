/* Cored sharpen of LABQ image.
 * 
 * Usage:
 *
 *   	int im_sharpen( IMAGE *in, IMAGE *out, 
 *		int mask_size, 
 *		int x1, int x2,
 *		double m1, double m2 )
 *
 * Returns 0 on success and -1 on error
 *
 * Copyright: 1995 A. Abbood 
 * Author: A. Abbood
 * Written on: 30/01/1995
 * 15/5/95 JC
 *	- updated for latest 7.3 mods
 *	- m3 parameter removed
 *	- bug fixes and speed-ups
 * 4/7/95 JC
 *	- x3 parameter added
 *	- xs are now double
 * 6/7/95 JC
 *	- xs are now ys
 *	- better LUT generation
 * 12/3/01 JC
 *	- uses seperable convolution for umask
 *	- tiny clean ups
 * 23/7/01 JC
 *	- fix for band extract index changed
 * 21/4/04
 *	- switched to gaussian mask and radius
 * 20/11/04 
 *	- uses extract_bands() to remove and reattach ab for slight speedup
 *	- accepts LabS as well as LabQ for slight speedup
 *	- small code tidies
 *	- ~15% speed up in total
 * 29/11/06
 * 	- convolve first to help region sharing
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

/* A lut --- we need indexes in the range [-x3,x2], so add x3 to indexes
 * before starting to index table.
 */
typedef struct {
	int *lut;		/* Start of lut */
	int x1, x2, x3;		/* Parameters scaled up to int */
} SharpenLut;

/* Make a lut.
 */
static SharpenLut *
build_lut( IMAGE *out, int x1, int x2, int x3, double m1, double m2 )
{
	int i;
	SharpenLut *slut = IM_NEW( out, SharpenLut );

	if( !slut )
		return( NULL );

	if( !(slut->lut = IM_ARRAY( out, x2 + x3 + 1, int )) )
		return( NULL );
	slut->x1 = x1;
	slut->x2 = x2;
	slut->x3 = x3;

	for( i = 0; i < x1; i++ ) {
		slut->lut[x3 + i] = i*m1;
		slut->lut[x3 - i] = -i*m1;
	}
	for( i = x1; i <= x2; i++ ) 
		slut->lut[x3 + i] = x1*m1 + (i-x1)*m2; 
	for( i = x1; i <= x3; i++ )
		slut->lut[x3 - i] = -(x1*m1 + (i-x1)*m2);

	return( slut );
}

/* Take the difference of in1 and in2 and LUT it.
 */
static void
buf_difflut( short **in, short *out, int n, SharpenLut *slut )
{
	int range = slut->x2 + slut->x3;
	int *lut = slut->lut;
	int x3 = slut->x3;
	short *p1 = in[1];
	short *p2 = in[0];
	int i;

	for( i = 0; i < n; i++ ) {
		int v1 = p1[i];
		int v2 = p2[i];

		/* v2 is the area average. If this is zero, then we pass the
		 * original image through unaltered.
		 */
		if( v2 == 0 ) 
			out[i] = v1;
		else {
			/* Find difference. Offset by x3 to get the expected 
			 * range of values.
			 */
			int s1 = x3 + (v1 - v2);
			int s2;

			/* Clip to LUT range.
			 */
			if( s1 < 0 )
				s1 = 0;
			else if( s1 > range )
				s1 = range;

			/* Transform!
			 */
			s2 = v1 + lut[s1];

			/* Clip to LabS range.
			 */
			if( s2 < 0 ) 
				s2 = 0;
			else if( s2 > 32767 ) 
				s2 = 32767;

			/* And write.
			 */
			out[i] = s2;
		}
	}
}

/* Make a 1 line gaussian of a specified radius.
 */
static INTMASK *
sharpen_mask_new( int radius )
{
	INTMASK *base;
	INTMASK *line;
	int total;
	int i;

	/* Stop at 20% of max ... bit mean, but means mask radius is roughly
	 * right.
	 */
	if( !(base = im_gauss_imask( "big1", radius / 2, 0.2 )) ) 
		return( NULL );

	if( !(line = im_create_imask( "sharpen-line", base->xsize, 1 )) ) {
		im_free_imask( base );
		return( NULL );
	}

	total = 0;
	for( i = 0; i < base->xsize; i++ ) {
		line->coeff[i] = 
			base->coeff[base->xsize * (base->ysize / 2) + i];
		total += line->coeff[i];
	}
	line->scale = total;

	im_free_imask( base );

#ifdef DEBUG
	printf( "sharpen_mask_new: created mask:\n" );
	im_print_imask( line );
#endif /*DEBUG*/

	return( line );
}

int
im_sharpen( IMAGE *in, IMAGE *out, 
	int mask_size, 
	double x1, double y2, double y3, 
	double m1, double m2 )
{ 
	IMAGE *arry[3];
	IMAGE *t[4];
	INTMASK *mask;
	SharpenLut *slut;

	/* Turn y parameters into xs.
	 */
	double x2 = (y2 - x1 * (m1 - m2)) / m2;
	double x3 = (y3 - x1 * (m1 - m2)) / m2;

	if( in->Coding == IM_CODING_LABQ ) {
		IMAGE *tc[2];

		if( im_open_local_array( out, tc, 2, "im_sharpen:1", "p" ) ||
			im_LabQ2LabS( in, tc[0] ) ||
			im_sharpen( tc[0], tc[1], 
				mask_size, x1, y2, y3, m1, m2 ) ||
			im_LabS2LabQ( tc[1], out ) )
			return( -1 );

		return( 0 );
	}

	/* Check IMAGE parameters 
	 */
	if( in->Coding != IM_CODING_NONE ||
		in->Bands != 3 || 
		in->BandFmt != IM_BANDFMT_SHORT ) {
		im_error( "im_sharpen", "%s", _( "input not 3-band short" ) );
	  	return( -1 );
  	}

  	if( im_piocheck( in, out ) )
  		return( -1 );

	/* Check number range.
	 */
	if( x1 < 0 || x2 < 0 || x1 > 99 || x2 > 99 || x1 > x2 ||
		x3 < 0 || x3 > 99 || x1 > x3 ) {
		im_error( "im_sharpen", "%s", _( "parameters out of range" ) );
		return( -1 );
	}

	/* Set up data structures we need. First, the convolution mask we will
	 * use.
	 */
	if( !(mask = (INTMASK *) im_local( out, 
		(im_construct_fn) sharpen_mask_new,
		(im_callback_fn) im_free_imask,
		GINT_TO_POINTER( mask_size ), NULL, NULL )) )
		return( -1 );

	/* Make the lut we will use. We need to scale up x1, x2, x3 to the
	 * LabS range.
	 */
	if( !(slut = build_lut( out, 
		x1 * 327.67, x2 * 327.67, x3 * 327.67, m1, m2 )) )
		return( -1 );

	/* Open a set of local image descriptors.
	 */
	if( im_open_local_array( out, t, 4, "im_sharpen:2", "p" ) )
		return( -1 );

	/* Extract L and ab, convolve L.
	 */
	if( im_extract_band( in, t[0], 0 ) ||
		im_extract_bands( in, t[1], 1, 2 ) ||
		im_convsep( t[0], t[2], mask ) )
		return( -1 );

	/* Find difference of L channel and convolved L channel, and pass
	 * through LUT.
	 */
	if( im_cp_desc( t[3], t[2] ) )
		return( -1 );
	arry[0] = t[2]; arry[1] = t[0]; arry[2] = NULL;
	if( im_wrapmany( arry, t[3],
		(im_wrapmany_fn) buf_difflut, slut, NULL ) )
		return( -1 );

	/* Reattach ab.
	 */
	if( im_bandjoin( t[3], t[1], out ) )
		return( -1 );

	return( 0 );
}
