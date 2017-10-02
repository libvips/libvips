/* composite an array of images with PDF operators
 *
 * 25/9/17
 * 	- from bandjoin.c
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

/*
#define VIPS_DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>

#include <vips/vips.h>
#include <vips/internal.h>
#include <vips/debug.h>

#include "pconversion.h"

/* Maximum number of input images -- why not?
 */
#define MAX_INPUT_IMAGES (64)

/* Maximum number of image bands.
 */
#define MAX_BANDS (64)

/**
 * VipsBlendMode:
 * VIPS_BLEND_MODE_CLEAR:
 * VIPS_BLEND_MODE_SOURCE:
 * VIPS_BLEND_MODE_OVER:
 * VIPS_BLEND_MODE_IN:
 * VIPS_BLEND_MODE_OUT:
 * VIPS_BLEND_MODE_ATOP:
 * VIPS_BLEND_MODE_DEST:
 * VIPS_BLEND_MODE_DEST_OVER:
 * VIPS_BLEND_MODE_DEST_IN:
 * VIPS_BLEND_MODE_DEST_OUT:
 * VIPS_BLEND_MODE_DEST_ATOP:
 * VIPS_BLEND_MODE_XOR:
 * VIPS_BLEND_MODE_ADD:
 * VIPS_BLEND_MODE_SATURATE:
 * VIPS_BLEND_MODE_MULTIPLY:
 * VIPS_BLEND_MODE_SCREEN:
 * VIPS_BLEND_MODE_OVERLAY:
 * VIPS_BLEND_MODE_DARKEN:
 * VIPS_BLEND_MODE_LIGHTEN:
 * VIPS_BLEND_MODE_COLOUR_DODGE:
 * VIPS_BLEND_MODE_COLOUR_BURN:
 * VIPS_BLEND_MODE_HARD_LIGHT:
 * VIPS_BLEND_MODE_SOFT_LIGHT:
 * VIPS_BLEND_MODE_DIFFERENCE:
 * VIPS_BLEND_MODE_EXCLUSION:
 *
 * The various Porter-Duff and PDF blend modes. See vips_composite(), 
 * for example.
 *
 * The PDF blend modes (MULTPLY onwards) require channels all in [0, 1], so 
 * they only work for spaces like RGB where all channels have the same range.
 */

/* References:
 *
 * @gasi's composite example https://gist.github.com/jcupitt/abacc012e2991f332e8b
 *
 * https://en.wikipedia.org/wiki/Alpha_compositing
 *
 * https://www.cairographics.org/operators/
 *
 * Benchmark:
 *
 * vips replicate PNG_transparency_demonstration_1.png x.png 15 15
 * vips crop x.png wtc_overlay.png 0 0 9372 9372
 *
 * composite -compose over wtc_overlay.png.png wtc.jpg x.jpg
 *
 * vips composite "wtc_overlay.png wtc.jpg" x.jpg 2
 *
 * convert -compose over -composite wtc.jpg wtc_overlay.png x.jpg
 *
 */

typedef struct _VipsComposite {
	VipsConversion parent_instance;

	/* The input images.
	 */
	VipsArrayImage *in;

	/* For N input images, N - 1 blend modes.
	 */
	VipsArrayInt *mode;

	/* Compositing space. This defaults to RGB, or B_W if we only have
	 * G and GA inputs.
	 */
	VipsInterpretation compositing_space;

	/* Set if the input images have already been premultiplied.
	 */
	gboolean premultiplied;

	/* The number of inputs. This can be less than the number of images in
	 * @in.
	 */
	int n;

	/* The number of bands we are blending.
	 */
	int bands;

} VipsComposite;

typedef VipsConversionClass VipsCompositeClass;

/* We need C linkage for this.
 */
extern "C" {
G_DEFINE_TYPE( VipsComposite, vips_composite, VIPS_TYPE_CONVERSION );
}

/* Cairo naming conventions:
 *
 * aR	alpha of result
 * aA	alpha of source A	(the new pixel)
 * aB	alpha of source B	(the thing we accumulate)
 * xR	colour channel of result
 * xA	colour channel of source A
 * xB	colour channel of source B
 */

static double inline
vips_composite_alpha( VipsBlendMode mode, double aA, double aB )
{
	double aR;

	switch( mode ) {
	/* CLEAR and SOURCE are bounded operators and don't really make sense
	 * here, since we are always unbounded. Replace them with something
	 * similar that uses alpha.
	 */
	case VIPS_BLEND_MODE_CLEAR:
		aR = 1 - aA;
		break;

	case VIPS_BLEND_MODE_SOURCE:
		aR = aA;
		break;

	case VIPS_BLEND_MODE_OVER:
		aR = aA + aB * (1.0 - aA);
		break;

	case VIPS_BLEND_MODE_IN:
		aR = aA * aB;
		break;

	case VIPS_BLEND_MODE_OUT:
		aR = aA * (1 - aB);
		break;

	case VIPS_BLEND_MODE_ATOP:
		aR = aB;
		break;

	case VIPS_BLEND_MODE_DEST:
		aR = aB;
		break;

	case VIPS_BLEND_MODE_DEST_OVER:
		aR = aB + aA * (1.0 - aB);
		break;

	case VIPS_BLEND_MODE_DEST_IN:
		aR = aA * aB;
		break;

	case VIPS_BLEND_MODE_DEST_OUT:
		aR = (1 - aA) * aB;
		break;

	case VIPS_BLEND_MODE_DEST_ATOP:
		aR = aA;
		break;

	case VIPS_BLEND_MODE_XOR:
		aR = aA + aB - 2 * aA * aB;
		break;

	case VIPS_BLEND_MODE_ADD:
		aR = VIPS_MIN( 1, aA + aB );
		break;

	case VIPS_BLEND_MODE_SATURATE:
		aR = VIPS_MIN( 1, aA + aB );
		break;

	case VIPS_BLEND_MODE_MULTIPLY:
	case VIPS_BLEND_MODE_SCREEN:
	case VIPS_BLEND_MODE_OVERLAY:
	case VIPS_BLEND_MODE_DARKEN:
	case VIPS_BLEND_MODE_LIGHTEN:
	case VIPS_BLEND_MODE_COLOUR_DODGE:
	case VIPS_BLEND_MODE_COLOUR_BURN:
	case VIPS_BLEND_MODE_HARD_LIGHT:
	case VIPS_BLEND_MODE_SOFT_LIGHT:
	case VIPS_BLEND_MODE_DIFFERENCE:
	case VIPS_BLEND_MODE_EXCLUSION:
		/* All the PDF modes have the same alpha function.
		 */
		aR = aA + aB * (1.0 - aA);
		break;

	default:
		 aR = 0;
		 g_assert_not_reached();
	}

	return( aR );
}

/* A is the new pixel coming in, B is the double pixel we are accumulating.
 */
template <typename T>
static void
vips_composite_blend_mul( VipsBlendMode mode,
	double * restrict B, T * restrict A, int bands ) 
{
	double aA;
	double aB;
	double aR;
	double t1;
	double t2;
	double t3;
	double f[MAX_BANDS + 1];
	int b;

	aA = A[bands];
	aB = B[bands];
	aR = vips_composite_alpha( mode, aA, aB );

	switch( mode ) {
	case VIPS_BLEND_MODE_CLEAR:
		for( b = 0; b < bands; b++ )
			B[b] = 1 - aA;
		break;

	case VIPS_BLEND_MODE_SOURCE:
		for( b = 0; b < bands; b++ )
			B[b] = A[b];
		break;

	case VIPS_BLEND_MODE_OVER:
		if( aR == 0 ) {
			for( b = 0; b < bands; b++ )
				B[b] = 0;
		}
		else {
			t1 = aB * (1 - aA);
			for( b = 0; b < bands; b++ )
				B[b] = (aA * A[b] + t1 * B[b]) / aR;
		}
		break;

	case VIPS_BLEND_MODE_IN:
		for( b = 0; b < bands; b++ )
			B[b] = A[b];
		break;

	case VIPS_BLEND_MODE_OUT:
		for( b = 0; b < bands; b++ )
			B[b] = A[b];
		break;

	case VIPS_BLEND_MODE_ATOP:
		for( b = 0; b < bands; b++ )
			B[b] = A[b] * aA + B[b] * (1 - aA);
		break;

	case VIPS_BLEND_MODE_DEST:
		// B = B
		break;

	case VIPS_BLEND_MODE_DEST_OVER:
		if( aR == 0 ) {
			for( b = 0; b < bands; b++ )
				B[b] = 0;
		}
		else {
			t1 = aA * (1 - aB);
			for( b = 0; b < bands; b++ )
				B[b] = (aB * B[b] + t1 * A[b]) / aR;
		}
		break;

	case VIPS_BLEND_MODE_DEST_IN:
		// B = B
		break;

	case VIPS_BLEND_MODE_DEST_OUT:
		// B = B
		break;

	case VIPS_BLEND_MODE_DEST_ATOP:
		for( b = 0; b < bands; b++ )
			B[b] = A[b] * (1 - aB) + B[b] * aB;
		break;

	case VIPS_BLEND_MODE_XOR:
		if( aR == 0 ) {
			for( b = 0; b < bands; b++ )
				B[b] = 0;
		}
		else {
			t1 = aA * (1 - aB);
			t2 = aB * (1 - aA);
			for( b = 0; b < bands; b++ )
				B[b] = (t1 * A[b] + t2 * B[b]) / aR;
		}
		break;

	case VIPS_BLEND_MODE_ADD:
		if( aR == 0 ) {
			for( b = 0; b < bands; b++ )
				B[b] = 0;
		}
		else {
			for( b = 0; b < bands; b++ )
				B[b] = (A[b] * aA + B[b] * aB) / aR;
		}
		break;

	case VIPS_BLEND_MODE_SATURATE:
		if( aR == 0 ) {
			for( b = 0; b < bands; b++ )
				B[b] = 0;
		}
		else {
			t1 = VIPS_MIN( aA, 1 - aB );
			for( b = 0; b < bands; b++ )
				B[b] = (t1 * A[b] + B[b] * aB) / aR;
		}
		break;

	default:
		/* The PDF modes are a bit different.
		 */
		t1 = (1 - aB) * aA;
		t2 = (1 - aA) * aB;
		t3 = aA * aB;

		switch( mode ) {
		case VIPS_BLEND_MODE_MULTIPLY:
			for( b = 0; b < bands; b++ ) 
				f[b] = A[b] * B[b];
			break;

		case VIPS_BLEND_MODE_SCREEN:
			for( b = 0; b < bands; b++ ) 
				f[b] = A[b] + B[b] - A[b] * B[b];
			break;

		case VIPS_BLEND_MODE_OVERLAY:
			for( b = 0; b < bands; b++ ) 
				if( B[b] <= 0.5 ) 
					f[b] = 2 * A[b] * B[b];
				else 
					f[b] = 1 - 2 * (1 - A[b]) * (1 - B[b]);
			break;

		case VIPS_BLEND_MODE_DARKEN:
			for( b = 0; b < bands; b++ ) 
				f[b] = VIPS_MIN( A[b], B[b] );
			break;

		case VIPS_BLEND_MODE_LIGHTEN:
			for( b = 0; b < bands; b++ ) 
				f[b] = VIPS_MAX( A[b], B[b] );
			break;

		case VIPS_BLEND_MODE_COLOUR_DODGE:
			for( b = 0; b < bands; b++ ) 
				if( A[b] < 1 ) 
					f[b] = VIPS_MIN( 1, B[b] / (1 - A[b]) );
				else 
					f[b] = 1;
			break;

		case VIPS_BLEND_MODE_COLOUR_BURN:
			for( b = 0; b < bands; b++ ) 
				if( A[b] > 0 ) 
					f[b] = 1 - VIPS_MIN( 1, 
						(1 - B[b]) / A[b] );
				else 
					f[b] = 0;
			break;

		case VIPS_BLEND_MODE_HARD_LIGHT:
			for( b = 0; b < bands; b++ ) 
				if( A[b] < 0.5 ) 
					f[b] = 2 * A[b] * B[b];
				else 
					f[b] = 1 - 2 * (1 - A[b]) * (1 - B[b]);
			break;

		case VIPS_BLEND_MODE_SOFT_LIGHT:
			for( b = 0; b < bands; b++ ) {
				double g;

				if( B[b] <= 0.25 ) 
					g = ((16 * B[b] - 12) * B[b] + 4) * 
						B[b];
				else 
					g = sqrt( B[b] );

				if( A[b] <= 0.5 )
					f[b] = B[b] - (1 - 2 * A[b]) * 
						B[b] * (1 - B[b]);
				else
					f[b] = B[b] + (2 * A[b] - 1) * 
						(g - B[b]);
			}
			break;

		case VIPS_BLEND_MODE_DIFFERENCE:
			for( b = 0; b < bands; b++ ) 
				f[b] = abs( B[b] - A[b] );
			break;

		case VIPS_BLEND_MODE_EXCLUSION:
			for( b = 0; b < bands; b++ ) 
				f[b] = A[b] + B[b] - 2 * A[b] * B[b];
			break;

		default:
			g_assert_not_reached();
			for( b = 0; b < bands; b++ )
				B[b] = 0;
		}

		if( aR == 0 ) {
			for( b = 0; b < bands; b++ )
				B[b] = 0;
		}
		else {
			for( b = 0; b < bands; b++ ) 
				B[b] = (t1 * A[b] + t2 * B[b] + t3 * f[b]) / aR;
		}
		break;
	}

	B[bands] = aR;
}

/* We have a vector path with gcc's vector attr.
 */
#ifdef HAVE_VECTOR_ARITH
/* A vector of four floats.
 */
typedef float v4f __attribute__((vector_size(4 * sizeof(float))));

/* Special path for RGBA with float pixels. This is overwhelmingly the most 
 * common case, and vectorises easily. 
 *
 * B is the pixel we are accumulating, A is the new pixel coming in from
 * memory.
 */
static void inline
vips_composite_blend_mul_3float( VipsBlendMode mode, v4f &B, float *A_memory )
{
	float aA;
	float aB;
	float aR;
	float t1;
	float t2;
	float t3;
	v4f f;
	v4f g;

	v4f A = *((v4f *) A_memory);

	aA = A[3];
	aB = B[3];
	aR = vips_composite_alpha( mode, aA, aB );

	if( aR == 0 ) {
		B[0] = 0;
		B[1] = 0;
		B[2] = 0;
		B[3] = 0;

		return;
	}

	switch( mode ) {
	case VIPS_BLEND_MODE_CLEAR:
		B[0] = 0;
		B[1] = 0;
		B[2] = 0;
		break;

	case VIPS_BLEND_MODE_SOURCE:
		B = A;
		break;

	case VIPS_BLEND_MODE_OVER:
		t1 = aB * (1 - aA);
		B = (aA * A + t1 * B) / aR;
		break;

	case VIPS_BLEND_MODE_IN:
		B = A;
		break;

	case VIPS_BLEND_MODE_OUT:
		B = A;
		break;

	case VIPS_BLEND_MODE_ATOP:
		B = A * aA + (1 - aA) * B;
		break;

	case VIPS_BLEND_MODE_DEST:
		break;

	case VIPS_BLEND_MODE_DEST_OVER:
		t1 = aA * (1 - aB);
		B = (t1 * A + aB * B) / aR;
		break;

	case VIPS_BLEND_MODE_DEST_IN:
		B = B;
		break;

	case VIPS_BLEND_MODE_DEST_OUT:
		B = B;
		break;

	case VIPS_BLEND_MODE_DEST_ATOP:
		B = (1 - aB) * A + aB * B;
		break;

	case VIPS_BLEND_MODE_XOR:
		t1 = aA * (1 - aB);
		t2 = aB * (1 - aA);
		B = (t1 * A + t2 * B) / aR;
		break;

	case VIPS_BLEND_MODE_ADD:
		B = (aA * A + aB * B) / aR;
		break;

	case VIPS_BLEND_MODE_SATURATE:
		t1 = VIPS_MIN( aA, 1 - aB );
		B = (t1 * A + aB * B) / aR;
		break;

	default:
		/* The PDF modes are a bit different.
		 */
		t1 = (1 - aB) * aA;
		t2 = (1 - aA) * aB;
		t3 = aA * aB;

		switch( mode ) {
		case VIPS_BLEND_MODE_MULTIPLY:
			f = A * B;
			break;

		case VIPS_BLEND_MODE_SCREEN:
			f = A + B - A * B;
			break;

		case VIPS_BLEND_MODE_OVERLAY:
			f = B <= 0.5 ? 
				2 * A * B : 1 - 2 * (1 - A) * (1 - B);
			break;

		case VIPS_BLEND_MODE_DARKEN:
			f = VIPS_MIN( A, B );
			break;

		case VIPS_BLEND_MODE_LIGHTEN:
			f = VIPS_MAX( A, B );
			break;

		case VIPS_BLEND_MODE_COLOUR_DODGE:
			f = A < 1 ?  VIPS_MIN( 1, B / (1 - A) ) : 1;
			break;

		case VIPS_BLEND_MODE_COLOUR_BURN:
			f = A > 0 ? 
				1 - VIPS_MIN( 1, (1 - B) / A ) :
				0;
			break;

		case VIPS_BLEND_MODE_HARD_LIGHT:
			f = A < 0.5 ? 
				2 * A * B : 
				1 - 2 * (1 - A) * (1 - B);
			break;

		case VIPS_BLEND_MODE_SOFT_LIGHT:
			/* sqrt does not work on vectors, you have to
			 * loop explicitly.
			 */
			for( int b = 0; b < 3; b++ ) {
				if( B[b] <= 0.25 ) 
					g[b] = ((16 * B[b] - 12) * 
						B[b] + 4) * B[b];
				else 
					g[b] = sqrt( B[b] );

				if( A[b] <= 0.5 )
					f[b] = B[b] - (1 - 2 * A[b]) * 
						B[b] * (1 - B[b]);
				else
					f[b] = B[b] + (2 * A[b] - 1) * 
						(g[b] - B[b]);
			}
			break;

		case VIPS_BLEND_MODE_DIFFERENCE:
			g = B - A;
			f = g > 0 ? g : -1 * g;
			break;

		case VIPS_BLEND_MODE_EXCLUSION:
			f = A + B - 2 * A * B;
			break;

		default:
			g_assert_not_reached();
			B[0] = 0;
			B[1] = 0;
			B[2] = 0;
			break;
		}

		B = (t1 * A + t2 * B + t3 * f) / aR;
	}

	B[3] = aR;
}
#endif /*HAVE_VECTOR_ARITH*/

/* A is the new pixel coming in, B is the double pixel we are accumulating.
 */
template <typename T>
static void
vips_composite_blend_premul( VipsBlendMode mode,
	double * restrict B, T * restrict A, int bands ) 
{
	// adapt multiply case once it's done
	g_assert_not_reached();
}

template <typename T>
static void vips_combine_pixels( VipsComposite *composite,
	VipsPel *q, VipsPel **p )
{
	VipsBlendMode *m = (VipsBlendMode *) composite->mode->area.data;
	int n = composite->n;
	int bands = composite->bands;
	T * restrict tq = (T * restrict) q;
	T ** restrict tp = (T ** restrict) p;

	double B[MAX_BANDS + 1];

	for( int b = 0; b <= bands; b++ )
		B[b] = tp[n - 1][b];

	for( int i = n - 2; i >= 0; i-- ) {
		if( composite->premultiplied )
			vips_composite_blend_premul<T>( m[i], B, tp[i], bands ); 
		else
			vips_composite_blend_mul<T>( m[i], B, tp[i], bands ); 
	}

	double rescale = 1.0;
	if( !composite->premultiplied )
		rescale = B[bands]; 
	for( int b = 0; b < bands; b++ )
		tq[b] = B[b] * rescale;
	tq[bands] = B[bands];
}

#ifdef HAVE_VECTOR_ARITH
static void 
vips_combine_pixels_3float( VipsComposite *composite,
	VipsPel *q, VipsPel **p )
{
	VipsBlendMode *m = (VipsBlendMode *) composite->mode->area.data;
	int n = composite->n;
	float * restrict tq = (float * restrict) q;
	float ** restrict tp = (float ** restrict) p;

	v4f B, R;

	B = *((v4f *) tp[n - 1]);
	for( int i = n - 2; i >= 0; i-- ) 
		vips_composite_blend_mul_3float( m[i], B, tp[i] );

	float rescale = 1.0;
	if( !composite->premultiplied )
		rescale = B[3]; 
	R = B * rescale;
	*((v4f *) tq) = R;
	tq[3] = B[3];
}
#endif /*HAVE_VECTOR_ARITH*/

static int
vips_composite_gen( VipsRegion *output_region,
	void *seq, void *a, void *b, gboolean *stop )
{
	VipsRegion **input_regions = (VipsRegion **) seq;
	VipsComposite *composite = (VipsComposite *) b;
	VipsRect *r = &output_region->valid;
	int ps = VIPS_IMAGE_SIZEOF_PEL( output_region->im );

	if( vips_reorder_prepare_many( output_region->im, input_regions, r ) )
		return( -1 );

	VIPS_GATE_START( "vips_composite_gen: work" );

	for( int y = 0; y < r->height; y++ ) {
		VipsPel *p[MAX_INPUT_IMAGES];
		VipsPel *q;
		int x, i;

		for( i = 0; i < composite->n; i++ )
			p[i] = VIPS_REGION_ADDR( input_regions[i],
				r->left, r->top + y );
		p[i] = NULL;
		q = VIPS_REGION_ADDR( output_region, r->left, r->top + y );

		for( x = 0; x < r->width; x++ ) {
			switch( input_regions[0]->im->BandFmt ) {
			case VIPS_FORMAT_FLOAT:
#ifdef HAVE_VECTOR_ARITH
				if( composite->bands == 3 ) 
					vips_combine_pixels_3float( composite, 
						q, p ); 
				else
#endif /*HAVE_VECTOR_ARITH*/
					vips_combine_pixels<float>( composite, 
						q, p );
				break;

			case VIPS_FORMAT_DOUBLE:
				vips_combine_pixels<double>( composite, q, p );
				break;

			default:
				g_assert_not_reached();
				return( -1 );
			}

			for( i = 0; i < composite->n; i++ )
				p[i] += ps;
			q += ps;
		}
	}

	VIPS_GATE_STOP( "vips_composite_gen: work" );

	return( 0 );
}

/* For each of the supported interpretations, the maximum value of each band.
 * This is used to scale all bands to 0 - 1.
 */
static int
vips_composite_prescale( VipsComposite *composite,
	VipsImage *image, double *scale )
{
	double max_alpha;
	int b;

	max_alpha = 255.0;
	if( composite->compositing_space == VIPS_INTERPRETATION_GREY16 ||
		composite->compositing_space == VIPS_INTERPRETATION_RGB16 )
		max_alpha = 65535.0;

	for( b = 0; b < image->Bands; b++ )
		scale[b] = max_alpha;

	switch( image->Type ) {
	case VIPS_INTERPRETATION_XYZ:
		scale[0] = VIPS_D65_X0;
		scale[1] = VIPS_D65_Y0;
		scale[2] = VIPS_D65_Z0;
		break;

	case VIPS_INTERPRETATION_LAB:
		scale[0] = 100;
		scale[1] = 128;
		scale[2] = 128;
		break;

	case VIPS_INTERPRETATION_LCH:
		scale[0] = 100;
		scale[1] = 128;
		scale[2] = 360;
		break;

	case VIPS_INTERPRETATION_CMC:
		scale[0] = 100;
		scale[1] = 128;
		scale[2] = 360;
		break;

	case VIPS_INTERPRETATION_scRGB:
		scale[0] = 1;
		scale[1] = 1;
		scale[2] = 1;
		break;

	case VIPS_INTERPRETATION_sRGB:
		scale[0] = 255;
		scale[1] = 255;
		scale[2] = 255;
		break;

	case VIPS_INTERPRETATION_HSV:
		scale[0] = 255;
		scale[1] = 255;
		scale[2] = 255;
		break;

	case VIPS_INTERPRETATION_RGB16:
		scale[0] = 65535;
		scale[1] = 65535;
		scale[2] = 65535;
		break;

	case VIPS_INTERPRETATION_GREY16:
		scale[0] = 65535;
		break;

	case VIPS_INTERPRETATION_YXY:
		scale[0] = 100;
		scale[1] = 1;
		scale[2] = 1;
		break;

	case VIPS_INTERPRETATION_B_W:
		scale[0] = 256;
		break;


	default:
		return( -1 );
	}

	return( 0 );
}

static int
vips_composite_build( VipsObject *object )
{
	VipsObjectClass *klass = VIPS_OBJECT_GET_CLASS( object );
	VipsConversion *conversion = VIPS_CONVERSION( object );
	VipsComposite *composite = (VipsComposite *) object;
	VipsImage **t = (VipsImage **) vips_object_local_array( object, 5 );

	int i;
	VipsImage **in;
	VipsImage **decode;
	VipsImage **compositing;
	VipsImage **format;
	VipsImage **size;
	double scale[MAX_BANDS];
	double offset[MAX_BANDS];
	VipsImage **prescale;
	VipsBlendMode *mode;
	VipsImage *out;

	if( VIPS_OBJECT_CLASS( vips_composite_parent_class )->build( object ) )
		return( -1 );

	composite->n = composite->in->area.n;

	if( composite->n <= 0 ) {
		vips_error( klass->nickname, "%s", _( "no input images" ) );
		return( -1 );
	}
	if( composite->mode->area.n != composite->n - 1 ) {
		vips_error( klass->nickname,
			_( "for %d input images there must be %d blend modes" ),
			composite->n, composite->n - 1 );
		return( -1 );
	}
	mode = (VipsBlendMode *) composite->mode->area.data;
	for( i = 0; i < composite->n - 1; i++ ) {
		if( mode[i] < 0 ||
			mode[i] >= VIPS_BLEND_MODE_LAST ) {
			vips_error( klass->nickname,
				_( "blend mode index %d (%d) invalid" ),
				i, mode[i] );
			return( -1 );
		}
	}

	in = (VipsImage **) composite->in->area.data;

	decode = (VipsImage **) vips_object_local_array( object, composite->n );
	for( i = 0; i < composite->n; i++ )
		if( vips_image_decode( in[i], &decode[i] ) )
			return( -1 );
	in = decode;

	/* Are any of the images missing alpha? The first missing alpha is
	 * given a solid 255 and becomes the background image, shortening n.
	 */
	for( i = 0; i < composite->n; i++ )
		if( !vips_image_hasalpha( in[i] ) ) {
			VipsImage *x;
			double solid;

			solid = 255;
			if( in[i]->Type == VIPS_INTERPRETATION_GREY16 ||
				in[i]->Type == VIPS_INTERPRETATION_RGB16 )
				solid = 65535;

			if( vips_bandjoin_const1( in[i], &x, solid, NULL ) )
				return( -1 );
			g_object_unref( in[i] );
			in[i] = x;
			composite->n = i + 1;
			break;
		}

	if( composite->n > MAX_INPUT_IMAGES ) {
		vips_error( klass->nickname,
			"%s", _( "too many input images" ) );
		return( -1 );
	}

	/* Transform to compositing space. It defaults to sRGB or B_W.
	 */
	if( !vips_object_argument_isset( object, "compositing_space" ) ) {
		gboolean all_grey;

		all_grey = TRUE;
		for( i = 0; i < composite->n; i++ )
			if( in[i]->Bands > 2 ) {
				all_grey = FALSE;
				break;
			}

		composite->compositing_space = all_grey ?
			VIPS_INTERPRETATION_B_W : VIPS_INTERPRETATION_sRGB;
	}

	compositing = (VipsImage **)
		vips_object_local_array( object, composite->n );
	for( i = 0; i < composite->n; i++ )
		if( vips_colourspace( in[i], &compositing[i],
			composite->compositing_space, NULL ) )
			return( -1 );
	in = compositing;

	/* Transform the input images to match in size and format.
	 */
	format = (VipsImage **) vips_object_local_array( object, composite->n );
	size = (VipsImage **) vips_object_local_array( object, composite->n );
	if( vips__formatalike_vec( decode, format, composite->n ) ||
		vips__sizealike_vec( format, size, composite->n ) )
		return( -1 );
	in = size;

	/* Check that they all now match in bands. This can fail for some
	 * inputs.
	 */
	for( i = 1; i < composite->n; i++ )
		if( in[i]->Bands != in[0]->Bands ) {
			vips_error( klass->nickname,
				_( "image %d does not have %d bands" ),
				i, in[0]->Bands );
			return( -1 );
		}

	if( in[0]->Bands > MAX_BANDS ) {
		vips_error( klass->nickname,
			"%s", _( "too many input bands" ) );
		return( -1 );
	}

	composite->bands = in[0]->Bands - 1;

	/* Prescale all bands to 0 - 1 range.
	 */
	prescale = (VipsImage **) 
		vips_object_local_array( object, composite->n );
	if( vips_composite_prescale( composite, in[0], scale ) ) {
		vips_error( klass->nickname,
			"%s", _( "unsupported compositing space" ) );
		return( -1 );
	}
	for( i = 0; i < in[0]->Bands; i++ ) {
		scale[i] = 1.0 / scale[i];
		offset[i] = 0;
	}
	for( i = 0; i < composite->n; i++ ) 
		if( vips_linear( in[i], &prescale[i], 
			scale, offset, in[0]->Bands, NULL ) )
			return( -1 );
	in = prescale;

	t[0] = vips_image_new();
	out = t[0];

	if( vips_image_pipeline_array( out,
		VIPS_DEMAND_STYLE_THINSTRIP, in ) )
		return( -1 );

	if( vips_image_generate( out,
		vips_start_many, vips_composite_gen, vips_stop_many,
		in, composite ) )
		return( -1 );

	/* Scale all bands back to their full range again.
	 */
	for( i = 0; i < out->Bands; i++ ) 
		scale[i] = 1.0 / scale[i];
	if( vips_linear( out, &t[1], scale, offset, out->Bands, NULL ) )
		return( -1 );
	out = t[1];

	if( vips_image_write( out, conversion->out ) )
		return( -1 );

	return( 0 );
}

static void
vips_composite_class_init( VipsCompositeClass *klass )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( klass );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( klass );
	VipsOperationClass *operation_class = VIPS_OPERATION_CLASS( klass );

	VIPS_DEBUG_MSG( "vips_composite_class_init\n" );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "composite";
	vobject_class->description =
		_( "blend an array of images with an array of blend modes" );
	vobject_class->build = vips_composite_build;

	operation_class->flags = VIPS_OPERATION_SEQUENTIAL;

	VIPS_ARG_BOXED( klass, "in", 0,
		_( "Inputs" ),
		_( "Array of input images" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsComposite, in ),
		VIPS_TYPE_ARRAY_IMAGE );

	VIPS_ARG_BOXED( klass, "mode", 3,
		_( "Blend modes" ),
		_( "Array of VipsBlendMode to join with" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsComposite, mode ),
		VIPS_TYPE_ARRAY_INT );

	VIPS_ARG_ENUM( klass, "compositing_space", 10,
		_( "Compositing space" ),
		_( "Composite images in this colour space" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsComposite, compositing_space ),
		VIPS_TYPE_INTERPRETATION, VIPS_INTERPRETATION_sRGB );

	VIPS_ARG_BOOL( klass, "premultiplied", 11,
		_( "Premultiplied" ),
		_( "Images have premultiplied alpha" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsComposite, premultiplied ),
		FALSE );

}

static void
vips_composite_init( VipsComposite *composite )
{
	composite->compositing_space = VIPS_INTERPRETATION_sRGB;
}

static int
vips_compositev( VipsImage **in, VipsImage **out, int n, int *mode, va_list ap )
{
	VipsArrayImage *image_array;
	VipsArrayInt *mode_array;
	int result;

	image_array = vips_array_image_new( in, n );
	mode_array = vips_array_int_new( mode, n - 1 );
	result = vips_call_split( "composite", ap,
		image_array, out, mode_array );
	vips_area_unref( VIPS_AREA( image_array ) );
	vips_area_unref( VIPS_AREA( mode_array ) );

	return( result );
}

/**
 * vips_composite:
 * @in: (array length=n) (transfer none): array of input images
 * @out: output image
 * @n: number of input images
 * @mode: array of (@n - 1) #VipsBlendMode
 * @...: %NULL-terminated list of optional named arguments
 *
 * Composite an array of images together.
 *
 * See also: vips_insert().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_composite( VipsImage **in, VipsImage **out, int n, int *mode, ... )
{
	va_list ap;
	int result;

	va_start( ap, mode );
	result = vips_compositev( in, out, n, mode, ap );
	va_end( ap );

	return( result );
}

/**
 * vips_composite2:
 * @in1: first input image
 * @in2: second input image
 * @out: output image
 * @mode: composite with this blend mode
 * @...: %NULL-terminated list of optional named arguments
 *
 * Composite a pair of images together. See vips_composite().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_composite2( VipsImage *in1, VipsImage *in2, VipsImage **out,
	VipsBlendMode mode1, ... )
{
	va_list ap;
	int result;
	VipsImage *in[2];
	int mode[1];

	in[0] = in1;
	in[1] = in2;
	mode[0] = mode1;

	va_start( ap, mode1 );
	result = vips_compositev( in, out, 2, mode, ap );
	va_end( ap );

	return( result );
}
