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
 */

/* References:
 *
 * @gasi's composite example https://gist.github.com/jcupitt/abacc012e2991f332e8b
 *
 * https://en.wikipedia.org/wiki/Alpha_compositing
 *
 * https://www.cairographics.org/operators/
 */

/* For each of the supported interpretations, the maximum value of each band.
 */
static int
vips_composite_prescale_max_band( VipsImage *image, double *scale )
{
	double max_alpha;
	int b;

	max_alpha = 255.0;
	if( image->Type == VIPS_INTERPRETATION_GREY16 ||
		image->Type == VIPS_INTERPRETATION_RGB16 )
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

#define LOOP_PRESCALE( IN, OUT ) { \
	IN *tp = (IN ) p; \
	OUT *tq = (OUT ) q; \
	\
	for( x = 0; x < sz; x++ ) \
		for( b = 0; b < bands; b++ ) \
			tq[b] = tp[b] * scale[b]; \
 		\
		tq += bands; \
		tp += bands; \
	} \
}

static int
vips_composite_prescale_gen( VipsRegion *output_region,
	void *seq, void *a, void *b, gboolean *stop )
{
	VipsRegion *input_region = (VipsRegion *) seq;
	VipsImage *in = (VipsImage *) a; 
	int bands = in->Bands; 
	double *scale = (double *) b;
	VipsRect *r = &output_region->valid;
	int sz = r->width * in->Bands; 

	int x, b;

	if( vips_region_prepare( input_region, r ) )
		return( -1 );

	VIPS_GATE_START( "vips_composite_prescale_gen: work" );

	for( int y = 0; y < r->height; y++ ) {
		VipsPel *p = VIPS_REGION_ADDR( input_region, 
			r->left, r->top + y );
		VipsPel *q = VIPS_REGION_ADDR( output_region,
			r->left, r->top + y );

		switch( input_region->im->BandFmt ) {
		case VIPS_FORMAT_UCHAR: 	
			LOOP_PRESCALE( unsigned char, float ); 
			break;

		case VIPS_FORMAT_CHAR: 		
			LOOP_PRESCALE( signed char, float ); 
			break; 

		case VIPS_FORMAT_USHORT: 	
			LOOP_PRESCALE( unsigned short, float ); 
			break; 

		case VIPS_FORMAT_SHORT: 	
			LOOP_PRESCALE( signed short, float ); 
			break; 

		case VIPS_FORMAT_UINT: 		
			LOOP_PRESCALE( unsigned int, float ); 
			break; 

		case VIPS_FORMAT_INT: 		
			LOOP_PRESCALE( signed int, float );  
			break; 

		case VIPS_FORMAT_FLOAT: 	
			LOOP_PRESCALE( float, float ); 
			break; 

		case VIPS_FORMAT_DOUBLE:	
			LOOP_PRESCALE( double, double ); 
			break; 

		default:
			g_assert_not_reached();
			return( -1 );
		}
	}

	VIPS_GATE_STOP( "vips_composite_prescale_gen: work" );

	return( 0 );
}

#define LOOP_PRESCALE_PREMULTIPLY( IN, OUT ) { \
	IN *tp = (IN ) p; \
	OUT *tq = (OUT ) q; \
	\
	for( x = 0; x < sz; x++ ) \
		for( b = 0; b < bands; b++ ) \
			tq[b] = tp[b] * scale[b]; \
 		\
		tq += bands; \
		tp += bands; \
	} \
}

static int
vips_composite_prescale_premultiply_gen( VipsRegion *output_region,
	void *seq, void *a, void *b, gboolean *stop )
{
	VipsRegion *input_region = (VipsRegion *) seq;
	VipsImage *in = (VipsImage *) a; 
	int bands = in->Bands; 
	double *scale = (double *) b;
	VipsRect *r = &output_region->valid;
	int sz = r->width * in->Bands; 

	int x, b;

	if( vips_region_prepare( input_region, r ) )
		return( -1 );

	VIPS_GATE_START( "vips_composite_prescale_premultiply_gen: work" );

	for( int y = 0; y < r->height; y++ ) {
		VipsPel *p = VIPS_REGION_ADDR( input_region, 
			r->left, r->top + y );
		VipsPel *q = VIPS_REGION_ADDR( output_region,
			r->left, r->top + y );

		switch( input_region->im->BandFmt ) {
		case VIPS_FORMAT_UCHAR: 	
			LOOP_PRESCALE_PREMULTIPLY( unsigned char, float ); 
			break;

		case VIPS_FORMAT_CHAR: 		
			LOOP_PRESCALE_PREMULTIPLY( signed char, float ); 
			break; 

		case VIPS_FORMAT_USHORT: 	
			LOOP_PRESCALE_PREMULTIPLY( unsigned short, float ); 
			break; 

		case VIPS_FORMAT_SHORT: 	
			LOOP_PRESCALE_PREMULTIPLY( signed short, float ); 
			break; 

		case VIPS_FORMAT_UINT: 		
			LOOP_PRESCALE_PREMULTIPLY( unsigned int, float ); 
			break; 

		case VIPS_FORMAT_INT: 		
			LOOP_PRESCALE_PREMULTIPLY( signed int, float );  
			break; 

		case VIPS_FORMAT_FLOAT: 	
			LOOP_PRESCALE_PREMULTIPLY( float, float ); 
			break; 

		case VIPS_FORMAT_DOUBLE:	
			LOOP_PRESCALE_PREMULTIPLY( double, double ); 
			break; 

		default:
			g_assert_not_reached();
			return( -1 );
		}
	}

	VIPS_GATE_STOP( "vips_composite_prescale_premultiply_gen: work" );

	return( 0 );
}

/* Prescale all bands to float 0 - 1, or double if the input is double. If
 * premultiplied is FALSE, also premultiply all non-alpha channels by alpha.
 */
static int
vips_composite_prescale( VipsImage *in, VipsImage **out, gboolean premultiplied )
{
	double *scale;

	if( vips_check_noncomplex( "vips_composite_prescale", in ) )
		return( -1 ); 

	*out = vips_image_new();

	if( !(scale = VIPS_ARRAY( *out, double, in->Bands )) )
		return( -1 );
	if( vips_composite_prescale_max_band( in, scale ) ) {
		vips_error( "vips_composite_prescale",
			"%s", _( "unsupported prescale space" ) );
		return( -1 );
	}

	*out->BandFmt == in->BandFmt == VIPS_FORMAT_DOUBLE ?
		VIPS_FORMAT_DOUBLE : VIPS_FORMAT_FLOAT;
	if( vips_image_pipelinev( out,
		VIPS_DEMAND_STYLE_THINSTRIP, in, NULL ) )
		return( -1 );
	if( vips_image_generate( out,
		vips_start_one, vips_composite_prescale_gen, vips_stop_one,
		in, scale ) )
		return( -1 );

	return( 0 );
}

#define LOOP_UNPRESCALE( IN, OUT ) { \
	IN *tp = (IN ) p; \
	OUT *tq = (OUT ) q; \
	\
	for( x = 0; x < sz; x++ ) \
		for( b = 0; b < bands; b++ ) \
			tq[b] = tp[b] * scale[b]; \
 		\
		tq += bands; \
		tp += bands; \
	} \
}

static int
vips_composite_unprescale_gen( VipsRegion *output_region,
	void *seq, void *a, void *b, gboolean *stop )
{
	VipsRegion *input_region = (VipsRegion *) seq;
	VipsImage *in = (VipsImage *) a; 
	int bands = in->Bands; 
	double *scale = (double *) b;
	VipsRect *r = &output_region->valid;
	int sz = r->width * in->Bands; 

	int x, b;

	if( vips_region_prepare( input_region, r ) )
		return( -1 );

	VIPS_GATE_START( "vips_composite_unprescale_gen: work" );

	for( int y = 0; y < r->height; y++ ) {
		VipsPel *p = VIPS_REGION_ADDR( input_region, 
			r->left, r->top + y );
		VipsPel *q = VIPS_REGION_ADDR( output_region,
			r->left, r->top + y );

		switch( input_region->im->BandFmt ) {
		case VIPS_FORMAT_UCHAR: 	
			LOOP_UNPRESCALE( unsigned char, float ); break;
		case VIPS_FORMAT_CHAR: 		
			LOOP_UNPRESCALE( signed char, float ); break; 
		case VIPS_FORMAT_USHORT: 	
			LOOP_UNPRESCALE( unsigned short, float ); break; 
		case VIPS_FORMAT_SHORT: 	
			LOOP_UNPRESCALE( signed short, float ); break; 
		case VIPS_FORMAT_UINT: 		
			LOOP_UNPRESCALE( unsigned int, float ); break; 
		case VIPS_FORMAT_INT: 		
			LOOP_UNPRESCALE( signed int, float );  break; 
		case VIPS_FORMAT_FLOAT: 	
			LOOP_UNPRESCALE( float, float ); break; 
		case VIPS_FORMAT_DOUBLE:	
			LOOP_UNPRESCALE( double, double ); break; 

		default:
			g_assert_not_reached();
			return( -1 );
		}
	}

	VIPS_GATE_STOP( "vips_composite_unprescale_gen: work" );

	return( 0 );
}

/* Undo vips_composite_prescale(). 
 */
static int
vips_composite_unprescale( VipsImage *in, VipsImage **out, 
	gboolean premultiplied )
{
	double *scale;
	int i;

	if( vips_check_noncomplex( "vips_composite_unprescale", in ) )
		return( -1 ); 

	*out = vips_image_new();

	if( !(scale = VIPS_ARRAY( *out, double, in->Bands )) )
		return( -1 );
	if( vips_composite_prescale_max_band( in, scale ) ) {
		vips_error( "vips_composite_unprescale",
			"%s", _( "unsupported unprescale space" ) );
		return( -1 );
	}
	for( i = 0; i < in->Bands; i++ ) 
		if( scale[i] != 0 )
			scale[i] = 1.0 / scale[i];

	*out->BandFmt == in->BandFmt == VIPS_FORMAT_DOUBLE ?
		VIPS_FORMAT_DOUBLE : VIPS_FORMAT_FLOAT;
	if( vips_image_pipelinev( out,
		VIPS_DEMAND_STYLE_THINSTRIP, in, NULL ) )
		return( -1 );
	if( vips_image_generate( out,
		vips_start_one, vips_composite_unprescale_gen, vips_stop_one,
		in, scale ) )
		return( -1 );

	return( 0 );
}

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
 * xR	colour band of result
 * xA	colour band of source A
 * xB	colour band of source B
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

/* A is the new pixel coming in, either float or double. B is the double pixel 
 * we are accumulating. Pixels are premultiplied.
 */
template <typename T>
static void
vips_composite_blend( VipsBlendMode mode,
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
			B[b] = 0;
		break;

	case VIPS_BLEND_MODE_SOURCE:
		for( b = 0; b < bands; b++ )
			B[b] = A[b];
		break;

	case VIPS_BLEND_MODE_OVER:
		t1 = 1 - aA;
		for( b = 0; b < bands; b++ )
			B[b] = A[b] + t1 * B[b];
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
		if( aB == 0 ) 
			for( b = 0; b < bands; b++ )
				B[b] = A[b];
		else
			for( b = 0; b < bands; b++ )
				B[b] = A[b] + (B[b] / aB) * (1 - aA);
		break;

	case VIPS_BLEND_MODE_DEST:
		// B = B
		break;

	case VIPS_BLEND_MODE_DEST_OVER:
		t1 = 1 - aB;
		for( b = 0; b < bands; b++ )
			B[b] = B[b] + t1 * A[b];
		break;

	case VIPS_BLEND_MODE_DEST_IN:
		// B = B
		break;

	case VIPS_BLEND_MODE_DEST_OUT:
		// B = B
		break;

	case VIPS_BLEND_MODE_DEST_ATOP:
		if( aB != 0 ) 
			for( b = 0; b < bands; b++ )
				B[b] = (A[b] / aB) * (1 - aB) + B[b];
		break;

	case VIPS_BLEND_MODE_XOR:
		t1 = 1 - aB;
		t2 = 1 - aA;
		for( b = 0; b < bands; b++ )
			B[b] = t1 * A[b] + t2 * B[b];
		break;

	case VIPS_BLEND_MODE_ADD:
		for( b = 0; b < bands; b++ )
			B[b] = A[b] + B[b];
		break;

	case VIPS_BLEND_MODE_SATURATE:
		if( aA != 0 ) {
			t1 = VIPS_MIN( aA, 1 - aB );
			for( b = 0; b < bands; b++ )
				B[b] = t1 * (A[b] / aA) + B[b];
		}
		break;

	default:
		/* The PDF modes are a bit different.
		 */
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

		t1 = 1 - aB;
		t2 = 1 - aA;
		t3 = aA * aB;

		for( b = 0; b < bands; b++ ) 
			B[b] = t1 * A[b] + t2 * B[b] + t3 * f[b];
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
 * B is the float pixel we are accumulating, A is the new float pixel coming 
 * in from memory.
 */
static void inline
vips_composite_blend_3float( VipsBlendMode mode, v4f &B, float *A_memory )
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
		t1 = 1 - aA;
		B = A + t1 * B;
		break;

	case VIPS_BLEND_MODE_IN:
		B = A;
		break;

	case VIPS_BLEND_MODE_OUT:
		B = A;
		break;

	case VIPS_BLEND_MODE_ATOP:
		t1 = 1 - aA;
                if( aB == 0 )
			B = A;
		else 
			B = A + t1 * (B / aB);
		break;

	case VIPS_BLEND_MODE_DEST:
		break;

	case VIPS_BLEND_MODE_DEST_OVER:
		t1 = 1 - aB;
		B = t1 * A + B;
		break;

	case VIPS_BLEND_MODE_DEST_IN:
		B = B;
		break;

	case VIPS_BLEND_MODE_DEST_OUT:
		B = B;
		break;

	case VIPS_BLEND_MODE_DEST_ATOP:
		t1 = 1 - aB;
                if( aB != 0 )
			B = t1 * A + B;
		break;

	case VIPS_BLEND_MODE_XOR:
		t1 = 1 - aB;
		t2 = 1 - aA;
		B = t1 * A + t2 * B;
		break;

	case VIPS_BLEND_MODE_ADD:
		B = A + B;
		break;

	case VIPS_BLEND_MODE_SATURATE:
		t1 = VIPS_MIN( aA, 1 - aB );
		if( aA != 0 ) 
			B = t1 * (A / aA) + B;
		break;

	default:
		/* The PDF modes are a bit different.
		 */
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
			f = A < 1 ? VIPS_MIN( 1, B / (1 - A) ) : 1;
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
				else if( B[b] >= 0 )
					g[b] = sqrt( B[b] );
				else
					g[b] = 0;

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

		t1 = 1 - aB;
		t2 = 1 - aA;
		t3 = aA * aB;
		B = t1 * A + t2 * B + t3 * f;
	}

	B[3] = aR;
}
#endif /*HAVE_VECTOR_ARITH*/

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

	for( int i = n - 2; i >= 0; i-- ) 
		vips_composite_blend<T>( m[i], B, tp[i], bands ); 

	for( int b = 0; b <= bands; b++ )
		tq[b] = B[b];
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
		vips_composite_blend_3float( m[i], B, tp[i] );

	*((v4f *) tq) = B;
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

	/* Transform to compositing space. It defaults to sRGB or B_W, usually 
	 * 8 bit, but 16 bit if any inputs are 16 bit.
	 */
	if( !vips_object_argument_isset( object, "compositing_space" ) ) {
		gboolean all_grey;
		gboolean any_16;

		all_grey = TRUE;
		for( i = 0; i < composite->n; i++ )
			if( in[i]->Bands > 2 ) {
				all_grey = FALSE;
				break;
			}

		any_16 = FALSE;
		for( i = 0; i < composite->n; i++ )
			if( in[i]->Type == VIPS_INTERPRETATION_GREY16 ||
				in[i]->Type == VIPS_INTERPRETATION_RGB16 ) {
				any_16 = TRUE;
				break;
			}

		composite->compositing_space = any_16 ?
			(all_grey ?
			 VIPS_INTERPRETATION_GREY16 : 
			 VIPS_INTERPRETATION_RGB16) :
			(all_grey ?
			 VIPS_INTERPRETATION_B_W : 
			 VIPS_INTERPRETATION_sRGB);
	}

	compositing = (VipsImage **)
		vips_object_local_array( object, composite->n );
	for( i = 0; i < composite->n; i++ )
		if( vips_colourspace( in[i], &compositing[i],
			composite->compositing_space, NULL ) )
			return( -1 );
	in = compositing;

	/* Check that they all now match in bands. This can fail for some
	 * input combinations.
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
	for( i = 0; i < composite->n; i++ )
		if( vips_composite_prescale( in[i], &prescale[i],
			composite->premultiplied ) )
			return( -1 );
	in = prescale;

	/* Transform the input images to match in size and format. We may have
	 * mixed float and double, for example.  
	 */
	format = (VipsImage **) vips_object_local_array( object, composite->n );
	size = (VipsImage **) vips_object_local_array( object, composite->n );
	if( vips__formatalike_vec( in, format, composite->n ) ||
		vips__sizealike_vec( format, size, composite->n ) )
		return( -1 );
	in = size;

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
	if( vips_composite_unprescale( out, &t[1], composite->premultiplied ) )
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
 * Optional arguments:
 *
 * * @compositing_space: #VipsInterpretation to composite in
 * * @premultiplied: %gboolean, images are already premultiplied
 *
 * Composite an array of images together. 
 *
 * Images are placed in a stack, with @in[@n - 1] at the bottom and @in[0] at
 * the top. Pixels are blended together working from the bottom upwards, with 
 * the blend mode at each step being set by the corresponding #VipsBlendMode
 * in @mode.
 *
 * Images are transformed to a compositing space before processing. This is
 * #VIPS_INTERPRETATION_sRGB, #VIPS_INTERPRETATION_B_W,
 * #VIPS_INTERPRETATION_RGB16, or #VIPS_INTERPRETATION_GREY16 
 * by default, depending on 
 * how many bands and bits the input images have. You select any other space, 
 * such as #VIPS_INTERPRETATION_LAB or #VIPS_INTERPRETATION_scRGB.
 *
 * The output image will always be #VIPS_FORMAT_FLOAT unless one of the inputs
 * is #VIPS_FORMAT_DOUBLE, which which case the output will be double as well.
 *
 * Complex images are not supported.
 *
 * The output image will always have an alpha band. A solid alpha is
 * added to any input missing an alpha. 
 *
 * The images do not need to match in size or format. They will be expanded to
 * the smallest common size and format in the usual way.
 *
 * Image are normally treated as unpremultiplied, so this oepration can be used
 * directly on PNG images. If your images have been through vips_premultiply(),
 * set @premultiplied. 
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
