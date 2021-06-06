/* composite an array of images with PDF operators
 *
 * 25/9/17
 * 	- from bandjoin.c
 * 30/11/17
 * 	- add composite2 class, to make a nice CLI interface
 * 30/1/18
 * 	- remove number of images limit
 * 	- allow one mode ... reused for all joins
 * 11/8/18 [medakk]
 * 	- x/y params let you position images
 * 27/11/18
 * 	- don't stop on first non-transparent image [felixbuenemann, GDmac]
 * 6/12/18
 *	- do our own subimage positioning
 * 8/5/19
 * 	- revise in/out/dest-in/dest-out to make smoother alpha
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
#ifdef _MSC_VER
#include <cstdlib>
#else
#include <stdlib.h>
#endif
#include <math.h>

#if defined(HAVE__ALIGNED_MALLOC) || defined(HAVE_MEMALIGN)
#include <malloc.h>
#endif

#include <vips/vips.h>
#include <vips/internal.h>
#include <vips/debug.h>

#include "pconversion.h"

/* Maximum number of image bands.
 */
#define MAX_BANDS (64)

/* Uncomment to disable the vector path ... handy for debugging. 
#undef HAVE_VECTOR_ARITH
 */

/* We have a vector path with gcc's vector attr.
 */
#ifdef HAVE_VECTOR_ARITH
/* A vector of four floats.
 */
typedef float v4f __attribute__((vector_size(4 * sizeof(float)),aligned(16)));
#endif /*HAVE_VECTOR_ARITH*/

typedef struct _VipsCompositeBase {
	VipsConversion parent_instance;

	/* The input images.
	 */
	VipsArrayImage *in;

	/* For N input images, 1 blend mode or N - 1 blend modes.
	 */
	VipsArrayInt *mode;

	/* Compositing space. This defaults to RGB, or B_W if we only have
	 * G and GA inputs.
	 */
	VipsInterpretation compositing_space;

	/* Set if the input images have already been premultiplied.
	 */
	gboolean premultiplied;

	/* The x and y positions for each image in the stack. There are n - 1 
	 * of these, since image 0 is always positioned at (0, 0). Set by
	 * subclasses. Can be NULL.
	 */
	int *x_offset;
	int *y_offset;

	/* A rect for the position of each input image. For each output region, 
	 * we composite the set of input images which intersect that area.
	 */
	VipsRect *subimages;

	/* The number of non-alpha bands we are blending.
	 */
	int bands;

	/* The maximum value for each band, set from the image interpretation.
	 * This is used to scale each band to 0 - 1.
	 */
	double max_band[MAX_BANDS + 1];

	/* TRUE if all our modes are skippable, ie. we can avoid compositing
	 * the whole stack for every pixel request.
	 */
	gboolean skippable;

} VipsCompositeBase;

typedef VipsConversionClass VipsCompositeBaseClass;

/* We need C linkage for this.
 */
extern "C" {
G_DEFINE_ABSTRACT_TYPE( VipsCompositeBase, vips_composite_base, 
	VIPS_TYPE_CONVERSION );
}

static void
vips_composite_base_dispose( GObject *gobject )
{
	VipsCompositeBase *composite = (VipsCompositeBase *) gobject;

	if( composite->in ) {
		vips_area_unref( (VipsArea *) composite->in );
		composite->in = NULL;
	}
	if( composite->mode ) {
		vips_area_unref( (VipsArea *) composite->mode );
		composite->mode = NULL;
	}
	VIPS_FREE( composite->subimages );

	G_OBJECT_CLASS( vips_composite_base_parent_class )->dispose( gobject );
}

/* Our sequence value.
 */
typedef struct {
#ifdef HAVE_VECTOR_ARITH
	/* max_band as a vector, for the RGBA case. This must be
	 * defined first to ensure that the member is aligned
	 * on a 16-byte boundary.
	 */
	v4f max_band_vec;
#endif /*HAVE_VECTOR_ARITH*/

	VipsCompositeBase *composite;

	/* Full set of input regions, each made on the corresponding input
	 * image.
	 */
	VipsRegion **input_regions;

	/* We then vips_region_prepare_to() to one of this set of regions,
	 * each defined on the base image.
	 */
	VipsRegion **composite_regions;

	/* Number of input regions which intersect this request rect.
	 */
	int n;

	/* For each of @n above (inputs which intersect this request), the
	 * index of the input image we need. We can use this index to get the
	 * position, input region and composite region.
	 */
	int *enabled;

	/* For each enabled image, an input pointer.
	 */
	VipsPel **p;

} VipsCompositeSequence;

#ifdef HAVE_VECTOR_ARITH
/* Allocate aligned memory. The return value can be released
 * by calling the vips_free_aligned() function, for example:
 * VIPS_FREEF( vips_free_aligned, ptr );
 */
static inline void *
vips_alloc_aligned( size_t sz, size_t align )
{
	g_assert( !(align & (align - 1)) );

#ifdef HAVE__ALIGNED_MALLOC
	return _aligned_malloc( sz, align );
#elif defined(HAVE_POSIX_MEMALIGN)
	void *ptr;
	if( posix_memalign( &ptr, align, sz ) ) return NULL;
	return ptr;
#elif defined(HAVE_MEMALIGN)
	return memalign( align, sz );
#else
#error Missing aligned alloc implementation
#endif
}

static inline void
vips_free_aligned( void* ptr )
{
#ifdef HAVE__ALIGNED_MALLOC
	_aligned_free( ptr );
#else /*defined(HAVE_POSIX_MEMALIGN) || defined(HAVE_MEMALIGN)*/
	free( ptr );
#endif
}
#endif /*HAVE_VECTOR_ARITH*/

static int
vips_composite_stop( void *vseq, void *a, void *b )
{
	VipsCompositeSequence *seq = (VipsCompositeSequence *) vseq;

	if( seq->input_regions ) {
		for( int i = 0; seq->input_regions[i]; i++ )
			VIPS_UNREF( seq->input_regions[i] );
		VIPS_FREE( seq->input_regions );
	}

	if( seq->composite_regions ) {
		for( int i = 0; seq->composite_regions[i]; i++ )
			VIPS_UNREF( seq->composite_regions[i] );
		VIPS_FREE( seq->composite_regions );
	}

	VIPS_FREE( seq->enabled );
	VIPS_FREE( seq->p );

#ifdef HAVE_VECTOR_ARITH
	VIPS_FREEF( vips_free_aligned, seq );
#else /*!defined(HAVE_VECTOR_ARITH)*/
	VIPS_FREE( seq );
#endif /*HAVE_VECTOR_ARITH*/

	return( 0 );
}

static void *
vips_composite_start( VipsImage *out, void *a, void *b )
{
	VipsImage **in = (VipsImage **) a;
	VipsCompositeBase *composite = (VipsCompositeBase *) b;

	VipsCompositeSequence *seq;
	int i, n;

#ifdef HAVE_VECTOR_ARITH
	/* Ensure that the memory is aligned on a 16-byte boundary.
	 */
	if( !(seq = ((VipsCompositeSequence *) vips_alloc_aligned(
		sizeof( VipsCompositeSequence ), 16 ))) )
#else /*!defined(HAVE_VECTOR_ARITH)*/
	if( !(seq = VIPS_NEW( NULL, VipsCompositeSequence )) )
#endif /*HAVE_VECTOR_ARITH*/
		return( NULL );

	seq->composite = composite;
	seq->input_regions = NULL;
	seq->enabled = NULL;
	seq->p = NULL;

	/* How many images?
	 */
	for( n = 0; in[n]; n++ )
		;

	/* Allocate space for region array.
	 */
	if( !(seq->input_regions = VIPS_ARRAY( NULL, n + 1, VipsRegion * )) ) {
		vips_composite_stop( seq, NULL, NULL );
		return( NULL );
	}
	for( i = 0; i < n + 1; i++ ) 
		seq->input_regions[i] = NULL;

	if( !(seq->composite_regions = 
		VIPS_ARRAY( NULL, n + 1, VipsRegion * )) ) {
		vips_composite_stop( seq, NULL, NULL );
		return( NULL );
	}
	for( i = 0; i < n + 1; i++ ) 
		seq->composite_regions[i] = NULL;

	seq->enabled = VIPS_ARRAY( NULL, n, int );
	seq->p = VIPS_ARRAY( NULL, n, VipsPel * );
	if( !seq->enabled ||
		!seq->p ) {
		vips_composite_stop( seq, NULL, NULL );
		return( NULL );
	}

	/* Create a set of regions.
	 */
	for( i = 0; i < n; i++ ) {
		seq->input_regions[i] = vips_region_new( in[i] );
		seq->composite_regions[i] = vips_region_new( in[0] );

		if( !seq->input_regions[i] ||
			!seq->composite_regions[i] ) {
			vips_composite_stop( seq, NULL, NULL );
			return( NULL );
		}
	}

#ifdef HAVE_VECTOR_ARITH
	/* We need a float version for the vector path.
	 */
	if( composite->bands == 3 )
		seq->max_band_vec = (v4f){
			(float) composite->max_band[0],
			(float) composite->max_band[1],
			(float) composite->max_band[2],
			(float) composite->max_band[3]
		};
#endif

	return( seq );
}

/* For each of the supported interpretations, the maximum value of each band.
 */
static int
vips_composite_base_max_band( VipsCompositeBase *composite, double *max_band )
{
	double max_alpha;
	int b;

	max_alpha = 255.0;
	if( composite->compositing_space == VIPS_INTERPRETATION_GREY16 ||
		composite->compositing_space == VIPS_INTERPRETATION_RGB16 )
		max_alpha = 65535.0;

	for( b = 0; b <= composite->bands; b++ )
		max_band[b] = max_alpha;

	switch( composite->compositing_space ) {
	case VIPS_INTERPRETATION_XYZ:
		max_band[0] = VIPS_D65_X0;
		max_band[1] = VIPS_D65_Y0;
		max_band[2] = VIPS_D65_Z0;
		break;

	case VIPS_INTERPRETATION_LAB:
		max_band[0] = 100;
		max_band[1] = 128;
		max_band[2] = 128;
		break;

	case VIPS_INTERPRETATION_LCH:
		max_band[0] = 100;
		max_band[1] = 128;
		max_band[2] = 360;
		break;

	case VIPS_INTERPRETATION_CMC:
		max_band[0] = 100;
		max_band[1] = 128;
		max_band[2] = 360;
		break;

	case VIPS_INTERPRETATION_scRGB:
		max_band[0] = 1;
		max_band[1] = 1;
		max_band[2] = 1;
		break;

	case VIPS_INTERPRETATION_sRGB:
		max_band[0] = 255;
		max_band[1] = 255;
		max_band[2] = 255;
		break;

	case VIPS_INTERPRETATION_HSV:
		max_band[0] = 255;
		max_band[1] = 255;
		max_band[2] = 255;
		break;

	case VIPS_INTERPRETATION_CMYK:
		max_band[0] = 255;
		max_band[1] = 255;
		max_band[2] = 255;
		max_band[3] = 255;
		break;

	case VIPS_INTERPRETATION_RGB16:
		max_band[0] = 65535;
		max_band[1] = 65535;
		max_band[2] = 65535;
		break;

	case VIPS_INTERPRETATION_GREY16:
		max_band[0] = 65535;
		break;

	case VIPS_INTERPRETATION_YXY:
		max_band[0] = 100;
		max_band[1] = 1;
		max_band[2] = 1;
		break;

	case VIPS_INTERPRETATION_B_W:
		max_band[0] = 255;
		break;

	default:
		return( -1 );
	}

	return( 0 );
}

/* Find the subset of our input images which intersect this region. If we are
 * not in skippable mode, we must enable all layers.
 */
static void
vips_composite_base_select( VipsCompositeSequence *seq, VipsRect *r )
{
        VipsCompositeBase *composite = seq->composite;
	int n = composite->in->area.n;

	seq->n = 0;
	for( int i = 0; i < n; i++ ) 
		if( !composite->skippable ||
			vips_rect_overlapsrect( r, 
				&composite->subimages[i] ) ) {
			seq->enabled[seq->n] = i;
			seq->n += 1;
		}
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

/* A is the new pixel coming in, of any non-complex type T. 
 *
 * We must scale incoming pixels to 0 - 1 by dividing by the scale[] vector.
 *
 * If premultipled is not set, we premultiply incoming pixels before blending.
 *
 * B is the double pixel we are accumulating. 
 */
template <typename T>
static void
vips_composite_base_blend( VipsCompositeBase *composite, 
	VipsBlendMode mode, double * restrict B, T * restrict p )
{
	const int bands = composite->bands;

	double A[MAX_BANDS + 1];
	double aA;
	double aB;
	double aR;
	double t1;
	double t2;
	double t3;
	double f[MAX_BANDS + 1];

	/* Load and scale the pixel to 0 - 1.
	 */
	for( int b = 0; b <= bands; b++ )
		A[b] = p[b] / composite->max_band[b];
	/* Not necessary, but it stops a compiler warning.
	 */
	for( int b = bands + 1; b < MAX_BANDS + 1; b++ )
		A[b] = 0.0;

	aA = A[bands];
	aB = B[bands];

	/* We may need to premultiply A.
	 */
	if( !composite->premultiplied )
		for( int b = 0; b < bands; b++ )
			A[b] *= aA;

	switch( mode ) {
	case VIPS_BLEND_MODE_CLEAR:
		aR = 0;
		for( int b = 0; b < bands; b++ )
			B[b] = 0;
		break;

	case VIPS_BLEND_MODE_SOURCE:
		aR = aA;
		for( int b = 0; b < bands; b++ )
			B[b] = A[b];
		break;

	case VIPS_BLEND_MODE_OVER:
		aR = aA + aB * (1 - aA);
		t1 = 1 - aA;
		for( int b = 0; b < bands; b++ )
			B[b] = A[b] + t1 * B[b];
		break;

	case VIPS_BLEND_MODE_IN:
		aR = aA * aB;
		// if aA == 0, then aR == 0 and so B will already be 0
		if( aA != 0 )
			for( int b = 0; b < bands; b++ )
				B[b] = A[b] * aR / aA;
		break;

	case VIPS_BLEND_MODE_OUT:
		aR = aA * (1 - aB);
		// if aA == 0, then aR == 0 and so B will already be 0
		if( aA != 0 )
			for( int b = 0; b < bands; b++ )
				B[b] = A[b] * aR / aA;
		break;

	case VIPS_BLEND_MODE_ATOP:
		aR = aB;
		t1 = 1 - aA;
		for( int b = 0; b < bands; b++ )
			B[b] = A[b] + t1 * B[b];
		break;

	case VIPS_BLEND_MODE_DEST:
		aR = aB;
		// B = B
		break;

	case VIPS_BLEND_MODE_DEST_OVER:
		aR = aB + aA * (1 - aB);
		t1 = 1 - aB;
		for( int b = 0; b < bands; b++ )
			B[b] = B[b] + t1 * A[b];
		break;

	case VIPS_BLEND_MODE_DEST_IN:
		aR = aA * aB;
		// B = B
		if( aB != 0 )
			for( int b = 0; b < bands; b++ )
				B[b] *= aR / aB;
		break;

	case VIPS_BLEND_MODE_DEST_OUT:
		aR = (1 - aA) * aB;
		// B = B
		// if aB is 0, then B is already 0 
		if( aB != 0 )
			for( int b = 0; b < bands; b++ )
				B[b] *= aR / aB;
		break;

	case VIPS_BLEND_MODE_DEST_ATOP:
		aR = aA;
		t1 = 1 - aA;
		for( int b = 0; b < bands; b++ )
			B[b] = t1 * A[b] + B[b];
		break;

	case VIPS_BLEND_MODE_XOR:
		aR = aA + aB - 2 * aA * aB;
		t1 = 1 - aB;
		t2 = 1 - aA;
		for( int b = 0; b < bands; b++ )
			B[b] = t1 * A[b] + t2 * B[b];
		break;

	case VIPS_BLEND_MODE_ADD:
		aR = VIPS_MIN( 1, aA + aB );
		for( int b = 0; b < bands; b++ )
			B[b] = A[b] + B[b];
		break;

	case VIPS_BLEND_MODE_SATURATE:
		aR = VIPS_MIN( 1, aA + aB );
		t1 = VIPS_MIN( aA, 1 - aB );
		for( int b = 0; b < bands; b++ )
			B[b] = t1 * A[b] + B[b];
		break;

	default:
		/* The PDF modes are a bit different.
		 */
		aR = aA + aB * (1 - aA);

		switch( mode ) {
		case VIPS_BLEND_MODE_MULTIPLY:
			for( int b = 0; b < bands; b++ ) 
				f[b] = A[b] * B[b];
			break;

		case VIPS_BLEND_MODE_SCREEN:
			for( int b = 0; b < bands; b++ ) 
				f[b] = A[b] + B[b] - A[b] * B[b];
			break;

		case VIPS_BLEND_MODE_OVERLAY:
			for( int b = 0; b < bands; b++ ) 
				if( B[b] <= 0.5 ) 
					f[b] = 2 * A[b] * B[b];
				else 
					f[b] = 1 - 2 * (1 - A[b]) * (1 - B[b]);
			break;

		case VIPS_BLEND_MODE_DARKEN:
			for( int b = 0; b < bands; b++ ) 
				f[b] = VIPS_MIN( A[b], B[b] );
			break;

		case VIPS_BLEND_MODE_LIGHTEN:
			for( int b = 0; b < bands; b++ ) 
				f[b] = VIPS_MAX( A[b], B[b] );
			break;

		case VIPS_BLEND_MODE_COLOUR_DODGE:
			for( int b = 0; b < bands; b++ ) 
				if( A[b] < 1 ) 
					f[b] = VIPS_MIN( 1, B[b] / (1 - A[b]) );
				else 
					f[b] = 1;
			break;

		case VIPS_BLEND_MODE_COLOUR_BURN:
			for( int b = 0; b < bands; b++ ) 
				if( A[b] > 0 ) 
					f[b] = 1 - VIPS_MIN( 1, 
						(1 - B[b]) / A[b] );
				else 
					f[b] = 0;
			break;

		case VIPS_BLEND_MODE_HARD_LIGHT:
			for( int b = 0; b < bands; b++ ) 
				if( A[b] <= 0.5 ) 
					f[b] = 2 * A[b] * B[b];
				else 
					f[b] = 1 - 2 * (1 - A[b]) * (1 - B[b]);
			break;

		case VIPS_BLEND_MODE_SOFT_LIGHT:
			for( int b = 0; b < bands; b++ ) {
				double g;

				if( B[b] <= 0.25 ) 
					g = ((16 * B[b] - 12) * 
						B[b] + 4) * B[b];
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
			for( int b = 0; b < bands; b++ ) 
				f[b] = fabs( B[b] - A[b] );
			break;

		case VIPS_BLEND_MODE_EXCLUSION:
			for( int b = 0; b < bands; b++ ) 
				f[b] = A[b] + B[b] - 2 * A[b] * B[b];
			break;

		default:
			g_assert_not_reached();
			for( int b = 0; b < bands; b++ )
				B[b] = 0;
		}

		t1 = 1 - aB;
		t2 = 1 - aA;
		t3 = aA * aB;
		for( int b = 0; b < bands; b++ ) 
			B[b] = t1 * A[b] + t2 * B[b] + t3 * f[b];
		break;
	}

	B[bands] = aR;
}

/* We have a vector path with gcc's vector attr.
 */
#ifdef HAVE_VECTOR_ARITH
/* Special path for RGBA with non-double output. This is overwhelmingly the 
 * most common case, and vectorises easily. 
 *
 * B is the float pixel we are accumulating, A is the new pixel coming 
 * in from memory.
 */
template <typename T>
static void
vips_composite_base_blend3( VipsCompositeSequence *seq,
	VipsBlendMode mode, v4f &B, T * restrict p )
{
	VipsCompositeBase *composite = seq->composite;

	v4f A;
	float aA;
	float aB;
	float aR;
	float t1;
	float t2;
	float t3;
	v4f f;
	v4f g;

	/* Load and scale the pixel to 0 - 1.
	 */
	A[0] = p[0];
	A[1] = p[1];
	A[2] = p[2];
	A[3] = p[3];

	A /= seq->max_band_vec;

	aA = A[3];
	aB = B[3];

	/* We may need to premultiply A.
	 */
	if( !composite->premultiplied )
		A *= aA;

	/* See https://www.cairographics.org/operators for a nice summary of 
	 * the operators and their meaning.
	 *
	 * Some operators need the unpremultiplied values (eg. dest-in), so 
	 * we have to do an extra unpremultiply/premultiply.
	 */

	switch( mode ) {
	case VIPS_BLEND_MODE_CLEAR:
		aR = 0;
		B[0] = 0;
		B[1] = 0;
		B[2] = 0;
		break;

	case VIPS_BLEND_MODE_SOURCE:
		aR = aA;
		B = A;
		break;

	case VIPS_BLEND_MODE_OVER:
		aR = aA + aB * (1 - aA);
		t1 = 1 - aA;
		B = A + t1 * B;
		break;

	case VIPS_BLEND_MODE_IN:
		aR = aA * aB;
		// if aA == 0, then aR == 0 and so B will already be 0
		if( aA != 0 )
			B = A * aR / aA;
		break;

	case VIPS_BLEND_MODE_OUT:
		aR = aA * (1 - aB);
		// if aA == 0, then aR == 0 and so B will already be 0
		if( aA != 0 )
			B = A * aR / aA;
		break;

	case VIPS_BLEND_MODE_ATOP:
		aR = aB;
		t1 = 1 - aA;
		B = A + t1 * B;
		break;

	case VIPS_BLEND_MODE_DEST:
		aR = aB;
		// B = B
		break;

	case VIPS_BLEND_MODE_DEST_OVER:
		aR = aB + aA * (1 - aB);
		t1 = 1 - aB;
		B = B + t1 * A;
		break;

	case VIPS_BLEND_MODE_DEST_IN:
		aR = aA * aB;
		// if aB is 0, then B is already 0 
		if( aB != 0 )
			B *= aR / aB;
		break;

	case VIPS_BLEND_MODE_DEST_OUT:
		aR = (1 - aA) * aB;
		// B = B
		// if aB is 0, then B is already 0 
		if( aB != 0 )
			B *= aR / aB;
		break;

	case VIPS_BLEND_MODE_DEST_ATOP:
		aR = aA;
		t1 = 1 - aA;
		B = t1 * A + B;
		break;

	case VIPS_BLEND_MODE_XOR:
		aR = aA + aB - 2 * aA * aB;
		t1 = 1 - aB;
		t2 = 1 - aA;
		B = t1 * A + t2 * B;
		break;

	case VIPS_BLEND_MODE_ADD:
		aR = VIPS_MIN( 1, aA + aB );
		B = A + B;
		break;

	case VIPS_BLEND_MODE_SATURATE:
		aR = VIPS_MIN( 1, aA + aB );
		t1 = VIPS_MIN( aA, 1 - aB );
		B = t1 * A + B;
		break;

	default:
		/* The PDF modes are a bit different.
		 */
		aR = aA + aB * (1 - aA);

		switch( mode ) {
		case VIPS_BLEND_MODE_MULTIPLY:
			f = A * B;
			break;

		case VIPS_BLEND_MODE_SCREEN:
			f = A + B - A * B;
			break;

		case VIPS_BLEND_MODE_OVERLAY:
			f = B <= 0.5 ? 
				2 * A * B :
				1 - 2 * (1 - A) * (1 - B);
			break;

		case VIPS_BLEND_MODE_DARKEN:
			f = VIPS_MIN( A, B );
			break;

		case VIPS_BLEND_MODE_LIGHTEN:
			f = VIPS_MAX( A, B );
			break;

		case VIPS_BLEND_MODE_COLOUR_DODGE:
			f = A < 1 ? 
				VIPS_MIN( 1, B / (1 - A) ) : 
				1;
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
			/* You can't sqrt a vector, so we must loop.
			 */
			for( int b = 0; b < 3; b++ ) {
				double g;

				if( B[b] <= 0.25 ) 
					g = ((16 * B[b] - 12) * B[b] + 4) * B[b];
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
			g = B - A;
			f = g > 0 ? g : -1 * g;
			break;

		case VIPS_BLEND_MODE_EXCLUSION:
			f = A + B - 2 * A * B;
			break;

		default:
			g_assert_not_reached();

			/* Stop compiler warnings.
			 */
			for( int b = 0; b < 3; b++ ) 
				B[b] = 0;
			f = A;
		}

		t1 = 1 - aB;
		t2 = 1 - aA;
		t3 = aA * aB;
		B = t1 * A + t2 * B + t3 * f;
		break;
	}

	B[3] = aR;
}
#endif /*HAVE_VECTOR_ARITH*/

/* min_T and max_T are the numeric range for this type. 0, 0 means no limit,
 * for example float.
 */
template <typename T, gint64 min_T, gint64 max_T>
static void 
vips_combine_pixels( VipsCompositeSequence *seq, VipsPel *q )
{
	VipsCompositeBase *composite = seq->composite;
	VipsBlendMode *mode = (VipsBlendMode *) composite->mode->area.data;
	int n_mode = composite->mode->area.n;
	int n = seq->n;
	int bands = composite->bands;
	T * restrict tq = (T * restrict) q;
	T ** restrict tp = (T ** restrict) seq->p;

	double B[MAX_BANDS + 1];
	double aB;

	/* Load and scale the base pixel to 0 - 1.
	 */
	for( int b = 0; b <= bands; b++ )
		B[b] = tp[0][b] / composite->max_band[b];

	aB = B[bands];
	if( !composite->premultiplied )
		for( int b = 0; b < bands; b++ )
			B[b] *= aB;

	for( int i = 1; i < n; i++ ) {
		int j = seq->enabled[i];
		VipsBlendMode m = n_mode == 1 ? mode[0] : mode[j - 1];

		vips_composite_base_blend<T>( composite, m, B, tp[i] ); 
	}

	/* Unpremultiply, if necessary.
	 */
	if( !composite->premultiplied ) {
		double aR = B[bands];

		if( aR == 0 )
			for( int b = 0; b < bands; b++ )
				B[b] = 0;
		else
			for( int b = 0; b < bands; b++ )
				B[b] = B[b] / aR;
	}

	/* Write back as a full range pixel, clipping to range.
	 */
	for( int b = 0; b <= bands; b++ ) {
		double v;

		v = B[b] * composite->max_band[b];
		if( min_T != 0 || 
			max_T != 0 ) {
			v = VIPS_CLIP( min_T, v, max_T ); 
		}

		tq[b] = v;
	}
}

#ifdef HAVE_VECTOR_ARITH
/* Three band (four with alpha) vector case. Non-double output. min_T and 
 * max_T are the numeric range for this type. 0, 0 means no limit,
 * for example float.
 */
template <typename T, gint64 min_T, gint64 max_T>
static void 
vips_combine_pixels3( VipsCompositeSequence *seq, VipsPel *q )
{
	VipsCompositeBase *composite = seq->composite;
	VipsBlendMode *mode = (VipsBlendMode *) composite->mode->area.data;
	int n_mode = composite->mode->area.n;
	int n = seq->n;
	T * restrict tq = (T * restrict) q;
	T ** restrict tp = (T ** restrict) seq->p;

	v4f B;
	float aB;

	B[0] = tp[0][0];
	B[1] = tp[0][1];
	B[2] = tp[0][2];
	B[3] = tp[0][3];

	/* Scale the base pixel to 0 - 1.
	 */
	B /= seq->max_band_vec;
	aB = B[3];

	if( !composite->premultiplied ) {
		B *= aB;
		B[3] = aB;
	}

	for( int i = 1; i < n; i++ ) {
		int j = seq->enabled[i];
		VipsBlendMode m = n_mode == 1 ? mode[0] : mode[j - 1];

		vips_composite_base_blend3<T>( seq, m, B, tp[i] );
	}

	/* Unpremultiply, if necessary.
	 */
	if( !composite->premultiplied ) {
		float aR = B[3];

		if( aR == 0 )
			for( int b = 0; b < 3; b++ ) 
				B[b] = 0;
		else {
			B /= aR;
			B[3] = aR;
		}
	}

	/* Write back as a full range pixel, clipping to range.
	 */
	B *= seq->max_band_vec;
	if( min_T != 0 || 
		max_T != 0 ) {
		float low = min_T;
		float high = max_T;

		B = VIPS_CLIP( low, B, high );
	}

	tq[0] = B[0];
	tq[1] = B[1];
	tq[2] = B[2];
	tq[3] = B[3];
}
#endif /*HAVE_VECTOR_ARITH*/

static int
vips_composite_base_gen( VipsRegion *output_region,
	void *vseq, void *a, void *b, gboolean *stop )
{
	VipsCompositeSequence *seq = (VipsCompositeSequence *) vseq;
	VipsCompositeBase *composite = (VipsCompositeBase *) b;
	VipsRect *r = &output_region->valid;
	int ps = VIPS_IMAGE_SIZEOF_PEL( output_region->im );

	VIPS_DEBUG_MSG( "vips_composite_base_gen: at %d x %d, size %d x %d\n",
		r->left, r->top, r->width, r->height );

	/* Find the subset of our input images which intersect this region.
	 */
	vips_composite_base_select( seq, r ); 

	VIPS_DEBUG_MSG( "  selected %d images\n", seq->n );

	/* Is there just one? We can prepare directly to output and return.
	 */
	if( seq->n == 1 ) {
		/* This can only be the background image, since it's the only
		 * image which exactly fills the whole output.
		 */
		g_assert( seq->enabled[0] == 0 );

		if( vips_region_prepare( seq->input_regions[0], r ) )
			return( -1 );
		if( vips_region_region( output_region, seq->input_regions[0], 
			r, r->left, r->top ) )
			return( -1 );

		return( 0 );
	}

	/* Prepare the appropriate parts into our set of composite
	 * regions.
	 */
	for( int i = 0; i < seq->n; i++ ) {
		int j = seq->enabled[i];

		VipsRect hit;
		VipsRect request;

		/* Set the composite region up to be a bit of memory at the
		 * right position.
		 */
		if( vips_region_buffer( seq->composite_regions[j], r ) )
			return( -1 );

		/* Clip against this subimage position and size.
		 */
		hit = *r;
		vips_rect_intersectrect( &hit, &composite->subimages[j], &hit );

		/* Translate request to subimage coordinates.
		 */
		request = hit;
		request.left -= composite->subimages[j].left;
		request.top -= composite->subimages[j].top;

		/* If the request is smaller than the target region, there
		 * will be some gaps. We must make sure these are zero.
		 */
		if( request.width < r->width ||
			request.height < r->height )
			vips_region_black( seq->composite_regions[j] );

		/* And render the right part of the input image to the
		 * composite region.
		 *
		 * If we are not in skippable mode, we can be completely
		 * outside the subimage area. 
		 */
		if( !vips_rect_isempty( &request ) ) {
			VIPS_DEBUG_MSG( "  fetching pixels for input %d\n", j );
			if( vips_region_prepare_to( seq->input_regions[j],
				seq->composite_regions[j], &request, 
				hit.left, hit.top ) )
				return( -1 );
		}
	}

	VIPS_GATE_START( "vips_composite_base_gen: work" );

	for( int y = 0; y < r->height; y++ ) {
		VipsPel *q;

		for( int i = 0; i < seq->n; i++ ) {
			int j = seq->enabled[i];

			seq->p[i] = VIPS_REGION_ADDR( seq->composite_regions[j],
				r->left, r->top + y );
		}
		q = VIPS_REGION_ADDR( output_region, r->left, r->top + y );

		for( int x = 0; x < r->width; x++ ) {
			switch( seq->input_regions[0]->im->BandFmt ) {
			case VIPS_FORMAT_UCHAR: 	
#ifdef HAVE_VECTOR_ARITH
				if( composite->bands == 3 ) 
					vips_combine_pixels3
						<unsigned char, 0, UCHAR_MAX>
						( seq, q ); 
				else
#endif 
					vips_combine_pixels
						<unsigned char, 0, UCHAR_MAX>
						( seq, q );
				break;

			case VIPS_FORMAT_CHAR: 		
				vips_combine_pixels
					<signed char, SCHAR_MIN, SCHAR_MAX>
					( seq, q );
				break; 

			case VIPS_FORMAT_USHORT: 	
#ifdef HAVE_VECTOR_ARITH
				if( composite->bands == 3 ) 
					vips_combine_pixels3
						<unsigned short, 0, USHRT_MAX>
						( seq, q );
				else
#endif 
					vips_combine_pixels
						<unsigned short, 0, USHRT_MAX>
						( seq, q );
				break; 

			case VIPS_FORMAT_SHORT: 	
				vips_combine_pixels
					<signed short, SHRT_MIN, SHRT_MAX>
					( seq, q );
				break; 

			case VIPS_FORMAT_UINT: 		
				vips_combine_pixels
					<unsigned int, 0, UINT_MAX>
					( seq, q );
				break; 

			case VIPS_FORMAT_INT: 		
				vips_combine_pixels
					<signed int, INT_MIN, INT_MAX>
					( seq, q );
				break; 

			case VIPS_FORMAT_FLOAT:
#ifdef HAVE_VECTOR_ARITH
				if( composite->bands == 3 ) 
					vips_combine_pixels3
						<float, 0, USHRT_MAX>
						( seq, q );
				else
#endif 
					vips_combine_pixels
						<float, 0, 0>
						( seq, q );
				break;

			case VIPS_FORMAT_DOUBLE:
				vips_combine_pixels
					<double, 0, 0>
					( seq, q );
				break;

			default:
				g_assert_not_reached();
				return( -1 );
			}

			for( int i = 0; i < seq->n; i++ )
				seq->p[i] += ps;
			q += ps;
		}
	}

	VIPS_GATE_STOP( "vips_composite_base_gen: work" );

	return( 0 );
}

/* Is a mode "skippable"? 
 *
 * Skippable modes are ones where a black (0, 0, 0, 0) layer placed over the
 * base image and composited has no effect. 
 *
 * If all the modes in our stack are skippable, we can avoid compositing the
 * whole stack for every request.
 */
static gboolean
vips_composite_mode_skippable( VipsBlendMode mode )
{
	switch( mode ) {
	case VIPS_BLEND_MODE_CLEAR:
	case VIPS_BLEND_MODE_SOURCE:
	case VIPS_BLEND_MODE_IN:
	case VIPS_BLEND_MODE_OUT:
	case VIPS_BLEND_MODE_DEST_IN:
	case VIPS_BLEND_MODE_DEST_ATOP:
		return( FALSE );

	default:
		return( TRUE );
	}
}

static int
vips_composite_base_build( VipsObject *object )
{
	VipsObjectClass *klass = VIPS_OBJECT_GET_CLASS( object );
	VipsConversion *conversion = VIPS_CONVERSION( object );
	VipsCompositeBase *composite = (VipsCompositeBase *) object;

	int n;
	VipsBlendMode *mode;
	VipsImage **in;
	VipsImage **decode;
	VipsImage **compositing;
	VipsImage **format;

	if( VIPS_OBJECT_CLASS( vips_composite_base_parent_class )->
		build( object ) )
		return( -1 );

	n = composite->in->area.n;

	if( n <= 0 ) {
		vips_error( klass->nickname, "%s", _( "no input images" ) );
		return( -1 );
	}
	if( composite->mode->area.n != n - 1 &&
		composite->mode->area.n != 1 ) {
		vips_error( klass->nickname, _( "must be 1 or %d blend modes" ),
			n - 1 );
		return( -1 );
	}
	mode = (VipsBlendMode *) composite->mode->area.data;
	composite->skippable = TRUE;
	for( int i = 0; i < composite->mode->area.n; i++ ) {
		if( mode[i] < 0 ||
			mode[i] >= VIPS_BLEND_MODE_LAST ) {
			vips_error( klass->nickname,
				_( "blend mode index %d (%d) invalid" ),
				i, mode[i] );
			return( -1 );
		}

		if( !vips_composite_mode_skippable( mode[i] ) )
			composite->skippable = FALSE;
	}

	in = (VipsImage **) composite->in->area.data;

	/* Make a set of rects for the positions of the input images. Image 0 
	 * (the background) is always at (0, 0).
	 */
	if( !(composite->subimages = 
		VIPS_ARRAY( NULL, n, VipsRect )) ) 
		return( -1 );
	for( int i = 0; i < n; i++ ) {
		composite->subimages[i].left = 0;
		composite->subimages[i].top = 0;
		composite->subimages[i].width = in[i]->Xsize;
		composite->subimages[i].height = in[i]->Ysize;
	}

	/* Position all images, if x/y is set. Image 0 
	 * (the background) is always at (0, 0).
	 */
	if( composite->x_offset &&
		composite->y_offset ) 
		for( int i = 1; i < n; i++ ) {
			composite->subimages[i].left = 
				composite->x_offset[i - 1];
			composite->subimages[i].top = 
				composite->y_offset[i - 1];
		}

	decode = (VipsImage **) vips_object_local_array( object, n );
	for( int i = 0; i < n; i++ )
		if( vips_image_decode( in[i], &decode[i] ) )
			return( -1 );
	in = decode;

	/* Add a solid alpha to any images missing one. 
	 */
	for( int i = n - 1; i >= 0; i-- )
		if( !vips_image_hasalpha( in[i] ) ) {
			VipsImage *x;

			if( vips_addalpha( in[i], &x, (void *) NULL ) )
				return( -1 );
			g_object_unref( in[i] );
			in[i] = x;
		}

	/* Transform to compositing space. It defaults to sRGB or B_W, usually 
	 * 8 bit, but 16 bit if any inputs are 16 bit.
	 */
	if( !vips_object_argument_isset( object, "compositing_space" ) ) {
		gboolean all_grey;
		gboolean any_16;

		all_grey = TRUE;
		for( int i = 0; i < n; i++ )
			if( in[i]->Bands > 2 ) {
				all_grey = FALSE;
				break;
			}

		any_16 = FALSE;
		for( int i = 0; i < n; i++ )
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
		vips_object_local_array( object, n );
	for( int i = 0; i < n; i++ )
		if( vips_colourspace( in[i], &compositing[i],
			composite->compositing_space, (void *) NULL ) )
			return( -1 );
	in = compositing;

	/* Check that they all now match in bands. This can fail for some
	 * input combinations.
	 */
	for( int i = 1; i < n; i++ )
		if( in[i]->Bands != in[0]->Bands ) {
			vips_error( klass->nickname, 
				"%s", _( "images do not have same "
					 "numbers of bands" ) );
			return( -1 );
		}

	if( in[0]->Bands > MAX_BANDS ) {
		vips_error( klass->nickname,
			"%s", _( "too many input bands" ) );
		return( -1 );
	}

	composite->bands = in[0]->Bands - 1;

	/* Set the max for each band now we know bands and compositing space.
	 */
	if( vips_composite_base_max_band( composite, composite->max_band ) ) {
		vips_error( klass->nickname, 
			"%s", _( "unsupported compositing space" ) );
		return( -1 ); 
	}

	/* Transform the input images to match in format. We may have
	 * mixed float and double, for example.  
	 */
	format = (VipsImage **) vips_object_local_array( object, n );
	if( vips__formatalike_vec( in, format, n ) )
		return( -1 );
	in = format;

	/* We want locality, so that we only prepare a few subimages each
	 * time.
	 */
	if( vips_image_pipeline_array( conversion->out,
		VIPS_DEMAND_STYLE_SMALLTILE, in ) )
		return( -1 );

	/* The output image is always the size of the base image.
	 */
	conversion->out->Xsize = in[0]->Xsize;
	conversion->out->Ysize = in[0]->Ysize;

	if( vips_image_generate( conversion->out,
		vips_composite_start, 
		vips_composite_base_gen, 
		vips_composite_stop,
		in, composite ) )
		return( -1 );

	return( 0 );
}

static void
vips_composite_base_class_init( VipsCompositeBaseClass *klass )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( klass );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( klass );
	VipsOperationClass *operation_class = VIPS_OPERATION_CLASS( klass );

	VIPS_DEBUG_MSG( "vips_composite_base_class_init\n" );

	gobject_class->dispose = vips_composite_base_dispose;
	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "composite_base";
	vobject_class->description = _( "blend images together" );
	vobject_class->build = vips_composite_base_build;

	operation_class->flags = VIPS_OPERATION_SEQUENTIAL;

	VIPS_ARG_ENUM( klass, "compositing_space", 10,
		_( "Compositing space" ),
		_( "Composite images in this colour space" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsCompositeBase, compositing_space ),
		VIPS_TYPE_INTERPRETATION, VIPS_INTERPRETATION_sRGB );

	VIPS_ARG_BOOL( klass, "premultiplied", 11,
		_( "Premultiplied" ),
		_( "Images have premultiplied alpha" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsCompositeBase, premultiplied ),
		FALSE );

}

static void
vips_composite_base_init( VipsCompositeBase *composite )
{
	composite->compositing_space = VIPS_INTERPRETATION_sRGB;
}

typedef struct _VipsComposite {
	VipsCompositeBase parent_instance;

	/* For N input images, N - 1 x coordinates.
	 */
	VipsArrayInt *x;

	/* For N input images, N - 1 y coordinates.
	 */
	VipsArrayInt *y;

} VipsComposite;

typedef VipsCompositeBaseClass VipsCompositeClass;

/* We need C linkage for this.
 */
extern "C" {
G_DEFINE_TYPE( VipsComposite, vips_composite, vips_composite_base_get_type() );
}

static int
vips_composite_build( VipsObject *object )
{
	VipsObjectClass *klass = VIPS_OBJECT_GET_CLASS( object );
	VipsCompositeBase *base = (VipsCompositeBase *) object;
	VipsComposite *composite = (VipsComposite *) object;

	int n;

	n = 0;
	if( vips_object_argument_isset( object, "in" ) ) 
		n = base->in->area.n;

	if( vips_object_argument_isset( object, "x" ) ) {
		if( composite->x->area.n != n - 1 ) {
			vips_error( klass->nickname, 
				_( "must be %d x coordinates" ), n - 1 );
			return( -1 );
		}
		base->x_offset = (int *) composite->x->area.data;
	}

	if( vips_object_argument_isset( object, "y" ) ) {
		if( composite->y->area.n != n - 1 ) {
			vips_error( klass->nickname, 
				_( "must be %d y coordinates" ), n - 1 );
			return( -1 );
		}
		base->y_offset = (int *) composite->y->area.data;
	}

	if( VIPS_OBJECT_CLASS( vips_composite_parent_class )->
		build( object ) )
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
		G_STRUCT_OFFSET( VipsCompositeBase, in ),
		VIPS_TYPE_ARRAY_IMAGE );

	VIPS_ARG_BOXED( klass, "mode", 3,
		_( "Blend modes" ),
		_( "Array of VipsBlendMode to join with" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsCompositeBase, mode ),
		VIPS_TYPE_ARRAY_INT );

	VIPS_ARG_BOXED( klass, "x", 4,
		_( "x coordinates" ),
		_( "Array of x coordinates to join at" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsComposite, x ),
		VIPS_TYPE_ARRAY_INT );

	VIPS_ARG_BOXED( klass, "y", 5,
		_( "y coordinates" ),
		_( "Array of y coordinates to join at" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsComposite, y ),
		VIPS_TYPE_ARRAY_INT );

}

static void
vips_composite_init( VipsComposite *composite )
{
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

/* See conversion.c for the doc comment.
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

typedef struct _VipsComposite2 {
	VipsCompositeBase parent_instance;

	VipsImage *base;
	VipsImage *overlay;
	VipsBlendMode mode;
	int x;
	int y;

} VipsComposite2;

typedef VipsCompositeBaseClass VipsComposite2Class;

/* We need C linkage for this.
 */
extern "C" {
G_DEFINE_TYPE( VipsComposite2, vips_composite2, vips_composite_base_get_type() );
}

static int
vips_composite2_build( VipsObject *object )
{
	VipsCompositeBase *base = (VipsCompositeBase *) object;
	VipsComposite2 *composite2 = (VipsComposite2 *) object;

	if( composite2->overlay &&
		composite2->base ) { 
		VipsImage *in[3];
		int mode[1];

		in[0] = composite2->base;
		in[1] = composite2->overlay;
		in[2] = NULL;
		base->in = vips_array_image_new( in, 2 );

		mode[0] = (int) composite2->mode;
		base->mode = vips_array_int_new( mode, 1 );
	}

	base->x_offset = &composite2->x;
	base->y_offset = &composite2->y;

	if( VIPS_OBJECT_CLASS( vips_composite2_parent_class )->build( object ) )
		return( -1 );

	return( 0 );
}

static void
vips_composite2_class_init( VipsCompositeClass *klass )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( klass );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( klass );
	VipsOperationClass *operation_class = VIPS_OPERATION_CLASS( klass );

	VIPS_DEBUG_MSG( "vips_composite_class_init\n" );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "composite2";
	vobject_class->description =
		_( "blend a pair of images with a blend mode" );
	vobject_class->build = vips_composite2_build;

	operation_class->flags = VIPS_OPERATION_SEQUENTIAL;

	VIPS_ARG_IMAGE( klass, "base", 0,
		_( "Base" ),
		_( "Base image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsComposite2, base ) );

	VIPS_ARG_IMAGE( klass, "overlay", 1,
		_( "Overlay" ),
		_( "Overlay image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsComposite2, overlay ) );

	VIPS_ARG_ENUM( klass, "mode", 3,
		_( "Blend mode" ),
		_( "VipsBlendMode to join with" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsComposite2, mode ),
		VIPS_TYPE_BLEND_MODE, VIPS_BLEND_MODE_OVER );

	VIPS_ARG_INT( klass, "x", 4,
		_( "x" ),
		_( "x position of overlay" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsComposite2, x ),
		-VIPS_MAX_COORD, VIPS_MAX_COORD, 0 );

	VIPS_ARG_INT( klass, "y", 5,
		_( "y" ),
		_( "y position of overlay" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsComposite2, y ),
		-VIPS_MAX_COORD, VIPS_MAX_COORD, 0 );

}

static void
vips_composite2_init( VipsComposite2 *composite2 )
{
}

/* See conversion.c for the doc comment.
 */

int
vips_composite2( VipsImage *base, VipsImage *overlay, VipsImage **out,
	VipsBlendMode mode, ... )
{
	va_list ap;
	int result;

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wvarargs"

	/* Triggers a clang compiler warning because mode might not be an int.
	 * I think the warning is harmless for all platforms we care about.
	 */
	va_start( ap, mode );

	g_assert( sizeof( mode ) == sizeof( int ) );

#pragma clang diagnostic pop

	result = vips_call_split( "composite2", ap, base, overlay, out, mode );
	va_end( ap );

	return( result );
}

