/* horizontal cubic (catmull-rom) interpolator
 *
 * 26/1/16
 * 	- from bicubic.cpp
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

/* Cubic (Catmull-Rom) interpolator derived from Nicolas Robidoux's
 * original YAFR resampler with permission and thanks.
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

#include <vips/vips.h>
#include <vips/internal.h>

#include "templates.h"

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

#define VIPS_TYPE_INTERPOLATE_CUBICH \
	(vips_interpolate_cubich_get_type())
#define VIPS_INTERPOLATE_CUBICH( obj ) \
	(G_TYPE_CHECK_INSTANCE_CAST( (obj), \
	VIPS_TYPE_INTERPOLATE_CUBICH, VipsInterpolateCubich ))
#define VIPS_INTERPOLATE_CUBICH_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_CAST( (klass), \
	VIPS_TYPE_INTERPOLATE_CUBICH, VipsInterpolateCubichClass))
#define VIPS_IS_INTERPOLATE_CUBICH( obj ) \
	(G_TYPE_CHECK_INSTANCE_TYPE( (obj), VIPS_TYPE_INTERPOLATE_CUBICH ))
#define VIPS_IS_INTERPOLATE_CUBICH_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_TYPE( (klass), VIPS_TYPE_INTERPOLATE_CUBICH ))
#define VIPS_INTERPOLATE_CUBICH_GET_CLASS( obj ) \
	(G_TYPE_INSTANCE_GET_CLASS( (obj), \
	VIPS_TYPE_INTERPOLATE_CUBICH, VipsInterpolateCubichClass ))

typedef VipsInterpolate VipsInterpolateCubich;

typedef VipsInterpolateClass VipsInterpolateCubichClass;

/* Precalculated interpolation matrices. int (used for pel
 * sizes up to short), and double (for all others). We go to
 * scale + 1 so we can round-to-nearest safely.
 */

static int vips_cubich_matrixi[VIPS_TRANSFORM_SCALE + 1][4];
static double vips_cubich_matrixf[VIPS_TRANSFORM_SCALE + 1][4];

/* We need C linkage for this.
 */
extern "C" {
G_DEFINE_TYPE( VipsInterpolateCubich, vips_interpolate_cubich,
	VIPS_TYPE_INTERPOLATE );
}

/* Pointers to write to / read from, number of bands,
 * how many bytes to add to move down a line.
 */

/* T is the type of pixels we are reading and writing.
 */

/* Fixed-point version, for 8 and 16-bit types.
 */

template <typename T, int max_value>
static void inline
cubich_unsigned_int_tab( void *pout, const VipsPel *pin,
	const int bands, const int *cx )
{
	T* restrict out = (T *) pout;
	const T* restrict in = (T *) pin;

	const int b1 = bands;
	const int b2 = b1 + b1;
	const int b3 = b1 + b2;

	for( int z = 0; z < bands; z++ ) {
		const T one = in[0];
		const T two = in[b1];
		const T thr = in[b2];
		const T fou = in[b3];

		int cubich = cubic_unsigned_int<T>(
			one, two, thr, fou, cx );

		cubich = VIPS_CLIP( 0, cubich, max_value ); 

		out[z] = cubich;

		in += 1;
	}
}

template <typename T, int min_value, int max_value>
static void inline
cubich_signed_int_tab( void *pout, const VipsPel *pin,
	const int bands, const int *cx )
{
	T* restrict out = (T *) pout;
	const T* restrict in = (T *) pin;

	const int b1 = bands;
	const int b2 = b1 + b1;
	const int b3 = b1 + b2;

	for( int z = 0; z < bands; z++ ) {
		const T one = in[0];
		const T two = in[b1];
		const T thr = in[b2];
		const T fou = in[b3];

		int cubich = cubic_signed_int<T>(
			one, two, thr, fou, cx );

		cubich = VIPS_CLIP( min_value, cubich, max_value ); 

		out[z] = cubich;

		in += 1;
	}
}

/* Floating-point version, for int/float types.
 */
template <typename T>
static void inline
cubich_float_tab( void *pout, const VipsPel *pin,
	const int bands, const double *cx )
{
	T* restrict out = (T *) pout;
	const T* restrict in = (T *) pin;

	const int b1 = bands;
	const int b2 = b1 + b1;
	const int b3 = b1 + b2;

	for( int z = 0; z < bands; z++ ) {
		const T one = in[0];
		const T two = in[b1];
		const T thr = in[b2];
		const T fou = in[b3];

		const T cubich = cubic_float<T>(
			one, two, thr, fou, cx );

		out[z] = cubich;

		in += 1;
	}
}

/* Ultra-high-quality version for double images.
 */
template <typename T>
static void inline
cubich_notab( void *pout, const VipsPel *pin,
	const int bands, double x )
{
	T* restrict out = (T *) pout;
	const T* restrict in = (T *) pin;

	const int b1 = bands;
	const int b2 = b1 + b1;
	const int b3 = b1 + b2;

	double cx[4];

	calculate_coefficients_catmull( x, cx );

	for( int z = 0; z < bands; z++ ) {
		const T one = in[0];
		const T two = in[b1];
		const T thr = in[b2];
		const T fou = in[b3];

		const T cubich = cubic_float<T>(
			one, two, thr, fou, cx );

		out[z] = cubich;

		in += 1;
	}
}

static void
vips_interpolate_cubich_interpolate( VipsInterpolate *interpolate,
	void *out, VipsRegion *in, double x, double y )
{
	/* Find the mask index. We round-to-nearest, so we need to generate 
	 * indexes in 0 to VIPS_TRANSFORM_SCALE, 2^n + 1 values. We multiply 
	 * by 2 more than we need to, add one, mask, then shift down again to 
	 * get the extra range.
	 */
	const int sx = x * VIPS_TRANSFORM_SCALE * 2;

	const int six = sx & (VIPS_TRANSFORM_SCALE * 2 - 1);

	const int tx = (six + 1) >> 1;

	/* We know (x, y) are always positive, so we can just (int) them. 
	 */
	const int ix = (int) x;
	const int iy = (int) y;

	/* Back one to get the left of the 4x1.
	 */
	const VipsPel *p = VIPS_REGION_ADDR( in, ix - 1, iy ); 

	/* Look up the tables we need.
	 */
	const int *cxi = vips_cubich_matrixi[tx];
	const double *cxf = vips_cubich_matrixf[tx];

	/* Pel size and line size.
	 */
	const int bands = in->im->Bands;

	g_assert( ix - 1 >= in->valid.left );
	g_assert( iy >= in->valid.top );
	g_assert( ix + 2 < VIPS_RECT_RIGHT( &in->valid ) );
	g_assert( iy < VIPS_RECT_BOTTOM( &in->valid ) );
	g_assert( iy == y ); 

	/* Confirm that absolute_x >= 1, because of window_offset.
	 */
	g_assert( x >= 1.0 );

#ifdef DEBUG
	printf( "vips_interpolate_cubich_interpolate: %g %g\n", x, y );
	printf( "\tleft=%d, top=%d, width=%d, height=%d\n",
		ix - 1, iy, 4, 1 );
	printf( "\tmaskx=%d\n", tx );
#endif /*DEBUG*/

	switch( in->im->BandFmt ) {
	case VIPS_FORMAT_UCHAR:
		cubich_unsigned_int_tab<unsigned char, UCHAR_MAX>( 
			out, p, bands, cxi );

	/*

	   Handy for benchmarking

		cubich_float_tab<unsigned char>(
			out, p, bands, cxf );

		cubich_notab<unsigned char>(
			out, p, bands, x - ix );

	 */

		break;

	case VIPS_FORMAT_CHAR:
		cubich_signed_int_tab<signed char, SCHAR_MIN, SCHAR_MAX>(
			out, p, bands, cxi );
		break;

	case VIPS_FORMAT_USHORT:
		cubich_unsigned_int_tab<unsigned short, USHRT_MAX>(
			out, p, bands, cxi );
		break;

	case VIPS_FORMAT_SHORT:
		cubich_signed_int_tab<signed short, SHRT_MIN, SHRT_MAX>(
			out, p, bands, cxi );
		break;

	case VIPS_FORMAT_UINT:
		cubich_float_tab<unsigned int>( 
			out, p, bands, cxf );
		break;

	case VIPS_FORMAT_INT:
		cubich_float_tab<signed int>( 
			out, p, bands, cxf );
		break;

	case VIPS_FORMAT_FLOAT:
		cubich_float_tab<float>( 
			out, p, bands, cxf );
		break;

	case VIPS_FORMAT_DOUBLE:
		cubich_notab<double>( 
			out, p, bands, x - ix );
		break;

	case VIPS_FORMAT_COMPLEX:
		cubich_float_tab<float>( 
			out, p, bands * 2, cxf );
		break;

	case VIPS_FORMAT_DPCOMPLEX:
		cubich_notab<double>( 
			out, p, bands * 2, x - ix );
		break;

	default:
		break;
	}
}

static void
vips_interpolate_cubich_class_init( VipsInterpolateCubichClass *iclass )
{
	VipsObjectClass *object_class = VIPS_OBJECT_CLASS( iclass );
	VipsInterpolateClass *interpolate_class =
		VIPS_INTERPOLATE_CLASS( iclass );

	object_class->nickname = "cubich";
	object_class->description = 
		_( "horizontal cubic interpolation (Catmull-Rom)" );

	interpolate_class->interpolate = vips_interpolate_cubich_interpolate;
	interpolate_class->window_size = 4;

	/* Build the tables of pre-computed coefficients.
	 */
	for( int x = 0; x < VIPS_TRANSFORM_SCALE + 1; x++ ) {
		calculate_coefficients_catmull(
			(float) x / VIPS_TRANSFORM_SCALE,
			vips_cubich_matrixf[x] );

		for( int i = 0; i < 4; i++ )
			vips_cubich_matrixi[x][i] =
				vips_cubich_matrixf[x][i] * 
				VIPS_INTERPOLATE_SCALE;
	}
}

static void
vips_interpolate_cubich_init( VipsInterpolateCubich *cubich )
{
#ifdef DEBUG
	printf( "vips_interpolate_cubich_init: " );
	vips_object_print( VIPS_OBJECT( cubich ) );
#endif /*DEBUG*/

}

