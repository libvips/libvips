/* vertical cubic (catmull-rom) interpolator
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

#define VIPS_TYPE_INTERPOLATE_CUBICV \
	(vips_interpolate_cubicv_get_type())
#define VIPS_INTERPOLATE_CUBICV( obj ) \
	(G_TYPE_CHECK_INSTANCE_CAST( (obj), \
	VIPS_TYPE_INTERPOLATE_CUBICV, VipsInterpolateCubicv ))
#define VIPS_INTERPOLATE_CUBICV_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_CAST( (klass), \
	VIPS_TYPE_INTERPOLATE_CUBICV, VipsInterpolateCubicvClass))
#define VIPS_IS_INTERPOLATE_CUBICV( obj ) \
	(G_TYPE_CHECK_INSTANCE_TYPE( (obj), VIPS_TYPE_INTERPOLATE_CUBICV ))
#define VIPS_IS_INTERPOLATE_CUBICV_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_TYPE( (klass), VIPS_TYPE_INTERPOLATE_CUBICV ))
#define VIPS_INTERPOLATE_CUBICV_GET_CLASS( obj ) \
	(G_TYPE_INSTANCE_GET_CLASS( (obj), \
	VIPS_TYPE_INTERPOLATE_CUBICV, VipsInterpolateCubicvClass ))

typedef VipsInterpolate VipsInterpolateCubicv;

typedef VipsInterpolateClass VipsInterpolateCubicvClass;

/* Precalculated interpolation matrices. int (used for pel
 * sizes up to short), and double (for all others). We go to
 * scale + 1 so we can round-to-nearest safely.
 */

/* We could keep a large set of 2d 4x4 matricies, but this actually
 * works out slower since for many resizes the thing will no longer
 * fit in L1.
 */
static int vips_cubicv_matrixi[VIPS_TRANSFORM_SCALE + 1][4];
static double vips_cubicv_matrixf[VIPS_TRANSFORM_SCALE + 1][4];

/* We need C linkage for this.
 */
extern "C" {
G_DEFINE_TYPE( VipsInterpolateCubicv, vips_interpolate_cubicv,
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
cubicv_unsigned_int_tab( void *pout, const VipsPel *pin,
	const int bands, const int lskip,
	const int *cy )
{
	T* restrict out = (T *) pout;
	const T* restrict in = (T *) pin;

	const int l1 = lskip / sizeof( T );
	const int l2 = l1 + l1;
	const int l3 = l1 + l2;

	for( int z = 0; z < bands; z++ ) {
		const T uno = in[0];
		const T dos = in[l1];
		const T tre = in[l2];
		const T qua = in[l3];

		int cubicv = cubic_unsigned_int<T>( uno, dos, tre, qua, cy );

		cubicv = VIPS_CLIP( 0, cubicv, max_value ); 

		out[z] = cubicv;

		in += 1;
	}
}

template <typename T, int min_value, int max_value>
static void inline
cubicv_signed_int_tab( void *pout, const VipsPel *pin,
	const int bands, const int lskip,
	const int *cy )
{
	T* restrict out = (T *) pout;
	const T* restrict in = (T *) pin;

	const int l1 = lskip / sizeof( T );
	const int l2 = l1 + l1;
	const int l3 = l1 + l2;

	for( int z = 0; z < bands; z++ ) {
		const T uno = in[0];
		const T dos = in[l1];
		const T tre = in[l2];
		const T qua = in[l3];

		int cubicv = cubic_signed_int<T>( uno, dos, tre, qua, cy );

		cubicv = VIPS_CLIP( min_value, cubicv, max_value ); 

		out[z] = cubicv;

		in += 1;
	}
}

/* Floating-point version, for int/float types.
 */
template <typename T>
static void inline
cubicv_float_tab( void *pout, const VipsPel *pin,
	const int bands, const int lskip,
	const double *cy )
{
	T* restrict out = (T *) pout;
	const T* restrict in = (T *) pin;

	const int l1 = lskip / sizeof( T );
	const int l2 = l1 + l1;
	const int l3 = l1 + l2;

	for( int z = 0; z < bands; z++ ) {
		const T uno = in[0];
		const T dos = in[l1];
		const T tre = in[l2];
		const T qua = in[l3];

		out[z] = cubic_float<T>( uno, dos, tre, qua, cy );

		in += 1;
	}
}

/* Ultra-high-quality version for double images.
 */
template <typename T>
static void inline
cubicv_notab( void *pout, const VipsPel *pin,
	const int bands, const int lskip,
	double y )
{
	T* restrict out = (T *) pout;
	const T* restrict in = (T *) pin;

	const int l1 = lskip / sizeof( T );
	const int l2 = l1 + l1;
	const int l3 = l1 + l2;

	double cy[4];

	calculate_coefficients_catmull( y, cy );

	for( int z = 0; z < bands; z++ ) {
		const T uno = in[0];
		const T dos = in[l1];
		const T tre = in[l2];
		const T qua = in[l3];

		out[z] = cubic_float<T>( uno, dos, tre, qua, cy );

		in += 1;
	}
}

static void
vips_interpolate_cubicv_interpolate( VipsInterpolate *interpolate,
	void *out, VipsRegion *in, double x, double y )
{
	/* Find the mask index. We round-to-nearest, so we need to generate 
	 * indexes in 0 to VIPS_TRANSFORM_SCALE, 2^n + 1 values. We multiply 
	 * by 2 more than we need to, add one, mask, then shift down again to 
	 * get the extra range.
	 */
	const int sy = y * VIPS_TRANSFORM_SCALE * 2;

	const int siy = sy & (VIPS_TRANSFORM_SCALE * 2 - 1);

	const int ty = (siy + 1) >> 1;

	/* We know x/y are always positive, so we can just (int) them. 
	 */
	const int ix = (int) x;
	const int iy = (int) y;

	/* Back and up one to get the top-left of the 4x4.
	 */
	const VipsPel *p = VIPS_REGION_ADDR( in, ix - 1, iy - 1 ); 

	/* Look up the tables we need.
	 */
	const int *cyi = vips_cubicv_matrixi[ty];
	const double *cyf = vips_cubicv_matrixf[ty];

	/* Pel size and line size.
	 */
	const int bands = in->im->Bands;
	const int lskip = VIPS_REGION_LSKIP( in );

	g_assert( ix >= in->valid.left );
	g_assert( iy - 1 >= in->valid.top );
	g_assert( ix < VIPS_RECT_RIGHT( &in->valid ) );
	g_assert( iy + 2 < VIPS_RECT_BOTTOM( &in->valid ) );
	g_assert( ix == x ); 

	/* Confirm that absolute_y is >= 1, because of window_offset.
	 */
	g_assert( y >= 1.0 );

#ifdef DEBUG
	printf( "vips_interpolate_cubicv_interpolate: %g %g\n", x, y );
	printf( "\tleft=%d, top=%d, width=%d, height=%d\n",
		ix, iy - 1, 1, 4 );
	printf( "\tmasky=%d\n", ty );
#endif /*DEBUG*/

	switch( in->im->BandFmt ) {
	case VIPS_FORMAT_UCHAR:
		cubicv_unsigned_int_tab<unsigned char, UCHAR_MAX>(
			out, p, bands, lskip,
			cyi );

	/*

	   Handy for benchmarking

		cubicv_float_tab<unsigned char>(
			out, p, bands, lskip,
			cyf );

		cubicv_notab<unsigned char>(
			out, p, bands, lskip,
			y - iy );

	 */

		break;

	case VIPS_FORMAT_CHAR:
		cubicv_signed_int_tab<signed char, SCHAR_MIN, SCHAR_MAX>(
			out, p, bands, lskip, cyi );
		break;

	case VIPS_FORMAT_USHORT:
		cubicv_unsigned_int_tab<unsigned short, USHRT_MAX>(
			out, p, bands, lskip, cyi );
		break;

	case VIPS_FORMAT_SHORT:
		cubicv_signed_int_tab<signed short, SHRT_MIN, SHRT_MAX>(
			out, p, bands, lskip, cyi );
		break;

	case VIPS_FORMAT_UINT:
		cubicv_float_tab<unsigned int>( out, p, bands, lskip, cyf );
		break;

	case VIPS_FORMAT_INT:
		cubicv_float_tab<signed int>( out, p, bands, lskip, cyf );
		break;

	case VIPS_FORMAT_FLOAT:
		cubicv_float_tab<float>( out, p, bands, lskip, cyf );
		break;

	case VIPS_FORMAT_DOUBLE:
		cubicv_notab<double>( out, p, bands, lskip, y - iy );
		break;

	case VIPS_FORMAT_COMPLEX:
		cubicv_float_tab<float>( out, p, bands * 2, lskip, cyf );
		break;

	case VIPS_FORMAT_DPCOMPLEX:
		cubicv_notab<double>( out, p, bands * 2, lskip, y - iy );
		break;

	default:
		break;
	}
}

static void
vips_interpolate_cubicv_class_init( VipsInterpolateCubicvClass *iclass )
{
	VipsObjectClass *object_class = VIPS_OBJECT_CLASS( iclass );
	VipsInterpolateClass *interpolate_class =
		VIPS_INTERPOLATE_CLASS( iclass );

	object_class->nickname = "cubicv";
	object_class->description = 
		_( "vertical cubic interpolation (Catmull-Rom)" );

	interpolate_class->interpolate = vips_interpolate_cubicv_interpolate;
	interpolate_class->window_size = 4;

	/* Build the tables of pre-computed coefficients.
	 */
	for( int y = 0; y < VIPS_TRANSFORM_SCALE + 1; y++ ) {
		calculate_coefficients_catmull(
			(float) y / VIPS_TRANSFORM_SCALE,
			vips_cubicv_matrixf[y] );

		for( int i = 0; i < 4; i++ )
			vips_cubicv_matrixi[y][i] =
				vips_cubicv_matrixf[y][i] * 
				VIPS_INTERPOLATE_SCALE;
	}
}

static void
vips_interpolate_cubicv_init( VipsInterpolateCubicv *cubicv )
{
#ifdef DEBUG
	printf( "vips_interpolate_cubicv_init: " );
	vips_object_print( VIPS_OBJECT( cubicv ) );
#endif /*DEBUG*/

}

