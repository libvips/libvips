/* bicubic (catmull-rom) interpolator
 *
 * 12/8/10
 * 	- revise window_size / window_offset stuff again
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

/* Bicubic (Catmull-Rom) interpolator derived from Nicolas Robidoux's
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

#define VIPS_TYPE_INTERPOLATE_BICUBIC \
	(vips_interpolate_bicubic_get_type())
#define VIPS_INTERPOLATE_BICUBIC( obj ) \
	(G_TYPE_CHECK_INSTANCE_CAST( (obj), \
	VIPS_TYPE_INTERPOLATE_BICUBIC, VipsInterpolateBicubic ))
#define VIPS_INTERPOLATE_BICUBIC_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_CAST( (klass), \
	VIPS_TYPE_INTERPOLATE_BICUBIC, VipsInterpolateBicubicClass))
#define VIPS_IS_INTERPOLATE_BICUBIC( obj ) \
	(G_TYPE_CHECK_INSTANCE_TYPE( (obj), VIPS_TYPE_INTERPOLATE_BICUBIC ))
#define VIPS_IS_INTERPOLATE_BICUBIC_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_TYPE( (klass), VIPS_TYPE_INTERPOLATE_BICUBIC ))
#define VIPS_INTERPOLATE_BICUBIC_GET_CLASS( obj ) \
	(G_TYPE_INSTANCE_GET_CLASS( (obj), \
	VIPS_TYPE_INTERPOLATE_BICUBIC, VipsInterpolateBicubicClass ))

typedef VipsInterpolate VipsInterpolateBicubic;

typedef VipsInterpolateClass VipsInterpolateBicubicClass;

/* Precalculated interpolation matrices. int (used for pel
 * sizes up to short), and double (for all others). We go to
 * scale + 1 so we can round-to-nearest safely.
 */

/* We could keep a large set of 2d 4x4 matricies, but this actually
 * works out slower since for many resizes the thing will no longer
 * fit in L1.
 */
static int vips_bicubic_matrixi[VIPS_TRANSFORM_SCALE + 1][4];
static double vips_bicubic_matrixf[VIPS_TRANSFORM_SCALE + 1][4];

/* We need C linkage for this.
 */
extern "C" {
G_DEFINE_TYPE( VipsInterpolateBicubic, vips_interpolate_bicubic,
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
bicubic_unsigned_int_tab( void *pout, const VipsPel *pin,
	const int bands, const int lskip,
	const int *cx, const int *cy )
{
	T* restrict out = (T *) pout;
	const T* restrict in = (T *) pin;

	const int b1 = bands;
	const int b2 = b1 + b1;
	const int b3 = b1 + b2;

	const int l1 = lskip / sizeof( T );
	const int l2 = l1 + l1;
	const int l3 = l1 + l2;

        const int l1_plus_b1 = l1 + b1;
        const int l1_plus_b2 = l1 + b2;
        const int l1_plus_b3 = l1 + b3;
        const int l2_plus_b1 = l2 + b1;
        const int l2_plus_b2 = l2 + b2;
        const int l2_plus_b3 = l2 + b3;
        const int l3_plus_b1 = l3 + b1;
        const int l3_plus_b2 = l3 + b2;
        const int l3_plus_b3 = l3 + b3;

	for( int z = 0; z < bands; z++ ) {
		const T uno_one = in[0];
		const T uno_two = in[b1];
		const T uno_thr = in[b2];
		const T uno_fou = in[b3];

		const T dos_one = in[l1];
		const T dos_two = in[l1_plus_b1];
		const T dos_thr = in[l1_plus_b2];
		const T dos_fou = in[l1_plus_b3];

		const T tre_one = in[l2];
		const T tre_two = in[l2_plus_b1];
		const T tre_thr = in[l2_plus_b2];
		const T tre_fou = in[l2_plus_b3];

		const T qua_one = in[l3];
		const T qua_two = in[l3_plus_b1];
		const T qua_thr = in[l3_plus_b2];
		const T qua_fou = in[l3_plus_b3];

		out[z] = bicubic_unsigned_int<T>(
			uno_one, uno_two, uno_thr, uno_fou,
			dos_one, dos_two, dos_thr, dos_fou,
			tre_one, tre_two, tre_thr, tre_fou,
			qua_one, qua_two, qua_thr, qua_fou,
			cx, cy );

		if( out[z] < 0 )
			out[z] = 0;
		else if( out[z] > max_value )
			out[z] = max_value;

		in += 1;
	}
}

template <typename T, int min_value, int max_value>
static void inline
bicubic_signed_int_tab( void *pout, const VipsPel *pin,
	const int bands, const int lskip,
	const int *cx, const int *cy )
{
	T* restrict out = (T *) pout;
	const T* restrict in = (T *) pin;

	const int b1 = bands;
	const int b2 = b1 + b1;
	const int b3 = b1 + b2;

	const int l1 = lskip / sizeof( T );
	const int l2 = l1 + l1;
	const int l3 = l1 + l2;

        const int l1_plus_b1 = l1 + b1;
        const int l1_plus_b2 = l1 + b2;
        const int l1_plus_b3 = l1 + b3;
        const int l2_plus_b1 = l2 + b1;
        const int l2_plus_b2 = l2 + b2;
        const int l2_plus_b3 = l2 + b3;
        const int l3_plus_b1 = l3 + b1;
        const int l3_plus_b2 = l3 + b2;
        const int l3_plus_b3 = l3 + b3;

	for( int z = 0; z < bands; z++ ) {
		const T uno_one = in[0];
		const T uno_two = in[b1];
		const T uno_thr = in[b2];
		const T uno_fou = in[b3];

		const T dos_one = in[l1];
		const T dos_two = in[l1_plus_b1];
		const T dos_thr = in[l1_plus_b2];
		const T dos_fou = in[l1_plus_b3];

		const T tre_one = in[l2];
		const T tre_two = in[l2_plus_b1];
		const T tre_thr = in[l2_plus_b2];
		const T tre_fou = in[l2_plus_b3];

		const T qua_one = in[l3];
		const T qua_two = in[l3_plus_b1];
		const T qua_thr = in[l3_plus_b2];
		const T qua_fou = in[l3_plus_b3];

		out[z] = bicubic_signed_int<T>(
			uno_one, uno_two, uno_thr, uno_fou,
			dos_one, dos_two, dos_thr, dos_fou,
			tre_one, tre_two, tre_thr, tre_fou,
			qua_one, qua_two, qua_thr, qua_fou,
			cx, cy );

		if( out[z] < min_value )
			out[z] = min_value;
		else if( out[z] > max_value )
			out[z] = max_value;

		in += 1;
	}
}

/* Floating-point version, for int/float types.
 */
template <typename T>
static void inline
bicubic_float_tab( void *pout, const VipsPel *pin,
	const int bands, const int lskip,
	const double *cx, const double *cy )
{
	T* restrict out = (T *) pout;
	const T* restrict in = (T *) pin;

	const int b1 = bands;
	const int b2 = b1 + b1;
	const int b3 = b1 + b2;

	const int l1 = lskip / sizeof( T );
	const int l2 = l1 + l1;
	const int l3 = l1 + l2;

        const int l1_plus_b1 = l1 + b1;
        const int l1_plus_b2 = l1 + b2;
        const int l1_plus_b3 = l1 + b3;
        const int l2_plus_b1 = l2 + b1;
        const int l2_plus_b2 = l2 + b2;
        const int l2_plus_b3 = l2 + b3;
        const int l3_plus_b1 = l3 + b1;
        const int l3_plus_b2 = l3 + b2;
        const int l3_plus_b3 = l3 + b3;

	for( int z = 0; z < bands; z++ ) {
		const T uno_one = in[0];
		const T uno_two = in[b1];
		const T uno_thr = in[b2];
		const T uno_fou = in[b3];

		const T dos_one = in[l1];
		const T dos_two = in[l1_plus_b1];
		const T dos_thr = in[l1_plus_b2];
		const T dos_fou = in[l1_plus_b3];

		const T tre_one = in[l2];
		const T tre_two = in[l2_plus_b1];
		const T tre_thr = in[l2_plus_b2];
		const T tre_fou = in[l2_plus_b3];

		const T qua_one = in[l3];
		const T qua_two = in[l3_plus_b1];
		const T qua_thr = in[l3_plus_b2];
		const T qua_fou = in[l3_plus_b3];

		const T bicubic = bicubic_float<T>(
			uno_one, uno_two, uno_thr, uno_fou,
			dos_one, dos_two, dos_thr, dos_fou,
			tre_one, tre_two, tre_thr, tre_fou,
			qua_one, qua_two, qua_thr, qua_fou,
			cx, cy );

		out[z] = bicubic;

		in += 1;
	}
}

/* Ultra-high-quality version for double images.
 */
template <typename T>
static void inline
bicubic_notab( void *pout, const VipsPel *pin,
	const int bands, const int lskip,
	double x, double y )
{
	T* restrict out = (T *) pout;
	const T* restrict in = (T *) pin;

	const int b1 = bands;
	const int b2 = b1 + b1;
	const int b3 = b1 + b2;

	const int l1 = lskip / sizeof( T );
	const int l2 = l1 + l1;
	const int l3 = l1 + l2;

        const int l1_plus_b1 = l1 + b1;
        const int l1_plus_b2 = l1 + b2;
        const int l1_plus_b3 = l1 + b3;
        const int l2_plus_b1 = l2 + b1;
        const int l2_plus_b2 = l2 + b2;
        const int l2_plus_b3 = l2 + b3;
        const int l3_plus_b1 = l3 + b1;
        const int l3_plus_b2 = l3 + b2;
        const int l3_plus_b3 = l3 + b3;

	double cx[4];
	double cy[4];

	calculate_coefficients_catmull( x, cx );
	calculate_coefficients_catmull( y, cy );

	for( int z = 0; z < bands; z++ ) {
		const T uno_one = in[0];
		const T uno_two = in[b1];
		const T uno_thr = in[b2];
		const T uno_fou = in[b3];

		const T dos_one = in[l1];
		const T dos_two = in[l1_plus_b1];
		const T dos_thr = in[l1_plus_b2];
		const T dos_fou = in[l1_plus_b3];

		const T tre_one = in[l2];
		const T tre_two = in[l2_plus_b1];
		const T tre_thr = in[l2_plus_b2];
		const T tre_fou = in[l2_plus_b3];

		const T qua_one = in[l3];
		const T qua_two = in[l3_plus_b1];
		const T qua_thr = in[l3_plus_b2];
		const T qua_fou = in[l3_plus_b3];

		const T bicubic = bicubic_float<T>(
			uno_one, uno_two, uno_thr, uno_fou,
			dos_one, dos_two, dos_thr, dos_fou,
			tre_one, tre_two, tre_thr, tre_fou,
			qua_one, qua_two, qua_thr, qua_fou,
			cx, cy );

		out[z] = bicubic;

		in += 1;
	}
}

static void
vips_interpolate_bicubic_interpolate( VipsInterpolate *interpolate,
	void *out, VipsRegion *in, double x, double y )
{
	/* Find the mask index. We round-to-nearest, so we need to generate 
	 * indexes in 0 to VIPS_TRANSFORM_SCALE, 2^n + 1 values. We multiply 
	 * by 2 more than we need to, add one, mask, then shift down again to 
	 * get the extra range.
	 */
	const int sx = x * VIPS_TRANSFORM_SCALE * 2;
	const int sy = y * VIPS_TRANSFORM_SCALE * 2;

	const int six = sx & (VIPS_TRANSFORM_SCALE * 2 - 1);
	const int siy = sy & (VIPS_TRANSFORM_SCALE * 2 - 1);

	const int tx = (six + 1) >> 1;
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
	const int *cxi = vips_bicubic_matrixi[tx];
	const int *cyi = vips_bicubic_matrixi[ty];
	const double *cxf = vips_bicubic_matrixf[tx];
	const double *cyf = vips_bicubic_matrixf[ty];

	/* Pel size and line size.
	 */
	const int bands = in->im->Bands;
	const int lskip = VIPS_REGION_LSKIP( in );

	g_assert( ix - 1 >= in->valid.left );
	g_assert( iy - 1 >= in->valid.top );
	g_assert( ix + 2 < VIPS_RECT_RIGHT( &in->valid ) );
	g_assert( iy + 2 < VIPS_RECT_BOTTOM( &in->valid ) );

	/* Confirm that absolute_x and absolute_y are >= 1, because of
	 * window_offset.
	 */
	g_assert( x >= 1.0 );
	g_assert( y >= 1.0 );

#ifdef DEBUG
	printf( "vips_interpolate_bicubic_interpolate: %g %g\n", x, y );
	printf( "\tleft=%d, top=%d, width=%d, height=%d\n",
		ix - 1, iy - 1, 4, 4 );
	printf( "\tmaskx=%d, masky=%d\n", tx, ty );
#endif /*DEBUG*/

	switch( in->im->BandFmt ) {
	case VIPS_FORMAT_UCHAR:
		bicubic_unsigned_int_tab<unsigned char, UCHAR_MAX>(
			out, p, bands, lskip,
			cxi, cyi );

	/*

	   Handy for benchmarking

		bicubic_float_tab<unsigned char>(
			out, p, bands, lskip,
			cxf, cyf );

		bicubic_notab<unsigned char>(
			out, p, bands, lskip,
			x - ix, y - iy );

	 */

		break;

	case VIPS_FORMAT_CHAR:
		bicubic_signed_int_tab<signed char, SCHAR_MIN, SCHAR_MAX>(
			out, p, bands, lskip,
			cxi, cyi );
		break;

	case VIPS_FORMAT_USHORT:
		bicubic_unsigned_int_tab<unsigned short, USHRT_MAX>(
			out, p, bands, lskip,
			cxi, cyi );
		break;

	case VIPS_FORMAT_SHORT:
		bicubic_signed_int_tab<signed short, SHRT_MIN, SHRT_MAX>(
			out, p, bands, lskip,
			cxi, cyi );
		break;

	case VIPS_FORMAT_UINT:
		bicubic_float_tab<unsigned int>( out, p, bands, lskip,
			cxf, cyf );
		break;

	case VIPS_FORMAT_INT:
		bicubic_float_tab<signed int>( out, p, bands, lskip,
			cxf, cyf );
		break;

	case VIPS_FORMAT_FLOAT:
		bicubic_float_tab<float>( out, p, bands, lskip,
			cxf, cyf );
		break;

	case VIPS_FORMAT_DOUBLE:
		bicubic_notab<double>( out, p, bands, lskip,
			x - ix, y - iy );
		break;

	case VIPS_FORMAT_COMPLEX:
		bicubic_float_tab<float>( out, p, bands * 2, lskip,
			cxf, cyf );
		break;

	case VIPS_FORMAT_DPCOMPLEX:
		bicubic_notab<double>( out, p, bands * 2, lskip,
			x - ix, y - iy );
		break;

	default:
		break;
	}
}

static void
vips_interpolate_bicubic_class_init( VipsInterpolateBicubicClass *iclass )
{
	VipsObjectClass *object_class = VIPS_OBJECT_CLASS( iclass );
	VipsInterpolateClass *interpolate_class =
		VIPS_INTERPOLATE_CLASS( iclass );

	object_class->nickname = "bicubic";
	object_class->description = _( "bicubic interpolation (Catmull-Rom)" );

	interpolate_class->interpolate = vips_interpolate_bicubic_interpolate;
	interpolate_class->window_size = 4;

	/* Build the tables of pre-computed coefficients.
	 */
	for( int x = 0; x < VIPS_TRANSFORM_SCALE + 1; x++ ) {
		calculate_coefficients_catmull(
			(float) x / VIPS_TRANSFORM_SCALE,
			vips_bicubic_matrixf[x] );

		for( int i = 0; i < 4; i++ )
			vips_bicubic_matrixi[x][i] =
				vips_bicubic_matrixf[x][i] * 
				VIPS_INTERPOLATE_SCALE;
	}
}

static void
vips_interpolate_bicubic_init( VipsInterpolateBicubic *bicubic )
{
#ifdef DEBUG
	printf( "vips_interpolate_bicubic_init: " );
	vips_object_print( VIPS_OBJECT( bicubic ) );
#endif /*DEBUG*/

}

