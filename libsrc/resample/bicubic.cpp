/* bicubic ... catmull-rom interpolator
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

/* Bicubic (catmull-rom) interpolator derived from Nicolas Robidoux's YAFR
 * resampler with permission and thanks.
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

typedef struct _VipsInterpolateBicubic {
	VipsInterpolate parent_object;

} VipsInterpolateBicubic;

typedef struct _VipsInterpolateBicubicClass {
	VipsInterpolateClass parent_class;

	/* Precalculated interpolation matricies. int (used for pel sizes up 
	 * to short), and double (for all others). We go to scale + 1, so
	 * we can round-to-nearest safely.
	 */

	/* We could keep a large set of 2d 4x4 matricies, but this actually
	 * works out slower, since for many resizes the thing will no longer
	 * fit in L1.
	 */
	int matrixi[VIPS_TRANSFORM_SCALE + 1][4];
	double matrixf[VIPS_TRANSFORM_SCALE + 1][4];
} VipsInterpolateBicubicClass;

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
template <typename T, int min_value, int max_value> 
static void inline
bicubic_int_tab( PEL *pout, const PEL *pin, 
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

		int bicubic = bicubic_int<T>(
			uno_one, uno_two, uno_thr, uno_fou,
			dos_one, dos_two, dos_thr, dos_fou,
			tre_one, tre_two, tre_thr, tre_fou,
			qua_one, qua_two, qua_thr, qua_fou,
			cx, cy );

		if( bicubic < min_value )
			bicubic = min_value;
		else if( bicubic > max_value )
			bicubic = max_value;

		out[z] = bicubic;

		in += 1;
	}
}

/* Floating-point version, for int/float types.
 */
template <typename T> 
static void inline
bicubic_float_tab( PEL *pout, const PEL *pin, 
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
bicubic_notab( PEL *pout, const PEL *pin, 
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
	PEL *out, REGION *in, double x, double y )
{
	VipsInterpolateBicubicClass *bicubic_class = 
		VIPS_INTERPOLATE_BICUBIC_GET_CLASS( interpolate );

	/* Scaled int. 
	 */
	const double sx = x * VIPS_TRANSFORM_SCALE;
	const double sy = y * VIPS_TRANSFORM_SCALE;
	const int sxi = FAST_PSEUDO_FLOOR( sx );
	const int syi = FAST_PSEUDO_FLOOR( sy );

	/* Get index into interpolation table and unscaled integer 
	 * position.
	 */
	const int tx = sxi & (VIPS_TRANSFORM_SCALE - 1);
	const int ty = syi & (VIPS_TRANSFORM_SCALE - 1);
	const int ix = sxi >> VIPS_TRANSFORM_SHIFT;
	const int iy = syi >> VIPS_TRANSFORM_SHIFT;

	/* Look up the tables we need.
	 */
	const int *cxi = bicubic_class->matrixi[tx];
	const int *cyi = bicubic_class->matrixi[ty];
	const double *cxf = bicubic_class->matrixf[tx];
	const double *cyf = bicubic_class->matrixf[ty];

	/* Back and up one to get the top-left of the 4x4.
	 */
	const PEL *p = (PEL *) IM_REGION_ADDR( in, ix - 1, iy - 1 ); 

	/* Pel size and line size.
	 */
	const int bands = in->im->Bands; 
	const int lskip = IM_REGION_LSKIP( in );

#ifdef DEBUG
	printf( "vips_interpolate_bicubic_interpolate: %g %g\n", x, y );
	printf( "\tleft=%d, top=%d, width=%d, height=%d\n", 
		ix - 1, iy - 1, 4, 4 ); 
#endif /*DEBUG*/

	switch( in->im->BandFmt ) {
	case IM_BANDFMT_UCHAR:
		bicubic_int_tab<unsigned char, 0, UCHAR_MAX>( 
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

	case IM_BANDFMT_CHAR:
		bicubic_int_tab<signed char, SCHAR_MIN, SCHAR_MAX>( 
			out, p, bands, lskip, 
			cxi, cyi );
		break;

	case IM_BANDFMT_USHORT:
		bicubic_int_tab<unsigned short, 0, USHRT_MAX>( 
			out, p, bands, lskip, 
			cxi, cyi );
		break;

	case IM_BANDFMT_SHORT:
		bicubic_int_tab<signed short, SHRT_MIN, SHRT_MAX>( 
			out, p, bands, lskip, 
			cxi, cyi );
		break;

	case IM_BANDFMT_UINT:
		bicubic_float_tab<unsigned int>( out, p, bands, lskip, 
			cxf, cyf );
		break;

	case IM_BANDFMT_INT:
		bicubic_float_tab<signed int>( out, p, bands, lskip, 
			cxf, cyf );
		break;

	case IM_BANDFMT_FLOAT:
		bicubic_float_tab<float>( out, p, bands, lskip, 
			cxf, cyf );
		break;

	case IM_BANDFMT_DOUBLE:
		bicubic_notab<double>( out, p, bands, lskip, 
			x - ix, y - iy );
		break;

	case IM_BANDFMT_COMPLEX:
		bicubic_float_tab<float>( out, p, bands * 2, lskip, 
			cxf, cyf );
		break;

	case IM_BANDFMT_DPCOMPLEX:
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
	object_class->description = _( "Bicubic interpolation (Catmull-Rom)" );

	interpolate_class->interpolate = vips_interpolate_bicubic_interpolate;
	interpolate_class->window_size = 4;

	/* Build the tables of pre-computed coefficients.
	 */
	for( int x = 0; x < VIPS_TRANSFORM_SCALE + 1; x++ ) {
		calculate_coefficients_catmull( 
			(float) x / VIPS_TRANSFORM_SCALE, 
			iclass->matrixf[x] );

		for( int i = 0; i < 4; i++ )
			iclass->matrixi[x][i] = 
				iclass->matrixf[x][i] * VIPS_INTERPOLATE_SCALE;
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

