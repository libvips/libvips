/* yafrsmooth interpolator
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
 * 2008 (c) Nicolas Robidoux (developer of Yet Another Fast
 * Resampler).
 *
 * Acknowledgement: N. Robidoux's research on YAFRSMOOTH funded in part by
 * an NSERC (National Science and Engineering Research Council of
 * Canada) Discovery Grant.
 */

/* Hacked for vips by J. Cupitt, 12/11/08.
 *
 * Bicubic component replaced with the one from bicubbic.cpp.
 */

/*
 * YAFRSMOOTH = Yet Another Fast Resampler
 *
 * Yet Another Fast Resampler is a nonlinear resampler which consists
 * of a linear scheme (in this version, Catmull-Rom) plus a nonlinear
 * sharpening correction the purpose of which is the straightening of
 * diagonal interfaces between flat colour areas.
 *
 * Key properties:
 *
 * YAFRSMOOTH (smooth) is interpolatory:
 *
 * If asked for the value at the center of an input pixel, it will
 * return the corresponding value, unchanged.
 *
 * YAFRSMOOTH (smooth) preserves local averages:
 *
 * The average of the reconstructed intensity surface over any region
 * is the same as the average of the piecewise constant surface with
 * values over pixel areas equal to the input pixel values (the
 * "nearest neighbour" surface), except for a small amount of blur at
 * the boundary of the region. More precicely: YAFRSMOOTH (smooth) is a box
 * filtered exact area method.
 *
 * Main weaknesses of YAFRSMOOTH (smooth):
 *
 * Weakness 1: YAFRSMOOTH (smooth) improves on Catmull-Rom only for images
 * with at least a little bit of smoothness.
 *
 * Weakness 2: Catmull-Rom introduces a lot of haloing. YAFRSMOOTH (smooth)
 * is based on Catmull-Rom, and consequently it too introduces a lot
 * of haloing.
 *
 * More details regarding Weakness 1: 
 *
 * If a portion of the image is such that every pixel has immediate
 * neighbours in the horizontal and vertical directions which have
 * exactly the same pixel value, then YAFRSMOOTH (smooth) boils down to
 * Catmull-Rom, and the computation of the correction is a waste.
 * Extreme case: If all the pixels are either pure black or pure white
 * in some region, as in some text images (more generally, if the
 * region is "bichromatic"), then the YAFRSMOOTH (smooth) correction is 0 in
 * the interior of the bichromatic region.
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

/* "fast" floor() ... on my laptop, anyway.
 */
#define FLOOR( V ) ((V) >= 0 ? (int)(V) : (int)((V) - 1))

#ifndef restrict
#ifdef __restrict
#define restrict __restrict
#else
#ifdef __restrict__
#define restrict __restrict__
#else
#define restrict
#endif
#endif
#endif

/* Scale sharpening by this to normalise.
 */
#define SMOOTH_SHARPENING_SCALE (0.453125f)

/* Properties.
 */
enum {
	PROP_SHARPENING = 1,
	PROP_LAST
};


#define VIPS_TYPE_INTERPOLATE_YAFRSMOOTH \
	(vips_interpolate_yafrsmooth_get_type())
#define VIPS_INTERPOLATE_YAFRSMOOTH( obj ) \
	(G_TYPE_CHECK_INSTANCE_CAST( (obj), \
	VIPS_TYPE_INTERPOLATE_YAFRSMOOTH, VipsInterpolateYafrsmooth ))
#define VIPS_INTERPOLATE_YAFRSMOOTH_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_CAST( (klass), \
	VIPS_TYPE_INTERPOLATE_YAFRSMOOTH, VipsInterpolateYafrsmoothClass))
#define VIPS_IS_INTERPOLATE_YAFRSMOOTH( obj ) \
	(G_TYPE_CHECK_INSTANCE_TYPE( (obj), VIPS_TYPE_INTERPOLATE_YAFRSMOOTH ))
#define VIPS_IS_INTERPOLATE_YAFRSMOOTH_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_TYPE( (klass), VIPS_TYPE_INTERPOLATE_YAFRSMOOTH ))
#define VIPS_INTERPOLATE_YAFRSMOOTH_GET_CLASS( obj ) \
	(G_TYPE_INSTANCE_GET_CLASS( (obj), \
	VIPS_TYPE_INTERPOLATE_YAFRSMOOTH, VipsInterpolateYafrsmoothClass ))

typedef struct _VipsInterpolateYafrsmooth {
	VipsInterpolate parent_object;

	/* "sharpening" is a continuous method parameter which is
	 * proportional to the amount of "diagonal straightening" which the
	 * nonlinear correction part of the method may add to the underlying
	 * linear scheme. You may also think of it as a sharpening
	 * parameter: higher values correspond to more sharpening, and
	 * negative values lead to strange looking effects.
	 *
	 * The default value is sharpening = 29/32 when the scheme being
	 * "straightened" is Catmull-Rom---as is the case here. This value
	 * fixes key pixel values near the diagonal boundary between two
	 * monochrome regions (the diagonal boundary pixel values being set
	 * to the halfway colour).
	 *
	 * If resampling seems to add unwanted texture artifacts, push
	 * sharpening toward 0. It is not generally not recommended to set
	 * sharpening to a value larger than 4.
	 *
	 * Sharpening is halved because the .5 which has to do with the
	 * relative coordinates of the evaluation points (which has to do
	 * with .5*rite_width etc) is folded into the constant to save
	 * flops. Consequently, the largest recommended value of
	 * sharpening_over_two is 2=4/2.
	 *
	 * In order to simplify interfacing with users, the parameter which
	 * should be set by the user is normalized so that user_sharpening =
	 * 1 when sharpening is equal to the recommended value. Consistently
	 * with the above discussion, values of user_sharpening between 0
	 * and about 3.625 give good results.
	 */
	double sharpening;
} VipsInterpolateYafrsmooth;

typedef struct _VipsInterpolateYafrsmoothClass {
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
} VipsInterpolateYafrsmoothClass;

/* We need C linkage for this.
 */
extern "C" {
G_DEFINE_TYPE( VipsInterpolateYafrsmooth, vips_interpolate_yafrsmooth, 
	VIPS_TYPE_INTERPOLATE );
}

/* T is the type of pixels we are computing, D is a type large enough to hold
 * (Ta - Tb) ** 2.
 */

/* The 16 values for this interpolation, four constants for this
 * interpolation position.
 */

template <typename T, typename D> static float inline
yafrsmooth( 
	const T uno_one, const T uno_two, const T uno_thr, const T uno_fou,
	const T dos_one, const T dos_two, const T dos_thr, const T dos_fou,
	const T tre_one, const T tre_two, const T tre_thr, const T tre_fou,
	const T qua_one, const T qua_two, const T qua_thr, const T qua_fou,
	const double *c )
{
	/*
	 * Computation of the YAFRSMOOTH correction:
	 *
	 * Basically, if two consecutive pixel value differences have the
	 * same sign, the smallest one (in absolute value) is taken to be
	 * the corresponding slope. If they don't have the same sign, the
	 * corresponding slope is set to 0.
	 *
	 * Four such pairs (vertical and horizontal) of slopes need to be
	 * computed, one pair for each of the pixels which potentially
	 * overlap the unit area centered at the interpolation point.
	 */
	/*
	 * Beginning of the computation of the "up" horizontal slopes:
	 */
	const D prem__up = dos_two - dos_one;
	const D deux__up = dos_thr - dos_two;
	const D troi__up = dos_fou - dos_thr;
	/*
	 * "down" horizontal slopes:
	 */
	const D prem_dow = tre_two - tre_one;
	const D deux_dow = tre_thr - tre_two;
	const D troi_dow = tre_fou - tre_thr;
	/*
	 * "left" vertical slopes:
	 */
	const D prem_left = dos_two - uno_two;
	const D deux_left = tre_two - dos_two;
	const D troi_left = qua_two - tre_two;
	/*
	 * "right" vertical slopes:
	 */
	const D prem_rite = dos_thr - uno_thr;
	const D deux_rite = tre_thr - dos_thr;
	const D troi_rite = qua_thr - tre_thr;

	/*
	 * Back to "up":
	 */
	const D prem__up_squared = prem__up * prem__up;
	const D deux__up_squared = deux__up * deux__up;
	const D troi__up_squared = troi__up * troi__up;
	/*
	 * Back to "down":
	 */
	const D prem_dow_squared = prem_dow * prem_dow;
	const D deux_dow_squared = deux_dow * deux_dow;
	const D troi_dow_squared = troi_dow * troi_dow;
	/*
	 * Back to "left":
	 */
	const D prem_left_squared = prem_left * prem_left;
	const D deux_left_squared = deux_left * deux_left;
	const D troi_left_squared = troi_left * troi_left;
	/*
	 * Back to "right":
	 */
	const D prem_rite_squared = prem_rite * prem_rite;
	const D deux_rite_squared = deux_rite * deux_rite;
	const D troi_rite_squared = troi_rite * troi_rite;

	/*
	 * "up":
	 */
	const D prem__up_times_deux__up = prem__up * deux__up;
	const D deux__up_times_troi__up = deux__up * troi__up;
	/*
	 * "down":
	 */
	const D prem_dow_times_deux_dow = prem_dow * deux_dow;
	const D deux_dow_times_troi_dow = deux_dow * troi_dow;
	/*
	 * "left":
	 */
	const D prem_left_times_deux_left = prem_left * deux_left;
	const D deux_left_times_troi_left = deux_left * troi_left;
	/*
	 * "right":
	 */
	const D prem_rite_times_deux_rite = prem_rite * deux_rite;
	const D deux_rite_times_troi_rite = deux_rite * troi_rite;

	/*
	 * Branching parts of the computation of the YAFRSMOOTH correction 
	 * (could be unbranched using arithmetic branching and C99 math 
	 * intrinsics, although the compiler may be smart enough to remove 
	 * the branching on its own):
	 */
	/*
	 * "up":
	 */
	const D prem__up_vs_deux__up =
		prem__up_squared < deux__up_squared ? prem__up : deux__up;
	const D deux__up_vs_troi__up =
		deux__up_squared < troi__up_squared ? deux__up : troi__up;
	/*
	 * "down":
	 */
	const D prem_dow_vs_deux_dow =
		prem_dow_squared < deux_dow_squared ? prem_dow : deux_dow;
	const D deux_dow_vs_troi_dow =
		deux_dow_squared < troi_dow_squared ? deux_dow : troi_dow;
	/*
	 * "left":
	 */
	const D prem_left_vs_deux_left =
		prem_left_squared < deux_left_squared ? prem_left : deux_left;
	const D deux_left_vs_troi_left =
		deux_left_squared < troi_left_squared ? deux_left : troi_left;
	/*
	 * "right":
	 */
	const D prem_rite_vs_deux_rite =
		prem_rite_squared < deux_rite_squared ? prem_rite : deux_rite;
	const D deux_rite_vs_troi_rite =
		deux_rite_squared < troi_rite_squared ? deux_rite : troi_rite;

	/*
	 * Computation of the YAFRSMOOTH slopes.
	 */
	/*
	 * "up":
	 */
	const D mx_left__up =
		prem__up_times_deux__up < 0.f ? 0.f : prem__up_vs_deux__up;
	const D mx_rite__up =
		deux__up_times_troi__up < 0.f ? 0.f : deux__up_vs_troi__up;
	/*
	 * "down":
	 */
	const D mx_left_dow =
		prem_dow_times_deux_dow < 0.f ? 0.f : prem_dow_vs_deux_dow;
	const D mx_rite_dow =
		deux_dow_times_troi_dow < 0.f ? 0.f : deux_dow_vs_troi_dow;
	/*
	 * "left":
	 */
	const D my_left__up =
		prem_left_times_deux_left < 0.f ? 0.f : prem_left_vs_deux_left;
	const D my_left_dow =
		deux_left_times_troi_left < 0.f ? 0.f : deux_left_vs_troi_left;
	/*
	 * "right":
	 */
	const D my_rite__up =
		prem_rite_times_deux_rite < 0.f ? 0.f : prem_rite_vs_deux_rite;
	const D my_rite_dow =
		deux_rite_times_troi_rite < 0.f ? 0.f : deux_rite_vs_troi_rite;

	/*
	 * Assemble the unweighted YAFRSMOOTH correction:
	 */
	const float yafr = 
		c[0] * (mx_left__up - mx_rite__up) +
		c[1] * (mx_left_dow - mx_rite_dow) +
		c[2] * (my_left__up - my_left_dow) +
		c[3] * (my_rite__up - my_rite_dow);

	return( yafr );
}

/* Pointers to write to / read from, number of bands,
 * how many bytes to add to move down a line.
 */

/* T is the type of pixels we are reading and writing, D is a type large
 * enough to hold (T1 - T2) ** 2.
 */

/* Fixed-point version for 8/16 bit ints.
 */
template <typename T, typename D, int min_value, int max_value> 
static void inline
yafrsmooth_int_tab( PEL *pout, const PEL *pin, 
	const int bands, const int lskip, 
	const double sharpening,
	const int *cx, const int *cy, const double *cs )
{
	T* restrict out = (T *) pout;
	const T* restrict in = (T *) pin; 

	const int b1 = bands;
	const int b2 = 2 * bands;
	const int b3 = 3 * bands;

	const int l1 = lskip / sizeof( T );
	const int l2 = 2 * lskip / sizeof( T );
	const int l3 = 3 * lskip / sizeof( T );

	for( int z = 0; z < bands; z++ ) {

		const T uno_one = in[0];
		const T uno_two = in[b1];
		const T uno_thr = in[b2];
		const T uno_fou = in[b3];

		const T dos_one = in[l1];
		const T dos_two = in[b1 + l1];
		const T dos_thr = in[b2 + l1];
		const T dos_fou = in[b3 + l1];

		const T tre_one = in[l2];
		const T tre_two = in[b1 + l2];
		const T tre_thr = in[b2 + l2];
		const T tre_fou = in[b3 + l2];

		const T qua_one = in[l3];
		const T qua_two = in[b1 + l3];
		const T qua_thr = in[b2 + l3];
		const T qua_fou = in[b3 + l3];

		const int bicubic = bicubic_int<T>(
			uno_one, uno_two, uno_thr, uno_fou,
			dos_one, dos_two, dos_thr, dos_fou,
			tre_one, tre_two, tre_thr, tre_fou,
			qua_one, qua_two, qua_thr, qua_fou,
			cx, cy );

		const float yafr = yafrsmooth<T, D>(
			uno_one, uno_two, uno_thr, uno_fou,
			dos_one, dos_two, dos_thr, dos_fou,
			tre_one, tre_two, tre_thr, tre_fou,
			qua_one, qua_two, qua_thr, qua_fou,
			cs );

		int result = bicubic + 
			sharpening * SMOOTH_SHARPENING_SCALE * yafr;

		if( result < min_value )
			result = min_value;
		else if( result > max_value )
			result = max_value;

		*out = result;

		in += 1;
		out += 1;
	}
}

/* Float version for int/float types.
 */
template <typename T, typename D> static void inline
yafrsmooth_float_tab( PEL *pout, const PEL *pin, 
	const int bands, const int lskip, 
	const double sharpening,
	const double *cx, const double *cy, const double *cs )
{
	T* restrict out = (T *) pout;
	const T* restrict in = (T *) pin; 

	const int b1 = bands;
	const int b2 = 2 * bands;
	const int b3 = 3 * bands;

	const int l1 = lskip / sizeof( T );
	const int l2 = 2 * lskip / sizeof( T );
	const int l3 = 3 * lskip / sizeof( T );

	for( int z = 0; z < bands; z++ ) {

		const T uno_one = in[0];
		const T uno_two = in[b1];
		const T uno_thr = in[b2];
		const T uno_fou = in[b3];

		const T dos_one = in[l1];
		const T dos_two = in[b1 + l1];
		const T dos_thr = in[b2 + l1];
		const T dos_fou = in[b3 + l1];

		const T tre_one = in[l2];
		const T tre_two = in[b1 + l2];
		const T tre_thr = in[b2 + l2];
		const T tre_fou = in[b3 + l2];

		const T qua_one = in[l3];
		const T qua_two = in[b1 + l3];
		const T qua_thr = in[b2 + l3];
		const T qua_fou = in[b3 + l3];

		const T bicubic = bicubic_float<T>(
			uno_one, uno_two, uno_thr, uno_fou,
			dos_one, dos_two, dos_thr, dos_fou,
			tre_one, tre_two, tre_thr, tre_fou,
			qua_one, qua_two, qua_thr, qua_fou,
			cx, cy );

		const float yafr = yafrsmooth<T, D>(
			uno_one, uno_two, uno_thr, uno_fou,
			dos_one, dos_two, dos_thr, dos_fou,
			tre_one, tre_two, tre_thr, tre_fou,
			qua_one, qua_two, qua_thr, qua_fou,
			cs );

		*out = bicubic + sharpening * SMOOTH_SHARPENING_SCALE * yafr;

		in += 1;
		out += 1;
	}
}

/* Given an offset in [0,1], calculate c0, c1, c2, c3, the yafr-smooth pixel 
 * weights. 
 */
static void inline
calculate_coefficients_smooth( const double x, const double y, double c[4] )
{
	const double dx = 1.f - x;
	const double dy = 1.f - y;

	g_assert( x >= 0 && x < 1 );
	g_assert( y >= 0 && y < 1 );

	c[0] = dx * x * dy;
	c[1] = dx * x * y;
	c[2] = dy * y * dx;
	c[3] = dy * y * x;
}

/* High-quality double-only version.
 */
static void inline
yafrsmooth_notab( PEL *pout, const PEL *pin, 
	const int bands, const int lskip, 
	const double sharpening,
	double x, double y )
{
	double * restrict out = (double  *) pout;
	const double * restrict in = (double  *) pin; 

	const int b1 = bands;
	const int b2 = 2 * bands;
	const int b3 = 3 * bands;

	const int l1 = lskip / sizeof( double  );
	const int l2 = 2 * lskip / sizeof( double  );
	const int l3 = 3 * lskip / sizeof( double  );

	double cx[4];
	double cy[4];

	calculate_coefficients_catmull( x, cx );
	calculate_coefficients_catmull( y, cy );

	double cs[4];

	calculate_coefficients_smooth( x, y, cs );

	for( int z = 0; z < bands; z++ ) {
		const double uno_one = in[0];
		const double uno_two = in[b1];
		const double uno_thr = in[b2];
		const double uno_fou = in[b3];

		const double dos_one = in[l1];
		const double dos_two = in[b1 + l1];
		const double dos_thr = in[b2 + l1];
		const double dos_fou = in[b3 + l1];

		const double tre_one = in[l2];
		const double tre_two = in[b1 + l2];
		const double tre_thr = in[b2 + l2];
		const double tre_fou = in[b3 + l2];

		const double qua_one = in[l3];
		const double qua_two = in[b1 + l3];
		const double qua_thr = in[b2 + l3];
		const double qua_fou = in[b3 + l3];

		const double bicubic = bicubic_float<double>(
			uno_one, uno_two, uno_thr, uno_fou,
			dos_one, dos_two, dos_thr, dos_fou,
			tre_one, tre_two, tre_thr, tre_fou,
			qua_one, qua_two, qua_thr, qua_fou,
			cx, cy );

		const double yafr = yafrsmooth<double, double>(
			uno_one, uno_two, uno_thr, uno_fou,
			dos_one, dos_two, dos_thr, dos_fou,
			tre_one, tre_two, tre_thr, tre_fou,
			qua_one, qua_two, qua_thr, qua_fou,
			cs );

		*out = bicubic + sharpening * SMOOTH_SHARPENING_SCALE * yafr;

		in += 1;
		out += 1;
	}
}

static void
vips_interpolate_yafrsmooth_interpolate( VipsInterpolate *interpolate, 
	PEL *out, REGION *in, double x, double y )
{
	VipsInterpolateYafrsmoothClass *yafrsmooth_class = 
		VIPS_INTERPOLATE_YAFRSMOOTH_GET_CLASS( interpolate );
	VipsInterpolateYafrsmooth *yafrsmooth = 
		VIPS_INTERPOLATE_YAFRSMOOTH( interpolate );

	/* Scaled int. 
	 */
	const double sx = x * VIPS_TRANSFORM_SCALE;
	const double sy = y * VIPS_TRANSFORM_SCALE;
	const int sxi = FLOOR( sx );
	const int syi = FLOOR( sy );

	/* Get index into interpolation table and unscaled integer 
	 * position.
	 */
	const int tx = sxi & (VIPS_TRANSFORM_SCALE - 1);
	const int ty = syi & (VIPS_TRANSFORM_SCALE - 1);
	const int xi = sxi >> VIPS_TRANSFORM_SHIFT;
	const int yi = syi >> VIPS_TRANSFORM_SHIFT;

	/* Look up the tables we need.
	 */
	const int *cxi = yafrsmooth_class->matrixi[tx];
	const int *cyi = yafrsmooth_class->matrixi[ty];
	const double *cxf = yafrsmooth_class->matrixf[tx];
	const double *cyf = yafrsmooth_class->matrixf[ty];

	/* Position weights for yafrsmooth.
	 */
	double cs[4];
	calculate_coefficients_smooth( x - xi, y - yi, cs );

	/* Back and up one to get the top-left of the 4x4.
	 */
	const PEL *p = (PEL *) IM_REGION_ADDR( in, xi - 1, yi - 1 ); 

	/* Pel size and line size.
	 */
	const int bands = in->im->Bands; 
	const int lskip = IM_REGION_LSKIP( in );

#ifdef DEBUG
	printf( "vips_interpolate_yafrsmooth_interpolate: %g %g\n", x, y );
	printf( "\tleft=%d, top=%d, width=%d, height=%d\n", 
		xi - 1, yi - 1, 4, 4 ); 
#endif /*DEBUG*/

	switch( in->im->BandFmt ) {
	case IM_BANDFMT_UCHAR:
		yafrsmooth_int_tab<unsigned char, int, 0, UCHAR_MAX>( 
			out, p, bands, lskip, 
			yafrsmooth->sharpening,
			cxi, cyi, cs );
		break;

	case IM_BANDFMT_CHAR:
		yafrsmooth_int_tab<signed char, int, SCHAR_MIN, SCHAR_MAX>( 
			out, p, bands, lskip, 
			yafrsmooth->sharpening,
			cxi, cyi, cs );
		break;

	case IM_BANDFMT_USHORT:
		yafrsmooth_int_tab<unsigned short, int, 0, USHRT_MAX>( 
			out, p, bands, lskip, 
			yafrsmooth->sharpening,
			cxi, cyi, cs );
		break;

	case IM_BANDFMT_SHORT:
		yafrsmooth_int_tab<signed short, int, SHRT_MIN, SHRT_MAX>( 
			out, p, bands, lskip, 
			yafrsmooth->sharpening,
			cxi, cyi, cs );
		break;

	case IM_BANDFMT_UINT:
		yafrsmooth_float_tab<unsigned int, float>( 
			out, p, bands, lskip, 
			yafrsmooth->sharpening,
			cxf, cyf, cs );
		break;

	case IM_BANDFMT_INT:
		yafrsmooth_float_tab<signed int, float>( 
			out, p, bands, lskip, 
			yafrsmooth->sharpening,
			cxf, cyf, cs );
		break;

	case IM_BANDFMT_FLOAT:
		yafrsmooth_float_tab<float, float>( 
			out, p, bands, lskip, 
			yafrsmooth->sharpening,
			cxf, cyf, cs );
		break;

	case IM_BANDFMT_DOUBLE:
		yafrsmooth_notab( 
			out, p, bands, lskip, 
			yafrsmooth->sharpening,
			x - xi, y - yi );
		break;

	case IM_BANDFMT_COMPLEX:
		yafrsmooth_float_tab<float, float>( 
			out, p, bands * 2, lskip, 
			yafrsmooth->sharpening,
			cxf, cyf, cs );
		break;

	case IM_BANDFMT_DPCOMPLEX:
		yafrsmooth_notab( 
			out, p, bands * 2, lskip, 
			yafrsmooth->sharpening,
			x - xi, y - yi );
		break;

	default:
		break;
	}
}

static void
vips_interpolate_yafrsmooth_class_init( VipsInterpolateYafrsmoothClass *iclass )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( iclass );
	VipsObjectClass *object_class = VIPS_OBJECT_CLASS( iclass );
	VipsInterpolateClass *interpolate_class = 
		VIPS_INTERPOLATE_CLASS( iclass );

	GParamSpec *pspec;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "yafrsmooth";
	object_class->description = _( "Bicubic plus edge enhance" );

	interpolate_class->interpolate = 
		vips_interpolate_yafrsmooth_interpolate;
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

	/* Create properties.
	 */
	pspec = g_param_spec_double( "sharpening", 
		_( "Sharpening" ),
		_( "Degree of extra edge enhancement" ),
		0, 4, 1, 
		(GParamFlags) G_PARAM_READWRITE );
	g_object_class_install_property( gobject_class, 
		PROP_SHARPENING, pspec );
	vips_object_class_install_argument( object_class, pspec,
		VIPS_ARGUMENT_SET_ONCE,
		G_STRUCT_OFFSET( VipsInterpolateYafrsmooth, sharpening ) );
}

static void
vips_interpolate_yafrsmooth_init( VipsInterpolateYafrsmooth *yafrsmooth )
{
#ifdef DEBUG
	printf( "vips_interpolate_yafrsmooth_init: " );
	vips_object_print( VIPS_OBJECT( yafrsmooth ) );
#endif /*DEBUG*/

	yafrsmooth->sharpening = 1.0;
}
