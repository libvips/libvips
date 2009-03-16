/* nohalo interpolator
 */

/*

    This file is part of VIPS.

    VIPS is free software; you can redistribute it and/or modify it
    under the terms of the GNU Lesser General Public License as
    published by the Free Software Foundation; either version 2 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this program; if not, write to the Free
    Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
    02111-1307 USA

 */

/*

    These files are distributed with VIPS - http://www.vips.ecs.soton.ac.uk

 */

/*
 * 2009 (c) Nicolas Robidoux
 *
 * Nicolas thanks Geert Jordaens, John Cupitt, Minglun Gong, Øyvind
 * Kolås and Sven Neumann for useful comments and code.
 *
 * Nicolas Robidoux's research on nohalo funded in part by an NSERC
 * (National Science and Engineering Research Council of Canada)
 * Discovery Grant.
 */

/* Hacked for vips by J. Cupitt, 20/1/09
 * Tweaks by N. Robidoux and J. Cupitt 5-15/03/09
 */

/*
 * ================
 * NOHALO RESAMPLER
 * ================
 *
 * "Nohalo" is a family of parameterized resamplers with a mission:
 * smoothly straightening oblique lines without undesirable
 * side-effects.
 *
 * The key parameter, which may be described as a "quality" parameter,
 * is an integer which specifies the number of "levels" of binary
 * subdivision which are performed. level = 0 can be thought of as
 * being plain vanilla bilinear resampling; level = 1 is then the
 * first "non-classical" method of the familiy.
 *
 * Although it increases computational cost, additional levels
 * increase the quality of the resampled pixel value unless the
 * resampled location happens to be exactly where a subdivided grid
 * point (for this level) is located, in which case further levels do
 * not change the answer, and consequently do not increase its
 * quality.
 *
 * ===================================================
 * THIS CODE ONLY IMPLEMENTS THE LOWEST QUALITY NOHALO
 * ===================================================
 *
 * This code implement nohalo for (quality) level = 1.  Nohalo for
 * higher quality levels will be implemented later.
 *
 * Key properties:
 *
 * =======================
 * Nohalo is interpolatory
 * =======================
 *
 * That is, nohalo preserves point values: If asked for the value at
 * the center of an input pixel, the sampler returns the corresponding
 * value, unchanged. In addition, because nohalo is continuous, if
 * asked for a value at a location "very close" to the center of an
 * input pixel, then the sampler returns a value "very close" to
 * it. (Nohalo is not smoothing like, say, B-Spline
 * pseudo-interpolation.)
 *
 * ========================================================
 * Nohalo is co-monotone (this is why it's called "nohalo")
 * ========================================================
 *
 * What monotonicity means here is that the resampled value is in the
 * range of the four closest input values. Consequently, nohalo does
 * not add haloing. It also means that clamping is unnecessary
 * (provided abyss values are within the range of acceptable values,
 * which is always the case). (Note: plain vanilla bilinear is also
 * co-monotone.)
 *
 * Note: If the abyss policy is an extrapolating one---for example,
 * linear or bilinear extrapolation---clamping is still unnecessary
 * unless one attempts to resample outside of the convex hull of the
 * input pixel positions. Consequence: the "corner" image size
 * convention does not require clamping when using linear
 * extrapolation abyss policy when performing image resizing, but the
 * "center" one does, when upscaling, at locations very close to the
 * boundary. If computing values at locations outside of the convex
 * hull of the pixel locations of the input image, nearest neighbour
 * abyss policy is most likely better anyway, because linear
 * extrapolation produces "streaks" if positions far outside the
 * original image boundary are resampled.
 *
 * ========================
 * Nohalo is a local method
 * ========================
 *
 * The value of the reconstructed intensity surface at any point
 * depends on the values of (at most) 12 nearby input values, located
 * in a "cross" centered at the closest four input pixel centers.
 *
 * ===========================================================
 * When level = infinity, nohalo's intensity surface is smooth
 * ===========================================================
 *
 * It is conjectured that the intensity surface is infinitely
 * differentiable. Consequently, "Mach banding" (primarily caused by
 * sharp "ridges" in the reconstructed intensity surface and
 * particularly noticeable, for example, when using bilinear
 * resampling) is (essentially) absent, even at high magnifications,
 * WHEN THE LEVEL IS HIGH (more or less when 2^(level+1) is at least
 * the largest local magnification factor, which means that the level
 * 1 nohalo does not show much Mach banding up to a magnification of
 * about 4).
 *
 * ===============================
 * Nohalo is second order accurate
 * ===============================
 *
 * (Except possibly near the boundary: it is easy to make this
 * property carry over everywhere but this requires a tuned abyss
 * policy---linear extrapolation, say---or building the boundary
 * conditions inside the sampler.)  Nohalo is exact on linear
 * intensity profiles, meaning that if the input pixel values (in the
 * stencil) are obtained from a function of the form f(x,y) = a + b*x
 * + c*y (a, b, c constants), then the computed pixel value is exactly
 * the value of f(x,y) at the asked-for sampling location. The
 * boundary condition which is emulated by VIPS throught the "extend"
 * extension of the input image---this corresponds to the nearest
 * neighbour abyss policy---does NOT make this resampler exact on
 * linears at the boundary. It does, however, guarantee that no
 * clamping is required even when resampled values are computed at
 * positions outside of the extent of the input image (when
 * extrapolation is required).
 *
 * ===================
 * Nohalo is nonlinear
 * ===================
 *
 * In particular, resampling a sum of images may not be the same as
 * summing the resamples. (This occurs even without taking into account
 * over and underflow issues: images can only take values within a
 * banded range, and consequently no sampler is truly linear.)
 *
 * ====================
 * Weaknesses of nohalo
 * ====================
 *
 * In some cases, the first level nonlinear computation is wasted:
 *
 * If a region is bichromatic, the nonlinear component of the level 1
 * nohalo is zero in the interior of the region, and consequently
 * nohalo boils down to bilinear. For such images, either stick to
 * bilinear, or use a higher level (quality) setting. (There is no
 * real harm in using nohalo when it boils down to bilinear if one
 * does not mind wasting cycles.)
 *
 * Low quality levels do NOT produce a continuously differentiable
 * intensity surface:
 *
 * With a "finite" level is used (that is, in practice), the nohalo
 * intensity surface is only continuous: there are gradient
 * discontinuities because the "final interpolation step" is performed
 * with bilinear. (Exception: if the "corner" image size convention is
 * used and the magnification factor is 2, that is, if the resampled
 * points sit exactly on the binary subdivided grid, then nohalo level
 * 1 gives the same result as as level=infinity, and consequently the
 * intensity surface can be treated as if smooth.)
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

#ifndef vips_restrict
#ifdef __restrict
#define vips_restrict __restrict
#else
#ifdef __restrict__
#define vips_restrict __restrict__
#else
#define vips_restrict
#endif
#endif
#endif

/*
 * FAST_PSEUDO_FLOOR is a floor and floorf replacement which has been
 * found to be faster on several linux boxes than the library
 * version. It returns the floor of its argument unless the argument
 * is a negative integer, in which case it returns one less than the
 * floor. For example:
 *
 * FAST_PSEUDO_FLOOR(0.5) = 0
 *
 * FAST_PSEUDO_FLOOR(0.) = 0
 *
 * FAST_PSEUDO_FLOOR(-.5) = -1
 *
 * as expected, but
 *
 * FAST_PSEUDO_FLOOR(-1.) = -2
 *
 * The locations of the discontinuities of FAST_PSEUDO_FLOOR are the
 * same as floor and floorf; it is just that at negative integers the
 * function is discontinuous on the right instead of the left.
 */
#define FAST_PSEUDO_FLOOR(x) ( (int)(x) - ( (x) < 0. ) )

/*
 * FAST_MINMOD is an implementation of the minmod function which only
 * needs two conditional moves. (Most implementations need at least
 * three branches.) In the Nohalo code, the square of the first
 * argument is used in two different minmod computations. The product
 * is also precomputed to keep it out of branching way. (Nicolas: I
 * think that this may be the first two branch minmod.)
 */
#define FAST_MINMOD(a,b,ab,abminusaa) \
        ( (ab)>=0. ? ( (abminusaa)>=0. ? (a) : (b) ) : 0. )

#define VIPS_TYPE_INTERPOLATE_NOHALO \
	(vips_interpolate_nohalo_get_type())
#define VIPS_INTERPOLATE_NOHALO( obj ) \
	(G_TYPE_CHECK_INSTANCE_CAST( (obj), \
	VIPS_TYPE_INTERPOLATE_NOHALO, VipsInterpolateNohalo ))
#define VIPS_INTERPOLATE_NOHALO_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_CAST( (klass), \
	VIPS_TYPE_INTERPOLATE_NOHALO, VipsInterpolateNohaloClass))
#define VIPS_IS_INTERPOLATE_NOHALO( obj ) \
	(G_TYPE_CHECK_INSTANCE_TYPE( (obj), VIPS_TYPE_INTERPOLATE_NOHALO ))
#define VIPS_IS_INTERPOLATE_NOHALO_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_TYPE( (klass), VIPS_TYPE_INTERPOLATE_NOHALO ))
#define VIPS_INTERPOLATE_NOHALO_GET_CLASS( obj ) \
	(G_TYPE_INSTANCE_GET_CLASS( (obj), \
	VIPS_TYPE_INTERPOLATE_NOHALO, VipsInterpolateNohaloClass ))

typedef struct _VipsInterpolateNohalo {
	VipsInterpolate parent_object;

} VipsInterpolateNohalo;

typedef struct _VipsInterpolateNohaloClass {
	VipsInterpolateClass parent_class;

} VipsInterpolateNohaloClass;

static void inline
nohalo_sharp_level_1( const double                uno_two,
                      const double                uno_thr,
                      const double                dos_one,
                      const double                dos_two,
                      const double                dos_thr,
                      const double                dos_fou,
                      const double                tre_one,
                      const double                tre_two,
                      const double                tre_thr,
                      const double                tre_fou,
                      const double                qua_two,
                      const double                qua_thr,
                            double* vips_restrict r1,
                            double* vips_restrict r2,
                            double* vips_restrict r3 )
{
  /*
   * This function calculates the missing three double density pixel
   * values. The caller does bilinear interpolation on them and
   * dos_two.
   */
  /*
   * THE STENCIL OF INPUT VALUES:
   *
   * Nohalo's stencil is the same as, say, Catmull-Rom, with the
   * exception that the four corner values are not used:
   *
   *               (ix-1,iy-2)  (ix,iy-2)
   *               = uno_two    = uno_thr
   *
   *  (ix-2,iy-1)  (ix-1,iy-1)  (ix,iy-1)    (ix+1,iy-1)
   *  = dos_one    = dos_two    = dos_thr    = dos_fou
   *
   *  (ix-2,iy)    (ix-1,iy)    (ix,iy)      (ix+1,iy)
   *  = tre_one    = tre_two    = tre_thr    = tre_fou
   *
   *               (ix-1,iy+1)  (ix,iy+1)
   *               = qua_two    = qua_thr
   *
   * The indices associated with the values shown above are in the
   * case that the resampling point is closer to (ix-1,iy-1) than the
   * other three central positions. Pointer arithmetic is used to
   * implicitly reflect the input stencil in the other three cases,
   * For example, if the sampling position is closer to dos_two (that
   * is, if relative_x_is_rite = 1 but relative_y_is_down = 0 below),
   * then dos_two corresponds to (ix,iy-1), dos_thr corresponds to
   * (ix-1,iy-1) etc. Consequently, the three missing double density
   * values are halfway between dos_two and dos_thr, halfway between
   * dos_two and tre_two, and at the average of the four central
   * positions.
   */
  /*
   * Computation of the nonlinear slopes: If two consecutive pixel
   * value differences have the same sign, the smallest one (in
   * absolute value) is taken to be the corresponding slope; if the
   * two consecutive pixel value differences don't have the same sign,
   * the corresponding slope is set to 0. (In other words, apply
   * minmod to comsecutive slopes.)
   */
  /*
   * Dos(s) horizontal differences:
   */
  const double prem_dos = dos_two - dos_one;
  const double deux_dos = dos_thr - dos_two;
  const double troi_dos = dos_fou - dos_thr;
  /*
   * Tre(s) horizontal differences:
   */
  const double prem_tre = tre_two - tre_one;
  const double deux_tre = tre_thr - tre_two;
  const double troi_tre = tre_fou - tre_thr;
  /*
   * Two vertical differences:
   */
  const double prem_two = dos_two - uno_two;
  const double deux_two = tre_two - dos_two;
  const double troi_two = qua_two - tre_two;
  /*
   * Thr(ee) vertical differences:
   */
  const double prem_thr = dos_thr - uno_thr;
  const double deux_thr = tre_thr - dos_thr;
  const double troi_thr = qua_thr - tre_thr;

  /*
   * Useful sums:
   */
  const double dos_two_plus_dos_thr = dos_two + dos_thr;
  const double dos_two_plus_tre_two = dos_two + tre_two;

  /*
   * Products useful for minmod:
   */
  const double deux_prem_dos = deux_dos * prem_dos;
  const double deux_deux_dos = deux_dos * deux_dos;
  const double deux_troi_dos = deux_dos * troi_dos;

  const double deux_prem_two = deux_two * prem_two;
  const double deux_deux_two = deux_two * deux_two;
  const double deux_troi_two = deux_two * troi_two;

  const double deux_prem_tre = deux_tre * prem_tre;
  const double deux_deux_tre = deux_tre * deux_tre;
  const double deux_troi_tre = deux_tre * troi_tre;

  const double deux_prem_thr = deux_thr * prem_thr;
  const double deux_deux_thr = deux_thr * deux_thr;
  const double deux_troi_thr = deux_thr * troi_thr;

  /*
   * Useful sum:
   */
  const double deux_thr_plus_deux_dos = deux_thr + deux_dos;

  /*
   * Differences useful for minmod:
   */
  const double deux_prem_minus_deux_deux_dos = deux_prem_dos - deux_deux_dos;
  const double deux_troi_minus_deux_deux_dos = deux_troi_dos - deux_deux_dos;

  const double deux_prem_minus_deux_deux_two = deux_prem_two - deux_deux_two;
  const double deux_troi_minus_deux_deux_two = deux_troi_two - deux_deux_two;

  const double deux_prem_minus_deux_deux_tre = deux_prem_tre - deux_deux_tre;
  const double deux_troi_minus_deux_deux_tre = deux_troi_tre - deux_deux_tre;

  const double deux_prem_minus_deux_deux_thr = deux_prem_thr - deux_deux_thr;
  const double deux_troi_minus_deux_deux_thr = deux_troi_thr - deux_deux_thr;

  /*
   * Compute the needed "right" (at the boundary between one input
   * pixel areas) double resolution pixel value:
   */
  const double four_times_dos_twothr =
    FAST_MINMOD( deux_dos, prem_dos, deux_prem_dos,
                 deux_prem_minus_deux_deux_dos )
    -
    FAST_MINMOD( deux_dos, troi_dos, deux_troi_dos,
                 deux_troi_minus_deux_deux_dos )
    +
    2. * dos_two_plus_dos_thr;

  /*
   * Compute the needed "down" double resolution pixel value:
   */
  const double four_times_dostre_two =
    FAST_MINMOD( deux_two, prem_two, deux_prem_two,
                 deux_prem_minus_deux_deux_two )
    -
    FAST_MINMOD( deux_two, troi_two, deux_troi_two,
                 deux_troi_minus_deux_deux_two )
    +
    2. * dos_two_plus_tre_two;

  /*
   * Compute the "diagonal" (at the boundary between thrr input
   * pixel areas) double resolution pixel value:
   */
  const double piece_of_eight_times_dostre_twothr =
    four_times_dos_twothr
    +
    four_times_dostre_two
    +
    2. * deux_thr_plus_deux_dos;

  const double eight_times_dostre_twothr =
    piece_of_eight_times_dostre_twothr
    +
    FAST_MINMOD( deux_tre, prem_tre, deux_prem_tre,
                 deux_prem_minus_deux_deux_tre )
    -
    FAST_MINMOD( deux_tre, troi_tre, deux_troi_tre,
                 deux_troi_minus_deux_deux_tre )
    +
    FAST_MINMOD( deux_thr, prem_thr, deux_prem_thr,
                 deux_prem_minus_deux_deux_thr )
    -
    FAST_MINMOD( deux_thr, troi_thr, deux_troi_thr,
                 deux_troi_minus_deux_deux_thr );

  /*
   * Return the first newly computed double density values:
   */
  *r1 = four_times_dos_twothr;
  *r2 = four_times_dostre_two;
  *r3 = eight_times_dostre_twothr;
}

/* Call nohalo_sharp_level_1 with an interpolator as a parameter.
 * It'd be nice to do this with templates somehow :-( but I can't see a
 * clean way to do it.
 */
#define NOHALO_SHARP_LEVEL_1_INTER( inter ) \
  template <typename T> static void inline \
  nohalo_sharp_level_1_ ## inter(       PEL*   vips_restrict pout, \
                                  const PEL*   vips_restrict pin, \
                                  const int                  bands, \
                                  const int                  lskip, \
                                  const double               relative_x, \
                                  const double               relative_y ) \
  { \
    T* vips_restrict out = (T *) pout; \
    \
    const int relative_x_is_rite = ( relative_x >= 0. ); \
    const int relative_y_is_down = ( relative_y >= 0. ); \
    \
    const int sign_of_relative_x = 2 * relative_x_is_rite - 1; \
    const int sign_of_relative_y = 2 * relative_y_is_down - 1; \
    \
    const int corner_reflection_shift = \
      relative_x_is_rite * bands + relative_y_is_down * lskip; \
    \
    const T* vips_restrict in = ( (T *) pin ) + corner_reflection_shift; \
    \
    const int shift_1_pixel  = sign_of_relative_x * bands; \
    const int shift_1_row    = sign_of_relative_y * lskip; \
    \
    const double w = ( 2 * sign_of_relative_x ) * relative_x; \
    const double z = ( 2 * sign_of_relative_y ) * relative_y; \
    \
    const int uno_two_shift = shift_1_row; \
    const int uno_thr_shift = shift_1_row - shift_1_pixel; \
    \
    const int dos_one_shift = shift_1_pixel; \
    const int dos_two_shift = 0; \
    const int dos_thr_shift = -shift_1_pixel; \
    const int dos_fou_shift = -2 * shift_1_pixel; \
    \
    const int tre_one_shift = dos_one_shift - shift_1_row; \
    const int tre_two_shift = -shift_1_row; \
    const int tre_thr_shift = dos_thr_shift - shift_1_row; \
    const int tre_fou_shift = dos_fou_shift - shift_1_row; \
    \
    const int qua_two_shift = tre_two_shift - shift_1_row; \
    const int qua_thr_shift = tre_thr_shift - shift_1_row; \
    \
    const double x = 1. - w; \
    const double w_times_z = w * z; \
    const double x_times_z = x * z; \
    const double w_times_y_over_4 = .25  * ( w - w_times_z ); \
    const double x_times_z_over_4 = .25  * x_times_z; \
    const double x_times_y_over_8 = .125 * ( x - x_times_z ); \
    \
    int band = bands; \
    \
    do \
      { \
        double four_times_dos_twothr; \
        double four_times_dostre_two; \
        double eight_times_dostre_twothr; \
        \
        const double dos_two = in[dos_two_shift]; \
        \
        nohalo_sharp_level_1( in[uno_two_shift], in[uno_thr_shift], \
                              in[dos_one_shift], dos_two, \
                              in[dos_thr_shift], in[dos_fou_shift], \
                              in[tre_one_shift], in[tre_two_shift], \
                              in[tre_thr_shift], in[tre_fou_shift], \
                              in[qua_two_shift], in[qua_thr_shift], \
                              &four_times_dos_twothr, \
                              &four_times_dostre_two, \
                              &eight_times_dostre_twothr ); \
        \
        const T result = bilinear_ ## inter<T>( w_times_z, \
                                                x_times_z_over_4, \
                                                w_times_y_over_4, \
                                                x_times_y_over_8, \
                                                dos_two, \
                                                four_times_dos_twothr, \
                                                four_times_dostre_two, \
                                                eight_times_dostre_twothr ); \
        \
        in++; \
        *out++ = result; \
      } while (--band); \
  }

NOHALO_SHARP_LEVEL_1_INTER( float )
NOHALO_SHARP_LEVEL_1_INTER( signed )
NOHALO_SHARP_LEVEL_1_INTER( unsigned )

/* We need C linkage for this.
 */
extern "C" {
G_DEFINE_TYPE( VipsInterpolateNohalo, vips_interpolate_nohalo,
	VIPS_TYPE_INTERPOLATE );
}

static void
vips_interpolate_nohalo_interpolate( VipsInterpolate* vips_restrict interpolate,
                                     PEL*             vips_restrict out,
                                     REGION*          vips_restrict in,
                                     double                         absolute_x,
                                     double                         absolute_y )
{
  /*
   * VIPS versions of Nicolas's pixel addressing values. Double bands for
   * complex images.
   */
  const int lskip = IM_REGION_LSKIP( in ) / IM_IMAGE_SIZEOF_ELEMENT( in->im );
  const int bands_actual = in->im->Bands;
  const int bands =
    ( im_iscomplex( in->im ) ? 2 * bands_actual : bands_actual );

  /*
   * floor's surrogate FAST_PSEUDO_FLOOR is used to make sure that the
   * transition through 0 is smooth. If it is known that absolute_x
   * and absolute_y will never be less than 0, plain cast---that is,
   * const int ix = absolute_x---should be used instead.  Actually,
   * any function which agrees with floor for non-integer values, and
   * picks one of the two possibilities for integer values, can be
   * used. FAST_PSEUDO_FLOOR fits the bill.
   *
   * Then, x is the x-coordinate of the sampling point relative to the
   * position of the center of the convex hull of the 2x2 block of
   * closest pixels. Similarly for y. Range of values: [-.5,.5).
   */
  const double absolute_y_minus_half = absolute_y - .5;
  const double absolute_x_minus_half = absolute_x - .5;
  const int iy                       = FAST_PSEUDO_FLOOR (absolute_y);
  const double relative_y            = absolute_y_minus_half - iy;
  const int ix                       = FAST_PSEUDO_FLOOR (absolute_x);
  const double relative_x            = absolute_x_minus_half - ix;

  /*
   * Move the pointer to (the first band of) the top/left pixel
   * of the 2x2 group of pixel centers which contains the
   * sampling location in its convex hull:
   */
  const PEL * vips_restrict p = (PEL *) IM_REGION_ADDR( in, ix, iy );

#define CALL( T, inter ) \
  nohalo_sharp_level_1_ ## inter<T>( out, \
                                     p, \
                                     bands, \
                                     lskip, \
                                     relative_x, \
                                     relative_y );

	switch( in->im->BandFmt ) {
	case IM_BANDFMT_UCHAR:
		CALL( unsigned char, unsigned );
		break;

	case IM_BANDFMT_CHAR:
		CALL( signed char, signed );
		break;

	case IM_BANDFMT_USHORT:
		CALL( unsigned short, unsigned );
		break;

	case IM_BANDFMT_SHORT:
		CALL( signed short, signed );
		break;

	case IM_BANDFMT_UINT:
		CALL( unsigned int, unsigned );
		break;

	case IM_BANDFMT_INT:
		CALL( signed int, signed );
		break;

	/* Complex images handled by doubling of bands, see above.
	 */
	case IM_BANDFMT_FLOAT:
	case IM_BANDFMT_COMPLEX:
		CALL( float, float );
		break;

	case IM_BANDFMT_DOUBLE:
	case IM_BANDFMT_DPCOMPLEX:
		CALL( double, float );
		break;

	default:
		g_assert( 0 );
		break;
	}
}

static void
vips_interpolate_nohalo_class_init( VipsInterpolateNohaloClass *klass )
{
	VipsObjectClass *object_class = VIPS_OBJECT_CLASS( klass );
	VipsInterpolateClass *interpolate_class =
		VIPS_INTERPOLATE_CLASS( klass );

	object_class->nickname = "nohalo";
	object_class->description = _( "Edge-enhancing bilinear" );

	interpolate_class->interpolate =
		vips_interpolate_nohalo_interpolate;
	interpolate_class->window_size = 4;
}

static void
vips_interpolate_nohalo_init( VipsInterpolateNohalo *nohalo )
{
}
