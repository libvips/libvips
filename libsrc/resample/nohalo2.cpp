/* nohalo level 2 interpolator
 *
 * N. Robidoux based on code by N. Robidoux and J. Cupitt 01/4-29/5/09
 *
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
 * Nicolas thanks Geert Jordaens, Ralf Meyer, John Cupitt, Øyvind
 * Kolås, Minglun Gong and Sven Neumann for useful comments and code.
 *
 * Nicolas Robidoux's research on nohalo funded in part by an NSERC
 * (National Science and Engineering Research Council of Canada)
 * Discovery Grant.
 */

/*
 * ================
 * NOHALO RESAMPLER
 * ================
 *
 * "Nohalo" is a family of parameterized resamplers with a mission:
 * smoothly straightening oblique lines without undesirable
 * side-effects. In particular, without much blurring and with
 * absolutely no added haloing.
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
 * ==========================================================
 * THIS CODE ONLY IMPLEMENTS THE SECOND LOWEST QUALITY NOHALO
 * ==========================================================
 *
 * This code implement nohalo for (quality) level = 2.  Nohalo for
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
 * What monotonicity more or less means here is that the resampled
 * value is in the range of the four closest input values. This
 * property is why there is no added haloing. It also implies that
 * clamping is unnecessary (provided abyss values are within the range
 * of acceptable values, which is always the case). (Note: plain
 * vanilla bilinear is also co-monotone.)
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
 * depends on the values of (at most) 19 nearby input values. An
 * explanatory diagram is found below.
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
 * used and the magnification factor is 4, that is, if the resampled
 * points sit exactly on the binary subdivided grid, then nohalo level
 * 2 gives the same result as as level=infinity, and consequently the
 * intensity surface can be treated as if smooth.)
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <stdlib.h>

/*
 * THIS CODE ALMOST CERTAINLY HAS A SMALL BUG. Nicolas Robidoux May
 * 31, 2009.
 */


#include <vips/vips.h>
#include <vips/internal.h>

#include "templates.h"

#define VIPS_TYPE_INTERPOLATE_NOHALO2 \
	(vips_interpolate_nohalo2_get_type())
#define VIPS_INTERPOLATE_NOHALO2( obj ) \
	(G_TYPE_CHECK_INSTANCE_CAST( (obj), \
	VIPS_TYPE_INTERPOLATE_NOHALO2, VipsInterpolateNohalo2 ))
#define VIPS_INTERPOLATE_NOHALO2_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_CAST( (klass), \
	VIPS_TYPE_INTERPOLATE_NOHALO2, VipsInterpolateNohalo2Class))
#define VIPS_IS_INTERPOLATE_NOHALO2( obj ) \
	(G_TYPE_CHECK_INSTANCE_TYPE( (obj), VIPS_TYPE_INTERPOLATE_NOHALO2 ))
#define VIPS_IS_INTERPOLATE_NOHALO2_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_TYPE( (klass), VIPS_TYPE_INTERPOLATE_NOHALO2 ))
#define VIPS_INTERPOLATE_NOHALO2_GET_CLASS( obj ) \
	(G_TYPE_INSTANCE_GET_CLASS( (obj), \
	VIPS_TYPE_INTERPOLATE_NOHALO2, VipsInterpolateNohalo2Class ))

typedef struct _VipsInterpolateNohalo2 {
	VipsInterpolate parent_object;

} VipsInterpolateNohalo2;

typedef struct _VipsInterpolateNohalo2Class {
	VipsInterpolateClass parent_class;

} VipsInterpolateNohalo2Class;

static void inline
nohalo_step2( const double           uno_two,
              const double           uno_thr,
              const double           dos_one,
              const double           dos_two,
              const double           dos_thr,
              const double           dos_fou,
              const double           tre_one,
              const double           tre_two,
              const double           tre_thr,
              const double           tre_fou,
              const double           qua_two,
              const double           qua_thr,
                    double* restrict r0,
                    double* restrict r1,
                    double* restrict r2,
                    double* restrict r3 )
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
   *               (ix,iy-1)    (ix+1,iy-1)
   *               = uno_two    = uno_thr
   *
   *  (ix-1,iy)    (ix,iy)      (ix+1,iy)    (ix+2,iy)
   *  = dos_one    = dos_two    = dos_thr    = dos_fou
   *
   *  (ix-1,iy+1)  (ix,iy+1)    (ix+1,iy+1)  (ix+2,iy+1)
   *  = tre_one    = tre_two    = tre_thr    = tre_fou
   *
   *               (ix,iy+2)    (ix+1,iy+2)
   *               = qua_two    = qua_thr
   *
   * Here, ix is the floor of the requested left-to-right location, iy
   * is the floor of the requested up-to-down location.
   *
   * Pointer arithmetic is used to implicitly reflect the input
   * stencil so that the requested pixel location is closer to
   * dos_two, The above consequently corresponds to the case in which
   * absolute_x is closer to ix than ix+1, and absolute_y is closer to
   * iy than iy+1. For example, if relative_x_is_rite = 1 but
   * relative_y_is_down = 0 (see below), then dos_two corresponds to
   * (ix+1,iy), dos_thr corresponds to (ix,iy) etc. Consequently, the
   * three missing double density values (corresponding to r1, r2 and
   * r3) are halfway between dos_two and dos_thr, halfway between
   * dos_two and tre_two, and at the average of the four central
   * positions.
   *
   * The following code assumes that the stencil reflection has
   * already been performed.
   */

  /*
   * Computation of the nonlinear slopes: If two consecutive pixel
   * value differences have the same sign, the smallest one (in
   * absolute value) is taken to be the corresponding slope; if the
   * two consecutive pixel value differences don't have the same sign,
   * the corresponding slope is set to 0. In other words, apply minmod
   * to comsecutive differences.
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
   * The following terms are computed here to put "space" between the
   * computation of components of flag variables and their use:
   */
  const double twice_dos_two_plus_dos_thr = ( dos_two + dos_thr ) * 2.;
  const double twice_dos_two_plus_tre_two = ( dos_two + tre_two ) * 2.;
  const double twice_deux_thr_plus_deux_dos = ( deux_thr + deux_dos ) * 2.;

  /*
   * Compute the needed "right" (at the boundary between one input
   * pixel areas) double resolution pixel value:
   */
  const double four_times_dos_twothr =
    twice_dos_two_plus_dos_thr
    +
    FAST_MINMOD( deux_dos, prem_dos, deux_prem_dos,
                 deux_prem_minus_deux_deux_dos )
    -
    FAST_MINMOD( deux_dos, troi_dos, deux_troi_dos,
                 deux_troi_minus_deux_deux_dos );

  /*
   * Compute the needed "down" double resolution pixel value:
   */
  const double four_times_dostre_two =
    twice_dos_two_plus_tre_two
    +
    FAST_MINMOD( deux_two, prem_two, deux_prem_two,
                 deux_prem_minus_deux_deux_two )
    -
    FAST_MINMOD( deux_two, troi_two, deux_troi_two,
                 deux_troi_minus_deux_deux_two );

  /*
   * Compute the "diagonal" (at the boundary between thrr input
   * pixel areas) double resolution pixel value:
   */
  const double eight_times_dostre_twothr =
    twice_deux_thr_plus_deux_dos
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
                 deux_troi_minus_deux_deux_thr )
    +
    four_times_dos_twothr
    +
    four_times_dostre_two;

  /*
   * Return the first newly computed double density values:
   */
  *r0 = dos_two;
  *r1 = four_times_dos_twothr;
  *r2 = four_times_dostre_two;
  *r3 = eight_times_dostre_twothr;
}

static void inline
nohalo_step1( const double           uno_thr,
              const double           uno_fou,
              const double           dos_two,
              const double           dos_thr,
              const double           dos_fou,
              const double           dos_fiv,
              const double           tre_one,
              const double           tre_two,
              const double           tre_thr,
              const double           tre_fou,
              const double           tre_fiv,
              const double           qua_one,
              const double           qua_two,
              const double           qua_thr,
              const double           qua_fou,
              const double           qua_fiv,
              const double           cin_two,
              const double           cin_thr,
              const double           cin_fou,
                    double* restrict uno_two_1,
                    double* restrict uno_thr_1,
                    double* restrict dos_one_1,
                    double* restrict dos_two_1,
                    double* restrict dos_thr_1,
                    double* restrict dos_fou_1,
                    double* restrict tre_one_1,
                    double* restrict tre_two_1,
                    double* restrict tre_thr_1,
                    double* restrict tre_fou_1,
                    double* restrict qua_two_1,
                    double* restrict qua_thr_1 )
{
  /*
   * This function calculates the missing ten double density pixel
   * values, and also returns the "already known" two, for a total of
   * twelve, which fills the stencil of nohalo level 1. The caller
   * then applies one level of nohalo subdivision to these 12 values,
   * prior to applying bilinear interpolation.
   */
  /*
   * THE STENCIL OF INPUT VALUES:
   *
   * Pointer arithmetic is used to implicitly reflect the input
   * stencil so that the requested pixel location (indicated by X
   * below) is closer to tre_thr than the other three points which
   * define the convex hull of input pixel positions in which it sits,
   *
   * The following code and picture assumes that the stencil reflexion
   * has already been performed.
   *
   *
   *                            (ix,iy-2)    (ix+1,iy-2)
   *                            = uno_thr    = uno_fou
   *
   *
   *
   *               (ix-1,iy-1)  (ix,iy-1)    (ix+1,iy-1)  (ix+2,iy-1)
   *               = dos_two    = dos_thr    = dos_fou    = dos_fiv
   *
   *
   *
   *  (ix-2,iy)    (ix-1,iy)    (ix,iy)      (ix+1,iy)    (ix+2,iy)
   *  = tre_one    = tre_two    = tre_thr    = tre_fou    = tre_fiv
   *                                     X
   *
   *
   *  (ix-2,iy)    (ix-1,iy+1)  (ix,iy+1)    (ix+1,iy+1)  (ix+2,iy+1)
   *  = qua_one    = qua_two    = qua_thr    = qua_fou    = qua_fiv
   *
   *
   *
   *               (ix-1,iy+2)  (ix,iy+2)    (ix+1,iy+2)
   *               = cin_two    = cin_thr    = cin_fou
   *
   *
   * Here, ix is the (pseudo-)floor of the requested left-to-right
   * location, iy is the floor of the requested up-to-down location.
   *
   * The above input pixel values are the ones needed in order to make
   * available to the second level the following first (and
   * zero=input) level values:
   *
   *                   uno_two_1 =  uno_thr_1 =
   *                   (ix,iy-1/2)  (ix+1/2,iy-1/2)
   *
   *
   *
   *
   *  dos_one_1 =      dos_two_1 =  dos_thr_1 =      dos_fou_1 =
   *  (ix-1/2,iy)      (ix,iy)      (ix+1/2,iy)      (ix+1,iy)
   *
   *                             X
   *
   *
   *  tre_one_1 =      tre_two_1 =  tre_thr_1 =      tre_fou_1 =
   *  (ix-1/2,iy+1/2)  (ix,iy+1/2)  (ix+1/2,iy+1/2)  (ix+1,iy+1/2)
   *
   *
   *
   *
   *                   qua_two_1 =  qua_thr_1 =
   *                   (ix,iy+1)    (ix+1/2,iy+1)
   *
   *
   * to which nohalo level 1 is applied by the caller.
   */

  /*
   * Computation of the nonlinear slopes: If two consecutive pixel
   * value differences have the same sign, the smallest one (in
   * absolute value) is taken to be the corresponding slope; if the
   * two consecutive pixel value differences don't have the same sign,
   * the corresponding slope is set to 0. In other words, apply minmod
   * to comsecutive differences.
   */
  /*
   * Two vertical simple differences:
   */
  const double d_dostre_two = tre_two - dos_two;
  const double d_trequa_two = qua_two - tre_two;
  const double d_quacin_two = cin_two - qua_two;
  /*
   * Thr(ee) vertical differences:
   */
  const double d_unodos_thr = dos_thr - uno_thr;
  const double d_dostre_thr = tre_thr - dos_thr;
  const double d_trequa_thr = qua_thr - tre_thr;
  const double d_quacin_thr = cin_thr - qua_thr;
  /*
   * Fou(r) vertical differences:
   */
  const double d_unodos_fou = dos_fou - uno_fou;
  const double d_dostre_fou = tre_fou - dos_fou;
  const double d_trequa_fou = qua_fou - tre_fou;
  const double d_quacin_fou = cin_fou - qua_fou;
  /*
   * Dos horizontal differences:
   */
  const double d_dos_twothr = dos_thr - dos_two;
  const double d_dos_thrfou = dos_fou - dos_thr;
  const double d_dos_foufiv = dos_fiv - dos_fou;
  /*
   * Tre(s) horizontal differences:
   */
  const double d_tre_onetwo = tre_two - tre_one;
  const double d_tre_twothr = tre_thr - tre_two;
  const double d_tre_thrfou = tre_fou - tre_thr;
  const double d_tre_foufiv = tre_fiv - tre_fou;
  /*
   * Qua(ttro) horizontal differences:
   */
  const double d_qua_onetwo = qua_two - qua_one;
  const double d_qua_twothr = qua_thr - qua_two;
  const double d_qua_thrfou = qua_fou - qua_thr;
  const double d_qua_foufiv = qua_fiv - qua_fou;

  /*
   * Recyclable vertical products and squares:
   */
  const double d_dostre_times_trequa_two = d_dostre_two * d_trequa_two;
  const double d_trequa_two_sq           = d_trequa_two * d_trequa_two;
  const double d_trequa_times_quacin_two = d_trequa_two * d_quacin_two;

  const double d_unodos_times_dostre_thr = d_unodos_thr * d_dostre_thr;
  const double d_dostre_thr_sq           = d_dostre_thr * d_dostre_thr;
  const double d_dostre_times_trequa_thr = d_dostre_thr * d_trequa_thr;
  const double d_trequa_times_quacin_thr = d_trequa_thr * d_quacin_thr;
  const double d_quacin_thr_sq           = d_quacin_thr * d_quacin_thr;

  const double d_unodos_times_dostre_fou = d_unodos_fou * d_dostre_fou;
  const double d_dostre_fou_sq           = d_dostre_fou * d_dostre_fou;
  const double d_dostre_times_trequa_fou = d_dostre_fou * d_trequa_fou;
  const double d_trequa_times_quacin_fou = d_trequa_fou * d_quacin_fou;
  const double d_quacin_fou_sq           = d_quacin_fou * d_quacin_fou;
  /*
   * Recyclable horizontal products and squares:
   */
  const double d_dos_twothr_times_thrfou = d_dos_twothr * d_dos_thrfou;
  const double d_dos_thrfou_sq           = d_dos_thrfou * d_dos_thrfou;
  const double d_dos_thrfou_times_foufiv = d_dos_thrfou * d_dos_foufiv;

  const double d_tre_onetwo_times_twothr = d_tre_onetwo * d_tre_twothr;
  const double d_tre_twothr_sq           = d_tre_twothr * d_tre_twothr;
  const double d_tre_twothr_times_thrfou = d_tre_twothr * d_tre_thrfou;
  const double d_tre_thrfou_times_foufiv = d_tre_thrfou * d_tre_foufiv;
  const double d_tre_foufiv_sq           = d_tre_foufiv * d_tre_foufiv;

  const double d_qua_onetwo_times_twothr = d_qua_onetwo * d_qua_twothr;
  const double d_qua_twothr_sq           = d_qua_twothr * d_qua_twothr;
  const double d_qua_twothr_times_thrfou = d_qua_twothr * d_qua_thrfou;
  const double d_qua_thrfou_times_foufiv = d_qua_thrfou * d_qua_foufiv;
  const double d_qua_foufiv_sq           = d_qua_foufiv * d_qua_foufiv;

  /*
   * Vertical differences useful for minmod:
   */
  const double d_dostre_times_trequa_minus_trequa_sq_two =
    d_dostre_times_trequa_two - d_trequa_two_sq;
  const double d_trequa_times_quacin_minus_trequa_sq_two =
    d_trequa_times_quacin_two - d_trequa_two_sq;

  const double d_unodos_times_dostre_minus_dostre_sq_thr =
    d_unodos_times_dostre_thr - d_dostre_thr_sq;
  const double d_dostre_times_trequa_minus_dostre_sq_thr =
    d_dostre_times_trequa_thr - d_dostre_thr_sq;
  const double d_trequa_times_quacin_minus_quacin_sq_thr =
    d_trequa_times_quacin_thr - d_quacin_thr_sq;

  const double d_unodos_times_dostre_minus_dostre_sq_fou =
    d_unodos_times_dostre_fou - d_dostre_fou_sq;
  const double d_dostre_times_trequa_minus_dostre_sq_fou =
    d_dostre_times_trequa_fou - d_dostre_fou_sq;
  const double d_trequa_times_quacin_minus_quacin_sq_fou =
    d_trequa_times_quacin_fou - d_quacin_fou_sq;
  /*
   * Horizontal differences useful for minmod:
   */
  const double d_dos_twothr_times_thrfou_minus_thrfou_sq =
    d_dos_twothr_times_thrfou - d_dos_thrfou_sq;
  const double d_dos_thrfou_times_foufiv_minus_thrfou_sq =
    d_dos_thrfou_times_foufiv - d_dos_thrfou_sq;

  const double d_tre_onetwo_times_twothr_minus_twothr_sq =
    d_tre_onetwo_times_twothr - d_tre_twothr_sq;
  const double d_tre_twothr_times_thrfou_minus_twothr_sq =
    d_tre_twothr_times_thrfou - d_tre_twothr_sq;
  const double d_tre_thrfou_times_foufiv_minus_foufiv_sq =
    d_tre_thrfou_times_foufiv - d_tre_foufiv_sq;

  const double d_qua_onetwo_times_twothr_minus_twothr_sq =
    d_qua_onetwo_times_twothr - d_qua_twothr_sq;
  const double d_qua_twothr_times_thrfou_minus_twothr_sq =
    d_qua_twothr_times_thrfou - d_qua_twothr_sq;
  const double d_qua_thrfou_times_foufiv_minus_foufiv_sq =
    d_qua_thrfou_times_foufiv - d_qua_foufiv_sq;

  /*
   * Minmod slopes and first level pixel values:
   */
  const double dos_thr_y =
    FAST_MINMOD( d_dostre_thr, d_unodos_thr,
                 d_unodos_times_dostre_thr,
                 d_unodos_times_dostre_minus_dostre_sq_thr );
  const double tre_thr_y =
    FAST_MINMOD( d_dostre_thr, d_trequa_thr,
                 d_dostre_times_trequa_thr,
                 d_dostre_times_trequa_minus_dostre_sq_thr );

  const double val_uno_two_1 =
    .5 * ( dos_thr + tre_thr )
    +
    .25 * ( dos_thr_y - tre_thr_y );

  const double qua_thr_y =
    FAST_MINMOD( d_quacin_thr, d_trequa_thr,
                 d_trequa_times_quacin_thr,
                 d_trequa_times_quacin_minus_quacin_sq_thr );

  const double val_tre_two_1 =
    .5 * ( tre_thr + qua_thr )
    +
    .25 * ( tre_thr_y - qua_thr_y );

  const double tre_fou_y =
    FAST_MINMOD( d_dostre_fou, d_trequa_fou,
                 d_dostre_times_trequa_fou,
                 d_dostre_times_trequa_minus_dostre_sq_fou );
  const double qua_fou_y =
    FAST_MINMOD( d_quacin_fou, d_trequa_fou,
                 d_trequa_times_quacin_fou,
                 d_trequa_times_quacin_minus_quacin_sq_fou );

  const double val_tre_fou_1 =
    .5 * ( tre_fou + qua_fou )
    +
    .25 * ( tre_fou_y - qua_fou_y );

  const double tre_two_x =
    FAST_MINMOD( d_tre_twothr, d_tre_onetwo,
                 d_tre_onetwo_times_twothr,
                 d_tre_onetwo_times_twothr_minus_twothr_sq );
  const double tre_thr_x =
    FAST_MINMOD( d_tre_twothr, d_tre_thrfou,
                 d_tre_twothr_times_thrfou,
                 d_tre_twothr_times_thrfou_minus_twothr_sq );

  const double val_dos_one_1 =
    .5 * ( tre_two + tre_thr )
    +
    .25 * ( tre_two_x - tre_thr_x );

  const double tre_fou_x =
    FAST_MINMOD( d_tre_foufiv, d_tre_thrfou,
                 d_tre_thrfou_times_foufiv,
                 d_tre_thrfou_times_foufiv_minus_foufiv_sq );

  const double tre_thr_x_minus_tre_fou_x =
    tre_thr_x - tre_fou_x;

  const double val_dos_thr_1 =
    .5 * ( tre_thr + tre_fou )
    +
    .25 * tre_thr_x_minus_tre_fou_x;

  const double qua_thr_x =
    FAST_MINMOD( d_qua_twothr, d_qua_thrfou,
                 d_qua_twothr_times_thrfou,
                 d_qua_twothr_times_thrfou_minus_twothr_sq );
  const double qua_fou_x =
    FAST_MINMOD( d_qua_foufiv, d_qua_thrfou,
                 d_qua_thrfou_times_foufiv,
                 d_qua_thrfou_times_foufiv_minus_foufiv_sq );

  const double qua_thr_x_minus_qua_fou_x =
    qua_thr_x - qua_fou_x;

  const double val_qua_thr_1 =
    .5 * ( qua_thr + qua_fou )
    +
    .25 * qua_thr_x_minus_qua_fou_x;
  const double val_tre_thr_1 =
    .125 * ( tre_thr_x_minus_tre_fou_x + qua_thr_x_minus_qua_fou_x )
    +
    .5 * ( val_tre_two_1 + val_tre_fou_1 );

  const double dos_fou_y =
    FAST_MINMOD( d_dostre_fou, d_unodos_fou,
                 d_unodos_times_dostre_fou,
                 d_unodos_times_dostre_minus_dostre_sq_fou );
  const double dos_thr_x =
    FAST_MINMOD( d_dos_thrfou, d_dos_twothr,
                 d_dos_twothr_times_thrfou,
                 d_dos_twothr_times_thrfou_minus_thrfou_sq );
  const double dos_fou_x =
    FAST_MINMOD( d_dos_thrfou, d_dos_foufiv,
                 d_dos_thrfou_times_foufiv,
                 d_dos_thrfou_times_foufiv_minus_thrfou_sq );

  const double val_uno_thr_1 =
    .25 * ( dos_fou - tre_thr )
    +
    .125 * ( dos_fou_y - tre_fou_y + dos_thr_x - dos_fou_x )
    +
    .5 * ( val_uno_two_1 + val_dos_thr_1 );

  const double qua_two_x =
    FAST_MINMOD( d_qua_twothr, d_qua_onetwo,
                 d_qua_onetwo_times_twothr,
                 d_qua_onetwo_times_twothr_minus_twothr_sq );
  const double tre_two_y =
    FAST_MINMOD( d_trequa_two, d_dostre_two,
                 d_dostre_times_trequa_two,
                 d_dostre_times_trequa_minus_trequa_sq_two );
  const double qua_two_y =
    FAST_MINMOD( d_trequa_two, d_quacin_two,
                 d_trequa_times_quacin_two,
                 d_trequa_times_quacin_minus_trequa_sq_two );

  const double val_tre_one_1 =
    .25 * ( qua_two - tre_thr )
    +
    .125 * ( qua_two_x - qua_thr_x + tre_two_y - qua_two_y )
    +
    .5 * ( val_dos_one_1 + val_tre_two_1 );

  /*
   * Return level 1 stencil values:
   */
  *uno_two_1 = val_uno_two_1;
  *uno_thr_1 = val_uno_thr_1;
  *dos_one_1 = val_dos_one_1;
  *dos_two_1 = tre_thr;
  *dos_thr_1 = val_dos_thr_1;
  *dos_fou_1 = tre_fiv;
  *tre_one_1 = val_tre_one_1;
  *tre_two_1 = val_tre_two_1;
  *tre_thr_1 = val_tre_thr_1;
  *tre_fou_1 = val_tre_fou_1;
  *qua_two_1 = qua_thr;
  *qua_thr_1 = val_qua_thr_1;
}

#define SELECT_REFLECT(tl,tr,bl,br) ( \
  (tl) * is_top_left_1 \
  + \
  (tr) * is_top_rite_1 \
  + \
  (bl) * is_bot_left_1 \
  + \
  (br) * is_bot_rite_1 )

/* Call nohalo2 with an interpolator as a parameter.  It'd be nice to
 * do this with templates somehow :-( but I can't see a clean way to
 * do it.
 */
#define NOHALO2_INTER( inter ) \
  template <typename T> static void inline \
  nohalo2_ ## inter(          PEL* restrict pout, \
                           REGION* restrict in, \
                     const int              bands, \
                     const int              lskip, \
                     const double           absolute_x, \
                     const double           absolute_y ) \
  { \
    const double absolute_x_minus_half = absolute_x - .5; \
    const double absolute_y_minus_half = absolute_y - .5; \
    \
    const int initial_ix = FAST_PSEUDO_FLOOR (absolute_x); \
    const int initial_iy = FAST_PSEUDO_FLOOR (absolute_y); \
    \
    const double relative_x = absolute_x_minus_half - initial_ix; \
    const double relative_y = absolute_y_minus_half - initial_iy; \
    \
    const int relative_x_is_rite = ( relative_x >= 0. ); \
    const int relative_y_is_down = ( relative_y >= 0. ); \
    \
    const PEL* restrict pin = \
      (PEL *) IM_REGION_ADDR( \
                              in, \
                              initial_ix + relative_x_is_rite, \
                              initial_iy + relative_y_is_down ); \
    \
    { \
      const T* restrict in = ( (T *) pin ); \
      \
      const int sign_of_relative_x = 2 * relative_x_is_rite - 1; \
      const int sign_of_relative_y = 2 * relative_y_is_down - 1; \
      \
      const int shift_back_1_pix = sign_of_relative_x * bands; \
      const int shift_back_1_row = sign_of_relative_y * lskip; \
      \
      const int shift_forw_1_pix = -shift_back_1_pix; \
      const int shift_forw_1_row = -shift_back_1_row; \
      \
      const int shift_back_2_pix = 2 * shift_back_1_pix; \
      const int shift_back_2_row = 2 * shift_back_1_row; \
      const int shift_forw_2_pix = 2 * shift_forw_1_pix; \
      const int shift_forw_2_row = 2 * shift_forw_1_row; \
      \
      const int uno_thr_shift =                    shift_back_2_row; \
      const int uno_fou_shift = shift_forw_1_pix + shift_back_2_row; \
      \
      const int dos_two_shift = shift_back_1_pix + shift_back_1_row; \
      const int dos_thr_shift =                    shift_back_1_row; \
      const int dos_fou_shift = shift_forw_1_pix + shift_back_1_row; \
      const int dos_fiv_shift = shift_forw_2_pix + shift_back_1_row; \
      \
      const int tre_one_shift = shift_back_2_pix; \
      const int tre_two_shift = shift_back_1_pix; \
      const int tre_thr_shift = 0; \
      const int tre_fou_shift = shift_forw_1_pix; \
      const int tre_fiv_shift = shift_forw_2_pix; \
      \
      const int qua_one_shift = shift_back_2_pix + shift_forw_1_row; \
      const int qua_two_shift = shift_back_1_pix + shift_forw_1_row; \
      const int qua_thr_shift =                    shift_forw_1_row; \
      const int qua_fou_shift = shift_forw_1_pix + shift_forw_1_row; \
      const int qua_fiv_shift = shift_forw_2_pix + shift_forw_1_row; \
      \
      const int cin_two_shift = shift_back_1_pix + shift_forw_2_row; \
      const int cin_thr_shift =                    shift_forw_2_row; \
      const int cin_fou_shift = shift_forw_1_pix + shift_forw_2_row; \
      \
      const double w = ( 2 * sign_of_relative_x ) * relative_x; \
      const double z = ( 2 * sign_of_relative_y ) * relative_y; \
      \
      const double relative_x_1 = .5 - w; \
      const double relative_y_1 = .5 - z; \
      \
      const int relative_x_is_rite_1 = ( relative_x_1 >= 0. ); \
      const int relative_y_is_down_1 = ( relative_y_1 >= 0. ); \
      const int relative_x_is_left_1 = 1 - relative_x_is_rite_1; \
      const int relative_y_is___up_1 = 1 - relative_y_is_down_1; \
      \
      const double is_bot_rite_1 = \
        relative_x_is_rite_1 * relative_y_is_down_1; \
      const double is_bot_left_1 = \
        relative_x_is_left_1 * relative_y_is_down_1; \
      const double is_top_rite_1 = \
        relative_x_is_rite_1 * relative_y_is___up_1;\
      const double is_top_left_1 = \
        relative_x_is_left_1 * relative_y_is___up_1; \
      \
      const int sign_of_relative_x_1 = 2 * relative_x_is_rite_1 - 1; \
      const int sign_of_relative_y_1 = 2 * relative_y_is_down_1 - 1; \
      \
      const double w_1 = ( 2 * sign_of_relative_x_1 ) * relative_x_1; \
      const double z_1 = ( 2 * sign_of_relative_y_1 ) * relative_y_1; \
      const double x_1 = 1. - w_1; \
      const double w_times_z_1 = w_1 * z_1; \
      const double x_times_z_1 = x_1 * z_1; \
      \
      const double w_times_y_over_4_1 = .25  * ( w_1 - w_times_z_1 ); \
      const double x_times_z_over_4_1 = .25  * x_times_z_1; \
      const double x_times_y_over_8_1 = .125 * ( x_1 - x_times_z_1 ); \
      \
      T* restrict out = (T *) pout; \
      \
      int band = bands; \
      \
      do \
        { \
          double uno_two_1; \
          double uno_thr_1; \
          double dos_one_1; \
          double dos_two_1; \
          double dos_thr_1; \
          double dos_fou_1; \
          double tre_one_1; \
          double tre_two_1; \
          double tre_thr_1; \
          double tre_fou_1; \
          double qua_two_1; \
          double qua_thr_1; \
          \
          double dos_two_2; \
          double four_times_dos_twothr_2; \
          double four_times_dostre_two_2; \
          double eight_times_dostre_twothr_2; \
          \
          nohalo_step1( in[uno_thr_shift], \
                        in[uno_fou_shift], \
                        in[dos_two_shift], \
                        in[dos_thr_shift], \
                        in[dos_fou_shift], \
                        in[dos_fiv_shift], \
                        in[tre_one_shift], \
                        in[tre_two_shift], \
                        in[tre_thr_shift], \
                        in[tre_fou_shift], \
                        in[tre_fiv_shift], \
                        in[qua_one_shift], \
                        in[qua_two_shift], \
                        in[qua_thr_shift], \
                        in[qua_fou_shift], \
                        in[qua_fiv_shift], \
                        in[cin_two_shift], \
                        in[cin_thr_shift], \
                        in[cin_fou_shift], \
                        &uno_two_1, \
                        &uno_thr_1, \
                        &dos_one_1, \
                        &dos_two_1, \
                        &dos_thr_1, \
                        &dos_fou_1, \
                        &tre_one_1, \
                        &tre_two_1, \
                        &tre_thr_1, \
                        &tre_fou_1, \
                        &qua_two_1, \
                        &qua_thr_1 ); \
          \
          nohalo_step2 ( \
            SELECT_REFLECT( uno_two_1, uno_thr_1, qua_two_1, qua_thr_1 ), \
            SELECT_REFLECT( uno_thr_1, uno_two_1, qua_thr_1, qua_two_1 ), \
            SELECT_REFLECT( dos_one_1, dos_fou_1, tre_one_1, tre_fou_1 ), \
            SELECT_REFLECT( dos_two_1, dos_thr_1, tre_two_1, tre_thr_1 ), \
            SELECT_REFLECT( dos_thr_1, dos_two_1, tre_thr_1, tre_two_1 ), \
            SELECT_REFLECT( dos_fou_1, dos_one_1, tre_fou_1, tre_one_1 ), \
            SELECT_REFLECT( tre_one_1, tre_fou_1, dos_one_1, dos_fou_1 ), \
            SELECT_REFLECT( tre_two_1, tre_thr_1, dos_two_1, dos_thr_1 ), \
            SELECT_REFLECT( tre_thr_1, tre_two_1, dos_thr_1, dos_two_1 ), \
            SELECT_REFLECT( tre_fou_1, tre_one_1, dos_fou_1, dos_one_1 ), \
            SELECT_REFLECT( qua_two_1, qua_thr_1, uno_two_1, uno_thr_1 ), \
            SELECT_REFLECT( qua_thr_1, qua_two_1, uno_thr_1, uno_two_1 ), \
            &dos_two_2, \
            &four_times_dos_twothr_2, \
            &four_times_dostre_two_2, \
            &eight_times_dostre_twothr_2 ); \
          \
          const T result = \
            bilinear_ ## inter<T>( w_times_z_1, \
                                   x_times_z_over_4_1, \
                                   w_times_y_over_4_1, \
                                   x_times_y_over_8_1, \
                                   dos_two_2, \
                                   four_times_dos_twothr_2, \
                                   four_times_dostre_two_2, \
                                   eight_times_dostre_twothr_2 ); \
          \
          in++; \
          *out++ = result; \
        } while (--band); \
    } \
}

NOHALO2_INTER( fptypes )
NOHALO2_INTER( withsign )
NOHALO2_INTER( nosign )

/* We need C linkage for this.
 */
extern "C" {
G_DEFINE_TYPE( VipsInterpolateNohalo2, vips_interpolate_nohalo2,
	VIPS_TYPE_INTERPOLATE );
}

static void
vips_interpolate_nohalo2_interpolate( VipsInterpolate* restrict interpolate,
                                      PEL*             restrict out,
                                      REGION*          restrict in,
                                      double                    absolute_x,
                                      double                    absolute_y )
{
  /*
   * VIPS versions of Nicolas's pixel addressing values.
   */
  const int actual_bands = in->im->Bands;
  const int lskip = IM_REGION_LSKIP( in ) / IM_IMAGE_SIZEOF_ELEMENT( in->im );

  /*
   * Double bands for complex images:
   */
  const int bands =
    ( im_iscomplex( in->im ) ? 2 * actual_bands : actual_bands );

#define CALL( T, inter ) \
  nohalo2_ ## inter<T>( out, \
                        in, \
                        bands, \
                        lskip, \
                        absolute_x, \
                        absolute_y );

  switch( in->im->BandFmt ) {
  case IM_BANDFMT_UCHAR:
    CALL( unsigned char, nosign );
    break;

  case IM_BANDFMT_CHAR:
    CALL( signed char, withsign );
    break;

  case IM_BANDFMT_USHORT:
    CALL( unsigned short, nosign );
    break;

  case IM_BANDFMT_SHORT:
    CALL( signed short, withsign );
    break;

  case IM_BANDFMT_UINT:
    CALL( unsigned int, nosign );
    break;

  case IM_BANDFMT_INT:
    CALL( signed int, withsign );
    break;

  /* Complex images handled by doubling of bands, see above.
   */
  case IM_BANDFMT_FLOAT:
  case IM_BANDFMT_COMPLEX:
    CALL( float, fptypes );
    break;

  case IM_BANDFMT_DOUBLE:
  case IM_BANDFMT_DPCOMPLEX:
    CALL( double, fptypes );
    break;

  default:
    g_assert( 0 );
    break;
  }
}

static void
vips_interpolate_nohalo2_class_init( VipsInterpolateNohalo2Class *klass )
{
  VipsObjectClass *object_class = VIPS_OBJECT_CLASS( klass );
  VipsInterpolateClass *interpolate_class =
    VIPS_INTERPOLATE_CLASS( klass );

  object_class->nickname = "nohalo2";
  object_class->description = _( "Smoother and more edge-enhancing nohalo1" );

  interpolate_class->interpolate = vips_interpolate_nohalo2_interpolate;
  interpolate_class->window_size = 5;
}

static void
vips_interpolate_nohalo2_init( VipsInterpolateNohalo2 *nohalo2 )
{
}
