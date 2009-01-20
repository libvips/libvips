/* nohalo interpolator
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
 * 2009 (c) Nicolas Robidoux 
 *
 * Thanks: Geert Jordaens, John Cupitt, Minglun Gong, Øyvind Kolås and
 * Sven Neumann for useful comments and code.
 * 
 * Acknowledgement: Nicolas Robidoux's research on nohalo funded in
 * part by an NSERC (National Science and Engineering Research Council
 * of Canada) Discovery Grant.
 */

/* Hacked for vips by J. Cupitt, 20/1/09
 */

/*
 * John: This is the version which I think you should base the code
 * for signed and unsigned ints, floats and doubles. IN_AND_OUT_TYPE
 * stands for the "input" and "output" types. The computation is
 * performed based on doubles (even for float data). There is a reason
 * for this, which is that I use implicit casts of flag variables into
 * ints into doubles, and I think that such casts may be slower from
 * ints to floats.
 *
 * IMPORTANT: Because nohalo is monotone, there is no need to clamp,
 * ever.
 *
 * I have inserted code which I hope does fairly quick rounding to
 * nearest when signed or unsigned ints are used. Look for the word
 * "John".
 *
 * Set the LGPL license to what you like. As long as my name is
 * suitably inserted, I don't care about the exact license.
 */

/*
 * This is not "REAL" gegl code, because I don't like the way
 * gegl_sampler_get_ptr works (when I use it as I like, there are
 * glitches in gegl which I think have nothing to do with my code). I
 * rewrote the following code the way I'd like get_ptr to work.
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
 * subdivision which are performed. If level = 0 can be thought of as
 * being plain vanilla bilinear resampling; level = 1 is the first
 * "non-classical" method.
 *
 * Besides increasing computational cost, increasing the number of
 * levels increases the quality of the resampled pixel value unless
 * the resampled location happens to be exactly where a subdivided
 * grid point (for this level) is located, in which case further
 * levels do not change the answer, and consequently do not increase
 * its quality.
 *
 * ============================================================
 * WARNING: THIS CODE ONLY IMPLEMENTS THE LOWEST QUALITY NOHALO
 * ============================================================
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
 * in a "cross" centered at the closest four input pixel centers. For
 * computational expediency, the input values corresponding to the
 * nearest 21 input pixel locations (5x5 minus the four corners)
 * should be made available through a data pointer. The code then
 * selects the needed ones from this enlarged stencil.
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
 * policy or building the boundary conditions inside the sampler.)
 * Nohalo is exact on linear intensity profiles, meaning that if the
 * input pixel values (in the stencil) are obtained from a function of
 * the form f(x,y) = a + b*x + c*y (a, b, c constants), then the
 * computed pixel value is exactly the value of f(x,y) at the
 * asked-for sampling location.
 *
 * ===================
 * Nohalo is nonlinear
 * ===================
 *
 * In particular, resampling a sum of images may not be the same as
 * summing the resamples (this occurs even without taking into account
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

/*
 * FAST_PSEUDO_FLOOR is a floor and floorf replacement which has been
 * found to be faster on several linux boxes than the library
 * version. It returns the floor of its argument unless the argument
 * is a negative integer, in which case it returns one less than the
 * floor. For example:
 *
 * FAST_PSEUDO_FLOOR(0.5) = 0
 *
 * FAST_PSEUDO_FLOOR(0.f) = 0
 *
 * FAST_PSEUDO_FLOOR(-.5) = -1
 *
 * as expected, but
 *
 * FAST_PSEUDO_FLOOR(-1.f) = -2
 *
 * The locations of the discontinuities of FAST_PSEUDO_FLOOR are the
 * same as floor and floorf; it is just that at negative integers the
 * function is discontinuous on the right instead of the left.
 */
#define FAST_PSEUDO_FLOOR(x) ( (int)(x) - ( (x) < 0. ) )
/*
 * Alternative (if conditional move is fast and correctly identified
 * by the compiler):
 *
 * #define FAST_PSEUDO_FLOOR(x) ( (x)>=0 ? (int)(x) : (int)(x)-1 )
 */

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

/* Calculate the four results surrounding the target point, our caller does
 * bilinear interpolation of them.
 */

static void inline
nohalo1( 
	const double dos_thr,
	const double dos_fou,
	const double tre_two,
	const double tre_thr,
	const double tre_fou,
	const double tre_fiv,
	const double qua_two,
	const double qua_thr,
	const double qua_fou,
	const double qua_fiv,
	const double cin_thr,
	const double cin_fou,
	double *r1,
	double *r2,
	double *r3,
	double *r4 )
{
	/*
	 * The potentially needed input pixel values are described by the
	 * following stencil, where (ix,iy) are the coordinates of the
	 * closest input pixel center (with ties resolved arbitrarily).
	 *
	 * Spanish abbreviations are used to label positions from top to
	 * bottom (rows), English ones to label positions from left to right
	 * (columns). 
	 *
	 *               (ix-1,iy-2)  (ix,iy-2)    (ix+1,iy-2)
	 *               = uno_two    = uno_thr    = uno_fou
	 *
	 *  (ix-2,iy-1)  (ix-1,iy-1)  (ix,iy-1)    (ix+1,iy-1)   (ix+2,iy-1)
	 *  = dos_one    = dos_two    = dos_thr    = dos_fou     = dos_fiv
	 *
	 *  (ix-2,iy)    (ix-1,iy)    (ix,iy)      (ix+1,iy)     (ix+2,iy)  
	 *  = tre_one    = tre_two    = tre_thr    = tre_fou     = tre_fiv
	 *
	 *  (ix-2,iy+1)  (ix-1,iy+1)  (ix,iy+1)    (ix+1,iy+1)   (ix+2,iy+1)
	 *  = qua_one    = qua_two    = qua_thr    = qua_fou     = qua_fiv
	 *
	 *               (ix-1,iy+2)  (ix,iy+2)    (ix+1,iy+2)
	 *               = cin_two    = cin_thr    = cin_fou
	 *
	 * Once symmetry has been used to assume that the sampling point is
	 * to the right and bottom of tre_thr---this is done by implicitly
	 * reflecting the data if this is not initially the case---the
	 * needed input values are named thus:
	 *
	 *                              dos_thr      dos_fou
	 *
	 *                 tre_two      tre_thr      tre_fou       tre_fiv
	 *
	 *                 qua_two      qua_thr      qua_fou       qua_fiv
	 *
	 *                              cin_thr      cin_fou
	 *
	 * (If, for exammple, relative_x_is_left is 1 but relative_y_is___up
	 * = 0, then dos_fou in this post-reflexion reduced stencil really
	 * corresponds to dos_two in the unreduced one, etc.)
	 *
	 * Given that the reflexions are performed "outside of the
	 * function," the above 12 input values are the only ones "seen" by
	 * this function.
	 */

	/*
	 * Computation of the nonlinear slopes: If two consecutive pixel
	 * value differences have the same sign, the smallest one (in
	 * absolute value) is taken to be the corresponding slope; if the
	 * two consecutive pixel value differences don't have the same sign,
	 * the corresponding slope is set to 0.
	 */

	/*
	 * Tre(s) horizontal differences:
	 */
	const double deux_tre = tre_thr - tre_two;
	const double troi_tre = tre_fou - tre_thr;
	const double quat_tre = tre_fiv - tre_fou;
	/*
	 * Qua(ttro) horizontal differences:
	 */
	const double deux_qua = qua_thr - qua_two;
	const double troi_qua = qua_fou - qua_thr;
	const double quat_qua = qua_fiv - qua_fou;
	/*
	 * Thr(ee) vertical differences:
	 */
	const double deux_thr = tre_thr - dos_thr;
	const double troi_thr = qua_thr - tre_thr;
	const double quat_thr = cin_thr - qua_thr;
	/*
	 * Fou(r) vertical differences:
	 */
	const double deux_fou = tre_fou - dos_fou;
	const double troi_fou = qua_fou - tre_fou;
	const double quat_fou = cin_fou - qua_fou;

	/*
	 * Tre:
	 */
	const int sign_deux_tre = 2 * (deux_tre >= 0.) - 1;
	const int sign_troi_tre = 2 * (troi_tre >= 0.) - 1;
	const int sign_quat_tre = 2 * (quat_tre >= 0.) - 1;
	/*
	 * Qua:
	 */
	const int sign_deux_qua = 2 * (deux_qua >= 0.) - 1;
	const int sign_troi_qua = 2 * (troi_qua >= 0.) - 1;
	const int sign_quat_qua = 2 * (quat_qua >= 0.) - 1;
	/*
	 * Thr:
	 */
	const int sign_deux_thr = 2 * (deux_thr >= 0.) - 1;
	const int sign_troi_thr = 2 * (troi_thr >= 0.) - 1;
	const int sign_quat_thr = 2 * (quat_thr >= 0.) - 1;
	/*
	 * Fou:
	 */
	const int sign_deux_fou = 2 * (deux_fou >= 0.) - 1;
	const int sign_troi_fou = 2 * (troi_fou >= 0.) - 1;
	const int sign_quat_fou = 2 * (quat_fou >= 0.) - 1;

	/*
	 * Tre:
	 */
	const double abs_deux_tre = sign_deux_tre * deux_tre;
	const double abs_troi_tre = sign_troi_tre * troi_tre;
	const double abs_quat_tre = sign_quat_tre * quat_tre;
	/*
	 * Qua:
	 */
	const double abs_deux_qua = sign_deux_qua * deux_qua;
	const double abs_troi_qua = sign_troi_qua * troi_qua;
	const double abs_quat_qua = sign_quat_qua * quat_qua;
	/*
	 * Thr:
	 */
	const double abs_deux_thr = sign_deux_thr * deux_thr;
	const double abs_troi_thr = sign_troi_thr * troi_thr;
	const double abs_quat_thr = sign_quat_thr * quat_thr;
	/*
	 * Fou:
	 */
	const double abs_deux_fou = sign_deux_fou * deux_fou;
	const double abs_troi_fou = sign_troi_fou * troi_fou;
	const double abs_quat_fou = sign_quat_fou * quat_fou;

	/*
	 * Tre:
	 */
	const double twice_tre_thr_horizo =
		(1 + sign_deux_tre * sign_troi_tre) * (
			(abs_deux_tre <= abs_troi_tre) * 
			(deux_tre - troi_tre) +
			troi_tre
		);
	const double twice_tre_fou_horizo =
		(1 + sign_troi_tre * sign_quat_tre) * (
			(abs_troi_tre <= abs_quat_tre) *
			(troi_tre - quat_tre) +
			quat_tre
		);
	/*
	 * Qua:
	 */
	const double twice_qua_thr_horizo =
		(1 + sign_deux_qua * sign_troi_qua) * (
			(abs_deux_qua <= abs_troi_qua) *
			(deux_qua - troi_qua) +
			troi_qua
		);
	const double twice_qua_fou_horizo =
		(1 + sign_troi_qua * sign_quat_qua) * (
			(abs_troi_qua <= abs_quat_qua) *
			(troi_qua - quat_qua) +
			quat_qua
		);
	/*
	 * Thr:
	 */
	const double twice_tre_thr_vertic =
		(1 + sign_deux_thr * sign_troi_thr) * (
			(abs_deux_thr <= abs_troi_thr) *
			(deux_thr - troi_thr) +
			troi_thr
		    );
	const double twice_qua_thr_vertic =
		(1 + sign_troi_thr * sign_quat_thr) * (
			(abs_troi_thr <= abs_quat_thr) * 
			(troi_thr - quat_thr) +
			quat_thr
		);
	/*
	 * Fou:
	 */
	const double twice_tre_fou_vertic =
		(1 + sign_deux_fou * sign_troi_fou) * (
			(abs_deux_fou <= abs_troi_fou) *
			(deux_fou - troi_fou) +
			troi_fou
		);
	const double twice_qua_fou_vertic =
		(1 + sign_troi_fou * sign_quat_fou) * (
			(abs_troi_fou <= abs_quat_fou) *
			(troi_fou - quat_fou) +
			quat_fou
		);

	/*
	 * Compute the needed "horizontal" (at the boundary between two
	 * input pixel areas) double resolution pixel value:
	 */
	/*
	 * Tre:
	 */
	const double tre_thrfou =
		.5 * (tre_thr + tre_fou) +
		.125 * (twice_tre_thr_horizo - twice_tre_fou_horizo);

	/*
	 * Compute the needed "vertical" double resolution pixel value:
	 */
	/*
	 * Thr:
	 */
	const double trequa_thr =
		.5 * (tre_thr + qua_thr) +
		.125 * (twice_tre_thr_vertic - twice_qua_thr_vertic);

	/*
	 * Compute the "diagonal" (at the boundary between four input pixel
	 * areas) double resolution pixel value:
	 */
	const double trequa_thrfou =
		.25 * (qua_fou - tre_thr) +
		.5 * (tre_thrfou + trequa_thr) +
		.0625 * (
			(twice_qua_thr_horizo + twice_tre_fou_vertic) -
			(twice_qua_fou_horizo + twice_qua_fou_vertic)
		);

	*r1 = tre_thr;
	*r2 = tre_thrfou;
	*r3 = trequa_thr;
	*r4 = trequa_thrfou;
}

/* Interpolate for float and double types.
 */
template <typename IN_AND_OUT_TYPE> static IN_AND_OUT_TYPE inline
interpolate_float( 
	const double w_times_z,
	const double x_times_z,
	const double w_times_y,
	const double x_times_y,
	const double tre_thr,
	const double tre_thrfou,
	const double trequa_thr,
	const double trequa_thrfou )
{
	const IN_AND_OUT_TYPE newval =
		w_times_z * tre_thr +
		x_times_z * tre_thrfou +
		w_times_y * trequa_thr +
		x_times_y * trequa_thrfou;

	return( newval );
}

/* Interpolate for signed integer types.
 */
template <typename IN_AND_OUT_TYPE> static IN_AND_OUT_TYPE inline
nohalo_signed( 
	const double w_times_z,
	const double x_times_z,
	const double w_times_y,
	const double x_times_y,
	const double tre_thr,
	const double tre_thrfou,
	const double trequa_thr,
	const double trequa_thrfou )
{
	const double val =
		(w_times_z / 16) * tre_thr +
		(x_times_z / 16) * tre_thrfou +
		(w_times_y / 16) * trequa_thr +
		(x_times_y / 16) * trequa_thrfou;

	const int sign_of_val = 2 * ( val >= 0. ) - 1;

	const int rounded_abs_val = .5 + sign_of_val * val;

	const IN_AND_OUT_TYPE newval = sign_of_val * rounded_abs_val;

	return( newval );
}

/* Interpolate for unsigned integer types.
 */
template <typename IN_AND_OUT_TYPE> static IN_AND_OUT_TYPE inline
nohalo_unsigned( 
	const double w_times_z,
	const double x_times_z,
	const double w_times_y,
	const double x_times_y,
	const double tre_thr,
	const double tre_thrfou,
	const double trequa_thr,
	const double trequa_thrfou )
{
	const IN_AND_OUT_TYPE newval =
		(w_times_z / 16) * tre_thr +
		(x_times_z / 16) * tre_thrfou +
		(w_times_y / 16) * trequa_thr +
		(x_times_y / 16) * trequa_thrfou + 
		0.5

	return( newval );
}

static void
gegl_sampler_yafr_get (      GeglSampler* restrict self,
                       const gdouble               absolute_x,
                       const gdouble               absolute_y,
                             void*        restrict output)
{
  /*
   * NEEDED CONSTANTS RELATED TO THE INPUT PIXEL POINTER:
   */
  const gint channels_per_pixel  = 4;
  const gint pixels_per_tile_row = 64;
  const gint values_per_tile_row = channels_per_pixel * pixels_per_tile_row;

  /*
   * floor's surrogate FAST_PSEUDO_FLOOR is used to make sure that the
   * transition through 0 is smooth. If it is known that absolute_x
   * and absolute_y will never be less than -.5, plain cast---that is,
   * const gint ix = absolute_x + .5---should be used instead.  Any
   * function which agrees with floor for non-integer values, and
   * picks one of the two possibilities for integer values, can be
   * used.
   */
  const gint ix = FAST_PSEUDO_FLOOR (absolute_x + .5);
  const gint iy = FAST_PSEUDO_FLOOR (absolute_y + .5);

  /*
   * x is the x-coordinate of the sampling point relative to the
   * position of the tre_thr pixel center. Similarly for y. Range of
   * values: [-.5,.5].
   */
  const gdouble relative_x = absolute_x - ix;
  const gdouble relative_y = absolute_y - iy;

  /*
   * "DIRTY" TRICK: In order to minimize the number of computed
   * "double density" pixels, we use symmetry to appropriately "flip
   * the data." (An alternative approach is to "compute everything and
   * select by zeroing coefficients.")
   */
  const gint relative_x_is_left = ( relative_x < 0. );
  const gint relative_y_is___up = ( relative_y < 0. );

  const gint basic_x_reflexion_shift = ( 5 - 1 ) * channels_per_pixel;
  const gint basic_y_reflexion_shift = ( 5 - 1 ) * values_per_tile_row;

  const gint x_reflexion_shift = basic_x_reflexion_shift * relative_x_is_left;
  const gint y_reflexion_shift = basic_y_reflexion_shift * relative_y_is___up;

  /*
   * gegl_sampler_get_ptr (self, ix-2, iy-2) should give me access to
   * a 5 by 5 black of pixel data, where the leftmost/topmost pixel is
   * located at (ix-2,iy-2)---that is, the data runs from "absolute
   * indices" ix-2 to ix+2 and iy-2 to iy+2. Note that the four
   * corners of this 5x5 block are never used.
   *
   * Adding x_reflexion_shift and y_reflexion_shift to the input data
   * pointer, otherwise pointing to the (first channel of the) top
   * left of the five by five stencil, will bring it to the desired
   * corner:
   */
  const IN_AND_OUT_TYPE* restrict uno_one_input_bptr =
    gegl_sampler_get_ptr (self, ix-2, iy-2)
    +
    (
      x_reflexion_shift
      +
      y_reflexion_shift
    );

  /*
   * The direction of movement within the (extended) possibly
   * reflected stencil is then determined by the following signs:
   */
  const gint sign_of_relative_x = 1 - 2 * relative_x_is_left;
  const gint sign_of_relative_y = 1 - 2 * relative_y_is___up;

  /*
   * Unit shifts:
   */
  const gint shift_1_pixel  = sign_of_relative_x * channels_per_pixel;
  const gint shift_1_row    = sign_of_relative_y * values_per_tile_row;

  /*
   * POST REFLEXION/POST RESCALING "DOUBLE DENSITY" COORDINATES:
   *
   * With the appropriate reflexions, we can assume that the
   * coordinates are positive (that we are in the bottom right
   * quadrant (in quadrant III) relative to tre_thr). It is also
   * convenient to scale things by 2, so that the "double density
   * pixels" are 1---instead of 1/2---apart:
   */
  const gdouble x = ( 2 * sign_of_relative_x ) * relative_x;
  const gdouble y = ( 2 * sign_of_relative_y ) * relative_y;

  /*
   * Basic shifts:
   */
  const gint shift_2_pixels = 2 * shift_1_pixel;
  const gint shift_2_rows   = 2 * shift_1_row;

  /*
   * FIRST BILINEAR WEIGHT:
   */
  const gdouble x_times_y = x * y;

  /*
   * More basic shifts:
   */
  const gint shift_3_pixels = shift_2_pixels + shift_1_pixel;
  const gint shift_3_rows   = shift_2_rows + shift_1_row;
  const gint shift_4_rows   = 2 * shift_2_rows;
  const gint shift_4_pixels = 2 * shift_2_pixels;

  /*
   * SECOND AND THIRD BILINEAR WEIGHTS:
   *
   * (Note: w = 1-x and z = 1-y.)
   */
  const gdouble w_times_y = y - x_times_y;
  const gdouble x_times_z = x - x_times_y;

  /*
   * OVERALL SHIFTS:
   */
  const gint dos_thr_shift = shift_1_row  + shift_2_pixels;
  const gint dos_fou_shift = shift_1_row  + shift_3_pixels;

  const gint tre_two_shift = shift_2_rows + shift_1_pixel;
  const gint tre_thr_shift = shift_2_rows + shift_2_pixels;
  const gint tre_fou_shift = shift_2_rows + shift_3_pixels;
  const gint tre_fiv_shift = shift_2_rows + shift_4_pixels;

  const gint qua_two_shift = shift_3_rows + shift_1_pixel;
  const gint qua_thr_shift = shift_3_rows + shift_2_pixels;
  const gint qua_fou_shift = shift_3_rows + shift_3_pixels;
  const gint qua_fiv_shift = shift_3_rows + shift_4_pixels;

  const gint cin_thr_shift = shift_4_rows + shift_2_pixels;
  const gint cin_fou_shift = shift_4_rows + shift_3_pixels;

  /*
   * LAST BILINEAR WEIGHT:
   */
  const gdouble w_times_z = 1. - ( x + w_times_y );

  /*
   * The newval array will contain the four (one per channel)
   * computed resampled values:
   */
  IN_AND_OUT_TYPE newval[4];

  /*
   * COMPUTATION OF EACH CHANNEL'S RESAMPLED PIXEL VALUE:
   */
  /*
   * First channel:
   */
  newval[0] = nohalo1 (w_times_z,
                       x_times_z,
                       w_times_y,
                       x_times_y,
                       uno_one_input_bptr[ dos_thr_shift ],
                       uno_one_input_bptr[ dos_fou_shift ],
                       uno_one_input_bptr[ tre_two_shift ],
                       uno_one_input_bptr[ tre_thr_shift ],
                       uno_one_input_bptr[ tre_fou_shift ],
                       uno_one_input_bptr[ tre_fiv_shift ],
                       uno_one_input_bptr[ qua_two_shift ],
                       uno_one_input_bptr[ qua_thr_shift ],
                       uno_one_input_bptr[ qua_fou_shift ],
                       uno_one_input_bptr[ qua_fiv_shift ],
                       uno_one_input_bptr[ cin_thr_shift ],
                       uno_one_input_bptr[ cin_fou_shift ]);

  /*
   * Shift input pointer by one channel:
   */
  uno_one_input_bptr++;

  /*
   * Second channel:
   */
  newval[1] = nohalo1 (w_times_z,
                       x_times_z,
                       w_times_y,
                       x_times_y,
                       uno_one_input_bptr[ dos_thr_shift ],
                       uno_one_input_bptr[ dos_fou_shift ],
                       uno_one_input_bptr[ tre_two_shift ],
                       uno_one_input_bptr[ tre_thr_shift ],
                       uno_one_input_bptr[ tre_fou_shift ],
                       uno_one_input_bptr[ tre_fiv_shift ],
                       uno_one_input_bptr[ qua_two_shift ],
                       uno_one_input_bptr[ qua_thr_shift ],
                       uno_one_input_bptr[ qua_fou_shift ],
                       uno_one_input_bptr[ qua_fiv_shift ],
                       uno_one_input_bptr[ cin_thr_shift ],
                       uno_one_input_bptr[ cin_fou_shift ]);

  uno_one_input_bptr++;

  newval[2] = nohalo1 (w_times_z,
                       x_times_z,
                       w_times_y,
                       x_times_y,
                       uno_one_input_bptr[ dos_thr_shift ],
                       uno_one_input_bptr[ dos_fou_shift ],
                       uno_one_input_bptr[ tre_two_shift ],
                       uno_one_input_bptr[ tre_thr_shift ],
                       uno_one_input_bptr[ tre_fou_shift ],
                       uno_one_input_bptr[ tre_fiv_shift ],
                       uno_one_input_bptr[ qua_two_shift ],
                       uno_one_input_bptr[ qua_thr_shift ],
                       uno_one_input_bptr[ qua_fou_shift ],
                       uno_one_input_bptr[ qua_fiv_shift ],
                       uno_one_input_bptr[ cin_thr_shift ],
                       uno_one_input_bptr[ cin_fou_shift ]);

  uno_one_input_bptr++;

  newval[3] = nohalo1 (w_times_z,
                       x_times_z,
                       w_times_y,
                       x_times_y,
                       uno_one_input_bptr[ dos_thr_shift ],
                       uno_one_input_bptr[ dos_fou_shift ],
                       uno_one_input_bptr[ tre_two_shift ],
                       uno_one_input_bptr[ tre_thr_shift ],
                       uno_one_input_bptr[ tre_fou_shift ],
                       uno_one_input_bptr[ tre_fiv_shift ],
                       uno_one_input_bptr[ qua_two_shift ],
                       uno_one_input_bptr[ qua_thr_shift ],
                       uno_one_input_bptr[ qua_fou_shift ],
                       uno_one_input_bptr[ qua_fiv_shift ],
                       uno_one_input_bptr[ cin_thr_shift ],
                       uno_one_input_bptr[ cin_fou_shift ]);

  /*
   * Ship out the newval (computed new pixel values):
   */
  babl_process (babl_fish (self->interpolate_format, self->format),
                newval,
                output,
                1);
}

static void
vips_interpolate_nohalo_interpolate( VipsInterpolate *interpolate, 
	PEL *out, REGION *in, double x, double y )
{
	VipsInterpolateNohaloClass *nohalo_class = 
		VIPS_INTERPOLATE_NOHALO_GET_CLASS( interpolate );
	VipsInterpolateNohalo *nohalo = VIPS_INTERPOLATE_NOHALO( interpolate );
}

/* We need C linkage for this.
 */
extern "C" {
G_DEFINE_TYPE( VipsInterpolateNohalo, vips_interpolate_nohalo, 
	VIPS_TYPE_INTERPOLATE );
}

static void
vips_interpolate_nohalo_class_init( VipsInterpolateNohaloClass *klass )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( klass );
	VipsObjectClass *object_class = VIPS_OBJECT_CLASS( klass );
	VipsInterpolateClass *interpolate_class = 
		VIPS_INTERPOLATE_CLASS( klass );

	object_class->nickname = "nohalo";
	object_class->description = _( "nohalo interpolation" );

	interpolate_class->interpolate = 
		vips_interpolate_nohalo_interpolate;
	interpolate_class->window_size = 5;
}

static void
vips_interpolate_nohalo_init( VipsInterpolateNohalo *nohalo )
{
}
