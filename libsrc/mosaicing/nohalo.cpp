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

#define FAST_MIN(a,b) ( (a) <= (b) ? (a) : (b) )

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

static void 
nohalo_sharp_level_1( 
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
	double *r3 )
{
	/* Start of copy-paste from Nicolas's source.
	 */

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
   * The above is the "enlarged" stencil: about half the values will
   * not be used.  Once symmetry has been used to assume that the
   * sampling point is to the right and bottom of tre_thr---this is
   * done by implicitly reflecting the data if needed---the actually
   * used input values are named thus:
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
   * corresponds to dos_two in the "enlarged" one, etc.)
   *
   * Given that the reflexions are performed "outside of the
   * nohalo_sharp_level_1 function," the above 12 input values are the
   * only ones which are read from the buffer.
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
  const double half_sign_deux_tre = deux_tre >= 0. ? .5 : -.5;
  const double half_sign_troi_tre = troi_tre >= 0. ? .5 : -.5;
  const double half_sign_quat_tre = quat_tre >= 0. ? .5 : -.5;
  /*
   * Qua:
   */
  const double half_sign_deux_qua = deux_qua >= 0. ? .5 : -.5;
  const double half_sign_troi_qua = troi_qua >= 0. ? .5 : -.5;
  const double half_sign_quat_qua = quat_qua >= 0. ? .5 : -.5;
  /*
   * Thr:
   */
  const double half_sign_deux_thr = deux_thr >= 0. ? .5 : -.5;
  const double half_sign_troi_thr = troi_thr >= 0. ? .5 : -.5;
  const double half_sign_quat_thr = quat_thr >= 0. ? .5 : -.5;
  /*
   * Fou:
   */
  const double half_sign_deux_fou = deux_fou >= 0. ? .5 : -.5;
  const double half_sign_troi_fou = troi_fou >= 0. ? .5 : -.5;
  const double half_sign_quat_fou = quat_fou >= 0. ? .5 : -.5;

  /*
   * Useful later:
   */
  const double tre_thr_plus_tre_fou  = tre_thr + tre_fou;
  const double tre_thr_plus_qua_thr  = tre_thr + qua_thr;
  const double qua_fou_minus_tre_thr = qua_fou - tre_thr;

  /*
   * Tre:
   */
  const double half_abs_deux_tre = half_sign_deux_tre * deux_tre;
  const double sign_tre_thr_horizo = half_sign_deux_tre + half_sign_troi_tre;
  const double half_abs_troi_tre = half_sign_troi_tre * troi_tre;
  const double sign_tre_fou_horizo = half_sign_troi_tre + half_sign_quat_tre;
  const double half_abs_quat_tre = half_sign_quat_tre * quat_tre;
  /*
   * Thr:
   */
  const double half_abs_deux_thr = half_sign_deux_thr * deux_thr;
  const double sign_tre_thr_vertic = half_sign_deux_thr + half_sign_troi_thr;
  const double half_abs_troi_thr = half_sign_troi_thr * troi_thr;
  const double sign_qua_thr_vertic = half_sign_troi_thr + half_sign_quat_thr;
  const double half_abs_quat_thr = half_sign_quat_thr * quat_thr;
  /*
   * Qua:
   */
  const double half_abs_deux_qua = half_sign_deux_qua * deux_qua;
  const double sign_qua_thr_horizo = half_sign_deux_qua + half_sign_troi_qua;
  const double half_abs_troi_qua = half_sign_troi_qua * troi_qua;
  const double sign_qua_fou_horizo = half_sign_troi_qua + half_sign_quat_qua;
  const double half_abs_quat_qua = half_sign_quat_qua * quat_qua;
  /*
   * Fou:
   */
  const double half_abs_deux_fou = half_sign_deux_fou * deux_fou;
  const double sign_tre_fou_vertic = half_sign_deux_fou + half_sign_troi_fou;
  const double half_abs_troi_fou = half_sign_troi_fou * troi_fou;
  const double sign_qua_fou_vertic = half_sign_troi_fou + half_sign_quat_fou;
  const double half_abs_quat_fou = half_sign_quat_fou * quat_fou;

  /*
   * Tre:
   */
  const double half_size_tre_thr_horizo =
    FAST_MIN( half_abs_deux_tre, half_abs_troi_tre );
  const double half_size_tre_fou_horizo =
    FAST_MIN( half_abs_quat_tre, half_abs_troi_tre );
  /*
   * Thr:
   */
  const double half_size_tre_thr_vertic =
    FAST_MIN( half_abs_deux_thr, half_abs_troi_thr );
  const double half_size_qua_thr_vertic =
    FAST_MIN( half_abs_quat_thr, half_abs_troi_thr );
  /*
   * Qua:
   */
  const double half_size_qua_thr_horizo =
    FAST_MIN( half_abs_deux_qua, half_abs_troi_qua );
  const double half_size_qua_fou_horizo =
    FAST_MIN( half_abs_quat_qua, half_abs_troi_qua );
  /*
   * Fou:
   */
  const double half_size_tre_fou_vertic =
    FAST_MIN( half_abs_deux_fou, half_abs_troi_fou );
  const double half_size_qua_fou_vertic =
    FAST_MIN( half_abs_quat_fou, half_abs_troi_fou );

  /*
   * Compute the needed "right" (at the boundary between two input
   * pixel areas) double resolution pixel value:
   */
  /*
   * Tre:
   */
  const double two_times_tre_thrfou =
    tre_thr_plus_tre_fou
    +
    sign_tre_thr_horizo * half_size_tre_thr_horizo
    -
    sign_tre_fou_horizo * half_size_tre_fou_horizo;

  /*
   * Compute the needed "down" double resolution pixel value:
   */
  /*
   * Thr:
   */
  const double two_times_trequa_thr =
    tre_thr_plus_qua_thr
    +
    sign_tre_thr_vertic * half_size_tre_thr_vertic
    -
    sign_qua_thr_vertic * half_size_qua_thr_vertic;

  /*
   * Compute the "diagonal" (at the boundary between four input
   * pixel areas) double resolution pixel value:
   */
  const double four_times_trequa_thrfou =
    qua_fou_minus_tre_thr
    +
    sign_qua_thr_horizo * half_size_qua_thr_horizo
    -
    sign_qua_fou_horizo * half_size_qua_fou_horizo
    +
    sign_tre_fou_vertic * half_size_tre_fou_vertic
    -
    sign_qua_fou_vertic * half_size_qua_fou_vertic
    +
    two_times_tre_thrfou
    +
    two_times_trequa_thr;

	/* End of copy-paste from Nicolas' source.
	 */

	*r1 = two_times_tre_thrfou;
	*r2 = two_times_trequa_thr;
	*r3 = four_times_trequa_thrfou;
}

/* Float/double version. 
 */
template <typename T> static void inline
nohalo_sharp_level_1_float( PEL *pout, const PEL *pin, 
	const int bands, const int lskip,
	const double w_times_z,
	const double x_times_z_over_2,
	const double w_times_y_over_2,
	const double x_times_y_over_4 )
{
	T* restrict out = (T *) pout;
	const T* restrict in = (T *) pin;

	const int b1 = bands;
	const int b2 = 2 * b1;
	const int b3 = 3 * b1;
	const int b4 = 4 * b1;

	const int l1 = lskip;
	const int l2 = 2 * l1;
	const int l3 = 3 * l1;
	const int l4 = 4 * l1;

	for( int z = 0; z < bands; z++ ) {

		const T dos_thr = in[b2 + l1];
		const T dos_fou = in[b3 + l1];

		const T tre_two = in[b1 + l2];
		const T tre_thr = in[b2 + l2];
		const T tre_fou = in[b3 + l2];
		const T tre_fiv = in[b4 + l2];

		const T qua_two = in[b1 + l3];
		const T qua_thr = in[b2 + l3];
		const T qua_fou = in[b3 + l3];
		const T qua_fiv = in[b4 + l3];

		const T cin_thr = in[b2 + l4];
		const T cin_fou = in[b3 + l4];

		double two_times_tre_thrfou;
		double two_times_trequa_thr;
		double four_times_trequa_thrfou;

		nohalo_sharp_level_1( 
			dos_thr, dos_fou,
			tre_two, tre_thr, tre_fou, tre_fiv,
			qua_two, qua_thr, qua_fou, qua_fiv,
			cin_thr, cin_fou,
			&two_times_tre_thrfou,
			&two_times_trequa_thr,
			&four_times_trequa_thrfou );

		const T result = bilinear_float<T>(
			w_times_z,
			x_times_z_over_2,
			w_times_y_over_2,
			x_times_y_over_4,
			tre_thr,
			two_times_tre_thrfou,
			two_times_trequa_thr,
			four_times_trequa_thrfou );

		*out = result;

		in += 1;
		out += 1;
	}
}

/* We need C linkage for this.
 */
extern "C" {
G_DEFINE_TYPE( VipsInterpolateNohalo, vips_interpolate_nohalo, 
	VIPS_TYPE_INTERPOLATE );
}

static void
vips_interpolate_nohalo_interpolate( VipsInterpolate *interpolate, 
	PEL *out, REGION *in, double absolute_x, double absolute_y )
{
	/* VIPS versions of Nicolas's pixel addressing values.
	 * values_per_tile_row is really how much to add to skip down a row.
	 */
	const int channels_per_pixel = in->im->Bands;
	const int values_per_tile_row = 
		IM_REGION_LSKIP( in ) / IM_IMAGE_SIZEOF_ELEMENT( in->im );

	/* Copy-paste of Nicolas's pixel addressing code starts. 
	 */

  /*
   * floor's surrogate FAST_PSEUDO_FLOOR is used to make sure that the
   * transition through 0 is smooth. If it is known that absolute_x
   * and absolute_y will never be less than -.5, plain cast---that is,
   * const int ix = absolute_x + .5---should be used instead.  Any
   * function which agrees with floor for non-integer values, and
   * picks one of the two possibilities for integer values, can be
   * used.
   */
  const int ix = FAST_PSEUDO_FLOOR (absolute_x + 0.5);
  const int iy = FAST_PSEUDO_FLOOR (absolute_y + 0.5);

	/* FIXME ... this ^^^ will go outsie the 5x5 stencil, argh
	 */

  /*
   * x is the x-coordinate of the sampling point relative to the
   * position of the tre_thr pixel center. Similarly for y. Range of
   * values: [-.5,.5].
   */
  const double relative_x = absolute_x - ix;
  const double relative_y = absolute_y - iy;

  /*
   * Start of the computation of values needed to extract the properly
   * reflected needed values:
   */
  const int relative_x_is_left = ( relative_x < 0. );
  const int relative_y_is___up = ( relative_y < 0. );

  /*
   * "DIRTY" TRICK: In order to minimize the number of computed
   * "double density" pixels, we use symmetry to appropriately "flip
   * the data." (An alternative approach is to "compute everything and
   * select by zeroing coefficients.")
   */

  /*
   * The direction of movement within the (extended) possibly
   * reflected stencil is then determined by the following signs:
   */
  const int sign_of_relative_x = 1 - 2 * relative_x_is_left;
  const int sign_of_relative_y = 1 - 2 * relative_y_is___up;

  /*
   * Basic shifts:
   */
  const int shift_1_pixel  = sign_of_relative_x * channels_per_pixel;
  const int shift_1_row    = sign_of_relative_y * values_per_tile_row;

  /*
   * POST REFLEXION/POST RESCALING "DOUBLE DENSITY" COORDINATES:
   *
   * With the appropriate reflexions, we can assume that the
   * coordinates are positive (that we are in the bottom right
   * quadrant (in quadrant III) relative to tre_thr). It is also
   * convenient to scale things by 2, so that the "double density
   * pixels" are 1---instead of 1/2---apart:
   */
  const double x = ( 2 * sign_of_relative_x ) * relative_x;
  const double y = ( 2 * sign_of_relative_y ) * relative_y;

  /*
   * BILINEAR WEIGHTS:
   *
   * (w = 1-x and z = 1-y.)
   */
  const double x_times_y = x * y;
  const double w_times_y = y - x_times_y;
  const double x_times_z = x - x_times_y;
  const double w_times_z = 1. - x - w_times_y;

  /*
   * WEIGHTED BILINEAR WEIGHTS (with forthcoming coefficient
   * "folded in"):
   */
  const double x_times_y_over_4 = .25 * x_times_y;
  const double w_times_y_over_2 = .5  * w_times_y;
  const double x_times_z_over_2 = .5  * x_times_z;

	/* We need to shift and reflect the start point.
	 */
	const int target_x = ix - 2 + relative_x_is_left * 4;
	const int target_y = iy - 2 + relative_y_is___up * 4;

	const PEL * restrict p =
		(PEL *) IM_REGION_ADDR( in, target_x, target_y );

	
#ifdef DEBUG
	/* And test that all of the bytes we look at are within the window.
	 */
	const int other_x = target_x + 4 * sign_of_relative_x;
	const int other_y = target_y + 4 * sign_of_relative_y;

	const PEL * restrict q =
		(PEL *) IM_REGION_ADDR( in, other_x, other_y ); 

	printf( "vips_interpolate_nohalo_interpolate:\n" );
	printf( "\tabsolute_x = %g, absolute_y = %g\n", 
		absolute_x, absolute_y );
	printf( "\ttarget_x = %d, target_y = %d\n", 
		target_x, target_y ); 
	printf( "\tother_x = %d, other_y = %d\n", 
		other_x, other_y ); 
	printf( "\tp = %p, q = %p\n", p, q ); 
	printf( "\tshift_1_pixel = %s, shift_1_row = %s\n", 
		shift_1_pixel, shift_1_row );
#endif /*DEBUG*/

{
	/* Top-left corner of our window.
	 */
	const PEL * restrict tl =
		(PEL *) IM_REGION_ADDR( in, ix - 2, iy - 2 ); 

	/* Bottom-right corner of our window.
	 */
	const PEL * restrict br =
		(PEL *) IM_REGION_ADDR( in, ix + 2, iy + 2 ); 

	/* Last pixel we address.
	 */
	const PEL * restrict last = p + 4 * shift_1_pixel + 4 * shift_1_row;

	g_assert( last >= tl );
	g_assert( last <= br );

}

	switch( in->im->BandFmt ) {
	/*
	case IM_BANDFMT_UCHAR:
		nohalo_unsigned<unsigned char>( out, p, 
			shift_1_pixel, shift_1_row,
			w_times_z, x_times_z, w_times_y, x_times_y );
		break;

	case IM_BANDFMT_CHAR:
		nohalo_signed<signed char>( out, p, 
			shift_1_pixel, shift_1_row,
			w_times_z, x_times_z, w_times_y, x_times_y );
		break;

	case IM_BANDFMT_USHORT:
		nohalo_unsigned<unsigned short>( out, p, 
			shift_1_pixel, shift_1_row,
			w_times_z, x_times_z, w_times_y, x_times_y );
		break;

	case IM_BANDFMT_SHORT:
		nohalo_signed<signed short>( out, p, 
			shift_1_pixel, shift_1_row,
			w_times_z, x_times_z, w_times_y, x_times_y );
		break;

	case IM_BANDFMT_UINT:
		nohalo_unsigned<unsigned int>( out, p, 
			shift_1_pixel, shift_1_row,
			w_times_z, x_times_z, w_times_y, x_times_y );
		break;

	case IM_BANDFMT_INT:
		nohalo_signed<signed int>( out, p, 
			shift_1_pixel, shift_1_row,
			w_times_z, x_times_z, w_times_y, x_times_y );
		break;
	 */

	case IM_BANDFMT_FLOAT:
		nohalo_sharp_level_1_float<float>( out, p, 
			shift_1_pixel, shift_1_row,
			w_times_z,
			x_times_z_over_2,
			w_times_y_over_2,
			x_times_y_over_4 );
		break;

	/*
	case IM_BANDFMT_DOUBLE:
		nohalo_float<double>( out, p, 
			shift_1_pixel, shift_1_row,
			w_times_z, x_times_z, w_times_y, x_times_y );
		break;

	case IM_BANDFMT_COMPLEX:
		nohalo_float<float>( out, p, 
			2 * shift_1_pixel, shift_1_row,
			w_times_z, x_times_z, w_times_y, x_times_y );
		break;

	case IM_BANDFMT_DPCOMPLEX:
		nohalo_float<double>( out, p, 
			2 * shift_1_pixel, shift_1_row,
			w_times_z, x_times_z, w_times_y, x_times_y );
		break;
	 */

	default:
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
	object_class->description = _( "Bilinear plus edge enhance" );

	interpolate_class->interpolate = 
		vips_interpolate_nohalo_interpolate;
	interpolate_class->window_size = 5;
}

static void
vips_interpolate_nohalo_init( VipsInterpolateNohalo *nohalo )
{
}
