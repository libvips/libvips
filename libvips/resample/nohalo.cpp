/* Nohalo subdivision followed by LBB (Locally Bounded Bicubic)
 * interpolation
 *
 * Nohalo level 1 with bilinear finishing scheme hacked for vips based
 * on code by N. Robidoux by J. Cupitt, 20/1/09
 *
 * N. Robidoux and J. Cupitt, 4-17/3/09
 *
 * N. Robidoux, 1/4-29/5/2009
 *
 * Nohalo level 2 with bilinear finishing scheme by N. Robidoux based
 * on code by N. Robidoux, A. Turcotte and J. Cupitt, 27/1/2010
 *
 * Nohalo level 1 with LBB finishing scheme by N. Robidoux and
 * C. Racette, 11-18/5/2010
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
 * 2009-2010 (c) Nicolas Robidoux, Chantal Racette, John Cupitt and
 * Adam Turcotte
 *
 * Nicolas Robidoux thanks Geert Jordaens, Ralf Meyer, Øyvind Kolås,
 * Minglun Gong, Eric Daoust and Sven Neumann for useful comments and
 * code.
 *
 * N. Robidoux's early research on Nohalo funded in part by an NSERC
 * (National Science and Engineering Research Council of Canada)
 * Discovery Grant awarded to him (298424--2004).
 *
 * Chantal Racette's image resampling research and programming funded
 * in part by a NSERC Discovery Grant awarded to Julien Dompierre
 * (20-61098).
 *
 * A. Turcotte's image resampling research on reduced halo funded in
 * part by an NSERC Alexander Graham Bell Canada Graduate Scholarhip
 * awarded to him and by a Google Summer of Code 2010 award awarded to
 * GIMP (Gnu Image Manipulation Program).
 *
 * Nohalo with LBB finishing scheme was developed by Nicolas Robidoux
 * and Chantal Racette of the Department of Mathematics and Computer
 * Science of Laurentian University in the course of Chantal's Masters
 * Thesis in Computational Sciences, itself the continuation of
 * Chantal's Honours Thesis in Mathematics.
 */

/*
 * ================
 * NOHALO RESAMPLER
 * ================
 *
 * "Nohalo" is a resampler with a mission: smoothly straightening
 * oblique lines without undesirable side-effects. In particular,
 * without much blurring and with no added haloing.
 *
 * In this code, one Nohalo subdivision is performed. The
 * interpolation is finished with LBB (Locally Bounded Bicubic).
 *
 * Key properties:
 *
 * =======================
 * Nohalo is interpolatory
 * =======================
 *
 * That is, Nohalo preserves point values: If asked for the value at
 * the center of an input pixel, the sampler returns the corresponding
 * value, unchanged. In addition, because Nohalo is continuous, if
 * asked for a value at a location "very close" to the center of an
 * input pixel, then the sampler returns a value "very close" to
 * it. (Nohalo is not smoothing like, say, B-Spline
 * pseudo-interpolation.)
 *
 * ====================================================================
 * Nohalo subdivision is co-monotone (this is why it's called "no-halo")
 * ====================================================================
 *
 * One consequence of monotonicity is that additional subdivided
 * values are in the range of the four closest input values, which is
 * a form of local boundedness.  (Note: plain vanilla bilinear and
 * nearest neighbour are also co-monotone.) LBB is also locally
 * bounded. Consequently, Nohalo subdivision followed by LBB is
 * locally bounded. When used as a finishing scheme for Nohalo, the
 * standard LBB bounds imply that the final interpolated value is in
 * the range of the nine closest input values. This property is why
 * there is very little added haloing, even when a finishing scheme
 * which is not strictly monotone. Another consequence of local
 * boundedness is that clamping is unnecessary (provided abyss values
 * are within the range of acceptable values, which is "always" the
 * case).
 *
 * Note: If the abyss policy is an extrapolating one---for example,
 * linear or bilinear extrapolation---clamping is still unnecessary
 * UNLESS one attempts to resample outside of the convex hull of the
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
 * The interpolated pixel value when using Nohalo subdivision followed
 * by LBB only depends on the 21 (5x5 minus the four corners) closest
 * input values.
 *
 * ===============================
 * Nohalo is second order accurate
 * ===============================
 *
 * (Except possibly near the boundary: it is easy to make this
 * property carry over everywhere but this requires a tuned abyss
 * policy---linear extrapolation, say---or building the boundary
 * conditions inside the sampler.)  Nohalo+LBB is exact on linear
 * intensity profiles, meaning that if the input pixel values (in the
 * stencil) are obtained from a function of the form f(x,y) = a + b*x
 * + c*y (a, b, c constants), then the computed pixel value is exactly
 * the value of f(x,y) at the asked-for sampling location. The
 * boundary condition which is emulated by VIPS through the "extend"
 * extension of the input image---this corresponds to the nearest
 * neighbour abyss policy---does NOT make this resampler exact on
 * linears near the boundary. It does, however, guarantee that no
 * clamping is required even when resampled values are computed at
 * positions outside of the extent of the input image (when
 * extrapolation is required).
 *
 * ===================
 * Nohalo is nonlinear
 * ===================
 *
 * Both Nohalo and LBB are nonlinear, consequently their composition
 * is nonlinear.  In particular, resampling a sum of images may not be
 * the same as summing the resamples. (This occurs even without taking
 * into account over and underflow issues: images can only take values
 * within a banded range, and consequently no sampler is truly
 * linear.)
 *
 * ====================
 * Weaknesses of Nohalo
 * ====================
 *
 * In some cases, the initial subdivision computation is wasted:
 *
 * If a region is bi-chromatic, the nonlinear component of Nohalo
 * subdivision is zero in the interior of the region, and consequently
 * Nohalo subdivision boils down to bilinear. For such images, LBB is
 * probably a better choice.
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

/*
 * MINMOD is an implementation of the minmod function which only needs
 * two conditional moves.
 *
 * MINMOD(a,b,a_times_a,a_times_b) "returns" minmod(a,b). The
 * parameter ("input") a_times_a is assumed to contain the square of
 * a; the parameter a_times_b, the product of a and b.
 *
 * The version most suitable for images with flat (constant) colour
 * areas, since a, which is a pixel difference, will often be 0, in
 * which case both forward branches are likely:
 *
 * ( (a_times_b)>=0 ? 1 : 0 ) * ( (a_times_a)<=(a_times_b) ? (a) : (b) )
 *
 * For uncompressed natural images in high bit depth (images for which
 * the slopes a and b are unlikely to be equal to zero or be equal to
 * each other), we recommend using
 *
 * ( (a_times_b)>=0. ? 1. : 0. ) * ( (a_times_b)<(a_times_a) ? (b) : (a) )
 *
 * instead. With this second version, the forward branch of the second
 * conditional move is taken when |b|>|a| and when a*b<0. However, the
 * "else" branch is taken when a=0 (or when a=b), which is why this
 * second version is not recommended for images with large regions
 * with constant pixel values (or even, actually, regions with nearby
 * pixel values which vary bilinearly, which may arise from dirt-cheap
 * demosaicing or computer graphics operations).
 *
 * Both of the above use a multiplication instead of a nested
 * "if-then-else" because gcc does not always rewrite the latter using
 * conditional moves.
 *
 * Implementation note: Both of the above are better than FAST_MINMOD
 * (currently found in templates.h and used by all the other Nohalo
 * methods). Unfortunately, MINMOD uses different parameters and
 * consequently is not a direct substitute. The other Nohalo methods
 * should be modified so they use the above new minmod implementation.
 */
#define MINMOD(a,b,a_times_a,a_times_b) \
  ( (a_times_b)>=0. ? 1. : 0. ) * ( (a_times_b)<(a_times_a) ? (b) : (a) )

#define LBB_ABS(x)  ( ((x)>=0.) ? (x) : -(x) )
#define LBB_SIGN(x) ( ((x)>=0.) ? 1.0 : -1.0 )

/*
 * MIN and MAX macros set up so that I can put the likely winner in
 * the first argument (forward branch likely blah blah blah):
 */
#define LBB_MIN(x,y) ( ((x)<=(y)) ? (x) : (y) )
#define LBB_MAX(x,y) ( ((x)>=(y)) ? (x) : (y) )


static void inline
nohalo_subdivision (const double           uno_two,
                    const double           uno_thr,
                    const double           uno_fou,
                    const double           dos_one,
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
                          double* restrict uno_one_1,
                          double* restrict uno_two_1,
                          double* restrict uno_thr_1,
                          double* restrict uno_fou_1,
                          double* restrict dos_one_1,
                          double* restrict dos_two_1,
                          double* restrict dos_thr_1,
                          double* restrict dos_fou_1,
                          double* restrict tre_one_1,
                          double* restrict tre_two_1,
                          double* restrict tre_thr_1,
                          double* restrict tre_fou_1,
                          double* restrict qua_one_1,
                          double* restrict qua_two_1,
                          double* restrict qua_thr_1,
                          double* restrict qua_fou_1)
{
  /*
   * nohalo_subdivision calculates the missing twelve double density
   * pixel values, and also returns the "already known" four, so that
   * the values which make up the stencil of LBB are available.
   */
  /*
   * THE STENCIL OF INPUT VALUES:
   *
   * Pointer arithmetic is used to implicitly reflect the input
   * stencil about tre_thr---assumed closer to the sampling location
   * than other pixels (ties are OK)---in such a way that after
   * reflection the sampling point is to the bottom right of tre_thr.
   *
   * The following code and picture assumes that the stencil reflexion
   * has already been performed.
   *
   *               (ix-1,iy-2)  (ix,iy-2)    (ix+1,iy-2)
   *               =uno_two     = uno_thr    = uno_fou
   *
   *
   *
   *  (ix-2,iy-1)  (ix-1,iy-1)  (ix,iy-1)    (ix+1,iy-1)  (ix+2,iy-1)
   *  = dos_one    = dos_two    = dos_thr    = dos_fou    = dos_fiv
   *
   *
   *
   *  (ix-2,iy)    (ix-1,iy)    (ix,iy)      (ix+1,iy)    (ix+2,iy)
   *  = tre_one    = tre_two    = tre_thr    = tre_fou    = tre_fiv
   *                                    X
   *
   *
   *  (ix-2,iy+1)  (ix-1,iy+1)  (ix,iy+1)    (ix+1,iy+1)  (ix+2,iy+1)
   *  = qua_one    = qua_two    = qua_thr    = qua_fou    = qua_fiv
   *
   *
   *
   *               (ix-1,iy+2)  (ix,iy+2)    (ix+1,iy+2)
   *               = cin_two    = cin_thr    = cin_fou
   *
   *
   * The above input pixel values are the ones needed in order to make
   * available the following values, needed by LBB:
   *
   *  uno_one_1 =      uno_two_1 =  uno_thr_1 =      uno_fou_1 =
   *  (ix-1/2,iy-1/2)  (ix,iy-1/2)  (ix+1/2,iy-1/2)  (ix+1,iy-1/2)
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
   *  qua_one_1 =      qua_two_1 =  qua_thr_1 =      qua_fou_1 =
   *  (ix-1/2,iy+1)    (ix,iy+1)    (ix+1/2,iy+1)    (ix+1,iy+1)
   *
   */

  /*
   * Computation of the nonlinear slopes: If two consecutive pixel
   * value differences have the same sign, the smallest one (in
   * absolute value) is taken to be the corresponding slope; if the
   * two consecutive pixel value differences don't have the same sign,
   * the corresponding slope is set to 0.
   *
   * In other words: Apply minmod to consecutive differences.
   */
  /*
   * Two vertical simple differences:
   */
  const double d_unodos_two = dos_two - uno_two;
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
  const double d_dos_onetwo = dos_two - dos_one;
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
  const double d_unodos_times_dostre_two = d_unodos_two * d_dostre_two;
  const double d_dostre_two_sq           = d_dostre_two * d_dostre_two;
  const double d_dostre_times_trequa_two = d_dostre_two * d_trequa_two;
  const double d_trequa_times_quacin_two = d_quacin_two * d_trequa_two;
  const double d_quacin_two_sq           = d_quacin_two * d_quacin_two;

  const double d_unodos_times_dostre_thr = d_unodos_thr * d_dostre_thr;
  const double d_dostre_thr_sq           = d_dostre_thr * d_dostre_thr;
  const double d_dostre_times_trequa_thr = d_trequa_thr * d_dostre_thr;
  const double d_trequa_times_quacin_thr = d_trequa_thr * d_quacin_thr;
  const double d_quacin_thr_sq           = d_quacin_thr * d_quacin_thr;

  const double d_unodos_times_dostre_fou = d_unodos_fou * d_dostre_fou;
  const double d_dostre_fou_sq           = d_dostre_fou * d_dostre_fou;
  const double d_dostre_times_trequa_fou = d_trequa_fou * d_dostre_fou;
  const double d_trequa_times_quacin_fou = d_trequa_fou * d_quacin_fou;
  const double d_quacin_fou_sq           = d_quacin_fou * d_quacin_fou;
  /*
   * Recyclable horizontal products and squares:
   */
  const double d_dos_onetwo_times_twothr = d_dos_onetwo * d_dos_twothr;
  const double d_dos_twothr_sq           = d_dos_twothr * d_dos_twothr;
  const double d_dos_twothr_times_thrfou = d_dos_twothr * d_dos_thrfou;
  const double d_dos_thrfou_times_foufiv = d_dos_thrfou * d_dos_foufiv;
  const double d_dos_foufiv_sq           = d_dos_foufiv * d_dos_foufiv;

  const double d_tre_onetwo_times_twothr = d_tre_onetwo * d_tre_twothr;
  const double d_tre_twothr_sq           = d_tre_twothr * d_tre_twothr;
  const double d_tre_twothr_times_thrfou = d_tre_thrfou * d_tre_twothr;
  const double d_tre_thrfou_times_foufiv = d_tre_thrfou * d_tre_foufiv;
  const double d_tre_foufiv_sq           = d_tre_foufiv * d_tre_foufiv;

  const double d_qua_onetwo_times_twothr = d_qua_onetwo * d_qua_twothr;
  const double d_qua_twothr_sq           = d_qua_twothr * d_qua_twothr;
  const double d_qua_twothr_times_thrfou = d_qua_thrfou * d_qua_twothr;
  const double d_qua_thrfou_times_foufiv = d_qua_thrfou * d_qua_foufiv;
  const double d_qua_foufiv_sq           = d_qua_foufiv * d_qua_foufiv;

  /*
   * Minmod slopes and first level pixel values:
   */
  const double dos_thr_y = MINMOD( d_dostre_thr, d_unodos_thr,
                                   d_dostre_thr_sq,
                                   d_unodos_times_dostre_thr );
  const double tre_thr_y = MINMOD( d_dostre_thr, d_trequa_thr,
                                   d_dostre_thr_sq,
                                   d_dostre_times_trequa_thr );

  const double val_uno_two_1 =
    .5 * ( dos_thr + tre_thr )
    +
    .25 * ( dos_thr_y - tre_thr_y );

  const double qua_thr_y = MINMOD( d_quacin_thr, d_trequa_thr,
                                   d_quacin_thr_sq,
                                   d_trequa_times_quacin_thr );

  const double val_tre_two_1 =
    .5 * ( tre_thr + qua_thr )
    +
    .25 * ( tre_thr_y - qua_thr_y );

  const double tre_fou_y = MINMOD( d_dostre_fou, d_trequa_fou,
                                   d_dostre_fou_sq,
                                   d_dostre_times_trequa_fou );
  const double qua_fou_y = MINMOD( d_quacin_fou, d_trequa_fou,
                                   d_quacin_fou_sq,
                                   d_trequa_times_quacin_fou );

  const double val_tre_fou_1 =
    .5 * ( tre_fou + qua_fou )
    +
    .25 * ( tre_fou_y - qua_fou_y );

  const double dos_fou_y = MINMOD( d_dostre_fou, d_unodos_fou,
                                   d_dostre_fou_sq,
                                   d_unodos_times_dostre_fou );

  const double val_uno_fou_1 =
     .5 * ( dos_fou + tre_fou )
     +
     .25 * (dos_fou_y - tre_fou_y );

  const double tre_two_x = MINMOD( d_tre_twothr, d_tre_onetwo,
                                   d_tre_twothr_sq,
                                   d_tre_onetwo_times_twothr );
  const double tre_thr_x = MINMOD( d_tre_twothr, d_tre_thrfou,
                                   d_tre_twothr_sq,
                                   d_tre_twothr_times_thrfou );

  const double val_dos_one_1 =
    .5 * ( tre_two + tre_thr )
    +
    .25 * ( tre_two_x - tre_thr_x );

  const double tre_fou_x = MINMOD( d_tre_foufiv, d_tre_thrfou,
                                   d_tre_foufiv_sq,
                                   d_tre_thrfou_times_foufiv );

  const double tre_thr_x_minus_tre_fou_x =
    tre_thr_x - tre_fou_x;

  const double val_dos_thr_1 =
    .5 * ( tre_thr + tre_fou )
    +
    .25 * tre_thr_x_minus_tre_fou_x;

  const double qua_thr_x = MINMOD( d_qua_twothr, d_qua_thrfou,
                                   d_qua_twothr_sq,
                                   d_qua_twothr_times_thrfou );
  const double qua_fou_x = MINMOD( d_qua_foufiv, d_qua_thrfou,
                                   d_qua_foufiv_sq,
                                   d_qua_thrfou_times_foufiv );

  const double qua_thr_x_minus_qua_fou_x =
    qua_thr_x - qua_fou_x;

  const double val_qua_thr_1 =
    .5 * ( qua_thr + qua_fou )
    +
    .25 * qua_thr_x_minus_qua_fou_x;

  const double qua_two_x = MINMOD( d_qua_twothr, d_qua_onetwo,
                                   d_qua_twothr_sq,
                                   d_qua_onetwo_times_twothr );

  const double val_qua_one_1 =
    .5 * ( qua_two + qua_thr )
    +
    .25 * ( qua_two_x - qua_thr_x );

  const double val_tre_thr_1 =
    .125 * ( tre_thr_x_minus_tre_fou_x + qua_thr_x_minus_qua_fou_x )
    +
    .5 * ( val_tre_two_1 + val_tre_fou_1 );

  const double dos_thr_x = MINMOD( d_dos_twothr, d_dos_thrfou,
                                   d_dos_twothr_sq,
                                   d_dos_twothr_times_thrfou );
  const double dos_fou_x = MINMOD( d_dos_foufiv, d_dos_thrfou,
                                   d_dos_foufiv_sq,
                                   d_dos_thrfou_times_foufiv );

  const double val_uno_thr_1 =
    .25 * ( dos_fou - tre_thr )
    +
    .125 * ( dos_fou_y - tre_fou_y + dos_thr_x - dos_fou_x )
    +
    .5 * ( val_uno_two_1 + val_dos_thr_1 );

  const double tre_two_y = MINMOD( d_dostre_two, d_trequa_two,
                                   d_dostre_two_sq,
                                   d_dostre_times_trequa_two );
  const double qua_two_y = MINMOD( d_quacin_two, d_trequa_two,
                                   d_quacin_two_sq,
                                   d_trequa_times_quacin_two );

  const double val_tre_one_1 =
    .25 * ( qua_two - tre_thr )
    +
    .125 * ( qua_two_x - qua_thr_x + tre_two_y - qua_two_y )
    +
    .5 * ( val_dos_one_1 + val_tre_two_1 );

  const double dos_two_x = MINMOD( d_dos_twothr, d_dos_onetwo,
                                   d_dos_twothr_sq,
                                   d_dos_onetwo_times_twothr );

  const double dos_two_y = MINMOD( d_dostre_two, d_unodos_two,
                                   d_dostre_two_sq,
                                   d_unodos_times_dostre_two );

  const double val_uno_one_1 =
    .25 * ( dos_two + dos_thr + tre_two + tre_thr )
    +
    .125 * ( dos_two_x - dos_thr_x + tre_two_x - tre_thr_x )
    +
    .125 * ( dos_two_y + dos_thr_y - tre_two_y - tre_thr_y );

  /*
   * Return the sixteen LBB stencil values:
   */
  *uno_one_1 = val_uno_one_1;
  *uno_two_1 = val_uno_two_1;
  *uno_thr_1 = val_uno_thr_1;
  *uno_fou_1 = val_uno_fou_1;
  *dos_one_1 = val_dos_one_1;
  *dos_two_1 = tre_thr;
  *dos_thr_1 = val_dos_thr_1;
  *dos_fou_1 = tre_fou;
  *tre_one_1 = val_tre_one_1;
  *tre_two_1 = val_tre_two_1;
  *tre_thr_1 = val_tre_thr_1;
  *tre_fou_1 = val_tre_fou_1;
  *qua_one_1 = val_qua_one_1;
  *qua_two_1 = qua_thr;
  *qua_thr_1 = val_qua_thr_1;
  *qua_fou_1 = qua_fou;
}

/*
 * LBB (Locally Bounded Bicubic) is a high quality nonlinear variant
 * of Catmull-Rom. Images resampled with LBB have much smaller halos
 * than images resampled with windowed sincs or other interpolatory
 * cubic spline filters. Specifically, LBB halos are narrower and the
 * over/undershoot amplitude is smaller. This is accomplished without
 * a significant reduction in the smoothness of the result (compared
 * to Catmull-Rom).
 *
 * Another important property is that the resampled values are
 * contained within the range of nearby input values. Consequently, no
 * final clamping is needed to stay "in range" (e.g., 0-255 for
 * standard 8-bit images).
 *
 * LBB was developed by Nicolas Robidoux and Chantal Racette of the
 * Department of Mathematics and Computer Science of Laurentian
 * University in the course of Chantal's Masters Thesis in
 * Computational Sciences.
 */

/*
 * LBB is a novel method with the following properties:
 *
 * --LBB is a Hermite bicubic method: The bicubic surface is defined,
 *   one convex hull of four nearby input points at a time, using four
 *   point values, four x-derivatives, four y-derivatives, and four
 *   cross-derivatives.
 *
 * --The stencil for values in a square patch is the usual 4x4.
 *
 * --LBB is interpolatory.
 *
 * --It is C^1 with continuous cross derivatives.
 *
 * --When the limiters are inactive, LBB gives the same results as
 *   Catmull-Rom.
 *
 * --When used on binary images, LBB gives results similar to bicubic
 *   Hermite with all first derivatives---but not necessarily the
 *   cross derivatives--at the input pixel locations set to zero.
 *
 * --The LBB reconstruction is locally bounded: Over each square
 *   patch, the surface is contained between the minimum and the
 *   maximum values among the 16 nearest input pixel values (those in
 *   the stencil).
 *
 * --Consequently, the LBB reconstruction is globally bounded between
 *   the very smallest input pixel value and the very largest input
 *   pixel value. (It is not necessary to clamp results.)
 *
 * The LBB method is based on the method of Ken Brodlie, Petros
 * Mashwama and Sohail Butt for constraining Hermite interpolants
 * between globally defined planes:
 *
 *   Visualization of surface data to preserve positivity and other
 *   simple constraints. Computer & Graphics, Vol. 19, Number 4, pages
 *   585-594, 1995. DOI: 10.1016/0097-8493(95)00036-C.
 *
 * Instead of forcing the reconstructed surface to lie between two
 * GLOBALLY defined planes, LBB constrains one patch at a time to lie
 * between LOCALLY defined planes. This is accomplished by
 * constraining the derivatives (x, y and cross) at each input pixel
 * location so that if the constraint was applied everywhere the
 * surface would fit between the min and max of the values at the 9
 * closest pixel locations. Because this is done with each of the four
 * pixel locations which define the bicubic patch, this forces the
 * reconstructed surface to lie between the min and max of the values
 * at the 16 closest values pixel locations. (Each corner defines its
 * own 3x3 subgroup of the 4x4 stencil. Consequently, the surface is
 * necessarily above the minimum of the four minima, which happens to
 * be the minimum over the 4x4. Similarly with the maxima.)
 */

static inline double
lbbicubic( const double c00,
           const double c10,
           const double c01,
           const double c11,
           const double c00dx,
           const double c10dx,
           const double c01dx,
           const double c11dx,
           const double c00dy,
           const double c10dy,
           const double c01dy,
           const double c11dy,
           const double c00dxdy,
           const double c10dxdy,
           const double c01dxdy,
           const double c11dxdy,
           const double uno_one,
           const double uno_two,
           const double uno_thr,
           const double uno_fou,
           const double dos_one,
           const double dos_two,
           const double dos_thr,
           const double dos_fou,
           const double tre_one,
           const double tre_two,
           const double tre_thr,
           const double tre_fou,
           const double qua_one,
           const double qua_two,
           const double qua_thr,
           const double qua_fou )
{
  /*
   * STENCIL (FOOTPRINT) OF INPUT VALUES:
   *
   * The stencil of LBB is the same as for any standard Hermite
   * bicubic (e.g., Catmull-Rom):
   *
   *  (ix-1,iy-1)  (ix,iy-1)    (ix+1,iy-1)  (ix+2,iy-1)
   *  = uno_one    = uno_two    = uno_thr    = uno_fou
   *
   *  (ix-1,iy)    (ix,iy)      (ix+1,iy)    (ix+2,iy)
   *  = dos_one    = dos_two    = dos_thr    = dos_fou
   *                        X
   *  (ix-1,iy+1)  (ix,iy+1)    (ix+1,iy+1)  (ix+2,iy+1)
   *  = tre_one    = tre_two    = tre_thr    = tre_fou
   *
   *  (ix-1,iy+2)  (ix,iy+2)    (ix+1,iy+2)  (ix+2,iy+2)
   *  = qua_one    = qua_two    = qua_thr    = qua_fou
   *
   * where ix is the (pseudo-)floor of the requested left-to-right
   * location ("X"), and iy is the floor of the requested up-to-down
   * location.
   */

  /*
   * Computation of the four min and four max over 3x3 input data
   * sub-blocks of the 4x4 input stencil.
   *
   * Surprisingly, we have not succeeded in using the fact that the
   * data comes from the (co-monotone) method Nohalo so that it is
   * known ahead of time that
   *
   *  dos_thr is between dos_two and dos_fou
   *
   *  tre_two is between dos_two and qua_two
   *
   *  tre_fou is between dos_fou and qua_fou
   *
   *  qua_thr is between qua_two and qua_fou
   *
   *  tre_thr is in the convex hull of dos_two, dos_fou, qua_two and qua_fou
   *
   *  to minimize the number of flags and conditional moves.
   *
   * (The "between" are not strict: "a between b and c" means
   *
   * "min(b,c) <= a <= max(b,c)".)
   *
   *  Suggestions welcome!
   */
  const double m1    = (dos_two <= dos_thr) ? dos_two : dos_thr  ;
  const double M1    = (dos_two <= dos_thr) ? dos_thr : dos_two  ;
  const double m2    = (tre_two <= tre_thr) ? tre_two : tre_thr  ;
  const double M2    = (tre_two <= tre_thr) ? tre_thr : tre_two  ;
  const double m3    = (uno_two <= uno_thr) ? uno_two : uno_thr  ;
  const double M3    = (uno_two <= uno_thr) ? uno_thr : uno_two  ;
  const double m4    = (qua_two <= qua_thr) ? qua_two : qua_thr  ;
  const double M4    = (qua_two <= qua_thr) ? qua_thr : qua_two  ;
  const double m5    = LBB_MIN(               m1,       m2      );
  const double M5    = LBB_MAX(               M1,       M2      );
  const double m6    = (dos_one <= tre_one) ? dos_one : tre_one  ;
  const double M6    = (dos_one <= tre_one) ? tre_one : dos_one  ;
  const double m7    = (dos_fou <= tre_fou) ? dos_fou : tre_fou  ;
  const double M7    = (dos_fou <= tre_fou) ? tre_fou : dos_fou  ;
  const double m8    = LBB_MIN(               m5,       m3      );
  const double M8    = LBB_MAX(               M5,       M3      );
  const double m9    = LBB_MIN(               m5,       m4      );
  const double M9    = LBB_MAX(               M5,       M4      );
  const double m10   = LBB_MIN(               m6,       uno_one );
  const double M10   = LBB_MAX(               M6,       uno_one );
  const double m11   = LBB_MIN(               m6,       qua_one );
  const double M11   = LBB_MAX(               M6,       qua_one );
  const double m12   = LBB_MIN(               m7,       uno_fou );
  const double M12   = LBB_MAX(               M7,       uno_fou );
  const double m13   = LBB_MIN(               m7,       qua_fou );
  const double M13   = LBB_MAX(               M7,       qua_fou );
  const double min00 = LBB_MIN(               m8,       m10     );
  const double max00 = LBB_MAX(               M8,       M10     );
  const double min01 = LBB_MIN(               m9,       m11     );
  const double max01 = LBB_MAX(               M9,       M11     );
  const double min10 = LBB_MIN(               m8,       m12     );
  const double max10 = LBB_MAX(               M8,       M12     );
  const double min11 = LBB_MIN(               m9,       m13     );
  const double max11 = LBB_MAX(               M9,       M13     );
  /*
   * The remainder of the "per channel" computation involves the
   * computation of:
   *
   * --8 conditional moves,
   *
   * --8 signs (in which the sign of zero is unimportant),
   *
   * --12 minima of two values,
   *
   * --8 maxima of two values,
   *
   * --8 absolute values,
   *
   * for a grand total of 29 minima, 25 maxima, 8 conditional moves, 8
   * signs, and 8 absolute values. If everything is done with
   * conditional moves, "only" 28+8+8+12+8+8=72 flags are involved
   * (because initial min and max can be computed with one flag).
   *
   * The "per channel" part of the computation also involves 107
   * arithmetic operations (54 *, 21 +, 42 -).
   */

  /*
   * Distances to the local min and max:
   */
  const double u00 = dos_two - min00;
  const double v00 = max00 - dos_two;
  const double u01 = tre_two - min01;
  const double v01 = max01 - tre_two;
  const double u10 = dos_thr - min10;
  const double v10 = max10 - dos_thr;
  const double u11 = tre_thr - min11;
  const double v11 = max11 - tre_thr;

  /*
   * Initial values of the derivatives computed with centered
   * differences. Factors of 1/2 are left out because they are folded
   * in later:
   */
  const double dble_dzdx00i = dos_thr - dos_one;
  const double dble_dzdy11i = qua_thr - dos_thr;
  const double dble_dzdx10i = dos_fou - dos_two;
  const double dble_dzdy01i = qua_two - dos_two;
  const double dble_dzdx01i = tre_thr - tre_one;
  const double dble_dzdy10i = tre_thr - uno_thr;
  const double dble_dzdx11i = tre_fou - tre_two;
  const double dble_dzdy00i = tre_two - uno_two;

  /*
   * Signs of the derivatives. The upcoming clamping does not change
   * them (except if the clamping sends a negative derivative to 0, in
   * which case the sign does not matter anyway).
   */
  const double sign_dzdx00 = LBB_SIGN( dble_dzdx00i );
  const double sign_dzdx10 = LBB_SIGN( dble_dzdx10i );
  const double sign_dzdx01 = LBB_SIGN( dble_dzdx01i );
  const double sign_dzdx11 = LBB_SIGN( dble_dzdx11i );

  const double sign_dzdy00 = LBB_SIGN( dble_dzdy00i );
  const double sign_dzdy10 = LBB_SIGN( dble_dzdy10i );
  const double sign_dzdy01 = LBB_SIGN( dble_dzdy01i );
  const double sign_dzdy11 = LBB_SIGN( dble_dzdy11i );

  /*
   * Initial values of the cross-derivatives. Factors of 1/4 are left
   * out because folded in later:
   */
  const double quad_d2zdxdy00i = uno_one - uno_thr + dble_dzdx01i;
  const double quad_d2zdxdy10i = uno_two - uno_fou + dble_dzdx11i;
  const double quad_d2zdxdy01i = qua_thr - qua_one - dble_dzdx00i;
  const double quad_d2zdxdy11i = qua_fou - qua_two - dble_dzdx10i;

  /*
   * Slope limiters. The key multiplier is 3 but we fold a factor of
   * 2, hence 6:
   */
  const double dble_slopelimit_00 = 6.0 * LBB_MIN( u00, v00 );
  const double dble_slopelimit_10 = 6.0 * LBB_MIN( u10, v10 );
  const double dble_slopelimit_01 = 6.0 * LBB_MIN( u01, v01 );
  const double dble_slopelimit_11 = 6.0 * LBB_MIN( u11, v11 );

  /*
   * Clamped first derivatives:
   */
  const double dble_dzdx00 =
    ( sign_dzdx00 * dble_dzdx00i <= dble_slopelimit_00 )
    ? dble_dzdx00i :  sign_dzdx00 * dble_slopelimit_00;
  const double dble_dzdy00 =
    ( sign_dzdy00 * dble_dzdy00i <= dble_slopelimit_00 )
    ? dble_dzdy00i :  sign_dzdy00 * dble_slopelimit_00;
  const double dble_dzdx10 =
    ( sign_dzdx10 * dble_dzdx10i <= dble_slopelimit_10 )
    ? dble_dzdx10i :  sign_dzdx10 * dble_slopelimit_10;
  const double dble_dzdy10 =
    ( sign_dzdy10 * dble_dzdy10i <= dble_slopelimit_10 )
    ? dble_dzdy10i :  sign_dzdy10 * dble_slopelimit_10;
  const double dble_dzdx01 =
    ( sign_dzdx01 * dble_dzdx01i <= dble_slopelimit_01 )
    ? dble_dzdx01i :  sign_dzdx01 * dble_slopelimit_01;
  const double dble_dzdy01 =
    ( sign_dzdy01 * dble_dzdy01i <= dble_slopelimit_01 )
    ? dble_dzdy01i :  sign_dzdy01 * dble_slopelimit_01;
  const double dble_dzdx11 =
    ( sign_dzdx11 * dble_dzdx11i <= dble_slopelimit_11 )
    ? dble_dzdx11i :  sign_dzdx11 * dble_slopelimit_11;
  const double dble_dzdy11 =
    ( sign_dzdy11 * dble_dzdy11i <= dble_slopelimit_11 )
    ? dble_dzdy11i :  sign_dzdy11 * dble_slopelimit_11;

  /*
   * Sums and differences of first derivatives:
   */
  const double twelve_sum00 = 6.0 * ( dble_dzdx00 + dble_dzdy00 );
  const double twelve_dif00 = 6.0 * ( dble_dzdx00 - dble_dzdy00 );
  const double twelve_sum10 = 6.0 * ( dble_dzdx10 + dble_dzdy10 );
  const double twelve_dif10 = 6.0 * ( dble_dzdx10 - dble_dzdy10 );
  const double twelve_sum01 = 6.0 * ( dble_dzdx01 + dble_dzdy01 );
  const double twelve_dif01 = 6.0 * ( dble_dzdx01 - dble_dzdy01 );
  const double twelve_sum11 = 6.0 * ( dble_dzdx11 + dble_dzdy11 );
  const double twelve_dif11 = 6.0 * ( dble_dzdx11 - dble_dzdy11 );

  /*
   * Absolute values of the sums:
   */
  const double twelve_abs_sum00 = LBB_ABS( twelve_sum00 );
  const double twelve_abs_sum10 = LBB_ABS( twelve_sum10 );
  const double twelve_abs_sum01 = LBB_ABS( twelve_sum01 );
  const double twelve_abs_sum11 = LBB_ABS( twelve_sum11 );

  /*
   * Scaled distances to the min:
   */
  const double u00_times_36 = 36.0 * u00;
  const double u10_times_36 = 36.0 * u10;
  const double u01_times_36 = 36.0 * u01;
  const double u11_times_36 = 36.0 * u11;

  /*
   * First cross-derivative limiter:
   */
  const double first_limit00 = twelve_abs_sum00 - u00_times_36;
  const double first_limit10 = twelve_abs_sum10 - u10_times_36;
  const double first_limit01 = twelve_abs_sum01 - u01_times_36;
  const double first_limit11 = twelve_abs_sum11 - u11_times_36;

  const double quad_d2zdxdy00ii = LBB_MAX( quad_d2zdxdy00i, first_limit00 );
  const double quad_d2zdxdy10ii = LBB_MAX( quad_d2zdxdy10i, first_limit10 );
  const double quad_d2zdxdy01ii = LBB_MAX( quad_d2zdxdy01i, first_limit01 );
  const double quad_d2zdxdy11ii = LBB_MAX( quad_d2zdxdy11i, first_limit11 );

  /*
   * Scaled distances to the max:
   */
  const double v00_times_36 = 36.0 * v00;
  const double v10_times_36 = 36.0 * v10;
  const double v01_times_36 = 36.0 * v01;
  const double v11_times_36 = 36.0 * v11;

  /*
   * Second cross-derivative limiter:
   */
  const double second_limit00 = v00_times_36 - twelve_abs_sum00;
  const double second_limit10 = v10_times_36 - twelve_abs_sum10;
  const double second_limit01 = v01_times_36 - twelve_abs_sum01;
  const double second_limit11 = v11_times_36 - twelve_abs_sum11;

  const double quad_d2zdxdy00iii = LBB_MIN( quad_d2zdxdy00ii, second_limit00 );
  const double quad_d2zdxdy10iii = LBB_MIN( quad_d2zdxdy10ii, second_limit10 );
  const double quad_d2zdxdy01iii = LBB_MIN( quad_d2zdxdy01ii, second_limit01 );
  const double quad_d2zdxdy11iii = LBB_MIN( quad_d2zdxdy11ii, second_limit11 );

  /*
   * Absolute values of the differences:
   */
  const double twelve_abs_dif00 = LBB_ABS( twelve_dif00 );
  const double twelve_abs_dif10 = LBB_ABS( twelve_dif10 );
  const double twelve_abs_dif01 = LBB_ABS( twelve_dif01 );
  const double twelve_abs_dif11 = LBB_ABS( twelve_dif11 );

  /*
   * Third cross-derivative limiter:
   */
  const double third_limit00 = twelve_abs_dif00 - v00_times_36;
  const double third_limit10 = twelve_abs_dif10 - v10_times_36;
  const double third_limit01 = twelve_abs_dif01 - v01_times_36;
  const double third_limit11 = twelve_abs_dif11 - v11_times_36;

  const double quad_d2zdxdy00iiii = LBB_MAX( quad_d2zdxdy00iii, third_limit00);
  const double quad_d2zdxdy10iiii = LBB_MAX( quad_d2zdxdy10iii, third_limit10);
  const double quad_d2zdxdy01iiii = LBB_MAX( quad_d2zdxdy01iii, third_limit01);
  const double quad_d2zdxdy11iiii = LBB_MAX( quad_d2zdxdy11iii, third_limit11);

  /*
   * Fourth cross-derivative limiter:
   */
  const double fourth_limit00 = u00_times_36 - twelve_abs_dif00;
  const double fourth_limit10 = u10_times_36 - twelve_abs_dif10;
  const double fourth_limit01 = u01_times_36 - twelve_abs_dif01;
  const double fourth_limit11 = u11_times_36 - twelve_abs_dif11;

  const double quad_d2zdxdy00 = LBB_MIN( quad_d2zdxdy00iiii, fourth_limit00);
  const double quad_d2zdxdy10 = LBB_MIN( quad_d2zdxdy10iiii, fourth_limit10);
  const double quad_d2zdxdy01 = LBB_MIN( quad_d2zdxdy01iiii, fourth_limit01);
  const double quad_d2zdxdy11 = LBB_MIN( quad_d2zdxdy11iiii, fourth_limit11);

  /*
   * Four times the part of the result which only uses cross
   * derivatives:
   */
  const double newval3 = c00dxdy * quad_d2zdxdy00
                         +
                         c10dxdy * quad_d2zdxdy10
                         +
                         c01dxdy * quad_d2zdxdy01
                         +
                         c11dxdy * quad_d2zdxdy11;

  /*
   * Twice the part of the result which only needs first derivatives.
   */
  const double newval2 = c00dx * dble_dzdx00
                         +
                         c10dx * dble_dzdx10
                         +
                         c01dx * dble_dzdx01
                         +
                         c11dx * dble_dzdx11
                         +
                         c00dy * dble_dzdy00
                         +
                         c10dy * dble_dzdy10
                         +
                         c01dy * dble_dzdy01
                         +
                         c11dy * dble_dzdy11;

  /*
   * Part of the result which does not need derivatives:
   */
  const double newval1 = c00 * dos_two
                         +
                         c10 * dos_thr
                         +
                         c01 * tre_two
                         +
                         c11 * tre_thr;

  const double newval = newval1 + .5 * newval2 + .25 * newval3;

  return newval;
}

/*
 * Call Nohalo+LBB with a careful type conversion as a parameter.
 *
 * It would be nice to do this with templates somehow---for one thing
 * this would allow code comments!---but we can't figure a clean way
 * to do it.
 */
#define NOHALO_CONVERSION( conversion )               \
  template <typename T> static void inline            \
  nohalo_ ## conversion(       PEL*   restrict pout,  \
                         const PEL*   restrict pin,   \
                         const int             bands, \
                         const int             lskip, \
                         const double          x_0,   \
                         const double          y_0 )  \
  { \
    T* restrict out = (T *) pout; \
    \
    const T* restrict in = (T *) pin; \
    \
    \
    const int sign_of_x_0 = 2 * ( x_0 >= 0. ) - 1; \
    const int sign_of_y_0 = 2 * ( y_0 >= 0. ) - 1; \
    \
    \
    const int shift_forw_1_pix = sign_of_x_0 * bands; \
    const int shift_forw_1_row = sign_of_y_0 * lskip; \
    \
    const int shift_back_1_pix = -shift_forw_1_pix; \
    const int shift_back_1_row = -shift_forw_1_row; \
    \
    const int shift_back_2_pix = 2 * shift_back_1_pix; \
    const int shift_back_2_row = 2 * shift_back_1_row; \
    const int shift_forw_2_pix = 2 * shift_forw_1_pix; \
    const int shift_forw_2_row = 2 * shift_forw_1_row; \
    \
    \
    const int uno_two_shift = shift_back_1_pix + shift_back_2_row; \
    const int uno_thr_shift =                    shift_back_2_row; \
    const int uno_fou_shift = shift_forw_1_pix + shift_back_2_row; \
    \
    const int dos_one_shift = shift_back_2_pix + shift_back_1_row; \
    const int dos_two_shift = shift_back_1_pix + shift_back_1_row; \
    const int dos_thr_shift =                    shift_back_1_row; \
    const int dos_fou_shift = shift_forw_1_pix + shift_back_1_row; \
    const int dos_fiv_shift = shift_forw_2_pix + shift_back_1_row; \
    \
    const int tre_one_shift = shift_back_2_pix; \
    const int tre_two_shift = shift_back_1_pix; \
    const int tre_thr_shift = 0;                \
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
    \
    const double xp1over2   = ( 2 * sign_of_x_0 ) * x_0; \
    const double xm1over2   = xp1over2 - 1.0; \
    const double onepx      = 0.5 + xp1over2; \
    const double onemx      = 1.5 - xp1over2; \
    const double xp1over2sq = xp1over2 * xp1over2; \
    \
    const double yp1over2   = ( 2 * sign_of_y_0 ) * y_0; \
    const double ym1over2   = yp1over2 - 1.0; \
    const double onepy      = 0.5 + yp1over2; \
    const double onemy      = 1.5 - yp1over2; \
    const double yp1over2sq = yp1over2 * yp1over2; \
    \
    const double xm1over2sq = xm1over2 * xm1over2; \
    const double ym1over2sq = ym1over2 * ym1over2; \
    \
    const double twice1px = onepx + onepx; \
    const double twice1py = onepy + onepy; \
    const double twice1mx = onemx + onemx; \
    const double twice1my = onemy + onemy; \
    \
    const double xm1over2sq_times_ym1over2sq = xm1over2sq * ym1over2sq; \
    const double xp1over2sq_times_ym1over2sq = xp1over2sq * ym1over2sq; \
    const double xp1over2sq_times_yp1over2sq = xp1over2sq * yp1over2sq; \
    const double xm1over2sq_times_yp1over2sq = xm1over2sq * yp1over2sq; \
    \
    const double four_times_1px_times_1py = twice1px * twice1py; \
    const double four_times_1mx_times_1py = twice1mx * twice1py; \
    const double twice_xp1over2_times_1py = xp1over2 * twice1py; \
    const double twice_xm1over2_times_1py = xm1over2 * twice1py; \
    \
    const double twice_xm1over2_times_1my = xm1over2 * twice1my; \
    const double twice_xp1over2_times_1my = xp1over2 * twice1my; \
    const double four_times_1mx_times_1my = twice1mx * twice1my; \
    const double four_times_1px_times_1my = twice1px * twice1my; \
    \
    const double twice_1px_times_ym1over2 = twice1px * ym1over2; \
    const double twice_1mx_times_ym1over2 = twice1mx * ym1over2; \
    const double xp1over2_times_ym1over2  = xp1over2 * ym1over2; \
    const double xm1over2_times_ym1over2  = xm1over2 * ym1over2; \
    \
    const double xm1over2_times_yp1over2  = xm1over2 * yp1over2; \
    const double xp1over2_times_yp1over2  = xp1over2 * yp1over2; \
    const double twice_1mx_times_yp1over2 = twice1mx * yp1over2; \
    const double twice_1px_times_yp1over2 = twice1px * yp1over2; \
    \
    \
    const double c00 = \
      four_times_1px_times_1py * xm1over2sq_times_ym1over2sq; \
    const double c00dx = \
      twice_xp1over2_times_1py * xm1over2sq_times_ym1over2sq; \
    const double c00dy = \
      twice_1px_times_yp1over2 * xm1over2sq_times_ym1over2sq; \
    const double c00dxdy = \
       xp1over2_times_yp1over2 * xm1over2sq_times_ym1over2sq; \
    \
    const double c10 = \
      four_times_1mx_times_1py * xp1over2sq_times_ym1over2sq; \
    const double c10dx = \
      twice_xm1over2_times_1py * xp1over2sq_times_ym1over2sq; \
    const double c10dy = \
      twice_1mx_times_yp1over2 * xp1over2sq_times_ym1over2sq; \
    const double c10dxdy = \
       xm1over2_times_yp1over2 * xp1over2sq_times_ym1over2sq; \
    \
    const double c01 = \
      four_times_1px_times_1my * xm1over2sq_times_yp1over2sq; \
    const double c01dx = \
      twice_xp1over2_times_1my * xm1over2sq_times_yp1over2sq; \
    const double c01dy = \
      twice_1px_times_ym1over2 * xm1over2sq_times_yp1over2sq; \
    const double c01dxdy = \
       xp1over2_times_ym1over2 * xm1over2sq_times_yp1over2sq; \
    \
    const double c11 = \
      four_times_1mx_times_1my * xp1over2sq_times_yp1over2sq; \
    const double c11dx = \
      twice_xm1over2_times_1my * xp1over2sq_times_yp1over2sq; \
    const double c11dy = \
      twice_1mx_times_ym1over2 * xp1over2sq_times_yp1over2sq; \
    const double c11dxdy = \
       xm1over2_times_ym1over2 * xp1over2sq_times_yp1over2sq; \
    \
    \
    int band = bands; \
    \
    \
    do \
      { \
        double uno_one, uno_two, uno_thr, uno_fou;  \
        double dos_one, dos_two, dos_thr, dos_fou;  \
        double tre_one, tre_two, tre_thr, tre_fou;  \
        double qua_one, qua_two, qua_thr, qua_fou;  \
        \
        nohalo_subdivision( in[ uno_two_shift ], \
                            in[ uno_thr_shift ], \
                            in[ uno_fou_shift ], \
                            in[ dos_one_shift ], \
                            in[ dos_two_shift ], \
                            in[ dos_thr_shift ], \
                            in[ dos_fou_shift ], \
                            in[ dos_fiv_shift ], \
                            in[ tre_one_shift ], \
                            in[ tre_two_shift ], \
                            in[ tre_thr_shift ], \
                            in[ tre_fou_shift ], \
                            in[ tre_fiv_shift ], \
                            in[ qua_one_shift ], \
                            in[ qua_two_shift ], \
                            in[ qua_thr_shift ], \
                            in[ qua_fou_shift ], \
                            in[ qua_fiv_shift ], \
                            in[ cin_two_shift ], \
                            in[ cin_thr_shift ], \
                            in[ cin_fou_shift ], \
                            &uno_one,            \
                            &uno_two,            \
                            &uno_thr,            \
                            &uno_fou,            \
                            &dos_one,            \
                            &dos_two,            \
                            &dos_thr,            \
                            &dos_fou,            \
                            &tre_one,            \
                            &tre_two,            \
                            &tre_thr,            \
                            &tre_fou,            \
                            &qua_one,            \
                            &qua_two,            \
                            &qua_thr,            \
                            &qua_fou );          \
        \
        const double double_result =        \
          lbbicubic( c00,                   \
                     c10,                   \
                     c01,                   \
                     c11,                   \
                     c00dx,                 \
                     c10dx,                 \
                     c01dx,                 \
                     c11dx,                 \
                     c00dy,                 \
                     c10dy,                 \
                     c01dy,                 \
                     c11dy,                 \
                     c00dxdy,               \
                     c10dxdy,               \
                     c01dxdy,               \
                     c11dxdy,               \
                     uno_one,               \
                     uno_two,               \
                     uno_thr,               \
                     uno_fou,               \
                     dos_one,               \
                     dos_two,               \
                     dos_thr,               \
                     dos_fou,               \
                     tre_one,               \
                     tre_two,               \
                     tre_thr,               \
                     tre_fou,               \
                     qua_one,               \
                     qua_two,               \
                     qua_thr,               \
                     qua_fou );             \
        \
        {                                                         \
          const T result = to_ ## conversion<T>( double_result ); \
          in++;                                                   \
          *out++ = result;                                        \
        }                                                         \
        \
      } while (--band); \
  }


NOHALO_CONVERSION( fptypes )
NOHALO_CONVERSION( withsign )
NOHALO_CONVERSION( nosign )


#define CALL( T, conversion )             \
  nohalo_ ## conversion<T>( out,          \
                            p,            \
                            bands,        \
                            lskip,        \
                            relative_x,   \
                            relative_y );


/*
 * We need C linkage:
 */
extern "C" {
G_DEFINE_TYPE( VipsInterpolateNohalo, vips_interpolate_nohalo,
	VIPS_TYPE_INTERPOLATE );
}


static void
vips_interpolate_nohalo_interpolate( VipsInterpolate* restrict interpolate,
                                     PEL*             restrict out,
                                     REGION*          restrict in,
                                     double                    absolute_x,
                                     double                    absolute_y )
{
  /*
   * Floor's surrogate FAST_PSEUDO_FLOOR is used to make sure that the
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
  const int ix = FAST_PSEUDO_FLOOR( absolute_x + .5 );
  const int iy = FAST_PSEUDO_FLOOR( absolute_y + .5 );

  /*
   * Move the pointer to (the first band of) the top/left pixel of the
   * 2x2 group of pixel centers which contains the sampling location
   * in its convex hull:
   */
  const PEL* restrict p = (PEL *) IM_REGION_ADDR( in, ix, iy );

  const double relative_x = absolute_x - ix;
  const double relative_y = absolute_y - iy;

  /*
   * VIPS versions of Nicolas's pixel addressing values.
   */
  const int actual_bands = in->im->Bands;
  const int lskip = IM_REGION_LSKIP( in ) / IM_IMAGE_SIZEOF_ELEMENT( in->im );
  /*
   * Double the bands for complex images to account for the real and
   * imaginary parts being computed independently:
   */
  const int bands =
    vips_bandfmt_iscomplex( in->im->BandFmt ) ? 2 * actual_bands : actual_bands;

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

  /*
   * Complex images are handled by doubling of bands.
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
vips_interpolate_nohalo_class_init( VipsInterpolateNohaloClass *klass )
{
  GObjectClass *gobject_class = G_OBJECT_CLASS( klass );
  VipsObjectClass *object_class = VIPS_OBJECT_CLASS( klass );
  VipsInterpolateClass *interpolate_class = VIPS_INTERPOLATE_CLASS( klass );

  gobject_class->set_property = vips_object_set_property;
  gobject_class->get_property = vips_object_get_property;

  object_class->nickname    = "nohalo";
  object_class->description =
    _( "Edge sharpening resampler with halo reduction" );

  interpolate_class->interpolate   = vips_interpolate_nohalo_interpolate;
  interpolate_class->window_size   = 5;
  interpolate_class->window_offset = 2;
}

static void
vips_interpolate_nohalo_init( VipsInterpolateNohalo *nohalo )
{
}
