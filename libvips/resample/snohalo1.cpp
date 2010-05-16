/* snohalo (level 1.5) interpolator
 *
 * Snohalo = "Smooth Nohalo" = Nohalo with custom antialiasing blur.
 *
 * When blur = 0. (minimum value), Snohalo level 1.5 gives the same
 * results as Nohalo level 2. At the maximum reasonable blur value
 * (1.), very strong antialiasing takes place.
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
 * 2009-2010 (c) Nicolas Robidoux, Adam Turcotte, John Cupitt, Eric
 * Daoust.
 *
 * N. Robidoux thanks Minglun Gong, Ralf Meyer, Geert Jordaens and
 * Øyvind Kolås for useful comments and code.
 *
 * N. Robidoux's early research on Nohalo funded in part by an NSERC
 * (National Science and Engineering Research Council of Canada)
 * Discovery Grant.
 *
 * A. Turcotte and E. Daoust's Nohalo programming funded in part by
 * two Google Summer of Code 2010 awards made to GIMP (Gnu Image
 * Manipulation Program).
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

/* Properties.
 */
enum {
	PROP_BLUR = 1,
	PROP_LAST
};

#define VIPS_TYPE_INTERPOLATE_SNOHALO1 \
	(vips_interpolate_snohalo1_get_type())
#define VIPS_INTERPOLATE_SNOHALO1( obj ) \
	(G_TYPE_CHECK_INSTANCE_CAST( (obj), \
	VIPS_TYPE_INTERPOLATE_SNOHALO1, VipsInterpolateSnohalo1 ))
#define VIPS_INTERPOLATE_SNOHALO1_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_CAST( (klass), \
	VIPS_TYPE_INTERPOLATE_SNOHALO1, VipsInterpolateSnohalo1Class))
#define VIPS_IS_INTERPOLATE_SNOHALO1( obj ) \
	(G_TYPE_CHECK_INSTANCE_TYPE( (obj), VIPS_TYPE_INTERPOLATE_SNOHALO1 ))
#define VIPS_IS_INTERPOLATE_SNOHALO1_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_TYPE( (klass), VIPS_TYPE_INTERPOLATE_SNOHALO1 ))
#define VIPS_INTERPOLATE_SNOHALO1_GET_CLASS( obj ) \
	(G_TYPE_INSTANCE_GET_CLASS( (obj), \
	VIPS_TYPE_INTERPOLATE_SNOHALO1, VipsInterpolateSnohalo1Class ))

typedef struct _VipsInterpolateSnohalo1 {
	VipsInterpolate parent_object;

	double blur;
} VipsInterpolateSnohalo1;

typedef struct _VipsInterpolateSnohalo1Class {
	VipsInterpolateClass parent_class;

} VipsInterpolateSnohalo1Class;

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

static void inline
snohalo_step1 (const double           blur,
               const double           cer_thr_in,
               const double           cer_fou_in,
               const double           uno_two_in,
               const double           uno_thr_in,
               const double           uno_fou_in,
               const double           uno_fiv_in,
               const double           dos_one_in,
               const double           dos_two_in,
               const double           dos_thr_in,
               const double           dos_fou_in,
               const double           dos_fiv_in,
               const double           dos_six_in,
               const double           tre_zer_in,
               const double           tre_one_in,
               const double           tre_two_in,
               const double           tre_thr_in,
               const double           tre_fou_in,
               const double           tre_fiv_in,
               const double           tre_six_in,
               const double           qua_zer_in,
               const double           qua_one_in,
               const double           qua_two_in,
               const double           qua_thr_in,
               const double           qua_fou_in,
               const double           qua_fiv_in,
               const double           qua_six_in,
               const double           cin_one_in,
               const double           cin_two_in,
               const double           cin_thr_in,
               const double           cin_fou_in,
               const double           cin_fiv_in,
               const double           sei_two_in,
               const double           sei_thr_in,
               const double           sei_fou_in,
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
                     double* restrict qua_thr_1)
{
  /*
   * snohalo_step1 calculates the missing ten double density pixel
   * values, and also returns the "already known" two, so that the
   * twelve values which make up the stencil of Nohalo level 1 are
   * available.
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
   *
   *                                         (ix,iy-3)    (ix+1,iy-3)
   *                                         = cer_thr    = cer_fou
   *
   *
   *
   *                            (ix-1,iy-2)  (ix,iy-2)    (ix+1,iy-2)  (ix+1,iy-3)
   *                            = uno_two    = uno_thr    = uno_fou    = uno_fiv
   *
   *
   *
   *               (ix-2,iy-1)  (ix-1,iy-1)  (ix,iy-1)    (ix+1,iy-1)  (ix+2,iy-1)  (ix+3,iy-1)
   *               = dos_one    = dos_two    = dos_thr    = dos_fou    = dos_fiv    = dos_six
   *
   *
   *
   *  (ix-3,iy)    (ix-2,iy)    (ix-1,iy)    (ix,iy)      (ix+1,iy)    (ix+2,iy)    (ix+3,iy)
   *  = tre_zer    = tre_one    = tre_two    = tre_thr    = tre_fou    = tre_fiv    = tre_six
   *                                                  X
   *
   *
   *  (ix-3,iy)    (ix-2,iy)    (ix-1,iy+1)  (ix,iy+1)    (ix+1,iy+1)  (ix+2,iy+1)  (ix+3,iy+1)
   *  = qua_zer    = qua_one    = qua_two    = qua_thr    = qua_fou    = qua_fiv    = qua_six
   *
   *
   *
   *               (ix-2,iy+2)  (ix-1,iy+2)  (ix,iy+2)    (ix+1,iy+2)  (ix+2,iy+2)
   *               = cin_one    = cin_two    = cin_thr    = cin_fou    = cin_fiv
   *
   *
   *
   *                            (ix-1,iy+3)  (ix,iy+3)    (ix+1,iy+3)
   *                            = sei_two    = sei_thr    = sei_fou
   *
   *
   * The above input pixel values are the ones needed in order to make
   * available to the second level the following first level values:
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
   * Nohalo/Snohalo blended weights:
   */
  const double beta = .125 * blur;
  const double theta = 1. + -.5 * blur;

  /*
   * Computation of the blurred input pixel values:
   */
  const double uno_two_plus_cer_thr_in = uno_two_in + cer_thr_in;
  const double uno_thr_plus_cer_fou_in = uno_thr_in + cer_fou_in;

  const double dos_one_plus_uno_two_in = dos_one_in + uno_two_in;
  const double dos_two_plus_uno_thr_in = dos_two_in + uno_thr_in;
  const double dos_thr_plus_uno_fou_in = dos_thr_in + uno_fou_in;
  const double dos_fou_plus_uno_fiv_in = dos_fou_in + uno_fiv_in;

  const double tre_zer_plus_dos_one_in = tre_zer_in + dos_one_in;
  const double tre_one_plus_dos_two_in = tre_one_in + dos_two_in;
  const double tre_two_plus_dos_thr_in = tre_two_in + dos_thr_in;
  const double tre_thr_plus_dos_fou_in = tre_thr_in + dos_fou_in;
  const double tre_fou_plus_dos_fiv_in = tre_fou_in + dos_fiv_in;
  const double tre_fiv_plus_dos_six_in = tre_fiv_in + dos_six_in;

  const double qua_zer_plus_tre_one_in = qua_zer_in + tre_one_in;
  const double qua_one_plus_tre_two_in = qua_one_in + tre_two_in;
  const double qua_two_plus_tre_thr_in = qua_two_in + tre_thr_in;
  const double qua_thr_plus_tre_fou_in = qua_thr_in + tre_fou_in;
  const double qua_fou_plus_tre_fiv_in = qua_fou_in + tre_fiv_in;
  const double qua_fiv_plus_tre_six_in = qua_fiv_in + tre_six_in;

  const double cin_one_plus_qua_two_in = cin_one_in + qua_two_in;
  const double cin_two_plus_qua_thr_in = cin_two_in + qua_thr_in;
  const double cin_thr_plus_qua_fou_in = cin_thr_in + qua_fou_in;
  const double cin_fou_plus_qua_fiv_in = cin_fou_in + qua_fiv_in;
  const double cin_fiv_plus_qua_six_in = cin_fiv_in + qua_six_in;

  const double sei_two_plus_cin_thr_in = sei_two_in + cin_thr_in;
  const double sei_thr_plus_cin_fou_in = sei_thr_in + cin_fou_in;
  const double sei_fou_plus_cin_fiv_in = sei_fou_in + cin_fiv_in;

  const double uno_thr =
    beta * ( uno_two_plus_cer_thr_in + dos_thr_plus_uno_fou_in )
    + theta * uno_thr_in;
  const double uno_fou =
    beta * ( uno_thr_plus_cer_fou_in + dos_fou_plus_uno_fiv_in )
    + theta * uno_fou_in;

  const double dos_two =
    beta * ( dos_one_plus_uno_two_in + tre_two_plus_dos_thr_in )
    + theta * dos_two_in;
  const double dos_thr =
    beta * ( dos_two_plus_uno_thr_in + tre_thr_plus_dos_fou_in )
    + theta * dos_thr_in;
  const double dos_fou =
    beta * ( dos_thr_plus_uno_fou_in + tre_fou_plus_dos_fiv_in )
    + theta * dos_fou_in;
  const double dos_fiv =
    beta * ( dos_fou_plus_uno_fiv_in + tre_fiv_plus_dos_six_in )
    + theta * dos_fiv_in;

  const double tre_one =
    beta * ( tre_zer_plus_dos_one_in + qua_one_plus_tre_two_in )
    + theta * tre_one_in;
  const double tre_two =
    beta * ( tre_one_plus_dos_two_in + qua_two_plus_tre_thr_in )
    + theta * tre_two_in;
  const double tre_thr =
    beta * ( tre_two_plus_dos_thr_in + qua_thr_plus_tre_fou_in )
    + theta * tre_thr_in;
  const double tre_fou =
    beta * ( tre_thr_plus_dos_fou_in + qua_fou_plus_tre_fiv_in )
    + theta * tre_fou_in;
  const double tre_fiv =
    beta * ( tre_fou_plus_dos_fiv_in + qua_fiv_plus_tre_six_in )
    + theta * tre_fiv_in;

  const double qua_one =
    beta * ( qua_zer_plus_tre_one_in + cin_one_plus_qua_two_in )
    + theta * qua_one_in;
  const double qua_two =
    beta * ( qua_one_plus_tre_two_in + cin_two_plus_qua_thr_in )
    + theta * qua_two_in;
  const double qua_thr =
    beta * ( qua_two_plus_tre_thr_in + cin_thr_plus_qua_fou_in )
    + theta * qua_thr_in;
  const double qua_fou =
    beta * ( qua_thr_plus_tre_fou_in + cin_fou_plus_qua_fiv_in )
    + theta * qua_fou_in;
  const double qua_fiv =
    beta * ( qua_fou_plus_tre_fiv_in + cin_fiv_plus_qua_six_in )
    + theta * qua_fiv_in;

  const double cin_two =
    beta * ( cin_one_plus_qua_two_in + sei_two_plus_cin_thr_in )
    + theta * cin_two_in;
  const double cin_thr =
    beta * ( cin_two_plus_qua_thr_in + sei_thr_plus_cin_fou_in )
    + theta * cin_thr_in;
  const double cin_fou =
    beta * ( cin_thr_plus_qua_fou_in + sei_fou_plus_cin_fiv_in )
    + theta * cin_fou_in;

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
  const double d_trequa_times_quacin_two = d_quacin_two * d_trequa_two;

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
  const double d_dos_twothr_times_thrfou = d_dos_twothr * d_dos_thrfou;
  const double d_dos_thrfou_sq           = d_dos_thrfou * d_dos_thrfou;
  const double d_dos_thrfou_times_foufiv = d_dos_foufiv * d_dos_thrfou;

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
  const double val_tre_thr_1 =
    .125 * ( tre_thr_x_minus_tre_fou_x + qua_thr_x_minus_qua_fou_x )
    +
    .5 * ( val_tre_two_1 + val_tre_fou_1 );

  const double dos_fou_y = MINMOD( d_dostre_fou, d_unodos_fou,
                                   d_dostre_fou_sq,
                                   d_unodos_times_dostre_fou );
  const double dos_thr_x = MINMOD( d_dos_thrfou, d_dos_twothr,
                                   d_dos_thrfou_sq,
                                   d_dos_twothr_times_thrfou );
  const double dos_fou_x = MINMOD( d_dos_thrfou, d_dos_foufiv,
                                   d_dos_thrfou_sq,
                                   d_dos_thrfou_times_foufiv );

  const double val_uno_thr_1 =
    .25 * ( dos_fou - tre_thr )
    +
    .125 * ( dos_fou_y - tre_fou_y + dos_thr_x - dos_fou_x )
    +
    .5 * ( val_uno_two_1 + val_dos_thr_1 );

  const double qua_two_x = MINMOD( d_qua_twothr, d_qua_onetwo,
                                   d_qua_twothr_sq,
                                   d_qua_onetwo_times_twothr );
  const double tre_two_y = MINMOD( d_trequa_two, d_dostre_two,
                                   d_trequa_two_sq,
                                   d_dostre_times_trequa_two );
  const double qua_two_y = MINMOD( d_trequa_two, d_quacin_two,
                                   d_trequa_two_sq,
                                   d_trequa_times_quacin_two );

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

static void inline
snohalo_step2( const double           uno_two,
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
                     double* restrict dos_two_out,
                     double* restrict four_times_dos_twothr_out,
                     double* restrict four_times_dostre_two_out,
                     double* restrict partial_eight_times_dostre_twothr_out )
{
  /*
   * The second step of Snohalo 1.5 is just plain Nohalo subdivision.
   */
  /*
   * THE STENCIL OF INPUT VALUES:
   *
   * The footprint (stencil) of Nohalo level 1 is the same as, say,
   * Catmull-Rom, with the exception that the four corner values are
   * not used:
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
   * Here, ix is the (pseudo-)floor of the requested left-to-right
   * location, iy is the floor of the requested up-to-down location.
   *
   * Pointer arithmetic is used to implicitly reflect the input
   * stencil so that the requested pixel location is closer to
   * dos_two, The above consequently corresponds to the case in which
   * absolute_x is closer to ix than ix+1, and absolute_y is closer to
   * iy than iy+1. For example, if relative_x_is_rite = 1 but
   * relative_y_is_down = 0 (see below), then dos_two corresponds to
   * (ix+1,iy), dos_thr corresponds to (ix,iy) etc, and the three
   * missing double density values are halfway between dos_two and
   * dos_thr, halfway between dos_two and tre_two, and at the average
   * of the four central positions.
   *
   * The following code assumes that the stencil has been suitably
   * reflected.
   */

  /*
   * Computation of the nonlinear slopes: If two consecutive pixel
   * value differences have the same sign, the smallest one (in
   * absolute value) is taken to be the corresponding slope; if the
   * two consecutive pixel value differences don't have the same sign,
   * the corresponding slope is set to 0. In other words, apply minmod
   * to comsecutive differences.
   *
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
   * Terms computed here to put space between the computation of key
   * quantities and the related conditionals:
   */
  const double twice_dos_two_plus_dos_thr   = ( dos_two + dos_thr ) * 2.f;
  const double twice_dos_two_plus_tre_two   = ( dos_two + tre_two ) * 2.f;
  const double twice_deux_thr_plus_deux_dos = ( deux_thr + deux_dos ) * 2.f;

  *dos_two_out = dos_two;

  /*
   * Compute the needed "right" (at the boundary between one input
   * pixel areas) double resolution pixel value:
   */
  *four_times_dos_twothr_out =
    twice_dos_two_plus_dos_thr
    +
    MINMOD( deux_dos, prem_dos, deux_deux_dos, deux_prem_dos )
    -
    MINMOD( deux_dos, troi_dos, deux_deux_dos, deux_troi_dos );

  /*
   * Compute the needed "down" double resolution pixel value:
   */
  *four_times_dostre_two_out =
    twice_dos_two_plus_tre_two
    +
    MINMOD( deux_two, prem_two, deux_deux_two, deux_prem_two )
    -
    MINMOD( deux_two, troi_two, deux_deux_two, deux_troi_two );

  /*
   * Compute the "diagonal" (at the boundary between four input pixel
   * areas) double resolution pixel value:
   */
  *partial_eight_times_dostre_twothr_out =
    twice_deux_thr_plus_deux_dos
    +
    MINMOD( deux_tre, prem_tre, deux_deux_tre, deux_prem_tre )
    -
    MINMOD( deux_tre, troi_tre, deux_deux_tre, deux_troi_tre )
    +
    MINMOD( deux_thr, prem_thr, deux_deux_thr, deux_prem_thr )
    -
    MINMOD( deux_thr, troi_thr, deux_deux_thr, deux_troi_thr );
}

#define SELECT_REFLECT(tl,tr,bl,br) ( \
  (tl) * is_top_left \
  + \
  (tr) * is_top_rite \
  + \
  (bl) * is_bot_left \
  + \
  (br) * is_bot_rite )

/*
 * Call Snohalo with an interpolator as a parameter.
 *
 * It would be nice to do this with templates somehow---for one thing
 * this would allow code comments!---but we can't figure a clean way
 * to do it.
 */
#define SNOHALO1_INTER( inter )                    \
  template <typename T> static void inline         \
  snohalo1_ ## inter(       PEL*   restrict pout,  \
                      const PEL*   restrict pin,   \
                      const int             bands, \
                      const int             lskip, \
                      const double          blur,  \
                      const double          x_0,   \
                      const double          y_0 )  \
  { \
    T* restrict out = (T *) pout; \
    \
    const T* restrict in = (T *) pin; \
    \
    const int sign_of_x_0 = 2 * ( x_0 >= 0. ) - 1; \
    const int sign_of_y_0 = 2 * ( y_0 >= 0. ) - 1; \
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
    const int shift_back_3_pix = 3 * shift_back_1_pix; \
    const int shift_back_3_row = 3 * shift_back_1_row; \
    const int shift_forw_3_pix = 3 * shift_forw_1_pix; \
    const int shift_forw_3_row = 3 * shift_forw_1_row; \
    \
    const int cer_thr_shift =                    shift_back_3_row; \
    const int cer_fou_shift = shift_forw_1_pix + shift_back_3_row; \
    \
    const int uno_two_shift = shift_back_1_pix + shift_back_2_row; \
    const int uno_thr_shift =                    shift_back_2_row; \
    const int uno_fou_shift = shift_forw_1_pix + shift_back_2_row; \
    const int uno_fiv_shift = shift_forw_2_pix + shift_back_2_row; \
    \
    const int dos_one_shift = shift_back_2_pix + shift_back_1_row; \
    const int dos_two_shift = shift_back_1_pix + shift_back_1_row; \
    const int dos_thr_shift =                    shift_back_1_row; \
    const int dos_fou_shift = shift_forw_1_pix + shift_back_1_row; \
    const int dos_fiv_shift = shift_forw_2_pix + shift_back_1_row; \
    const int dos_six_shift = shift_forw_3_pix + shift_back_1_row; \
    \
    const int tre_zer_shift = shift_back_3_pix; \
    const int tre_one_shift = shift_back_2_pix; \
    const int tre_two_shift = shift_back_1_pix; \
    const int tre_thr_shift = 0;                \
    const int tre_fou_shift = shift_forw_1_pix; \
    const int tre_fiv_shift = shift_forw_2_pix; \
    const int tre_six_shift = shift_forw_3_pix; \
    \
    const int qua_zer_shift = shift_back_3_pix + shift_forw_1_row; \
    const int qua_one_shift = shift_back_2_pix + shift_forw_1_row; \
    const int qua_two_shift = shift_back_1_pix + shift_forw_1_row; \
    const int qua_thr_shift =                    shift_forw_1_row; \
    const int qua_fou_shift = shift_forw_1_pix + shift_forw_1_row; \
    const int qua_fiv_shift = shift_forw_2_pix + shift_forw_1_row; \
    const int qua_six_shift = shift_forw_3_pix + shift_forw_1_row; \
    \
    const int cin_one_shift = shift_back_2_pix + shift_forw_2_row; \
    const int cin_two_shift = shift_back_1_pix + shift_forw_2_row; \
    const int cin_thr_shift =                    shift_forw_2_row; \
    const int cin_fou_shift = shift_forw_1_pix + shift_forw_2_row; \
    const int cin_fiv_shift = shift_forw_2_pix + shift_forw_2_row; \
    \
    const int sei_two_shift = shift_back_1_pix + shift_forw_3_row; \
    const int sei_thr_shift =                    shift_forw_3_row; \
    const int sei_fou_shift = shift_forw_1_pix + shift_forw_3_row; \
    \
    const double x = ( 2 * sign_of_x_0 ) * x_0 - .5; \
    const double y = ( 2 * sign_of_y_0 ) * y_0 - .5; \
    \
    const int x_is_rite = ( x >= 0. ); \
    const int y_is_down = ( y >= 0. ); \
    const int x_is_left = !x_is_rite;  \
    const int y_is___up = !y_is_down;  \
    \
    const int is_bot_rite = x_is_rite & y_is_down; \
    const int is_bot_left = x_is_left & y_is_down; \
    const int is_top_rite = x_is_rite & y_is___up; \
    const int is_top_left = x_is_left & y_is___up; \
    \
    const int sign_of_x = 2 * x_is_rite - 1; \
    const int sign_of_y = 2 * y_is_down - 1; \
    \
    const double w_1 = ( 2 * sign_of_x ) * x; \
    const double z_1 = ( 2 * sign_of_y ) * y; \
    const double x_1 = 1. - w_1;              \
    \
    const double w_1_times_z_1 = w_1 * z_1; \
    const double x_1_times_z_1 = x_1 * z_1; \
    \
    const double w_1_times_y_1_over_4 = .25  * ( w_1 - w_1_times_z_1 ); \
    const double x_1_times_z_1_over_4 = .25  * x_1_times_z_1;           \
    const double x_1_times_y_1_over_8 = .125 * ( x_1 - x_1_times_z_1 ); \
    \
    const double w_1_times_y_1_over_4_plus_x_1_times_y_1_over_8 = \
      w_1_times_y_1_over_4 + x_1_times_y_1_over_8;                \
    const double x_1_times_z_1_over_4_plus_x_1_times_y_1_over_8 = \
      x_1_times_z_1_over_4 + x_1_times_y_1_over_8;                \
    \
    int band = bands; \
    \
    do \
      { \
        double          uno_two, uno_thr;           \
        double dos_one, dos_two, dos_thr, dos_fou;  \
        double tre_one, tre_two, tre_thr, tre_fou;  \
        double          qua_two, qua_thr;           \
        \
        double final_dos_two;                           \
        double final_four_times_dos_twothr;             \
        double final_four_times_dostre_two;             \
        double final_partial_eight_times_dostre_twothr; \
        \
        snohalo_step1( blur,                \
                       in[ cer_thr_shift ], \
                       in[ cer_fou_shift ], \
                       in[ uno_two_shift ], \
                       in[ uno_thr_shift ], \
                       in[ uno_fou_shift ], \
                       in[ uno_fiv_shift ], \
                       in[ dos_one_shift ], \
                       in[ dos_two_shift ], \
                       in[ dos_thr_shift ], \
                       in[ dos_fou_shift ], \
                       in[ dos_fiv_shift ], \
                       in[ dos_six_shift ], \
                       in[ tre_zer_shift ], \
                       in[ tre_one_shift ], \
                       in[ tre_two_shift ], \
                       in[ tre_thr_shift ], \
                       in[ tre_fou_shift ], \
                       in[ tre_fiv_shift ], \
                       in[ tre_six_shift ], \
                       in[ qua_zer_shift ], \
                       in[ qua_one_shift ], \
                       in[ qua_two_shift ], \
                       in[ qua_thr_shift ], \
                       in[ qua_fou_shift ], \
                       in[ qua_fiv_shift ], \
                       in[ qua_six_shift ], \
                       in[ cin_one_shift ], \
                       in[ cin_two_shift ], \
                       in[ cin_thr_shift ], \
                       in[ cin_fou_shift ], \
                       in[ cin_fiv_shift ], \
                       in[ sei_two_shift ], \
                       in[ sei_thr_shift ], \
                       in[ sei_fou_shift ], \
                       &uno_two,            \
                       &uno_thr,            \
                       &dos_one,            \
                       &dos_two,            \
                       &dos_thr,            \
                       &dos_fou,            \
                       &tre_one,            \
                       &tre_two,            \
                       &tre_thr,            \
                       &tre_fou,            \
                       &qua_two,            \
                       &qua_thr );          \
        \
        snohalo_step2(                                          \
          SELECT_REFLECT( uno_two, uno_thr, qua_two, qua_thr ), \
          SELECT_REFLECT( uno_thr, uno_two, qua_thr, qua_two ), \
          SELECT_REFLECT( dos_one, dos_fou, tre_one, tre_fou ), \
          SELECT_REFLECT( dos_two, dos_thr, tre_two, tre_thr ), \
          SELECT_REFLECT( dos_thr, dos_two, tre_thr, tre_two ), \
          SELECT_REFLECT( dos_fou, dos_one, tre_fou, tre_one ), \
          SELECT_REFLECT( tre_one, tre_fou, dos_one, dos_fou ), \
          SELECT_REFLECT( tre_two, tre_thr, dos_two, dos_thr ), \
          SELECT_REFLECT( tre_thr, tre_two, dos_thr, dos_two ), \
          SELECT_REFLECT( tre_fou, tre_one, dos_fou, dos_one ), \
          SELECT_REFLECT( qua_two, qua_thr, uno_two, uno_thr ), \
          SELECT_REFLECT( qua_thr, qua_two, uno_thr, uno_two ), \
          &final_dos_two,                                       \
          &final_four_times_dos_twothr,                         \
          &final_four_times_dostre_two,                         \
          &final_partial_eight_times_dostre_twothr );           \
        \
        { \
          const T result =                                    \
            bilinear_ ## inter<T>(                            \
              w_1_times_z_1,                                  \
              x_1_times_z_1_over_4_plus_x_1_times_y_1_over_8, \
              w_1_times_y_1_over_4_plus_x_1_times_y_1_over_8, \
              x_1_times_y_1_over_8,                           \
              final_dos_two,                                  \
              final_four_times_dos_twothr,                    \
              final_four_times_dostre_two,                    \
              final_partial_eight_times_dostre_twothr );      \
          \
          *out++ = result; \
          \
          in++; \
        } \
      } while (--band); \
  }

SNOHALO1_INTER( fptypes )
SNOHALO1_INTER( withsign )
SNOHALO1_INTER( nosign )

#define CALL( T, inter ) \
  snohalo1_ ## inter<T>( out, \
                         p, \
                         bands, \
                         lskip, \
                         snohalo1->blur, \
                         relative_x, \
                         relative_y );

/*
 * We need C linkage:
 */
extern "C" {
G_DEFINE_TYPE( VipsInterpolateSnohalo1, vips_interpolate_snohalo1,
	VIPS_TYPE_INTERPOLATE );
}

static void
vips_interpolate_snohalo1_interpolate( VipsInterpolate* restrict interpolate,
                                       PEL*             restrict out,
                                       REGION*          restrict in,
                                       double                    absolute_x,
                                       double                    absolute_y )
{
  VipsInterpolateSnohalo1 *snohalo1 =
    VIPS_INTERPOLATE_SNOHALO1( interpolate );

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
vips_interpolate_snohalo1_class_init( VipsInterpolateSnohalo1Class *klass )
{
  GObjectClass *gobject_class = G_OBJECT_CLASS( klass );
  VipsObjectClass *object_class = VIPS_OBJECT_CLASS( klass );
  VipsInterpolateClass *interpolate_class =
    VIPS_INTERPOLATE_CLASS( klass );

  GParamSpec *pspec;

  gobject_class->set_property = vips_object_set_property;
  gobject_class->get_property = vips_object_get_property;

  object_class->nickname = "snohalo1";
  object_class->description = _( "Nohalo level 2 with antialiasing blur" );

  interpolate_class->interpolate =
    vips_interpolate_snohalo1_interpolate;
  interpolate_class->window_size = 7;
  interpolate_class->window_size = 3;

  /*
   * Create properties:
   */
  pspec =
    g_param_spec_double(
      "blur",
      _( "Blur" ),
      _( "Antialiasing (diagonal straightening) blur amount" ),
      0.,
      1.,
      1.,
      (GParamFlags) G_PARAM_READWRITE );

  g_object_class_install_property( gobject_class,
                                   PROP_BLUR, pspec );

  vips_object_class_install_argument(
    object_class,
    pspec,
    VIPS_ARGUMENT_SET_ONCE,
    G_STRUCT_OFFSET( VipsInterpolateSnohalo1, blur ) );
}

static void
vips_interpolate_snohalo1_init( VipsInterpolateSnohalo1 *snohalo1 )
{
	snohalo1->blur = 0.3333333;
}
