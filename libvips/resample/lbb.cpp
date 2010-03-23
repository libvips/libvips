/* lbb (locally bounded bicubic) resampler
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
 * 2010 (c) Nicolas Robidoux, John Cupitt, Chantal Racette.
 *
 * Nicolas Robidoux thanks Ralf Meyer, Minglun Gong, Adam Turcotte,
 * Eric Daoust, Øyvind Kolås, Geert Jordaens, and Sven Neumann for
 * useful comments and code.
 */

/*
 * LBB (Locally Bounded Bicubic) is a high quality nonlinear variant
 * of Catmull-Rom. Compared to Catmull-Rom, it produces resampled
 * images with halos much reduced, both in terms of physical extent
 * and over/undershoot amplitude. This is accomplished without
 * noticeable changes to image smoothness.
 *
 * Another important property is that the resampled values are
 * contained within the range of nearby input values.
 */

/*
 * LBB is a novel method with the following properties:
 *
 * --When the limiters are inactive, it gives the same results as
 *   Catmull-Rom.
 *
 * --When used on binary images, in which case the limiters clamp
 *   everything to zero, LBB gives the same results as bicubic Hermite
 *   with all derivatives at the input pixel locations set to zero.
 *
 * --It is interpolatory.
 *
 * --It is C^1 with continuous cross derivatives.
 *
 * --It is locally bounded, in the following sense: Over each square
 *   patch, the surface is contained between the minimum and the
 *   maximum values among the 16 nearest input pixel values (those in
 *   the stencil).
 *
 * --It is globally bounded between the very smallest input pixel
 *   value and the very largest input pixel value. Consequently, it is
 *   not necessary to clamp results.
 *
 * --It is a Hermite bicubic method: The bicubic surface is defined,
 *   one convex hull of four nearby input points at a time, using the
 *   four point values, four x-derivatives, four y-derivatives, and four
 *   cross-derivatives.
 *
 * --The stencil for values in a square patch is the usual 4x4.
 *
 * --The LBB method is based on the method of Ken Brodlie, Petros
 *   Mashwama and Sohail Butt for constraining Hermite interpolants
 *   between globally defined planes:
 *
 *     Visualization of surface data to preserve positivity and other
 *     simple constraints, Computer & Graphics, Vol. 19, #4, pages
 *     585-594, 1995. DOI: 10.1016/0097-8493(95)00036-C.
 *
 *   The main novelty of the LBB method (besides its reliance on slope
 *   limiters for image resampling) lies in the fact that the method
 *   of Brodlie et al is used to enforce local, as opposed to global,
 *   boundedness. This method was developed by Nicolas Robidoux and
 *   Chantal Racette of the Department of Mathematics and Computer
 *   Science of Laurentian University.
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

#define VIPS_TYPE_INTERPOLATE_LBB \
	(vips_interpolate_lbb_get_type())
#define VIPS_INTERPOLATE_LBB( obj ) \
	(G_TYPE_CHECK_INSTANCE_CAST( (obj), \
	VIPS_TYPE_INTERPOLATE_LBB, VipsInterpolateLbb ))
#define VIPS_INTERPOLATE_LBB_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_CAST( (klass), \
	VIPS_TYPE_INTERPOLATE_LBB, VipsInterpolateLbbClass))
#define VIPS_IS_INTERPOLATE_LBB( obj ) \
	(G_TYPE_CHECK_INSTANCE_TYPE( (obj), VIPS_TYPE_INTERPOLATE_LBB ))
#define VIPS_IS_INTERPOLATE_LBB_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_TYPE( (klass), VIPS_TYPE_INTERPOLATE_LBB ))
#define VIPS_INTERPOLATE_LBB_GET_CLASS( obj ) \
	(G_TYPE_INSTANCE_GET_CLASS( (obj), \
	VIPS_TYPE_INTERPOLATE_LBB, VipsInterpolateLbbClass ))

typedef struct _VipsInterpolateLbb {
	VipsInterpolate parent_object;

} VipsInterpolateLbb;

typedef struct _VipsInterpolateLbbClass {
	VipsInterpolateClass parent_class;

} VipsInterpolateLbbClass;

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
   * sub-blocks of the 4x4 input stencil (involves 28 flag
   * computations):
   */
  const double m1    = (dos_two <= dos_thr) ? dos_two : dos_thr;
  const double M1    = (dos_two <= dos_thr) ? dos_thr : dos_two;
  const double m2    = (tre_two <= tre_thr) ? tre_two : tre_thr;
  const double M2    = (tre_two <= tre_thr) ? tre_thr : tre_two;
  const double m3    = (uno_two <= uno_thr) ? uno_two : uno_thr;
  const double M3    = (uno_two <= uno_thr) ? uno_thr : uno_two;
  const double m4    = (qua_two <= qua_thr) ? qua_two : qua_thr;
  const double M4    = (qua_two <= qua_thr) ? qua_thr : qua_two;
  const double m5    = (m1      <= m2     ) ? m1      : m2     ;
  const double M5    = (M1      >= M2     ) ? M1      : M2     ;
  const double m6    = (dos_one <= tre_one) ? dos_one : tre_one;
  const double M6    = (dos_one <= tre_one) ? tre_one : dos_one;
  const double m7    = (dos_fou <= tre_fou) ? dos_fou : tre_fou;
  const double M7    = (dos_fou <= tre_fou) ? tre_fou : dos_fou;
  const double m8    = (m5      <= m3     ) ? m5      : m3     ;
  const double M8    = (M5      >= M3     ) ? M5      : M3     ;
  const double m9    = (m5      <= m4     ) ? m5      : m4     ;
  const double M9    = (M5      >= M4     ) ? M5      : M4     ;
  const double m10   = (m6      <= uno_one) ? m6      : uno_one;
  const double M10   = (M6      >= uno_one) ? M6      : uno_one;
  const double m11   = (m7      <= uno_fou) ? m7      : uno_fou;
  const double M11   = (M7      >= uno_fou) ? M7      : uno_fou;
  const double m12   = (m6      <= qua_one) ? m6      : qua_one;
  const double M12   = (M6      >= qua_one) ? M6      : qua_one;
  const double m13   = (m7      <= qua_fou) ? m7      : qua_fou;
  const double M13   = (M7      >= qua_fou) ? M7      : qua_fou;
  const double min00 = (m8      <= m10    ) ? m8      : m10    ;
  const double max00 = (M8      >= M10    ) ? M8      : M10    ;
  const double min10 = (m8      <= m11    ) ? m8      : m11    ;
  const double max10 = (M8      >= M11    ) ? M8      : M11    ;
  const double min01 = (m9      <= m12    ) ? m9      : m12    ;
  const double max01 = (M9      >= M12    ) ? M9      : M12    ;
  const double min11 = (m9      <= m13    ) ? m9      : m13    ;
  const double max11 = (M9      >= M13    ) ? M9      : M13    ;

  /*
   * Distances to the local min and max:
   */
  const double u00 = dos_two - min00;
  const double v00 = max00 - dos_two;
  const double u10 = dos_thr - min10;
  const double v10 = max10 - dos_thr;
  const double u01 = tre_two - min01;
  const double v01 = max01 - tre_two;
  const double u11 = tre_thr - min11;
  const double v11 = max11 - tre_thr;

  /*
   * Initial values of the derivatives computed with centered
   * differences. Factors of 1/2 are left out because they are folded
   * in later:
   */
  const double dble_dzdx00i = dos_thr - dos_one;
  const double dble_dzdx10i = dos_fou - dos_two;
  const double dble_dzdx01i = tre_thr - tre_one;
  const double dble_dzdx11i = tre_fou - tre_two;

  const double dble_dzdy00i = tre_two - uno_two;
  const double dble_dzdy10i = tre_thr - uno_thr;
  const double dble_dzdy01i = qua_two - dos_two;
  const double dble_dzdy11i = qua_thr - dos_thr;

  /*
   * Signs of the derivatives:
   */
  const double sign_dzdx00 = (dble_dzdx00i >= 0.) ? 1. : -1.;
  const double sign_dzdx10 = (dble_dzdx10i >= 0.) ? 1. : -1.;
  const double sign_dzdx01 = (dble_dzdx01i >= 0.) ? 1. : -1.;
  const double sign_dzdx11 = (dble_dzdx11i >= 0.) ? 1. : -1.;

  const double sign_dzdy00 = (dble_dzdy00i >= 0.) ? 1. : -1.;
  const double sign_dzdy10 = (dble_dzdy10i >= 0.) ? 1. : -1.;
  const double sign_dzdy01 = (dble_dzdy01i >= 0.) ? 1. : -1.;
  const double sign_dzdy11 = (dble_dzdy11i >= 0.) ? 1. : -1.;

  /*
   * Slope limiters. The key multiplier is 3 but we fold a factor of
   * 2, hence 6:
   */
  const double dble_slopelimit_00 = 6.0 * ( (u00 <= v00) ? u00 : v00 );
  const double dble_slopelimit_10 = 6.0 * ( (u10 <= v10) ? u10 : v10 );
  const double dble_slopelimit_01 = 6.0 * ( (u01 <= v01) ? u01 : v01 );
  const double dble_slopelimit_11 = 6.0 * ( (u11 <= v11) ? u11 : v11 );

  /*
   * Initial values of the cross-derivatives. Factors of 1/4 are left
   * out because folded in later:
   */
  const double quad_d2zdxdy00i = ( uno_one - uno_thr ) + dble_dzdx01i;
  const double quad_d2zdxdy10i = ( uno_two - uno_fou ) + dble_dzdx11i;
  const double quad_d2zdxdy01i = ( qua_thr - qua_one ) - dble_dzdx00i;
  const double quad_d2zdxdy11i = ( qua_fou - qua_two ) - dble_dzdx10i;

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

  /*
   * Clamped first derivatives:
   */
  const double dble_dzdx00 =
    ( sign_dzdx00 * dble_dzdx00i <= dble_slopelimit_00 )
    ? dble_dzdx00i :  sign_dzdx00 * dble_slopelimit_00;
  const double dble_dzdx10 =
    ( sign_dzdx10 * dble_dzdx10i <= dble_slopelimit_10 )
    ? dble_dzdx10i :  sign_dzdx10 * dble_slopelimit_10;
  const double dble_dzdx01 =
    ( sign_dzdx01 * dble_dzdx01i <= dble_slopelimit_01 )
    ? dble_dzdx01i :  sign_dzdx01 * dble_slopelimit_01;
  const double dble_dzdx11 =
    ( sign_dzdx11 * dble_dzdx11i <= dble_slopelimit_11 )
    ? dble_dzdx11i :  sign_dzdx11 * dble_slopelimit_11;
  const double dble_dzdy00 =
    ( sign_dzdy00 * dble_dzdy00i <= dble_slopelimit_00 )
    ? dble_dzdy00i :  sign_dzdy00 * dble_slopelimit_00;
  const double dble_dzdy10 =
    ( sign_dzdy10 * dble_dzdy10i <= dble_slopelimit_10 )
    ? dble_dzdy10i :  sign_dzdy10 * dble_slopelimit_10;
  const double dble_dzdy01 =
    ( sign_dzdy01 * dble_dzdy01i <= dble_slopelimit_01 )
    ? dble_dzdy01i :  sign_dzdy01 * dble_slopelimit_01;
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
   * Part of the result which only needs first derivatives.
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
   * Absolute values of the sums:
   */
  const double twelve_abs_sum00 =
    (twelve_sum00 >= 0.0) ? twelve_sum00 : -twelve_sum00;
  const double twelve_abs_sum10 =
    (twelve_sum10 >= 0.0) ? twelve_sum10 : -twelve_sum10;
  const double twelve_abs_sum01 =
    (twelve_sum01 >= 0.0) ? twelve_sum01 : -twelve_sum01;
  const double twelve_abs_sum11 =
    (twelve_sum11 >= 0.0) ? twelve_sum11 : -twelve_sum11;

  /*
   * Scaled 'u' differences:
   */
  const double u00_times_36 = 36. * u00;
  const double u10_times_36 = 36. * u10;
  const double u01_times_36 = 36. * u01;
  const double u11_times_36 = 36. * u11;

  /*
   * First cross-derivative limiter:
   */
  const double first_limit00  = twelve_abs_sum00 - u00_times_36;
  const double first_limit10  = twelve_abs_sum10 - u10_times_36;
  const double first_limit01  = twelve_abs_sum01 - u01_times_36;
  const double first_limit11  = twelve_abs_sum11 - u11_times_36;

  const double quad_d2zdxdy00ii =
    (quad_d2zdxdy00i >= first_limit00)
    ? quad_d2zdxdy00i : first_limit00;
  const double quad_d2zdxdy10ii =
    (quad_d2zdxdy10i >= first_limit10)
    ? quad_d2zdxdy10i : first_limit10;
  const double quad_d2zdxdy01ii =
    (quad_d2zdxdy01i >= first_limit01)
    ? quad_d2zdxdy01i : first_limit01;
  const double quad_d2zdxdy11ii =
    (quad_d2zdxdy11i >= first_limit11)
    ? quad_d2zdxdy11i : first_limit11;

  /*
   * Absolute values of the differences:
   */
  const double twelve_abs_dif00 =
    (twelve_dif00 >= 0.0) ? twelve_dif00 : -twelve_dif00;
  const double twelve_abs_dif10 =
    (twelve_dif10 >= 0.0) ? twelve_dif10 : -twelve_dif10;
  const double twelve_abs_dif01 =
    (twelve_dif01 >= 0.0) ? twelve_dif01 : -twelve_dif01;
  const double twelve_abs_dif11 =
    (twelve_dif11 >= 0.0) ? twelve_dif11 : -twelve_dif11;

  /*
   * Scaled 'v' differences:
   */
  const double v00_times_36 = 36. * v00;
  const double v10_times_36 = 36. * v10;
  const double v01_times_36 = 36. * v01;
  const double v11_times_36 = 36. * v11;

  /*
   * Second cross-derivative limiter:
   */
  const double second_limit00 = v00_times_36 - twelve_abs_sum00;
  const double second_limit10 = v10_times_36 - twelve_abs_sum10;
  const double second_limit01 = v01_times_36 - twelve_abs_sum01;
  const double second_limit11 = v11_times_36 - twelve_abs_sum11;

  const double quad_d2zdxdy00iii =
    (quad_d2zdxdy00ii <= second_limit00)
    ? quad_d2zdxdy00ii : second_limit00;
  const double quad_d2zdxdy10iii =
    (quad_d2zdxdy10ii <= second_limit10)
    ? quad_d2zdxdy10ii : second_limit10;
  const double quad_d2zdxdy01iii =
    (quad_d2zdxdy01ii <= second_limit01)
    ? quad_d2zdxdy01ii : second_limit01;
  const double quad_d2zdxdy11iii =
    (quad_d2zdxdy11ii <= second_limit11)
    ? quad_d2zdxdy11ii : second_limit11;

  /*
   * Third cross-derivative limiter:
   */
  const double third_limit00  = u00_times_36 - twelve_abs_dif00;
  const double third_limit10  = u10_times_36 - twelve_abs_dif10;
  const double third_limit01  = u01_times_36 - twelve_abs_dif01;
  const double third_limit11  = u11_times_36 - twelve_abs_dif11;

  const double quad_d2zdxdy00iiii =
    (quad_d2zdxdy00iii <= third_limit00)
    ? quad_d2zdxdy00iii : third_limit00;
  const double quad_d2zdxdy10iiii =
    (quad_d2zdxdy10iii <= third_limit10)
    ? quad_d2zdxdy10iii : third_limit10;
  const double quad_d2zdxdy01iiii =
    (quad_d2zdxdy01iii <= third_limit01)
    ? quad_d2zdxdy01iii : third_limit01;
  const double quad_d2zdxdy11iiii =
    (quad_d2zdxdy11iii <= third_limit11)
    ? quad_d2zdxdy11iii : third_limit11;

  /*
   * Fourth cross-derivative limiter:
   */
  const double fourth_limit00 = twelve_abs_dif00 - v00_times_36;
  const double fourth_limit10 = twelve_abs_dif10 - v10_times_36;
  const double fourth_limit01 = twelve_abs_dif01 - v01_times_36;
  const double fourth_limit11 = twelve_abs_dif11 - v11_times_36;

  const double quad_d2zdxdy00 =
    (quad_d2zdxdy00iiii >= fourth_limit00)
    ? quad_d2zdxdy00iiii : fourth_limit00;
  const double quad_d2zdxdy10 =
    (quad_d2zdxdy10iiii >= fourth_limit10)
    ? quad_d2zdxdy10iiii : fourth_limit10;
  const double quad_d2zdxdy01 =
    (quad_d2zdxdy01iiii >= fourth_limit01)
    ? quad_d2zdxdy01iiii : fourth_limit01;
  const double quad_d2zdxdy11 =
    (quad_d2zdxdy11iiii >= fourth_limit11)
    ? quad_d2zdxdy11iiii : fourth_limit11;

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

  const double newval = newval1 + .5 * newval2 + .25 * newval3;

  return newval;
}

/*
 * Call lbb with a type conversion operator as a parameter.
 *
 * It would be nice to do this with templates but we can't figure out
 * how to do it cleanly. Suggestions welcome!
 */
#define LBB_CONVERSION( conversion )                     \
  template <typename T> static void inline               \
  lbb_ ## conversion(       PEL*   restrict pout,        \
                      const PEL*   restrict pin,         \
                      const int             bands,       \
                      const int             lskip,       \
                      const double          relative_x,  \
                      const double          relative_y ) \
  { \
    T* restrict out = (T *) pout; \
    \
    const T* restrict in = (T *) pin; \
    \
    const int one_shift =  -bands; \
    const int thr_shift =   bands; \
    const int fou_shift = 2*bands; \
    \
    const int uno_two_shift =  -lskip; \
    const int dos_two_shift =       0; \
    const int tre_two_shift =   lskip; \
    const int qua_two_shift = 2*lskip; \
    \
    const int uno_one_shift = uno_two_shift + one_shift; \
    const int dos_one_shift = dos_two_shift + one_shift; \
    const int tre_one_shift = tre_two_shift + one_shift; \
    const int qua_one_shift = qua_two_shift + one_shift; \
    \
    const int uno_thr_shift = uno_two_shift + thr_shift; \
    const int dos_thr_shift = dos_two_shift + thr_shift; \
    const int tre_thr_shift = tre_two_shift + thr_shift; \
    const int qua_thr_shift = qua_two_shift + thr_shift; \
    \
    const int uno_fou_shift = uno_two_shift + fou_shift; \
    const int dos_fou_shift = dos_two_shift + fou_shift; \
    const int tre_fou_shift = tre_two_shift + fou_shift; \
    const int qua_fou_shift = qua_two_shift + fou_shift; \
    \
    const double xp1over2   = relative_x; \
    const double xm1over2   = xp1over2 - 1.0; \
    const double onemx      = 1.5 - xp1over2; \
    const double onepx      = 0.5 + xp1over2; \
    const double xp1over2sq = xp1over2 * xp1over2; \
    \
    const double yp1over2   = relative_y; \
    const double ym1over2   = yp1over2 - 1.0; \
    const double onemy      = 1.5 - yp1over2; \
    const double onepy      = 0.5 + yp1over2; \
    const double yp1over2sq = yp1over2 * yp1over2; \
    \
    const double xm1over2sq = xm1over2 * xm1over2; \
    const double ym1over2sq = ym1over2 * ym1over2; \
    \
    const double twice1mx = onemx + onemx; \
    const double twice1px = onepx + onepx; \
    const double twice1my = onemy + onemy; \
    const double twice1py = onepy + onepy; \
    \
    const double xm1over2sq_times_ym1over2sq = xm1over2sq * ym1over2sq; \
    const double xp1over2sq_times_ym1over2sq = xp1over2sq * ym1over2sq; \
    const double xp1over2sq_times_yp1over2sq = xp1over2sq * yp1over2sq; \
    const double xm1over2sq_times_yp1over2sq = xm1over2sq * yp1over2sq; \
    \
    const double xm1over2_times_ym1over2  = xm1over2 * ym1over2; \
    const double xp1over2_times_ym1over2  = xp1over2 * ym1over2; \
    const double twice_1mx_times_ym1over2 = twice1mx * ym1over2; \
    const double twice_1px_times_ym1over2 = twice1px * ym1over2; \
    \
    const double xm1over2_times_yp1over2  = xm1over2 * yp1over2; \
    const double xp1over2_times_yp1over2  = xp1over2 * yp1over2; \
    const double twice_1mx_times_yp1over2 = twice1mx * yp1over2; \
    const double twice_1px_times_yp1over2 = twice1px * yp1over2; \
    \
    const double twice_xm1over2_times_1my = xm1over2 * twice1my; \
    const double twice_xp1over2_times_1my = xp1over2 * twice1my; \
    const double four_times_1mx_times_1my = twice1mx * twice1my; \
    const double four_times_1px_times_1my = twice1px * twice1my; \
    \
    const double twice_xm1over2_times_1py = xm1over2 * twice1py; \
    const double twice_xp1over2_times_1py = xp1over2 * twice1py; \
    const double four_times_1mx_times_1py = twice1mx * twice1py; \
    const double four_times_1px_times_1py = twice1px * twice1py; \
    \
    const double c00     = \
      four_times_1px_times_1py * xm1over2sq_times_ym1over2sq; \
    const double c00dx   = \
      twice_xp1over2_times_1py * xm1over2sq_times_ym1over2sq; \
    const double c00dy   = \
      twice_1px_times_yp1over2 * xm1over2sq_times_ym1over2sq; \
    const double c00dxdy = \
       xp1over2_times_yp1over2 * xm1over2sq_times_ym1over2sq; \
    \
    const double c10     = \
      four_times_1mx_times_1py * xp1over2sq_times_ym1over2sq; \
    const double c10dx   = \
      twice_xm1over2_times_1py * xp1over2sq_times_ym1over2sq; \
    const double c10dy   = \
      twice_1mx_times_yp1over2 * xp1over2sq_times_ym1over2sq; \
    const double c10dxdy = \
       xm1over2_times_yp1over2 * xp1over2sq_times_ym1over2sq; \
    \
    const double c01     = \
      four_times_1px_times_1my * xm1over2sq_times_yp1over2sq; \
    const double c01dx   = \
      twice_xp1over2_times_1my * xm1over2sq_times_yp1over2sq; \
    const double c01dy   = \
      twice_1px_times_ym1over2 * xm1over2sq_times_yp1over2sq; \
    const double c01dxdy = \
       xp1over2_times_ym1over2 * xm1over2sq_times_yp1over2sq; \
    \
    const double c11     = \
      four_times_1mx_times_1my * xp1over2sq_times_yp1over2sq; \
    const double c11dx   = \
      twice_xm1over2_times_1my * xp1over2sq_times_yp1over2sq; \
    const double c11dy   = \
      twice_1mx_times_ym1over2 * xp1over2sq_times_yp1over2sq; \
    const double c11dxdy = \
       xm1over2_times_ym1over2 * xp1over2sq_times_yp1over2sq; \
    \
    int band = bands; \
    \
    do \
      { \
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
                     in[ uno_one_shift ],   \
                     in[ uno_two_shift ],   \
                     in[ uno_thr_shift ],   \
                     in[ uno_fou_shift ],   \
                     in[ dos_one_shift ],   \
                     in[ dos_two_shift ],   \
                     in[ dos_thr_shift ],   \
                     in[ dos_fou_shift ],   \
                     in[ tre_one_shift ],   \
                     in[ tre_two_shift ],   \
                     in[ tre_thr_shift ],   \
                     in[ tre_fou_shift ],   \
                     in[ qua_one_shift ],   \
                     in[ qua_two_shift ],   \
                     in[ qua_thr_shift ],   \
                     in[ qua_fou_shift ] ); \
        \
        const T result = to_ ## conversion<T>( double_result ); \
        in++; \
        *out++ = result; \
      } while (--band); \
  }

LBB_CONVERSION( fptypes )
LBB_CONVERSION( withsign )
LBB_CONVERSION( nosign )

#define CALL( T, conversion )          \
  lbb_ ## conversion<T>( out,          \
                         p,            \
                         bands,        \
                         lskip,        \
                         relative_x,   \
                         relative_y );

/*
 * We need C linkage:
 */
extern "C" {
G_DEFINE_TYPE( VipsInterpolateLbb, vips_interpolate_lbb,
	VIPS_TYPE_INTERPOLATE );
}

static void
vips_interpolate_lbb_interpolate( VipsInterpolate* restrict interpolate,
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
   * position of the top left corner of the convex hull of the 2x2
   * block of closest pixels. Similarly for y. Range of values: [0,1).
   */
  const int ix = FAST_PSEUDO_FLOOR( absolute_x );
  const int iy = FAST_PSEUDO_FLOOR( absolute_y );

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
vips_interpolate_lbb_class_init( VipsInterpolateLbbClass *klass )
{
  VipsObjectClass *object_class = VIPS_OBJECT_CLASS( klass );
  VipsInterpolateClass *interpolate_class =
    VIPS_INTERPOLATE_CLASS( klass );

  object_class->nickname = "lbb";
  object_class->description = _( "Reduced halo bicubic" );

  interpolate_class->interpolate = vips_interpolate_lbb_interpolate;
  interpolate_class->window_size = 4;
}

static void
vips_interpolate_lbb_init( VipsInterpolateLbb *lbb )
{
}
