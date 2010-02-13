/* symmetrized monotone cubic splines
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
 * 2009-2010 (c) Nicolas Robidoux, John Cupitt, Eric Daoust and Adam
 * Turcotte
 *
 * E. Daoust and A. Turcotte's symmetrized monotone cubic splines
 * programming funded in part by two Google Summer of Code 2010 awards
 * made to GIMP (Gnu Image Manipulation Program) and its library GEGL.
 *
 * Nicolas Robidoux thanks Chantal Racette, Ralf Meyer, Minglun Gong,
 * Øyvind Kolås, Geert Jordaens and Sven Neumann for useful comments
 * and code.
 */

/*
 * mbicubic is the VIPS name of the symmetrized implementation in 2D
 * of monotone cubic spline interpolation method a.k.a. MP-Quadratic
 * (Monotonicity Preserving with derivative estimated by fitting a
 * parabola (quadratic polynomial)) method, which essentially is
 * Catmull-Rom with derivatives clamped with Fristsh and Carlson's
 * "rule of 3" so as to ensure monotonicity.
 *
 * 1D MP-quadratic (for curve, not surface, interpolation) is
 * described in
 *
 * Accurate Monotone Cubic Interpolation, by Hung T. Huynh, published
 * in the SIAM Journal on Numerical Analysis, Volume 30, Issue 1
 * (February 1993), pages 57-100, 1993. ISSN:0036-1429.
 *
 * and in NASA technical memorandum 103789, which can be downloaded
 * from http://
 * ntrs.nasa.gov/archive/nasa/casi.ntrs.nasa.gov/19910011517_1991011517.pdf
 *
 * In order to ensure reflexion symmetry about diagonal lines, 1D
 * MP-quadratic is performed two different ways---horizontally then
 * vertically, and vertically then horizontally---and
 * averaged. (Symmetry about 45 degree lines is not automatically
 * respected because MP-quadratic is a nonlinear method: interpolating
 * horizontally then vertically does not necessarily give the same as
 * interpolating vertically then horizontally.)
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

#define VIPS_TYPE_INTERPOLATE_MBICUBIC \
	(vips_interpolate_mbicubic_get_type())
#define VIPS_INTERPOLATE_MBICUBIC( obj ) \
	(G_TYPE_CHECK_INSTANCE_CAST( (obj), \
	VIPS_TYPE_INTERPOLATE_MBICUBIC, VipsInterpolateMbicubic ))
#define VIPS_INTERPOLATE_MBICUBIC_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_CAST( (klass), \
	VIPS_TYPE_INTERPOLATE_MBICUBIC, VipsInterpolateMbicubicClass))
#define VIPS_IS_INTERPOLATE_MBICUBIC( obj ) \
	(G_TYPE_CHECK_INSTANCE_TYPE( (obj), VIPS_TYPE_INTERPOLATE_MBICUBIC ))
#define VIPS_IS_INTERPOLATE_MBICUBIC_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_TYPE( (klass), VIPS_TYPE_INTERPOLATE_MBICUBIC ))
#define VIPS_INTERPOLATE_MBICUBIC_GET_CLASS( obj ) \
	(G_TYPE_INSTANCE_GET_CLASS( (obj), \
	VIPS_TYPE_INTERPOLATE_MBICUBIC, VipsInterpolateMbicubicClass ))

typedef struct _VipsInterpolateMbicubic {
	VipsInterpolate parent_object;

} VipsInterpolateMbicubic;

typedef struct _VipsInterpolateMbicubicClass {
	VipsInterpolateClass parent_class;

} VipsInterpolateMbicubicClass;

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
 * ( (a_times_b)>=0 ? 1. : 0. ) * ( (a_times_a)<=(a_times_b) ? (a) : (b) )
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
 * (currently found in templates.h and used by the "classic"
 * implementations of the other Nohalo methods). Unfortunately, MINMOD
 * uses different parameters and consequently is not a direct
 * substitute. To be fixed in the future.
 *
 * Note that the two variants differ in whether (a) or (b) follows the
 * forward branch. If there is a difference in likelihood, put the
 * likely one in (a) in the first variant, and the likely one in (b)
 * in the second.
 */
#define MINMOD(a,b,a_times_a,a_times_b) \
  ( (a_times_b)>=0. ? 1. : 0. ) * ( (a_times_b)<(a_times_a) ? (b) : (a) )

static inline double
mcubic( const double one,
        const double two,
        const double thr,
        const double fou,
        const double coef_thr_point,
        const double half_coef_two_slope,
        const double half_coef_thr_slope )
{
  /*
   * Computation of the slopes and slope limiters:
   *
   * Differences:
   */
  const double prem = two - one;
  const double deux = thr - two;
  const double troi = fou - thr;

  const double part = two + deux * coef_thr_point;

  /*
   * Products useful for the minmod computations:
   */
  const double deux_prem = deux * prem;
  const double deux_deux = deux * deux;
  const double deux_troi = deux * troi;

  /*
   * Twice the horizontal limiter slopes (twice_lx) interwoven with
   * twice the Catmull-Rom slopes (twice_sx).  Because we have twice
   * the Catmull-Rom slope, we need to use 6 times the minmod slope
   * instead of the usual 3 (specified by the cited article).
   */
  const double twice_lx_two =
    6. * MINMOD( deux, prem, deux_deux, deux_prem );
  const double twice_sx_two = deux + prem;
  const double twice_lx_thr =
    6. * MINMOD( deux, troi, deux_deux, deux_troi );
  const double twice_sx_thr = deux + troi;

  const double lx_lx_two = twice_lx_two * twice_lx_two;
  const double lx_sx_two = twice_lx_two * twice_sx_two;
  const double lx_lx_thr = twice_lx_thr * twice_lx_thr;
  const double lx_sx_thr = twice_lx_thr * twice_sx_thr;

  /*
   * Result of the first interpolations along horizontal lines. Note
   * that the Catmull-Rom slope almost always satisfies the
   * monotonicity constraint, hence twice_sx is "likely" to be the one
   * selected by minmod.
   */
  const double newval =
    part +
    + half_coef_two_slope
    * MINMOD( twice_lx_two, twice_sx_two, lx_lx_two, lx_sx_two )
    + half_coef_thr_slope
    * MINMOD( twice_lx_thr, twice_sx_thr, lx_lx_thr, lx_sx_thr );

  return newval;
}

static inline double
symmetrized_monotone_cubic_splines( const double coef_rite_point,
                                    const double coef_bot_point,
                                    const double half_coef_left_slope,
                                    const double half_coef_rite_slope,
                                    const double half_coef_top_slope,
                                    const double half_coef_bot_slope,
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
   * The stencil of Symmetrized Monotone Catmull-Rom is the same as
   * the standard Catmull-Rom's:
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
   * Outline of the computation:
   *
   * First, four horizontal cubic Hermite interpolations are performed
   * to get values on the vertical line which passes through X, and
   * then these four values are used to perform cubic Hermite
   * interpolation in the vertical direction to get one approximation
   * of the pixel value at X,
   *
   * Then, four vertical cubic Hermite interpolations are performed to
   * get values on the horizontal line which passes through X, and
   * then these four values are used to perform cubic Hermite
   * interpolation in the horizontal direction to get another
   * approximation of the pixel value at X,
   *
   * These two interpolated pixel values are then averaged.
   */

  /*
   * Computation of the slopes and slope limiters:
   *
   * Uno horizontal differences:
   */
  const double uno = mcubic( uno_one,
                             uno_two,
                             uno_thr,
                             uno_fou,
                             coef_rite_point,
                             half_coef_left_slope,
                             half_coef_rite_slope );
  /*
   * Do the same with the other three horizontal lines.
   *
   * Dos horizontal line:
   */
  const double dos = mcubic( dos_one,
                             dos_two,
                             dos_thr,
                             dos_fou,
                             coef_rite_point,
                             half_coef_left_slope,
                             half_coef_rite_slope );
  /*
   * Tre(s) horizontal line:
   */
  const double tre = mcubic( tre_one,
                             tre_two,
                             tre_thr,
                             tre_fou,
                             coef_rite_point,
                             half_coef_left_slope,
                             half_coef_rite_slope );
  /*
   * Qua(ttro) horizontal line:
   */
  const double qua = mcubic( qua_one,
                             qua_two,
                             qua_thr,
                             qua_fou,
                             coef_rite_point,
                             half_coef_left_slope,
                             half_coef_rite_slope );

  /*
   * Perform the interpolation along the one vertical line (filled
   * with results obtained by interpolating along horizontal lines):
   */
  const double partial_y = mcubic( uno,
                                   dos,
                                   tre,
                                   qua,
                                   coef_bot_point,
                                   half_coef_top_slope,
                                   half_coef_bot_slope );

  /*
   * Redo with four vertical lines (and the corresponding horizontal
   * one).
   *
   * One:
   */
  const double one = mcubic( uno_one,
                             dos_one,
                             tre_one,
                             qua_one,
                             coef_bot_point,
                             half_coef_top_slope,
                             half_coef_bot_slope );
  /*
   * Two:
   */
  const double two = mcubic( uno_two,
                             dos_two,
                             tre_two,
                             qua_two,
                             coef_bot_point,
                             half_coef_top_slope,
                             half_coef_bot_slope );
  /*
   * Thr(ee):
   */
  const double thr = mcubic( uno_thr,
                             dos_thr,
                             tre_thr,
                             qua_thr,
                             coef_bot_point,
                             half_coef_top_slope,
                             half_coef_bot_slope );
  /*
   * Fou(r):
   */
  const double fou = mcubic( uno_fou,
                             dos_fou,
                             tre_fou,
                             qua_fou,
                             coef_bot_point,
                             half_coef_top_slope,
                             half_coef_bot_slope );

  /*
   * Final horizontal line of vertical results:
   */
  const double prem_x = two - one;
  const double deux_x = thr - two;
  const double troi_x = fou - thr;

  const double partial_newval = partial_y + two + coef_rite_point * deux_x;

  const double deux_prem_x = deux_x * prem_x;
  const double deux_deux_x = deux_x * deux_x;
  const double deux_troi_x = deux_x * troi_x;

  const double twice_l_two =
    6. * MINMOD( deux_x, prem_x, deux_deux_x, deux_prem_x );
  const double twice_s_two = deux_x + prem_x;
  const double twice_l_thr =
    6. * MINMOD( deux_x, troi_x, deux_deux_x, deux_troi_x );
  const double twice_s_thr = deux_x + troi_x;

  const double l_l_two = twice_l_two * twice_l_two;
  const double l_s_two = twice_l_two * twice_s_two;
  const double l_l_thr = twice_l_thr * twice_l_thr;
  const double l_s_thr = twice_l_thr * twice_s_thr;

  const double newval =
    (
      partial_newval
      +
      half_coef_left_slope
      *
      MINMOD( twice_l_two, twice_s_two, l_l_two, l_s_two )
      +
      half_coef_rite_slope
      *
      MINMOD( twice_l_thr, twice_s_thr, l_l_thr, l_l_thr )
    ) * .5;

  return newval;
}

/*
 * Call Snohalo with an conversion operator as a parameter.
 *
 * It would be nice to do this with templates somehow---for one thing
 * this would allow code comments!---but we can't figure a clean way
 * to do it.
 */
#define MBICUBIC_CONVERSION( conversion )               \
  template <typename T> static void inline              \
  mbicubic_ ## conversion(       PEL*   restrict pout,  \
                           const PEL*   restrict pin,   \
                           const int             bands, \
                           const int             lskip, \
                           const double          x,     \
                           const double          y )    \
  { \
    T* restrict out = (T *) pout; \
    \
    const T* restrict in = (T *) pin; \
    \
    const int uno_one_shift =  -lskip -   bands; \
    const int uno_two_shift =  -lskip          ; \
    const int uno_thr_shift =  -lskip +   bands; \
    const int uno_fou_shift =  -lskip + 2*bands; \
    \
    const int dos_one_shift =         -   bands; \
    const int dos_two_shift =                 0; \
    const int dos_thr_shift =             bands; \
    const int dos_fou_shift =           2*bands; \
    \
    const int tre_one_shift =   lskip -   bands; \
    const int tre_two_shift =   lskip          ; \
    const int tre_thr_shift =   lskip +   bands; \
    const int tre_fou_shift =   lskip + 2*bands; \
    \
    const int qua_one_shift = 2*lskip -   bands; \
    const int qua_two_shift = 2*lskip          ; \
    const int qua_thr_shift = 2*lskip +   bands; \
    const int qua_fou_shift = 2*lskip + 2*bands; \
    \
    const double x_squared = x * x; \
    const double y_squared = y * y; \
    const double twice_x   = x + x; \
    const double twice_y   = y + y; \
    const double half_x_squared_minus_x = .5 * ( x_squared - x ); \
    const double half_y_squared_minus_y = .5 * ( y_squared - y ); \
    \
    const double coef_rite_point = x_squared * ( 3. - twice_x ); \
    const double coef_bot_point  = y_squared * ( 3. - twice_y ); \
    \
    const double half_coef_rite_slope = x * half_x_squared_minus_x; \
    const double half_coef_bot_slope  = y * half_y_squared_minus_y; \
    const double half_coef_left_slope = \
      half_coef_rite_slope - half_x_squared_minus_x; \
    const double half_coef_top_slope  = \
      half_coef_bot_slope  - half_y_squared_minus_y; \
    \
    int band = bands; \
    \
    do \
      { \
        const double double_result = \
          symmetrized_monotone_cubic_splines( coef_rite_point,       \
                                              coef_bot_point,        \
                                              half_coef_left_slope,  \
                                              half_coef_rite_slope,  \
                                              half_coef_top_slope,   \
                                              half_coef_bot_slope,   \
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

MBICUBIC_CONVERSION( fptypes )
MBICUBIC_CONVERSION( withsign )
MBICUBIC_CONVERSION( nosign )

#define CALL( T, conversion )               \
  mbicubic_ ## conversion<T>( out,          \
                              p,            \
                              bands,        \
                              lskip,        \
                              relative_x,   \
                              relative_y );

/*
 * We need C linkage:
 */
extern "C" {
G_DEFINE_TYPE( VipsInterpolateMbicubic, vips_interpolate_mbicubic,
	VIPS_TYPE_INTERPOLATE );
}

static void
vips_interpolate_mbicubic_interpolate( VipsInterpolate* restrict interpolate,
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
vips_interpolate_mbicubic_class_init( VipsInterpolateMbicubicClass *klass )
{
  GObjectClass *gobject_class = G_OBJECT_CLASS( klass );
  VipsObjectClass *object_class = VIPS_OBJECT_CLASS( klass );
  VipsInterpolateClass *interpolate_class =
    VIPS_INTERPOLATE_CLASS( klass );

  object_class->nickname = "mbicubic";
  object_class->description = _( "Halo-free mbicubic" );

  interpolate_class->interpolate = vips_interpolate_mbicubic_interpolate;
  interpolate_class->window_size = 4;
}

static void
vips_interpolate_mbicubic_init( VipsInterpolateMbicubic *mbicubic )
{
}
