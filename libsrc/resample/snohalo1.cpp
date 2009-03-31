/* snohalo (smooth nohalo) level 1 interpolator
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
 * needs two conditional moves.  (Nicolas: I think that this may be
 * the very first two branch minmod.) The product of the two arguments
 * and a useful difference involving them are also precomputed to keep
 * them out of branching way.
 */
#define FAST_MINMOD(a,b,ab,abminusaa) \
        ( (ab)>=0. ? ( (abminusaa)>=0. ? (a) : (b) ) : 0. )

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

static void inline
snohalo1( const double           blur,
          const double           zer_two_in,
          const double           zer_thr_in,
          const double           uno_one_in,
          const double           uno_two_in,
          const double           uno_thr_in,
          const double           uno_fou_in,
          const double           dos_zer_in,
          const double           dos_one_in,
          const double           dos_two_in,
          const double           dos_thr_in,
          const double           dos_fou_in,
          const double           dos_fiv_in,
          const double           tre_zer_in,
          const double           tre_one_in,
          const double           tre_two_in,
          const double           tre_thr_in,
          const double           tre_fou_in,
          const double           tre_fiv_in,
          const double           qua_one_in,
          const double           qua_two_in,
          const double           qua_thr_in,
          const double           qua_fou_in,
          const double           cin_two_in,
          const double           cin_thr_in,
                double* restrict r0,
                double* restrict r1,
                double* restrict r2,
                double* restrict r3 )
{
  const double beta  = 1. + -.5 * blur;
  const double gamma = .125 * blur;
  
  /*
   * Computation of the blurred pixel values:
   */
  const double uno_one_plus_zer_two_in = uno_one_in + zer_two_in;
  const double uno_two_plus_zer_thr_in = uno_two_in + zer_thr_in;

  const double dos_zer_plus_uno_one_in = dos_zer_in + uno_one_in;
  const double dos_one_plus_uno_two_in = dos_one_in + uno_two_in;
  const double dos_two_plus_uno_thr_in = dos_two_in + uno_thr_in;
  const double dos_thr_plus_uno_fou_in = dos_thr_in + uno_fou_in;

  const double tre_zer_plus_dos_one_in = tre_zer_in + dos_one_in;
  const double tre_one_plus_dos_two_in = tre_one_in + dos_two_in;
  const double tre_two_plus_dos_thr_in = tre_two_in + dos_thr_in;
  const double tre_thr_plus_dos_fou_in = tre_thr_in + dos_fou_in;
  const double tre_fou_plus_dos_fiv_in = tre_fou_in + dos_fiv_in;

  const double qua_one_plus_tre_two_in = qua_one_in + tre_two_in;
  const double qua_two_plus_tre_thr_in = qua_two_in + tre_thr_in;
  const double qua_thr_plus_tre_fou_in = qua_thr_in + tre_fou_in;
  const double qua_fou_plus_tre_fiv_in = qua_fou_in + tre_fiv_in;

  const double cin_two_plus_qua_thr_in = cin_two_in + qua_thr_in;
  const double cin_thr_plus_qua_fou_in = cin_thr_in + qua_fou_in;

  const double uno_two =
    beta * uno_two_in
    +
    ( uno_one_plus_zer_two_in + dos_two_plus_uno_thr_in ) * gamma;

  const double uno_thr =
    beta * uno_thr_in 
    +
    ( uno_two_plus_zer_thr_in + dos_thr_plus_uno_fou_in ) * gamma;

  const double dos_one =
    beta * dos_one_in
    +
    ( dos_zer_plus_uno_one_in + tre_one_plus_dos_two_in ) * gamma;

  const double dos_two =
    beta * dos_two_in
    +
    ( dos_one_plus_uno_two_in + tre_two_plus_dos_thr_in ) * gamma;

  const double dos_thr =
    beta * dos_thr_in 
    +
    ( dos_two_plus_uno_thr_in + tre_thr_plus_dos_fou_in ) * gamma;

  const double dos_fou =
    beta * dos_fou_in 
    +
    ( dos_thr_plus_uno_fou_in + tre_fou_plus_dos_fiv_in ) * gamma;

  const double tre_one =
    beta * tre_one_in
    +
    ( tre_zer_plus_dos_one_in + qua_one_plus_tre_two_in ) * gamma;

  const double tre_two =
    beta * tre_two_in
    +
    ( tre_one_plus_dos_two_in + qua_two_plus_tre_thr_in ) * gamma;

  const double tre_thr =
    beta * tre_thr_in 
    +
    ( tre_two_plus_dos_thr_in + qua_thr_plus_tre_fou_in ) * gamma;

  const double tre_fou =
    beta * tre_fou_in 
    +
    ( tre_thr_plus_dos_fou_in + qua_fou_plus_tre_fiv_in ) * gamma;

  const double qua_two =
    beta * qua_two_in
    +
    ( qua_one_plus_tre_two_in + cin_two_plus_qua_thr_in ) * gamma;

  const double qua_thr =
    beta * qua_thr_in 
    +
    ( qua_two_plus_tre_thr_in + cin_thr_plus_qua_fou_in ) * gamma;

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
   * Apply minmod to comsecutive differences:
   */
  /*
   * Products and differences useful for minmod:
   */
  const double deux_prem_dos = deux_dos * prem_dos;
  const double deux_deux_dos = deux_dos * deux_dos;
  const double deux_troi_dos = deux_dos * troi_dos;

  const double deux_prem_two = deux_two * prem_two;
  const double deux_deux_two = deux_two * deux_two;
  const double deux_troi_two = deux_two * troi_two;

  const double deux_prem_minus_deux_deux_dos = deux_prem_dos - deux_deux_dos;
  const double deux_troi_minus_deux_deux_dos = deux_troi_dos - deux_deux_dos;

  const double deux_prem_minus_deux_deux_two = deux_prem_two - deux_deux_two;
  const double deux_troi_minus_deux_deux_two = deux_troi_two - deux_deux_two;

  const double deux_prem_tre = deux_tre * prem_tre;
  const double deux_deux_tre = deux_tre * deux_tre;
  const double deux_troi_tre = deux_tre * troi_tre;

  const double deux_prem_thr = deux_thr * prem_thr;
  const double deux_deux_thr = deux_thr * deux_thr;
  const double deux_troi_thr = deux_thr * troi_thr;

  const double deux_prem_minus_deux_deux_tre = deux_prem_tre - deux_deux_tre;
  const double deux_troi_minus_deux_deux_tre = deux_troi_tre - deux_deux_tre;

  const double deux_prem_minus_deux_deux_thr = deux_prem_thr - deux_deux_thr;
  const double deux_troi_minus_deux_deux_thr = deux_troi_thr - deux_deux_thr;

  /*
   * Useful sums:
   */
  const double dos_two_plus_dos_thr = dos_two + dos_thr;
  const double dos_two_plus_tre_two = dos_two + tre_two;
  const double deux_thr_plus_deux_dos = deux_thr + deux_dos;

  /*
   * Compute the needed "right" (at the boundary between one input
   * pixel areas) double resolution pixel value:
   */
  const double four_times_dos_twothr =
    FAST_MINMOD( deux_dos, prem_dos, deux_prem_dos,
                 deux_prem_minus_deux_deux_dos )
    +
    2. * dos_two_plus_dos_thr
    -
    FAST_MINMOD( deux_dos, troi_dos, deux_troi_dos,
                 deux_troi_minus_deux_deux_dos );

  /*
   * Compute the needed "down" double resolution pixel value:
   */
  const double four_times_dostre_two =
    FAST_MINMOD( deux_two, prem_two, deux_prem_two,
                 deux_prem_minus_deux_deux_two )
    +
    2. * dos_two_plus_tre_two
    -
    FAST_MINMOD( deux_two, troi_two, deux_troi_two,
                 deux_troi_minus_deux_deux_two );

  /*
   * Compute the "diagonal" (at the boundary between thrr input
   * pixel areas) double resolution pixel value:
   */
  const double eight_times_dostre_twothr =
    FAST_MINMOD( deux_tre, prem_tre, deux_prem_tre,
                 deux_prem_minus_deux_deux_tre )
    +
    2. * deux_thr_plus_deux_dos
    -
    FAST_MINMOD( deux_tre, troi_tre, deux_troi_tre,
                 deux_troi_minus_deux_deux_tre )
    +
    four_times_dos_twothr
    +
    FAST_MINMOD( deux_thr, prem_thr, deux_prem_thr,
                 deux_prem_minus_deux_deux_thr )
    +
    four_times_dostre_two
    -
    FAST_MINMOD( deux_thr, troi_thr, deux_troi_thr,
                 deux_troi_minus_deux_deux_thr );

  /*
   * Return the first newly computed double density values:
   */
  *r0 = dos_two;
  *r1 = four_times_dos_twothr;
  *r2 = four_times_dostre_two;
  *r3 = eight_times_dostre_twothr;
}

/* Call snohalo1 with an interpolator as a parameter.
 * It'd be nice to do this with templates somehow :-( but I can't see a
 * clean way to do it.
 */
#define SNOHALO1_INTER( inter ) \
  template <typename T> static void inline \
  snohalo1_ ## inter(       PEL*   restrict pout, \
                      const PEL*   restrict pin, \
                      const int             bands, \
                      const int             lskip, \
                      const double          blur, \
                      const double          relative_x, \
                      const double          relative_y ) \
  { \
    T* restrict out = (T *) pout; \
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
    const int shift_back_1_pixel = sign_of_relative_x * bands; \
    const int shift_back_1_row   = sign_of_relative_y * lskip; \
    \
    const T* restrict in = ( (T *) pin ) + corner_reflection_shift; \
    \
    const int shift_forw_1_pixel = -shift_back_1_pixel; \
    const int shift_forw_1_row   = -shift_back_1_row; \
    \
    const int shift_back_2_pixel = 2 * shift_back_1_pixel; \
    const int shift_back_2_row   = 2 * shift_back_2_row; \
    \
    const double w = ( 2 * sign_of_relative_x ) * relative_x; \
    const double z = ( 2 * sign_of_relative_y ) * relative_y; \
    \
    const int shift_forw_2_pixel = 2 * shift_forw_1_pixel; \
    const int shift_forw_2_row   = 2 * shift_forw_1_row; \
    \
    const int shift_forw_3_pixel = 3 * shift_forw_1_pixel; \
    const int shift_forw_3_row   = 3 * shift_forw_1_row; \
    \
    const int zer_two_shift =                      shift_back_2_row; \
    const int zer_thr_shift = shift_forw_1_pixel + shift_back_2_row; \
    \
    const int uno_one_shift = shift_back_1_pixel + shift_back_1_row; \
    const int uno_two_shift =                      shift_back_1_row; \
    const int uno_thr_shift = shift_forw_1_pixel + shift_back_1_row; \
    const int uno_fou_shift = shift_forw_2_pixel + shift_back_1_row; \
    \
    const double x = 1. - w; \
    const double w_times_z = w * z; \
    \
    const int dos_zer_shift = shift_back_2_pixel; \
    const int dos_one_shift = shift_back_1_pixel; \
    const int dos_two_shift = 0; \
    const int dos_thr_shift = shift_forw_1_pixel; \
    const int dos_fou_shift = shift_forw_2_pixel; \
    const int dos_fiv_shift = shift_forw_3_pixel; \
    \
    const int tre_zer_shift = shift_back_2_pixel + shift_forw_1_row; \
    const int tre_one_shift = shift_back_1_pixel + shift_forw_1_row; \
    const int tre_two_shift =                      shift_forw_1_row; \
    const int tre_thr_shift = shift_forw_1_pixel + shift_forw_1_row; \
    const int tre_fou_shift = shift_forw_2_pixel + shift_forw_1_row; \
    const int tre_fiv_shift = shift_forw_3_pixel + shift_forw_1_row; \
    \
    const double x_times_z = x * z; \
    \
    const int qua_one_shift = shift_back_1_pixel + shift_forw_2_row; \
    const int qua_two_shift =                      shift_forw_2_row; \
    const int qua_thr_shift = shift_forw_1_pixel + shift_forw_2_row; \
    const int qua_fou_shift = shift_forw_2_pixel + shift_forw_2_row; \
    \
    const int cin_two_shift =                      shift_forw_3_row; \
    const int cin_thr_shift = shift_forw_1_pixel + shift_forw_3_row; \
    \
    const double w_times_y_over_4 = .25  * ( w - w_times_z ); \
    const double x_times_z_over_4 = .25  * x_times_z; \
    const double x_times_y_over_8 = .125 * ( x - x_times_z ); \
    \
    int band = bands; \
    \
    do \
      { \
        double dos_two; \
        double four_times_dos_twothr; \
        double four_times_dostre_two; \
        double eight_times_dostre_twothr; \
        \
        snohalo1( blur, \
                  in[zer_two_shift], in[zer_thr_shift], \
                  in[uno_one_shift], in[uno_two_shift], \
                  in[uno_thr_shift], in[uno_fou_shift], \
                  in[dos_zer_shift], in[dos_one_shift], \
                  in[dos_two_shift], in[dos_thr_shift], \
                  in[dos_fou_shift], in[dos_fiv_shift], \
                  in[tre_zer_shift], in[tre_one_shift], \
                  in[tre_two_shift], in[tre_thr_shift], \
                  in[tre_fou_shift], in[tre_fiv_shift], \
                  in[qua_one_shift], in[qua_two_shift], \
                  in[qua_thr_shift], in[qua_fou_shift], \
                  in[cin_two_shift], in[cin_thr_shift], \
                  &dos_two, \
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

SNOHALO1_INTER( float )
SNOHALO1_INTER( signed )
SNOHALO1_INTER( unsigned )

/* We need C linkage for this.
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
   * VIPS versions of Nicolas's pixel addressing values.
   */
  const int actual_bands = in->im->Bands;
  const int lskip = IM_REGION_LSKIP( in ) / IM_IMAGE_SIZEOF_ELEMENT( in->im );

  const double absolute_y_minus_half = absolute_y - .5;
  const double absolute_x_minus_half = absolute_x - .5;
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
  const int iy = FAST_PSEUDO_FLOOR (absolute_y);
  const double relative_y = absolute_y_minus_half - iy;
  const int ix = FAST_PSEUDO_FLOOR (absolute_x);
  const double relative_x = absolute_x_minus_half - ix;

  /*
   * Move the pointer to (the first band of) the top/left pixel of the
   * 2x2 group of pixel centers which contains the sampling location
   * in its convex hull:
   */
  const PEL* restrict p = (PEL *) IM_REGION_ADDR( in, ix, iy );

  /*
   * Restrict blur parameter to [0,1]:
   */
  const double actual_blur = snohalo1->blur;
  const double blur =
    ( actual_blur >= 0. ? ( actual_blur <= 1. ? actual_blur : 1. ) : 0. );

  /*
   * Double bands for complex images:
   */
  const int bands =
    ( im_iscomplex( in->im ) ? 2 * actual_bands : actual_bands );

#define CALL( T, inter ) \
  snohalo1_ ## inter<T>( out, \
                         p, \
                         bands, \
                         lskip, \
                         blur, \
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
  object_class->description = _( "Nohalo level 1 with antialiasing blur" );

  interpolate_class->interpolate =
    vips_interpolate_snohalo1_interpolate;
  interpolate_class->window_size = 6;

  /* Create properties.
   */
  pspec =
    g_param_spec_double( "blur", 
                         _( "Blur" ),
                         _( "Antialiasing blur amount: 0. = none, 1. = max" ),
                         0, 4, 1, 
                         (GParamFlags) G_PARAM_READWRITE );
  g_object_class_install_property( gobject_class, 
                                   PROP_BLUR, pspec );
  vips_object_class_install_argument( object_class, pspec,
        VIPS_ARGUMENT_SET_ONCE,
        G_STRUCT_OFFSET( VipsInterpolateSnohalo1, blur ) );

}

static void
vips_interpolate_snohalo1_init( VipsInterpolateSnohalo1 *snohalo1 )
{
}
