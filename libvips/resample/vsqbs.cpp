/* vertex-split subdivision followed by quadratic b-spline smoothing
 *
 * C. Racette 23-28/05/2010 based on code by N. Robidoux and J. Cupitt
 *
 * N. Robidoux 29-30/05/2010
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
 * 2010 (c) Chantal Racette, Nicolas Robidoux, John Cupitt.
 *
 * Nicolas Robidoux thanks Adam Turcotte, Geert Jordaens, Ralf Meyer,
 * Øyvind Kolås, Minglun Gong and Eric Daoust for useful comments and
 * code.
 *
 * Chantal Racette's image resampling research and programming funded
 * in part by a NSERC Discovery Grant awarded to Julien Dompierre
 * (20-61098).
 */

/*
 * Vertex-Split Quadratic B-Splines (VSQBS) is a brand new method
 * which consists of vertex-split subdivision, a subdivision method
 * with the (as yet unknown?) property that data which is (locally)
 * constant on diagonals is subdivided into data which is (locally)
 * constant on diagonals, followed by quadratic B-Spline smoothing.
 * Because both methods are linear, their combination can be
 * implemented as if there is no subdivision.
 *
 * At high enlargement ratios, VSQBS is very effective at "masking"
 * that the original has pixels uniformly distributed on a grid. In
 * particular, VSQBS produces resamples with only very mild
 * staircasing. Like cubic B-Spline smoothing, however, VSQBS is not
 * an interpolatory method. For example, using VSQBS to perform the
 * identity geometric transformation (enlargement by a scaling factor
 * equal to 1) on an image does not return the original: VSQBS
 * effectively smooths out the image with the convolution mask
 *
 *     1/8
 * 1/8 1/2 1/8
 *     1/8
 *
 * which is a fairly moderate blur (although the checkerboard mode is
 * in its nullspace).
 *
 * By blending VSQBS with an interpolatory method (bilinear, say) in a
 * transformation adaptive environment (current GEGL, for example), it
 * is quite easy to restore that resampling for identity geometric
 * transformation is equivalent to the identity, and rotations are not
 * affected by the above, implicit, blur. Contact N. Robidoux for
 * details.
 *
 * An article on VSQBS is forthcoming.
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

#define VIPS_TYPE_INTERPOLATE_VSQBS \
	(vips_interpolate_vsqbs_get_type())
#define VIPS_INTERPOLATE_VSQBS( obj ) \
	(G_TYPE_CHECK_INSTANCE_CAST( (obj), \
	VIPS_TYPE_INTERPOLATE_VSQBS, VipsInterpolateVsqbs ))
#define VIPS_INTERPOLATE_VSQBS_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_CAST( (klass), \
	VIPS_TYPE_INTERPOLATE_VSQBS, VipsInterpolateVsqbsClass))
#define VIPS_IS_INTERPOLATE_VSQBS( obj ) \
	(G_TYPE_CHECK_INSTANCE_TYPE( (obj), VIPS_TYPE_INTERPOLATE_VSQBS ))
#define VIPS_IS_INTERPOLATE_VSQBS_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_TYPE( (klass), VIPS_TYPE_INTERPOLATE_VSQBS ))
#define VIPS_INTERPOLATE_VSQBS_GET_CLASS( obj ) \
	(G_TYPE_INSTANCE_GET_CLASS( (obj), \
	VIPS_TYPE_INTERPOLATE_VSQBS, VipsInterpolateVsqbsClass ))

typedef struct _VipsInterpolateVsqbs {
	VipsInterpolate parent_object;

} VipsInterpolateVsqbs;

typedef struct _VipsInterpolateVsqbsClass {
	VipsInterpolateClass parent_class;

} VipsInterpolateVsqbsClass;

/*
 * THE STENCIL OF INPUT VALUES:
 *
 * Pointer arithmetic is used to implicitly reflect the input stencil
 * about dos_two---assumed closer to the sampling location than other
 * pixels (ties are OK)---in such a way that after reflection the
 * sampling point is to the bottom right of dos_two.
 *
 * The following code and picture assumes that the stencil reflexion
 * has already been performed. (X is the sampling location.)
 *
 *
 *               (ix,iy-1)    (ix+1,iy-1)
 *               = uno_two    = uno_thr
 *
 *
 *
 *  (ix-1,iy)    (ix,iy)      (ix+1,iy)
 *  = dos_one    = dos_two    = dos_thr
 *                       X
 *
 *
 *  (ix-1,iy+1)  (ix,iy+1)    (ix+1,iy+1)
 *  = tre_one    = tre_two    = tre_thr
 *
 *
 * The above input pixel values are the ones needed in order to
 * IMPLICITLY make available the following values, needed by quadratic
 * B-Splines, which is performed on (shifted) double density data:
 *
 *
 *  uno_one_1 =      uno_two_1 =      uno_thr_1 =
 *  (ix-1/4,iy-1/4)  (ix+1/4,iy-1/4)  (ix+3/4,iy-1/4)
 *
 *
 *
 *                 X            or X
 *  dos_one_1 =      dos_two_1 =      dos_thr_1 =
 *  (ix-1/4,iy+1/4)  (ix+1/4,iy+1/4)  (ix+3/4,iy+1/4)
 *              or X            or X
 *
 *
 *
 *  tre_one_1 =      tre_two_1 =      tre_thr_1 =
 *  (ix-1/4,iy+3/4)  (ix+1/4,iy+3/4)  (ix+3/4,iy+3/4)
 *
 *
 * In the coefficient computations, we fix things so that coordinates
 * are relative to dos_two_1, and so that distances are rescaled so
 * that double density pixel locations are at a distance of 1.
 */

/*
 * Call vertex-split + quadratic B-splines with a careful type
 * conversion as a parameter. (It would be nice to do this with
 * templates somehow---for one thing this would allow code
 * comments---but we can't figure a clean way to do it.)
 */
#define VSQBS_CONVERSION( conversion )               \
  template <typename T> static void inline           \
  vsqbs_ ## conversion(       void*    restrict pout, \
                        const VipsPel* restrict pin,  \
                        const int             bands, \
                        const int             lskip, \
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
    const int uno_two_shift =                    shift_back_1_row; \
    const int uno_thr_shift = shift_forw_1_pix + shift_back_1_row; \
    \
    const int dos_one_shift = shift_back_1_pix; \
    const int dos_two_shift = 0;                \
    const int dos_thr_shift = shift_forw_1_pix; \
    \
    const int tre_one_shift = shift_back_1_pix + shift_forw_1_row; \
    const int tre_two_shift =                    shift_forw_1_row; \
    const int tre_thr_shift = shift_forw_1_pix + shift_forw_1_row; \
    \
    \
    const double twice_abs_x_0 = ( 2 * sign_of_x_0 ) * x_0; \
    const double twice_abs_y_0 = ( 2 * sign_of_y_0 ) * y_0; \
    const double x             = twice_abs_x_0 + -0.5;      \
    const double y             = twice_abs_y_0 + -0.5;      \
    const double cent          = 0.75 - x * x;              \
    const double mid           = 0.75 - y * y;              \
    const double left          = -0.5 * ( x + cent ) + 0.5; \
    const double top           = -0.5 * ( y + mid  ) + 0.5; \
    const double left_p_cent   = left + cent;               \
    const double top_p_mid     = top  + mid;                \
    const double cent_p_rite   = 1.0 - left;                \
    const double mid_p_bot     = 1.0 - top;                 \
    const double rite          = 1.0 - left_p_cent;         \
    const double bot           = 1.0 - top_p_mid;           \
    \
    const double four_c_uno_two = left_p_cent * top;                    \
    const double four_c_dos_one = left        * top_p_mid;              \
    const double four_c_dos_two = left_p_cent + top_p_mid;              \
    const double four_c_dos_thr = cent_p_rite * top_p_mid + rite;       \
    const double four_c_tre_two = mid_p_bot * left_p_cent + bot;        \
    const double four_c_tre_thr = mid_p_bot * rite + cent_p_rite * bot; \
    const double four_c_uno_thr = top  - four_c_uno_two;                \
    const double four_c_tre_one = left - four_c_dos_one;                \
    \
    \
    int band = bands; \
    \
    do \
      { \
        const double double_result =               \
          (                                        \
            (                                      \
              (                                    \
                four_c_uno_two * in[uno_two_shift] \
                +                                  \
                four_c_dos_one * in[dos_one_shift] \
              )                                    \
              +                                    \
              (                                    \
                four_c_dos_two * in[dos_two_shift] \
                +                                  \
                four_c_dos_thr * in[dos_thr_shift] \
              )                                    \
            )                                      \
            +                                      \
            (                                      \
              (                                    \
                four_c_tre_two * in[tre_two_shift] \
                +                                  \
                four_c_tre_thr * in[tre_thr_shift] \
              )                                    \
              +                                    \
              (                                    \
                four_c_uno_thr * in[uno_thr_shift] \
                +                                  \
                four_c_tre_one * in[tre_one_shift] \
              )                                    \
            )                                      \
          ) * 0.25;                                \
        \
        const T result = to_ ## conversion<T>( double_result ); \
        in++;                                                   \
        *out++ = result;                                        \
        \
      } while (--band); \
  }


VSQBS_CONVERSION( fptypes )
VSQBS_CONVERSION( withsign )
VSQBS_CONVERSION( nosign )


#define CALL( T, conversion )               \
  vsqbs_ ## conversion<T>( out,             \
                              p,            \
                              bands,        \
                              lskip,        \
                              relative_x,   \
                              relative_y );


/*
 * We need C linkage:
 */
extern "C" {
  G_DEFINE_TYPE( VipsInterpolateVsqbs, vips_interpolate_vsqbs,
                 VIPS_TYPE_INTERPOLATE );
}


static void
vips_interpolate_vsqbs_interpolate( VipsInterpolate* restrict interpolate,
                                    void*            restrict out,
                                    REGION*          restrict in,
                                    double                    absolute_x,
                                    double                    absolute_y )
{
  /* absolute_x and absolute_y are always >= 1.0 (see double-check assert
   * below), so we don't need floor(). 
   *
   * It's 1 not 0 since we ask for a window_offset of 1 at the bottom.
   */
  const int ix = (int) (absolute_x + 0.5);
  const int iy = (int) (absolute_y + 0.5);

  /*
   * Move the pointer to (the first band of) the top/left pixel of the
   * 2x2 group of pixel centers which contains the sampling location
   * in its convex hull:
   */
  const VipsPel* restrict p = VIPS_REGION_ADDR( in, ix, iy );

  const double relative_x = absolute_x - ix;
  const double relative_y = absolute_y - iy;

  /*
   * VIPS versions of Nicolas's pixel addressing values.
   */
  const int lskip = VIPS_REGION_LSKIP( in ) / 
	  VIPS_IMAGE_SIZEOF_ELEMENT( in->im );

  /*
   * Double the bands for complex images to account for the real and
   * imaginary parts being computed independently:
   */
  const int actual_bands = in->im->Bands;
  const int bands =
    vips_bandfmt_iscomplex( in->im->BandFmt ) ? 2 * actual_bands : actual_bands;

  /* Confirm that absolute_x and absolute_y are >= 1, see above. 
   */
  g_assert( absolute_x >= 1.0 );
  g_assert( absolute_y >= 1.0 );

  switch( in->im->BandFmt ) {
  case VIPS_FORMAT_UCHAR:
    CALL( unsigned char, nosign );
    break;

  case VIPS_FORMAT_CHAR:
    CALL( signed char, withsign );
    break;

  case VIPS_FORMAT_USHORT:
    CALL( unsigned short, nosign );
    break;

  case VIPS_FORMAT_SHORT:
    CALL( signed short, withsign );
    break;

  case VIPS_FORMAT_UINT:
    CALL( unsigned int, nosign );
    break;

  case VIPS_FORMAT_INT:
    CALL( signed int, withsign );
    break;

  /*
   * Complex images are handled by doubling bands:
   */
  case VIPS_FORMAT_FLOAT:
  case VIPS_FORMAT_COMPLEX:
    CALL( float, fptypes );
    break;

  case VIPS_FORMAT_DOUBLE:
  case VIPS_FORMAT_DPCOMPLEX:
    CALL( double, fptypes );
    break;

  default:
    g_assert( 0 );
    break;
  }
}

static void
vips_interpolate_vsqbs_class_init( VipsInterpolateVsqbsClass *klass )
{
  VipsObjectClass           *object_class =      VIPS_OBJECT_CLASS( klass );
  VipsInterpolateClass *interpolate_class = VIPS_INTERPOLATE_CLASS( klass );

  object_class->nickname    = "vsqbs";
  object_class->description = _( "B-Splines with antialiasing smoothing" );

  interpolate_class->interpolate   = vips_interpolate_vsqbs_interpolate;
  interpolate_class->window_size   = 3;
  interpolate_class->window_offset = 1;
}

static void
vips_interpolate_vsqbs_init( VipsInterpolateVsqbs *vsqbs )
{
}
