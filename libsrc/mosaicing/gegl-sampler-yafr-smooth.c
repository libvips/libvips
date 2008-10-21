/* This file is part of GEGL
 *
 * GEGL is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 3 of the
 * License, or (at your option) any later version.
 *
 * GEGL is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General
 * Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with GEGL; if not, see
 * <http://www.gnu.org/licenses/>.
 *
 * 2008 (c) Nicolas Robidoux (developer of Yet Another Fast
 * Resampler).
 *
 * Acknowledgement: N. Robidoux's research on YAFR funded in part by
 * an NSERC (National Science and Engineering Research Council of
 * Canada) Discovery Grant.
 */

#include <glib-object.h>
#include "gegl-types.h"
#include "gegl-buffer-private.h"
#include "gegl-sampler-yafr.h"

#include <math.h>

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

#ifndef unlikely
#ifdef __builtin_expect
#define unlikely(x) __builtin_expect((x),0)
#else
#define unlikely(x) (x)
#endif
#endif

enum
{
  PROP_0,
  PROP_LAST
};

static void gegl_sampler_yafr_get (      GeglSampler *self,
                                   const gdouble      x,
                                   const gdouble      y,
                                         void        *output);

static void set_property (      GObject    *gobject,
                                guint       property_id,
                          const GValue     *value,
                                GParamSpec *pspec);

static void get_property (GObject    *gobject,
                          guint       property_id,
                          GValue     *value,
                          GParamSpec *pspec);

G_DEFINE_TYPE (GeglSamplerYafr, gegl_sampler_yafr, GEGL_TYPE_SAMPLER)

/*
 * YAFR = Yet Another Fast Resampler
 *
 * Yet Another Fast Resampler is a nonlinear resampler which consists
 * of a linear scheme (in this version, Catmull-Rom) plus a nonlinear
 * sharpening correction the purpose of which is the straightening of
 * diagonal interfaces between flat colour areas.
 *
 * Key properties:
 *
 * YAFR (smooth) is interpolatory:
 *
 * If asked for the value at the center of an input pixel, it will
 * return the corresponding value, unchanged.
 *
 * YAFR (smooth) preserves local averages:
 *
 * The average of the reconstructed intensity surface over any region
 * is the same as the average of the piecewise constant surface with
 * values over pixel areas equal to the input pixel values (the
 * "nearest neighbour" surface), except for a small amount of blur at
 * the boundary of the region. More precicely: YAFR (smooth) is a box
 * filtered exact area method.
 *
 * Main weaknesses of YAFR (smooth):
 *
 * Weakness 1: YAFR (smooth) improves on Catmull-Rom only for images
 * with at least a little bit of smoothness.
 *
 * Weakness 2: Catmull-Rom introduces a lot of haloing. YAFR (smooth)
 * is based on Catmull-Rom, and consequently it too introduces a lot
 * of haloing.
 *
 * More details regarding Weakness 1: 
 *
 * If a portion of the image is such that every pixel has immediate
 * neighbours in the horizontal and vertical directions which have
 * exactly the same pixel value, then YAFR (smooth) boils down to
 * Catmull-Rom, and the computation of the correction is a waste.
 * Extreme case: If all the pixels are either pure black or pure white
 * in some region, as in some text images (more generally, if the
 * region is "bichromatic"), then the YAFR (smooth) correction is 0 in
 * the interior of the bichromatic region.
 */

static void
gegl_sampler_yafr_class_init (GeglSamplerYafrClass *klass)
{
  GeglSamplerClass *sampler_class = GEGL_SAMPLER_CLASS (klass);
  GObjectClass     *object_class  = G_OBJECT_CLASS (klass);

  object_class->set_property = set_property;
  object_class->get_property = get_property;

  sampler_class->get = gegl_sampler_yafr_get;
 }

static void
gegl_sampler_yafr_init (GeglSamplerYafr *self)
{
  /*
   * The computation stencil is 4x4, and sticks out one column to the
   * left and one row above the requested integer position:
   */
  GEGL_SAMPLER (self)->context_rect = (GeglRectangle){-1,-1,4,4};

  GEGL_SAMPLER (self)->interpolate_format = babl_format ("RaGaBaA float");
}

static inline gfloat
catrom_yafr (const gfloat cardinal_one,
             const gfloat cardinal_two,
             const gfloat cardinal_thr,
             const gfloat cardinal_fou,
             const gfloat cardinal_uno,
             const gfloat cardinal_dos,
             const gfloat cardinal_tre,
             const gfloat cardinal_qua,
             const gfloat left_width_times_up__height_times_rite_width,
             const gfloat left_width_times_dow_height_times_rite_width,
             const gfloat left_width_times_up__height_times_dow_height,
             const gfloat rite_width_times_up__height_times_dow_height,
             const gfloat* restrict this_channels_uno_one_bptr)
{
  /*
   * "sharpening" is a continuous method parameter which is
   * proportional to the amount of "diagonal straightening" which the
   * nonlinear correction part of the method may add to the underlying
   * linear scheme. You may also think of it as a sharpening
   * parameter: higher values correspond to more sharpening, and
   * negative values lead to strange looking effects.
   *
   * The default value is sharpening = 29/32 when the scheme being
   * "straightened" is Catmull-Rom---as is the case here. This value
   * fixes key pixel values near the diagonal boundary between two
   * monochrome regions (the diagonal boundary pixel values being set
   * to the halfway colour).
   *
   * If resampling seems to add unwanted texture artifacts, push
   * sharpening toward 0. It is not generally not recommended to set
   * sharpening to a value larger than 4.
   *
   * Sharpening is halved because the .5 which has to do with the
   * relative coordinates of the evaluation points (which has to do
   * with .5*rite_width etc) is folded into the constant to save
   * flops. Consequently, the largest recommended value of
   * sharpening_over_two is 2=4/2.
   *
   * In order to simplify interfacing with users, the parameter which
   * should be set by the user is normalized so that user_sharpening =
   * 1 when sharpening is equal to the recommended value. Consistently
   * with the above discussion, values of user_sharpening between 0
   * and about 3.625 give good results.
   */
  const gfloat user_sharpening = 1.f;
  const gfloat sharpening_over_two = user_sharpening * 0.453125f;

  /*
   * The input pixel values are described by the following stencil.
   *  Spanish abbreviations are used to label positions from top to
   *  bottom, English ones to label positions from left to right,:
   *
   *   (ix-1,iy-1)     (ix,iy-1)       (ix+1,iy-1)     (ix+2,iy-1)
   *   =uno_one        =uno_two        =uno_thr        = uno_fou
   *
   *   (ix-1,iy)       (ix,iy)         (ix+1,iy)       (ix+2,iy)
   *   =dos_one        =dos_two        =dos_thr        = dos_fou
   *
   *   (ix-1,iy+1)     (ix,iy+1)       (ix+1,iy+1)     (ix+2,iy+1)
   *   =tre_one        =tre_two        =tre_thr        = tre_fou
   *
   *   (ix-1,iy+2)     (ix,iy+2)       (ix+1,iy+2)     (ix+2,iy+2)
   *   =qua_one        =qua_two        =qua_thr        = qua_fou
   */

  /*
   * Load the useful pixel values for the channel under
   * consideration. The this_channels_uno_one_bptr pointer is assumed
   * to point to uno_one when catrom_yafr is entered.
   */
  const gint channels = 4;
  const gint pixels_per_buffer_row = 64;
  const gfloat uno_one =
    this_channels_uno_one_bptr[   0                                          ];
  const gfloat uno_two =
    this_channels_uno_one_bptr[                                     channels ];
  const gfloat uno_thr =
    this_channels_uno_one_bptr[   2                               * channels ];
  const gfloat uno_fou =
    this_channels_uno_one_bptr[   3                               * channels ];

  const gfloat dos_one =
    this_channels_uno_one_bptr[           pixels_per_buffer_row   * channels ];
  const gfloat dos_two =
    this_channels_uno_one_bptr[ ( 1 +     pixels_per_buffer_row ) * channels ];
  const gfloat dos_thr =
    this_channels_uno_one_bptr[ ( 2 +     pixels_per_buffer_row ) * channels ];
  const gfloat dos_fou =
    this_channels_uno_one_bptr[ ( 3 +     pixels_per_buffer_row ) * channels ];

  const gfloat tre_one =
    this_channels_uno_one_bptr[       2 * pixels_per_buffer_row   * channels ];
  const gfloat tre_two =
    this_channels_uno_one_bptr[ ( 1 + 2 * pixels_per_buffer_row ) * channels ];
  const gfloat tre_thr =
    this_channels_uno_one_bptr[ ( 2 + 2 * pixels_per_buffer_row ) * channels ];
  const gfloat tre_fou =
    this_channels_uno_one_bptr[ ( 3 + 2 * pixels_per_buffer_row ) * channels ];

  const gfloat qua_one =
    this_channels_uno_one_bptr[       3 * pixels_per_buffer_row   * channels ];
  const gfloat qua_two =
    this_channels_uno_one_bptr[ ( 1 + 3 * pixels_per_buffer_row ) * channels ];
  const gfloat qua_thr =
    this_channels_uno_one_bptr[ ( 2 + 3 * pixels_per_buffer_row ) * channels ];
  const gfloat qua_fou =
    this_channels_uno_one_bptr[ ( 3 + 3 * pixels_per_buffer_row ) * channels ];

  /*
   * Computation of the YAFR correction:
   *
   * Basically, if two consecutive pixel value differences have the
   * same sign, the smallest one (in absolute value) is taken to be
   * the corresponding slope. If they don't have the same sign, the
   * corresponding slope is set to 0.
   *
   * Four such pairs (vertical and horizontal) of slopes need to be
   * computed, one pair for each of the pixels which potentially
   * overlap the unit area centered at the interpolation point.
   */
  /*
   * Beginning of the computation of the "up" horizontal slopes:
   */
  const gfloat prem__up = dos_two - dos_one;
  const gfloat deux__up = dos_thr - dos_two;
  const gfloat troi__up = dos_fou - dos_thr;
  /*
   * "down" horizontal slopes:
   */
  const gfloat prem_dow = tre_two - tre_one;
  const gfloat deux_dow = tre_thr - tre_two;
  const gfloat troi_dow = tre_fou - tre_thr;
  /*
   * "left" vertical slopes:
   */
  const gfloat prem_left = dos_two - uno_two;
  const gfloat deux_left = tre_two - dos_two;
  const gfloat troi_left = qua_two - tre_two;
  /*
   * "right" vertical slopes:
   */
  const gfloat prem_rite = dos_thr - uno_thr;
  const gfloat deux_rite = tre_thr - dos_thr;
  const gfloat troi_rite = qua_thr - tre_thr;

  /*
   * Back to "up":
   */
  const gfloat prem__up_squared = prem__up * prem__up;
  const gfloat deux__up_squared = deux__up * deux__up;
  const gfloat troi__up_squared = troi__up * troi__up;
  /*
   * Back to "down":
   */
  const gfloat prem_dow_squared = prem_dow * prem_dow;
  const gfloat deux_dow_squared = deux_dow * deux_dow;
  const gfloat troi_dow_squared = troi_dow * troi_dow;
  /*
   * Back to "left":
   */
  const gfloat prem_left_squared = prem_left * prem_left;
  const gfloat deux_left_squared = deux_left * deux_left;
  const gfloat troi_left_squared = troi_left * troi_left;
  /*
   * Back to "right":
   */
  const gfloat prem_rite_squared = prem_rite * prem_rite;
  const gfloat deux_rite_squared = deux_rite * deux_rite;
  const gfloat troi_rite_squared = troi_rite * troi_rite;

  /*
   * "up":
   */
  const gfloat prem__up_times_deux__up = prem__up * deux__up;
  const gfloat deux__up_times_troi__up = deux__up * troi__up;
  /*
   * "down":
   */
  const gfloat prem_dow_times_deux_dow = prem_dow * deux_dow;
  const gfloat deux_dow_times_troi_dow = deux_dow * troi_dow;
  /*
   * "left":
   */
  const gfloat prem_left_times_deux_left = prem_left * deux_left;
  const gfloat deux_left_times_troi_left = deux_left * troi_left;
  /*
   * "right":
   */
  const gfloat prem_rite_times_deux_rite = prem_rite * deux_rite;
  const gfloat deux_rite_times_troi_rite = deux_rite * troi_rite;

  /*
   * Branching parts of the computation of the YAFR correction (could
   * be unbranched using arithmetic branching and C99 math intrinsics,
   * although the compiler may be smart enough to remove the branching
   * on its own):
   */
  /*
   * "up":
   */
  const gfloat prem__up_vs_deux__up =
    prem__up_squared < deux__up_squared ? prem__up : deux__up;
  const gfloat deux__up_vs_troi__up =
    deux__up_squared < troi__up_squared ? deux__up : troi__up;
  /*
   * "down":
   */
  const gfloat prem_dow_vs_deux_dow =
    prem_dow_squared < deux_dow_squared ? prem_dow : deux_dow;
  const gfloat deux_dow_vs_troi_dow =
    deux_dow_squared < troi_dow_squared ? deux_dow : troi_dow;
  /*
   * "left":
   */
  const gfloat prem_left_vs_deux_left =
    prem_left_squared < deux_left_squared ? prem_left : deux_left;
  const gfloat deux_left_vs_troi_left =
    deux_left_squared < troi_left_squared ? deux_left : troi_left;
  /*
   * "right":
   */
  const gfloat prem_rite_vs_deux_rite =
    prem_rite_squared < deux_rite_squared ? prem_rite : deux_rite;
  const gfloat deux_rite_vs_troi_rite =
    deux_rite_squared < troi_rite_squared ? deux_rite : troi_rite;
  /*
   * The YAFR correction computation will resume after the computation
   * of the Catmull-Rom baseline.
   */

  /*
   * Catmull-Rom baseline contribution:
   */
  const gfloat catmull_rom =
    cardinal_uno *
    (
      cardinal_one * uno_one
      +
      cardinal_two * uno_two
      +
      cardinal_thr * uno_thr
      +
      cardinal_fou * uno_fou
    )
    +
    cardinal_dos *
    (
      cardinal_one * dos_one
      +
      cardinal_two * dos_two
      +
      cardinal_thr * dos_thr
      +
      cardinal_fou * dos_fou
    )
    +
    cardinal_tre *
    (
      cardinal_one * tre_one
      +
      cardinal_two * tre_two
      +
      cardinal_thr * tre_thr
      +
      cardinal_fou * tre_fou
    )
    +
    cardinal_qua *
    (
      cardinal_one * qua_one
      +
      cardinal_two * qua_two
      +
      cardinal_thr * qua_thr
      +
      cardinal_fou * qua_fou
    );

  /*
   * Computation of the YAFR slopes.
   */
  /*
   * "up":
   */
  const gfloat mx_left__up =
    prem__up_times_deux__up < 0.f ? 0.f : prem__up_vs_deux__up;
  const gfloat mx_rite__up =
    deux__up_times_troi__up < 0.f ? 0.f : deux__up_vs_troi__up;
  /*
   * "down":
   */
  const gfloat mx_left_dow =
    prem_dow_times_deux_dow < 0.f ? 0.f : prem_dow_vs_deux_dow;
  const gfloat mx_rite_dow =
    deux_dow_times_troi_dow < 0.f ? 0.f : deux_dow_vs_troi_dow;
  /*
   * "left":
   */
  const gfloat my_left__up =
    prem_left_times_deux_left < 0.f ? 0.f : prem_left_vs_deux_left;
  const gfloat my_left_dow =
    deux_left_times_troi_left < 0.f ? 0.f : deux_left_vs_troi_left;
  /*
   * "down":
   */
  const gfloat my_rite__up =
    prem_rite_times_deux_rite < 0.f ? 0.f : prem_rite_vs_deux_rite;
  const gfloat my_rite_dow =
    deux_rite_times_troi_rite < 0.f ? 0.f : deux_rite_vs_troi_rite;

  /*
   * Assemble the unweighted YAFR correction:
   */
  const gfloat unweighted_yafr_correction =
    left_width_times_up__height_times_rite_width
    *
    ( mx_left__up - mx_rite__up )
    +
    left_width_times_dow_height_times_rite_width
    *
    ( mx_left_dow - mx_rite_dow )
    +
    left_width_times_up__height_times_dow_height
    *
    ( my_left__up - my_left_dow )
    +
    rite_width_times_up__height_times_dow_height
    *
    ( my_rite__up - my_rite_dow );

  /*
   * Add the Catmull-Rom baseline and the weighted YAFR correction:
   */
  const gfloat newval =
    sharpening_over_two * unweighted_yafr_correction + catmull_rom;

  return newval;
}

static void
gegl_sampler_yafr_get (      GeglSampler *self,
                       const gdouble      x,
                       const gdouble      y,
                             void        *output)
{
  /*
   * Note: The computation is structured to foster software
   * pipelining.
   */

  /*
   * x is understood to increase from left to right, y, from top to
   * bottom.  Consequently, ix and iy are the indices of the pixel
   * located at or to the left, and at or above. the sampling point.
   *
   * floor is used to make sure that the transition through 0 is
   * smooth. If it is known that negative x and y will never be used,
   * cast (which truncates) could be used instead.
   */
  const gint ix = floorf (x);
  const gint iy = floorf (y);

  /*
   * Pointer to enlarged input stencil values:
   */
  const gfloat* restrict sampler_bptr = gegl_sampler_get_ptr (self, ix, iy);

  /*
   * Each (channel's) output pixel value is obtained by combining four
   * "pieces," each piece corresponding to the set of points which are
   * closest to the four pixels closest to the (x,y) position, pixel
   * positions which have coordinates and labels as follows:
   *
   *                   (ix,iy)         (ix+1,iy)
   *                   =left__up       =rite__up
   *
   *                          <- (x,y) is somewhere in the convex hull
   *
   *                   (ix,iy+1)       (ix+1,iy+1)
   *                   =left_dow       =rite_dow
   */
  /*
   * rite_width is the width of the overlaps of the unit averaging box
   * (which is centered at the position where an interpolated value is
   * desired), with the closest unit pixel areas to the right.
   *
   * left_width is the width of the overlaps of the unit averaging box
   * (which is centered at the position where an interpolated value is
   * desired), with the closest unit pixel areas to the left.
   */
  const gfloat rite_width = x - ix;
  const gfloat dow_height = y - iy;
  const gfloat left_width = 1.f - rite_width;
  const gfloat up__height = 1.f - dow_height;
  /*
   * .5*rite_width is the x-coordinate of the center of the overlap of
   * the averaging box with the left pixel areas, relative to the
   * position of the centers of the left pixels.
   *
   * -.5*left_width is the x-coordinate ... right pixel areas,
   * relative to ... the right pixels.
   *
   * .5*dow_height is the y-coordinate of the center of the overlap
   * of the averaging box with the up pixel areas, relative to the
   * position of the centers of the up pixels.
   *
   * -.5*up__height is the y-coordinate ... down pixel areas, relative
   * to ... the down pixels.
   */
  const gfloat left_width_times_rite_width = left_width * rite_width;
  const gfloat up__height_times_dow_height = up__height * dow_height;

  const gfloat cardinal_two =
    left_width_times_rite_width * ( -1.5f * rite_width + 1.f )
    + left_width;
  const gfloat cardinal_dos =
    up__height_times_dow_height * ( -1.5f * dow_height + 1.f )
    + up__height;

  const gfloat minus_half_left_width_times_rite_width =
    -.5f * left_width_times_rite_width;
  const gfloat minus_half_up__height_times_dow_height =
    -.5f * up__height_times_dow_height;

  const gfloat left_width_times_up__height_times_rite_width =
    left_width_times_rite_width * up__height;
  const gfloat left_width_times_dow_height_times_rite_width =
    left_width_times_rite_width * dow_height;
  const gfloat left_width_times_up__height_times_dow_height =
    up__height_times_dow_height * left_width;
  const gfloat rite_width_times_up__height_times_dow_height =
    up__height_times_dow_height * rite_width;

  const gfloat cardinal_one =
    minus_half_left_width_times_rite_width * left_width;
  const gfloat cardinal_uno =
    minus_half_up__height_times_dow_height * up__height;

  const gfloat cardinal_fou =
    minus_half_left_width_times_rite_width * rite_width;
  const gfloat cardinal_qua =
    minus_half_up__height_times_dow_height * dow_height;

  const gfloat cardinal_thr =
    1.f - ( minus_half_left_width_times_rite_width + cardinal_two );
  const gfloat cardinal_tre =
    1.f - ( minus_half_up__height_times_dow_height + cardinal_dos );

  /*
   * The newval array will contain the four (one per channel)
   * computed resampled values:
   */
  gfloat newval[4];

  /*
   * Set the tile pointer to the first relevant value. Since the
   * pointer initially points to dos_two, we need to rewind it one
   * tile row, then go back one additional pixel.
   */
  const gint channels = 4;
  const gint pixels_per_buffer_row = 64;
  sampler_bptr -= ( pixels_per_buffer_row + 1 ) * channels;

  newval[0] = catrom_yafr (cardinal_one,
                           cardinal_two,
                           cardinal_thr,
                           cardinal_fou,
                           cardinal_uno,
                           cardinal_dos,
                           cardinal_tre,
                           cardinal_qua,
                           left_width_times_up__height_times_rite_width,
                           left_width_times_dow_height_times_rite_width,
                           left_width_times_up__height_times_dow_height,
                           rite_width_times_up__height_times_dow_height,
                           sampler_bptr++);
  newval[1] = catrom_yafr (cardinal_one,
                           cardinal_two,
                           cardinal_thr,
                           cardinal_fou,
                           cardinal_uno,
                           cardinal_dos,
                           cardinal_tre,
                           cardinal_qua,
                           left_width_times_up__height_times_rite_width,
                           left_width_times_dow_height_times_rite_width,
                           left_width_times_up__height_times_dow_height,
                           rite_width_times_up__height_times_dow_height,
                           sampler_bptr++);
  newval[2] = catrom_yafr (cardinal_one,
                           cardinal_two,
                           cardinal_thr,
                           cardinal_fou,
                           cardinal_uno,
                           cardinal_dos,
                           cardinal_tre,
                           cardinal_qua,
                           left_width_times_up__height_times_rite_width,
                           left_width_times_dow_height_times_rite_width,
                           left_width_times_up__height_times_dow_height,
                           rite_width_times_up__height_times_dow_height,
                           sampler_bptr++);
  newval[3] = catrom_yafr (cardinal_one,
                           cardinal_two,
                           cardinal_thr,
                           cardinal_fou,
                           cardinal_uno,
                           cardinal_dos,
                           cardinal_tre,
                           cardinal_qua,
                           left_width_times_up__height_times_rite_width,
                           left_width_times_dow_height_times_rite_width,
                           left_width_times_up__height_times_dow_height,
                           rite_width_times_up__height_times_dow_height,
                           sampler_bptr);

  /*
   * Ship out newval:
   */
  babl_process (babl_fish (self->interpolate_format, self->format),
                newval,
                output,
                1);
}

static void
set_property (      GObject      *gobject,
                    guint         property_id,
              const GValue       *value,
                    GParamSpec   *pspec)
{
  G_OBJECT_WARN_INVALID_PROPERTY_ID (gobject, property_id, pspec);
}

static void
get_property (GObject    *gobject,
              guint       property_id,
              GValue     *value,
              GParamSpec *pspec)
{
  G_OBJECT_WARN_INVALID_PROPERTY_ID (gobject, property_id, pspec);
}
