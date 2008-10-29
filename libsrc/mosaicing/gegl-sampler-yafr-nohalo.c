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
 * of a linear scheme (in this version, bilinear) plus a nonlinear
 * sharpening correction the purpose of which is the straightening of
 * diagonal interfaces between flat colour areas.
 *
 * Key properties:
 *
 * YAFR (nohalo) is a parameterized method:
 *
 * The key parameter is called "sharpening." When sharpening = 0, YAFR
 * (nohalo) is standard bilinear interpolation, method which is
 * coconvex (and comonotone). More generally, YAFR (nohalo) is a
 * coconvex (and comonotone) method when sharpening <= .5, When
 * sharpening <= 1, YAFR (nohalo) is comonotone (but not coconvex),
 * and consequently does not add haloing where it is not present. For
 * the default value of sharpening, namely 4/3, YAFR (nohalo) does add
 * some haloing, so little that it is generally not noticeable;
 * however, for this sharpening value, YAFR (nohalo) correctly fixes
 * key values near a sharp diagonal interface between flat color
 * areas. In some situations (for example, photographs of text),
 * values of sharpening as large as 2 are recommended. (Negative
 * values of sharpening gives "artistic" results, as do very large
 * ones).
 *
 * YAFR (nohalo) is interpolatory:
 *
 * If asked for the value at the center of an input pixel, it will
 * return the corresponding value, unchanged.
 *
 * YAFR (nohalo) preserves local averages:
 *
 * The average of the reconstructed intensity surface over any region
 * is the same as the average of the piecewise constant surface with
 * values over pixel areas equal to the input pixel values (the
 * "nearest neighbour" surface), except for a small amount of blur at
 * the boundary of the region. More precicely: YAFR (nohalo) is a box
 * filtered exact area method.
 *
 * Main weaknesses of YAFR (nohalo):
 *
 * YAFR (nohalo) improves on the standard bilinear method only for
 * images with at least a little bit of smoothness.
 *
 * Like bilinear, YAFR (nohalo) often suffers from noticeable Mach
 * banding. When the images are reasonably smooth, however, the Mach
 * banding produced by YAFR for moderate values of the sharpening
 * parameter is much less noticeable than the one for bilinear.
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
bilinear_yafr (const gfloat c_horizo_left___up,
               const gfloat c_horizo_left_down,
               const gfloat c_horizo_rite___up,
               const gfloat c_horizo_rite_down,
               const gfloat c_vertic_left___up,
               const gfloat c_vertic_rite___up,
               const gfloat c_vertic_left_down,
               const gfloat c_vertic_rite_down,
               const gfloat c_settin_left___up,
               const gfloat c_settin_rite___up,
               const gfloat c_settin_left_down,
               const gfloat c_settin_rite_down,
               const gfloat c_rising_left___up,
               const gfloat c_rising_rite___up,
               const gfloat c_rising_left_down,
               const gfloat c_rising_rite_down,
               const gfloat left_width_times___up_hight,
               const gfloat rite_width_times___up_hight,
               const gfloat left_width_times_down_hight,
               const gfloat rite_width_times_down_hight,
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
   * The default value is sharpening = 4/3 when the scheme being
   * "straightened" is bilinear---as is the case here. This value
   * fixes key pixel values near the diagonal boundary between two
   * monochrome regions (the diagonal boundary pixel values being set
   * to the halfway colour).
   *
   * If resampling seems to add unwanted texture artifacts, push
   * sharpening toward 0. It is not generally not recommended to set
   * sharpening to a value much larger than 2.
   *
   * In order to simplify interfacing with users, the parameter which
   * should be set by the user is normalized so that user_sharpening =
   * 1 when sharpening is equal to the recommended value. Consistently
   * with the above discussion, values of user_sharpening between 0
   * and about 1.5 give good results.
   */
  const gfloat user_sharpening = 1.f;
  const gfloat sharpening = user_sharpening * ( 4.f / 3.f );

  /*
   * The input pixel values are described by the following stencil.
   * Spanish abbreviations are used to label positions from top to
   * bottom, English ones to label positions from left to right,:
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
   * to point to uno_one when bilinear_yafr is entered.
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
   * Bilinear (piecewise constant histopolant pieces) baseline
   * contribution:
   */
  const gfloat bilinear =
    left_width_times___up_hight * dos_two
    +
    rite_width_times___up_hight * dos_thr
    +
    left_width_times_down_hight * tre_two
    +
    rite_width_times_down_hight * tre_thr;

  /*
   * Computation of the YAFR correction:
   *
   * Basically, if two consecutive pixel value differences have the
   * same sign, the smallest one (in absolute value) is taken to be
   * the corresponding slope. If they don't have the same sign, the
   * corresponding slope is set to 0.
   *
   * For each of the four overlapped pixels, four slopes are thus
   * computed: horizontal, vertical, "rising" (45 degree angle) and
   * "setting" (-45 degree angle).
   */

  /*
   * Beginning of the computation of the "up" horizontal differences
   * (left to right):
   */
  const gfloat prem___up_horizo = dos_two - dos_one;
  const gfloat deux___up_horizo = dos_thr - dos_two;
  const gfloat troi___up_horizo = dos_fou - dos_thr;
  /*
   * "down" horizontal differences:
   */
  const gfloat prem_down_horizo = tre_two - tre_one;
  const gfloat deux_down_horizo = tre_thr - tre_two;
  const gfloat troi_down_horizo = tre_fou - tre_thr;
  /*
   * "left" vertical differences (top to bottom):
   */
  const gfloat prem_left_vertic = dos_two - uno_two;
  const gfloat deux_left_vertic = tre_two - dos_two;
  const gfloat troi_left_vertic = qua_two - tre_two;
  /*
   * "right" vertical differences:
   */
  const gfloat prem_rite_vertic = dos_thr - uno_thr;
  const gfloat deux_rite_vertic = tre_thr - dos_thr;
  const gfloat troi_rite_vertic = qua_thr - tre_thr;
  /*
   * "left rising" diagonal differences (bottom left to upper right):
   */
  const gfloat prem_left_rising = dos_two - tre_one;
  const gfloat deux_left_rising = uno_thr - dos_two;
  /*
   * "middle rising" diagonal differences:
   */
  const gfloat prem_midl_rising = tre_two - qua_one;
  const gfloat deux_midl_rising = dos_thr - tre_two;
  const gfloat troi_midl_rising = uno_fou - dos_thr;
  /*
   * "right rising" diagonal differences:
   */
  const gfloat prem_rite_rising = tre_thr - qua_two;
  const gfloat deux_rite_rising = dos_fou - tre_thr;
  /*
   * "left setting" diagonal differences (top left to bottom right):
   */
  const gfloat prem_left_settin = tre_two - dos_one;
  const gfloat deux_left_settin = qua_thr - tre_two;
  /*
   * "middle setting" diagonal differences:
   */
  const gfloat prem_midl_settin = dos_two - uno_one;
  const gfloat deux_midl_settin = tre_thr - dos_two;
  const gfloat troi_midl_settin = qua_fou - tre_thr;
  /*
   * "right" setting diagonal differences:
   */
  const gfloat prem_rite_settin = dos_thr - uno_two;
  const gfloat deux_rite_settin = tre_fou - dos_thr;

  /*
   * Back to "up":
   */
  const gfloat prem___up_horizo_squared = prem___up_horizo * prem___up_horizo;
  const gfloat deux___up_horizo_squared = deux___up_horizo * deux___up_horizo;
  const gfloat troi___up_horizo_squared = troi___up_horizo * troi___up_horizo;
  /*
   * Back to "down":
   */
  const gfloat prem_down_horizo_squared = prem_down_horizo * prem_down_horizo;
  const gfloat deux_down_horizo_squared = deux_down_horizo * deux_down_horizo;
  const gfloat troi_down_horizo_squared = troi_down_horizo * troi_down_horizo;
  /*
   * Back to "left":
   */
  const gfloat prem_left_vertic_squared = prem_left_vertic * prem_left_vertic;
  const gfloat deux_left_vertic_squared = deux_left_vertic * deux_left_vertic;
  const gfloat troi_left_vertic_squared = troi_left_vertic * troi_left_vertic;
  /*
   * Back to "right":
   */
  const gfloat prem_rite_vertic_squared = prem_rite_vertic * prem_rite_vertic;
  const gfloat deux_rite_vertic_squared = deux_rite_vertic * deux_rite_vertic;
  const gfloat troi_rite_vertic_squared = troi_rite_vertic * troi_rite_vertic;
  /*
   * Back to "left rising":
   */
  const gfloat prem_left_rising_squared = prem_left_rising * prem_left_rising;
  const gfloat deux_left_rising_squared = deux_left_rising * deux_left_rising;
  /*
   * Back to "middle rising":
   */
  const gfloat prem_midl_rising_squared = prem_midl_rising * prem_midl_rising;
  const gfloat deux_midl_rising_squared = deux_midl_rising * deux_midl_rising;
  const gfloat troi_midl_rising_squared = troi_midl_rising * troi_midl_rising;
  /*
   * Back to "right rising":
   */
  const gfloat prem_rite_rising_squared = prem_rite_rising * prem_rite_rising;
  const gfloat deux_rite_rising_squared = deux_rite_rising * deux_rite_rising;
  /*
   * Back to "left setting":
   */
  const gfloat prem_left_settin_squared = prem_left_settin * prem_left_settin;
  const gfloat deux_left_settin_squared = deux_left_settin * deux_left_settin;
  /*
   * Back to "middle setting":
   */
  const gfloat prem_midl_settin_squared = prem_midl_settin * prem_midl_settin;
  const gfloat deux_midl_settin_squared = deux_midl_settin * deux_midl_settin;
  const gfloat troi_midl_settin_squared = troi_midl_settin * troi_midl_settin;
  /*
   * Back to "right setting":
   */
  const gfloat prem_rite_settin_squared = prem_rite_settin * prem_rite_settin;
  const gfloat deux_rite_settin_squared = deux_rite_settin * deux_rite_settin;

  /*
   * "up":
   */
  const gfloat prem___up_horizo_times_deux___up_horizo =
    prem___up_horizo * deux___up_horizo;
  const gfloat deux___up_horizo_times_troi___up_horizo =
    deux___up_horizo * troi___up_horizo;
  /*
   * "down":
   */
  const gfloat prem_down_horizo_times_deux_down_horizo =
    prem_down_horizo * deux_down_horizo;
  const gfloat deux_down_horizo_times_troi_down_horizo =
    deux_down_horizo * troi_down_horizo;
  /*
   * "left":
   */
  const gfloat prem_left_vertic_times_deux_left_vertic =
    prem_left_vertic * deux_left_vertic;
  const gfloat deux_left_vertic_times_troi_left_vertic =
    deux_left_vertic * troi_left_vertic;
  /*
   * "right":
   */
  const gfloat prem_rite_vertic_times_deux_rite_vertic =
    prem_rite_vertic * deux_rite_vertic;
  const gfloat deux_rite_vertic_times_troi_rite_vertic =
    deux_rite_vertic * troi_rite_vertic;
  /*
   * "left rising":
   */
  const gfloat prem_left_rising_times_deux_left_rising =
    prem_left_rising * deux_left_rising;
  /*
   * "middle rising":
   */
  const gfloat prem_midl_rising_times_deux_midl_rising =
    prem_midl_rising * deux_midl_rising;
  const gfloat deux_midl_rising_times_troi_midl_rising =
    deux_midl_rising * troi_midl_rising;
  /*
   * "right rising":
   */
  const gfloat prem_rite_rising_times_deux_rite_rising =
    prem_rite_rising * deux_rite_rising;
  /*
   * "left setting":
   */
  const gfloat prem_left_settin_times_deux_left_settin =
    prem_left_settin * deux_left_settin;
  /*
   * "middle setting":
   */
  const gfloat prem_midl_settin_times_deux_midl_settin =
    prem_midl_settin * deux_midl_settin;
  const gfloat deux_midl_settin_times_troi_midl_settin =
    deux_midl_settin * troi_midl_settin;
  /*
   * "right setting":
   */
  const gfloat prem_rite_settin_times_deux_rite_settin =
    prem_rite_settin * deux_rite_settin;
  
  /*
   * Branching parts of the computation of the YAFR correction (could
   * be unbranched using arithmetic branching and C99 math intrinsics,
   * although the compiler may be smart enough to remove the branching
   * on its own):
   */
  /*
   * "up":
   */
  const gfloat prem___up_horizo_vs_deux___up_horizo =
    prem___up_horizo_squared < deux___up_horizo_squared
    ? prem___up_horizo
    : deux___up_horizo;
  const gfloat deux___up_horizo_vs_troi___up_horizo =
    deux___up_horizo_squared < troi___up_horizo_squared
    ? deux___up_horizo
    : troi___up_horizo;
  /*
   * "down":
   */
  const gfloat prem_down_horizo_vs_deux_down_horizo =
    prem_down_horizo_squared < deux_down_horizo_squared
    ? prem_down_horizo
    : deux_down_horizo;
  const gfloat deux_down_horizo_vs_troi_down_horizo =
    deux_down_horizo_squared < troi_down_horizo_squared
    ? deux_down_horizo
    : troi_down_horizo;
  /*
   * "left":
   */
  const gfloat prem_left_vertic_vs_deux_left_vertic =
    prem_left_vertic_squared < deux_left_vertic_squared
    ? prem_left_vertic
    : deux_left_vertic;
  const gfloat deux_left_vertic_vs_troi_left_vertic =
    deux_left_vertic_squared < troi_left_vertic_squared
    ? deux_left_vertic
    : troi_left_vertic;
  /*
   * "right":
   */
  const gfloat prem_rite_vertic_vs_deux_rite_vertic =
    prem_rite_vertic_squared < deux_rite_vertic_squared
    ? prem_rite_vertic
    : deux_rite_vertic;
  const gfloat deux_rite_vertic_vs_troi_rite_vertic =
    deux_rite_vertic_squared < troi_rite_vertic_squared
    ? deux_rite_vertic
    : troi_rite_vertic;
  /*
   * "left rising":
   */
  const gfloat prem_left_rising_vs_deux_left_rising =
    prem_left_rising_squared < deux_left_rising_squared
    ? prem_left_rising
    : deux_left_rising;
  /*
   * "middle rising":
   */
  const gfloat prem_midl_rising_vs_deux_midl_rising =
    prem_midl_rising_squared < deux_midl_rising_squared
    ? prem_midl_rising
    : deux_midl_rising;
  const gfloat deux_midl_rising_vs_troi_midl_rising =
    deux_midl_rising_squared < troi_midl_rising_squared
    ? deux_midl_rising
    : troi_midl_rising;
  /*
   * "right rising":
   */
  const gfloat prem_rite_rising_vs_deux_rite_rising =
    prem_rite_rising_squared < deux_rite_rising_squared
    ? prem_rite_rising
    : deux_rite_rising;
  /*
   * "left setting":
   */
  const gfloat prem_left_settin_vs_deux_left_settin =
    prem_left_settin_squared < deux_left_settin_squared
    ? prem_left_settin
    : deux_left_settin;
  /*
   * "middle setting":
   */
  const gfloat prem_midl_settin_vs_deux_midl_settin =
    prem_midl_settin_squared < deux_midl_settin_squared
    ? prem_midl_settin
    : deux_midl_settin;
  const gfloat deux_midl_settin_vs_troi_midl_settin =
    deux_midl_settin_squared < troi_midl_settin_squared
    ? deux_midl_settin
    : troi_midl_settin;
  /*
   * "right setting":
   */
  const gfloat prem_rite_settin_vs_deux_rite_settin =
    prem_rite_settin_squared < deux_rite_settin_squared
    ? prem_rite_settin
    : deux_rite_settin;

  /*
   * Computation of the YAFR slopes.
   */
  /*
   * "up":
   */
  const gfloat slope_horizo_left___up =
    prem___up_horizo_times_deux___up_horizo < 0.f
    ? 0.f
    : prem___up_horizo_vs_deux___up_horizo;
  const gfloat slope_horizo_rite___up =
    deux___up_horizo_times_troi___up_horizo < 0.f
    ? 0.f
    : deux___up_horizo_vs_troi___up_horizo;
  /*
   * "down":
   */
  const gfloat slope_horizo_left_down =
    prem_down_horizo_times_deux_down_horizo < 0.f
    ? 0.f
    : prem_down_horizo_vs_deux_down_horizo;
  const gfloat slope_horizo_rite_down =
    deux_down_horizo_times_troi_down_horizo < 0.f
    ? 0.f
    : deux_down_horizo_vs_troi_down_horizo;
  /*
   * "left":
   */
  const gfloat slope_vertic_left___up =
    prem_left_vertic_times_deux_left_vertic < 0.f
    ? 0.f
    : prem_left_vertic_vs_deux_left_vertic;
  const gfloat slope_vertic_left_down =
    deux_left_vertic_times_troi_left_vertic < 0.f
    ? 0.f
    : deux_left_vertic_vs_troi_left_vertic;
  /*
   * "down":
   */
  const gfloat slope_vertic_rite___up =
    prem_rite_vertic_times_deux_rite_vertic < 0.f
    ? 0.f
    : prem_rite_vertic_vs_deux_rite_vertic;
  const gfloat slope_vertic_rite_down =
    deux_rite_vertic_times_troi_rite_vertic < 0.f
    ? 0.f
    : deux_rite_vertic_vs_troi_rite_vertic;
  /*
   * "left rising":
   */
  const gfloat slope_rising_left___up =
    prem_left_rising_times_deux_left_rising < 0.f 
    ? 0.f
    : prem_left_rising_vs_deux_left_rising;
  /*
   * "middle rising":
   */
  const gfloat slope_rising_left_down =
    prem_midl_rising_times_deux_midl_rising < 0.f
    ? 0.f
    : prem_midl_rising_vs_deux_midl_rising;
  const gfloat slope_rising_rite___up =
    deux_midl_rising_times_troi_midl_rising < 0.f
    ? 0.f
    : deux_midl_rising_vs_troi_midl_rising;
  /*
   * "right rising":
   */
  const gfloat slope_rising_rite_down =
    prem_rite_rising_times_deux_rite_rising < 0.f 
    ? 0.f
    : prem_rite_rising_vs_deux_rite_rising;
  /*
   * "left setting":
   */
  const gfloat slope_settin_left_down =
    prem_left_settin_times_deux_left_settin < 0.f 
    ? 0.f
    : prem_left_settin_vs_deux_left_settin;
  /*
   * "middle setting":
   */
  const gfloat slope_settin_left___up =
    prem_midl_settin_times_deux_midl_settin < 0.f
    ? 0.f
    : prem_midl_settin_vs_deux_midl_settin;
  const gfloat slope_settin_rite_down =
    deux_midl_settin_times_troi_midl_settin < 0.f
    ? 0.f
    : deux_midl_settin_vs_troi_midl_settin;
  /*
   * "right setting":
   */
  const gfloat slope_settin_rite___up =
    prem_rite_settin_times_deux_rite_settin < 0.f 
    ? 0.f
    : prem_rite_settin_vs_deux_rite_settin;

  /*
   * Assemble the unweighted YAFR correction:
   */
  const gfloat unweighted_yafr_correction =
    c_horizo_left___up * slope_horizo_left___up
    +
    c_horizo_left_down * slope_horizo_left_down
    +
    c_horizo_rite___up * slope_horizo_rite___up
    +
    c_horizo_rite_down * slope_horizo_rite_down
    +
    c_vertic_left___up * slope_vertic_left___up
    +
    c_vertic_rite___up * slope_vertic_rite___up
    +
    c_vertic_left_down * slope_vertic_left_down
    +
    c_vertic_rite_down * slope_vertic_rite_down
    +
    c_settin_left___up * slope_settin_left___up
    +
    c_settin_rite___up * slope_settin_rite___up
    +
    c_settin_left_down * slope_settin_left_down
    +
    c_settin_rite_down * slope_settin_rite_down
    +
    c_rising_left___up * slope_rising_left___up
    +
    c_rising_rite___up * slope_rising_rite___up
    +
    c_rising_left_down * slope_rising_left_down
    +
    c_rising_rite_down * slope_rising_rite_down;

  /*
   * Add the bilinear baseline and the weighted YAFR correction:
   */
  const gfloat newval = sharpening * unweighted_yafr_correction + bilinear;

  return newval;
}

static void
gegl_sampler_yafr_get (      GeglSampler *self,
                       const gdouble      x,
                       const gdouble      y,
                             void        *output)
{
  /*
   * x is understood to increase from left to right, y, from top to
   * bottom.  Consequently, ix and iy are the indices of the pixel
   * located at or to the left, and at or above. the sampling point.
   *
   * floor is used to make sure that the transition through 0 is
   * smooth. If it is known that negative x and y will never be used,
   * simple integer casting (which truncates) could be used instead.
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
   *                   =left___up       =rite___up
   *
   *                          <- (x,y) is somewhere in the convex hull
   *
   *                   (ix,iy+1)       (ix+1,iy+1)
   *                   =left_down       =rite_down
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
  const gfloat down_hight = y - iy;
  const gfloat left_width = 1.f - rite_width;
  const gfloat up___hight = 1.f - down_hight;

  const gfloat rite_width_minus_half = rite_width - .5f;
  const gfloat down_hight_minus_half = down_hight - .5f;
  const gfloat left_width_minus_half = left_width - .5f;
  const gfloat up___hight_minus_half = up___hight - .5f;

  const gfloat rite_rite_overlap =
    rite_width_minus_half < 0.f ? 0.f : rite_width_minus_half;
  const gfloat down_down_overlap =
    down_hight_minus_half < 0.f ? 0.f : down_hight_minus_half;
  /*
   * Note that if rite_width_minus_half is (non)negative,
   * left_width_minus_half is (non)positive. Consequently, the
   * following two branching tests could be merged with the above two.
   * The duplications are kept in the hope that the compiler translate
   * them into "max" machine instructions:
   */
  const gfloat left_left_overlap =
    left_width_minus_half < 0.f ? 0.f : left_width_minus_half;
  const gfloat up_____up_overlap =
    up___hight_minus_half < 0.f ? 0.f : up___hight_minus_half;
  /*
   * The computation of quantities useful for the YAFR correction
   * resumes after the computation of the needed bilinear baseline
   * weights.
   */

  /*
   * Bilinear (the plain vanilla standard bilinear) weights:
   */
  const gfloat left_width_times___up_hight = left_width * up___hight;
  const gfloat rite_width_times___up_hight = rite_width * up___hight;
  const gfloat left_width_times_down_hight = left_width * down_hight;
  const gfloat rite_width_times_down_hight = rite_width * down_hight;

  /*
   * Back to quantities useful for the YAFR correction:
   */
  /*
   * Remaining overlap lengths:
   */
  const gfloat rite_left_overlap = left_width - left_left_overlap;
  const gfloat left_rite_overlap = rite_width - rite_rite_overlap;
  const gfloat down___up_overlap = up___hight - up_____up_overlap;
  const gfloat up___down_overlap = down_hight - down_down_overlap;

  const gfloat one_minus_left_left_overlap = 1.f - left_left_overlap;
  const gfloat one_minus_rite_rite_overlap = 1.f - rite_rite_overlap;
  const gfloat one_minus_up_____up_overlap = 1.f - up_____up_overlap;
  const gfloat one_minus_down_down_overlap = 1.f - down_down_overlap;
  const gfloat one_minus_rite_left_overlap = 1.f - rite_left_overlap;
  const gfloat one_minus_left_rite_overlap = 1.f - left_rite_overlap;
  const gfloat one_minus_down___up_overlap = 1.f - down___up_overlap;
  const gfloat one_minus_up___down_overlap = 1.f - up___down_overlap;

  /*
   * Recyclable products:
   */
  const gfloat left_left_overlap_times_left_left_overlap =
    left_left_overlap * left_left_overlap;
  const gfloat rite_rite_overlap_times_rite_rite_overlap =
    rite_rite_overlap * rite_rite_overlap;
  const gfloat up_____up_overlap_times_up_____up_overlap =
    up_____up_overlap * up_____up_overlap;
  const gfloat down_down_overlap_times_down_down_overlap =
    down_down_overlap * down_down_overlap;

  const gfloat rite_left_overlap_times_one_minus_rite_left_overlap =
    rite_left_overlap * one_minus_rite_left_overlap;
  const gfloat left_rite_overlap_times_one_minus_left_rite_overlap =
    left_rite_overlap * one_minus_left_rite_overlap;
  const gfloat down___up_overlap_times_one_minus_down___up_overlap =
    down___up_overlap * one_minus_down___up_overlap;
  const gfloat up___down_overlap_times_one_minus_up___down_overlap =
    up___down_overlap * one_minus_up___down_overlap;

  /*
   * "Cardinal" contributions of the various YAFR slopes. Each of the
   * (up to) four contributing pixels contributes four slopes: one
   * horizontal slope, one vertical slope, and two diagonal slopes
   * (one "rising", and one "setting"). Consequently, sixteen
   * "cardinal" basis contributions need to be computed.
   */
  /*
   * "Cardinal" contributions of the horizontal and vertical slopes:
   */
  /*
   * Common factors:
   */
  const gfloat horizo___up =
    up_____up_overlap           /* height of the overlap     */
    *
    one_minus_up_____up_overlap /* bilinear coefficient      */
    +                           /* second interpolated value */
    down___up_overlap           /* height of the overlap     */
    *
    down___up_overlap;          /* bilinear coefficient      */
  const gfloat horizo_down =
    down_down_overlap           /* height of the overlap     */
    *
    one_minus_down_down_overlap /* bilinear coefficient      */
    +                           /* second interpolated value */
    up___down_overlap           /* height of the overlap     */
    *
    up___down_overlap;          /* bilinear coefficient      */
  const gfloat horizo_left =
    rite_left_overlap_times_one_minus_rite_left_overlap
    -
    left_left_overlap_times_left_left_overlap;
  const gfloat horizo_rite =
    rite_rite_overlap_times_rite_rite_overlap
    -
    left_rite_overlap_times_one_minus_left_rite_overlap;
  const gfloat vertic_left =
    left_left_overlap
    *
    one_minus_left_left_overlap
    +
    rite_left_overlap
    *
    rite_left_overlap;
  const gfloat vertic_rite =
    rite_rite_overlap
    *
    one_minus_rite_rite_overlap
    +
    left_rite_overlap
    *
    left_rite_overlap;
  const gfloat vertic___up =
    down___up_overlap_times_one_minus_down___up_overlap
    -
    up_____up_overlap_times_up_____up_overlap;
  const gfloat vertic_down =
    down_down_overlap_times_down_down_overlap
    -
    up___down_overlap_times_one_minus_up___down_overlap;
  /*
   * "Cardinal" contribution of the left horizontal slopes:
   */
  const gfloat c_horizo_left___up = horizo_left * horizo___up;
  const gfloat c_horizo_left_down = horizo_left * horizo_down;
  /*
   * "Cardinal" contribution of the right horizontal slopes:
   */
  const gfloat c_horizo_rite___up = horizo_rite * horizo___up;
  const gfloat c_horizo_rite_down = horizo_rite * horizo_down;
  /*
   * "Cardinal" contribution of the up vertical slopes:
   */
  const gfloat c_vertic_left___up = vertic___up * vertic_left;
  const gfloat c_vertic_rite___up = vertic___up * vertic_rite;
  /*
   * "Cardinal" contribution of the down vertical slopes:
   */
  const gfloat c_vertic_left_down = vertic_down * vertic_left;
  const gfloat c_vertic_rite_down = vertic_down * vertic_rite;

  /*
   * "Cardinal" contributions of the diagonal slopes:
   */
  const gfloat c_settin_left___up =
    rite_left_overlap_times_one_minus_rite_left_overlap
    *
    down___up_overlap_times_one_minus_down___up_overlap
    -
    left_left_overlap_times_left_left_overlap
    *
    up_____up_overlap_times_up_____up_overlap;
  const gfloat c_settin_rite___up =
    rite_rite_overlap_times_rite_rite_overlap
    *
    down___up_overlap_times_one_minus_down___up_overlap
    -
    left_rite_overlap_times_one_minus_left_rite_overlap
    *
    up_____up_overlap_times_up_____up_overlap;
  const gfloat c_settin_left_down =
    rite_left_overlap_times_one_minus_rite_left_overlap
    *
    down_down_overlap_times_down_down_overlap
    -
    left_left_overlap_times_left_left_overlap
    *
    up___down_overlap_times_one_minus_up___down_overlap;
  const gfloat c_settin_rite_down =
    rite_rite_overlap_times_rite_rite_overlap
    *
    down_down_overlap_times_down_down_overlap
    -
    left_rite_overlap_times_one_minus_left_rite_overlap
    *
    up___down_overlap_times_one_minus_up___down_overlap;
  const gfloat c_rising_left___up =
    rite_left_overlap_times_one_minus_rite_left_overlap
    *
    up_____up_overlap_times_up_____up_overlap
    -
    left_left_overlap_times_left_left_overlap
    *
    down___up_overlap_times_one_minus_down___up_overlap;
  const gfloat c_rising_rite___up =
    rite_rite_overlap_times_rite_rite_overlap
    *
    up_____up_overlap_times_up_____up_overlap
    -
    left_rite_overlap_times_one_minus_left_rite_overlap
    *
    down___up_overlap_times_one_minus_down___up_overlap;
  const gfloat c_rising_left_down =
    rite_left_overlap_times_one_minus_rite_left_overlap
    *
    up___down_overlap_times_one_minus_up___down_overlap
    -
    left_left_overlap_times_left_left_overlap
    *
    down_down_overlap_times_down_down_overlap;
  const gfloat c_rising_rite_down =
    rite_rite_overlap_times_rite_rite_overlap
    *
    up___down_overlap_times_one_minus_up___down_overlap
    -
    left_rite_overlap_times_one_minus_left_rite_overlap
    *
    down_down_overlap_times_down_down_overlap;

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

  newval[0] = bilinear_yafr (c_horizo_left___up,
                             c_horizo_left_down,
                             c_horizo_rite___up,
                             c_horizo_rite_down,
                             c_vertic_left___up,
                             c_vertic_rite___up,
                             c_vertic_left_down,
                             c_vertic_rite_down,
                             c_settin_left___up,
                             c_settin_rite___up,
                             c_settin_left_down,
                             c_settin_rite_down,
                             c_rising_left___up,
                             c_rising_rite___up,
                             c_rising_left_down,
                             c_rising_rite_down,
                             left_width_times___up_hight,
                             rite_width_times___up_hight,
                             left_width_times_down_hight,
                             rite_width_times_down_hight,
                             sampler_bptr++);
  newval[1] = bilinear_yafr (c_horizo_left___up,
                             c_horizo_left_down,
                             c_horizo_rite___up,
                             c_horizo_rite_down,
                             c_vertic_left___up,
                             c_vertic_rite___up,
                             c_vertic_left_down,
                             c_vertic_rite_down,
                             c_settin_left___up,
                             c_settin_rite___up,
                             c_settin_left_down,
                             c_settin_rite_down,
                             c_rising_left___up,
                             c_rising_rite___up,
                             c_rising_left_down,
                             c_rising_rite_down,
                             left_width_times___up_hight,
                             rite_width_times___up_hight,
                             left_width_times_down_hight,
                             rite_width_times_down_hight,
                             sampler_bptr++);
  newval[2] = bilinear_yafr (c_horizo_left___up,
                             c_horizo_left_down,
                             c_horizo_rite___up,
                             c_horizo_rite_down,
                             c_vertic_left___up,
                             c_vertic_rite___up,
                             c_vertic_left_down,
                             c_vertic_rite_down,
                             c_settin_left___up,
                             c_settin_rite___up,
                             c_settin_left_down,
                             c_settin_rite_down,
                             c_rising_left___up,
                             c_rising_rite___up,
                             c_rising_left_down,
                             c_rising_rite_down,
                             left_width_times___up_hight,
                             rite_width_times___up_hight,
                             left_width_times_down_hight,
                             rite_width_times_down_hight,
                             sampler_bptr++);
  newval[3] = bilinear_yafr (c_horizo_left___up,
                             c_horizo_left_down,
                             c_horizo_rite___up,
                             c_horizo_rite_down,
                             c_vertic_left___up,
                             c_vertic_rite___up,
                             c_vertic_left_down,
                             c_vertic_rite_down,
                             c_settin_left___up,
                             c_settin_rite___up,
                             c_settin_left_down,
                             c_settin_rite_down,
                             c_rising_left___up,
                             c_rising_rite___up,
                             c_rising_left_down,
                             c_rising_rite_down,
                             left_width_times___up_hight,
                             rite_width_times___up_hight,
                             left_width_times_down_hight,
                             rite_width_times_down_hight,
                             sampler_bptr);

  /*
   * Ship out the newval (computed new pixel values):
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
