/* yafrsmooth ... yafr-smooth as a vips interpolate class
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

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* "fast" floor() ... on my laptop, anyway.
 */
#define FLOOR( V ) ((V) >= 0 ? (int)(V) : (int)((V) - 1))

static VipsInterpolateClass *vips_interpolate_yafrsmooth_parent_class = NULL;

/* Copy-paste of gegl-sampler-yafrsmooth-smooth.c starts
 */

/*
 * 2008 (c) Nicolas Robidoux (developer of Yet Another Fast
 * Resampler).
 *
 * Acknowledgement: N. Robidoux's research on YAFRSMOOTH funded in part by
 * an NSERC (National Science and Engineering Research Council of
 * Canada) Discovery Grant.
 */

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

/*
 * YAFRSMOOTH = Yet Another Fast Resampler
 *
 * Yet Another Fast Resampler is a nonlinear resampler which consists
 * of a linear scheme (in this version, Catmull-Rom) plus a nonlinear
 * sharpening correction the purpose of which is the straightening of
 * diagonal interfaces between flat colour areas.
 *
 * Key properties:
 *
 * YAFRSMOOTH (smooth) is interpolatory:
 *
 * If asked for the value at the center of an input pixel, it will
 * return the corresponding value, unchanged.
 *
 * YAFRSMOOTH (smooth) preserves local averages:
 *
 * The average of the reconstructed intensity surface over any region
 * is the same as the average of the piecewise constant surface with
 * values over pixel areas equal to the input pixel values (the
 * "nearest neighbour" surface), except for a small amount of blur at
 * the boundary of the region. More precicely: YAFRSMOOTH (smooth) is a box
 * filtered exact area method.
 *
 * Main weaknesses of YAFRSMOOTH (smooth):
 *
 * Weakness 1: YAFRSMOOTH (smooth) improves on Catmull-Rom only for images
 * with at least a little bit of smoothness.
 *
 * Weakness 2: Catmull-Rom introduces a lot of haloing. YAFRSMOOTH (smooth)
 * is based on Catmull-Rom, and consequently it too introduces a lot
 * of haloing.
 *
 * More details regarding Weakness 1: 
 *
 * If a portion of the image is such that every pixel has immediate
 * neighbours in the horizontal and vertical directions which have
 * exactly the same pixel value, then YAFRSMOOTH (smooth) boils down to
 * Catmull-Rom, and the computation of the correction is a waste.
 * Extreme case: If all the pixels are either pure black or pure white
 * in some region, as in some text images (more generally, if the
 * region is "bichromatic"), then the YAFRSMOOTH (smooth) correction is 0 in
 * the interior of the bichromatic region.
 */

/* Pointers to write to / read from, how much to add to move right a pixel,
 * how much to add to move down a line.
 */

static inline void
catrom_yafrsmooth (float* restrict out, const float* restrict in, 
	     const int channels, 
	     const int pixels_per_buffer_row,
	     const float sharpening,

	     const float cardinal_one,
             const float cardinal_two,
             const float cardinal_thr,
             const float cardinal_fou,
             const float cardinal_uno,
             const float cardinal_dos,
             const float cardinal_tre,
             const float cardinal_qua,
             const float left_width_times_up__height_times_rite_width,
             const float left_width_times_dow_height_times_rite_width,
             const float left_width_times_up__height_times_dow_height,
             const float rite_width_times_up__height_times_dow_height)
{

	/* "sharpening" is a continuous method parameter which is
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

  const float sharpening_over_two = sharpening * 0.453125f;

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
   * consideration. The in pointer is assumed
   * to point to uno_one when catrom_yafrsmooth is entered.
   */
  const float uno_one = in[   0                                          ];
  const float uno_two = in[                                     channels ];
  const float uno_thr = in[   2                               * channels ];
  const float uno_fou = in[   3                               * channels ];

  const float dos_one = in[           pixels_per_buffer_row   * channels ];
  const float dos_two = in[ ( 1 +     pixels_per_buffer_row ) * channels ];
  const float dos_thr = in[ ( 2 +     pixels_per_buffer_row ) * channels ];
  const float dos_fou = in[ ( 3 +     pixels_per_buffer_row ) * channels ];

  const float tre_one = in[       2 * pixels_per_buffer_row   * channels ];
  const float tre_two = in[ ( 1 + 2 * pixels_per_buffer_row ) * channels ];
  const float tre_thr = in[ ( 2 + 2 * pixels_per_buffer_row ) * channels ];
  const float tre_fou = in[ ( 3 + 2 * pixels_per_buffer_row ) * channels ];

  const float qua_one = in[       3 * pixels_per_buffer_row   * channels ];
  const float qua_two = in[ ( 1 + 3 * pixels_per_buffer_row ) * channels ];
  const float qua_thr = in[ ( 2 + 3 * pixels_per_buffer_row ) * channels ];
  const float qua_fou = in[ ( 3 + 3 * pixels_per_buffer_row ) * channels ];

  /*
   * Computation of the YAFRSMOOTH correction:
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
  const float prem__up = dos_two - dos_one;
  const float deux__up = dos_thr - dos_two;
  const float troi__up = dos_fou - dos_thr;
  /*
   * "down" horizontal slopes:
   */
  const float prem_dow = tre_two - tre_one;
  const float deux_dow = tre_thr - tre_two;
  const float troi_dow = tre_fou - tre_thr;
  /*
   * "left" vertical slopes:
   */
  const float prem_left = dos_two - uno_two;
  const float deux_left = tre_two - dos_two;
  const float troi_left = qua_two - tre_two;
  /*
   * "right" vertical slopes:
   */
  const float prem_rite = dos_thr - uno_thr;
  const float deux_rite = tre_thr - dos_thr;
  const float troi_rite = qua_thr - tre_thr;

  /*
   * Back to "up":
   */
  const float prem__up_squared = prem__up * prem__up;
  const float deux__up_squared = deux__up * deux__up;
  const float troi__up_squared = troi__up * troi__up;
  /*
   * Back to "down":
   */
  const float prem_dow_squared = prem_dow * prem_dow;
  const float deux_dow_squared = deux_dow * deux_dow;
  const float troi_dow_squared = troi_dow * troi_dow;
  /*
   * Back to "left":
   */
  const float prem_left_squared = prem_left * prem_left;
  const float deux_left_squared = deux_left * deux_left;
  const float troi_left_squared = troi_left * troi_left;
  /*
   * Back to "right":
   */
  const float prem_rite_squared = prem_rite * prem_rite;
  const float deux_rite_squared = deux_rite * deux_rite;
  const float troi_rite_squared = troi_rite * troi_rite;

  /*
   * "up":
   */
  const float prem__up_times_deux__up = prem__up * deux__up;
  const float deux__up_times_troi__up = deux__up * troi__up;
  /*
   * "down":
   */
  const float prem_dow_times_deux_dow = prem_dow * deux_dow;
  const float deux_dow_times_troi_dow = deux_dow * troi_dow;
  /*
   * "left":
   */
  const float prem_left_times_deux_left = prem_left * deux_left;
  const float deux_left_times_troi_left = deux_left * troi_left;
  /*
   * "right":
   */
  const float prem_rite_times_deux_rite = prem_rite * deux_rite;
  const float deux_rite_times_troi_rite = deux_rite * troi_rite;

  /*
   * Branching parts of the computation of the YAFRSMOOTH correction (could
   * be unbranched using arithmetic branching and C99 math intrinsics,
   * although the compiler may be smart enough to remove the branching
   * on its own):
   */
  /*
   * "up":
   */
  const float prem__up_vs_deux__up =
    prem__up_squared < deux__up_squared ? prem__up : deux__up;
  const float deux__up_vs_troi__up =
    deux__up_squared < troi__up_squared ? deux__up : troi__up;
  /*
   * "down":
   */
  const float prem_dow_vs_deux_dow =
    prem_dow_squared < deux_dow_squared ? prem_dow : deux_dow;
  const float deux_dow_vs_troi_dow =
    deux_dow_squared < troi_dow_squared ? deux_dow : troi_dow;
  /*
   * "left":
   */
  const float prem_left_vs_deux_left =
    prem_left_squared < deux_left_squared ? prem_left : deux_left;
  const float deux_left_vs_troi_left =
    deux_left_squared < troi_left_squared ? deux_left : troi_left;
  /*
   * "right":
   */
  const float prem_rite_vs_deux_rite =
    prem_rite_squared < deux_rite_squared ? prem_rite : deux_rite;
  const float deux_rite_vs_troi_rite =
    deux_rite_squared < troi_rite_squared ? deux_rite : troi_rite;
  /*
   * The YAFRSMOOTH correction computation will resume after the computation
   * of the Catmull-Rom baseline.
   */

  /*
   * Catmull-Rom baseline contribution:
   */
  const float catmull_rom =
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
   * Computation of the YAFRSMOOTH slopes.
   */
  /*
   * "up":
   */
  const float mx_left__up =
    prem__up_times_deux__up < 0.f ? 0.f : prem__up_vs_deux__up;
  const float mx_rite__up =
    deux__up_times_troi__up < 0.f ? 0.f : deux__up_vs_troi__up;
  /*
   * "down":
   */
  const float mx_left_dow =
    prem_dow_times_deux_dow < 0.f ? 0.f : prem_dow_vs_deux_dow;
  const float mx_rite_dow =
    deux_dow_times_troi_dow < 0.f ? 0.f : deux_dow_vs_troi_dow;
  /*
   * "left":
   */
  const float my_left__up =
    prem_left_times_deux_left < 0.f ? 0.f : prem_left_vs_deux_left;
  const float my_left_dow =
    deux_left_times_troi_left < 0.f ? 0.f : deux_left_vs_troi_left;
  /*
   * "right":
   */
  const float my_rite__up =
    prem_rite_times_deux_rite < 0.f ? 0.f : prem_rite_vs_deux_rite;
  const float my_rite_dow =
    deux_rite_times_troi_rite < 0.f ? 0.f : deux_rite_vs_troi_rite;

  /*
   * Assemble the unweighted YAFRSMOOTH correction:
   */
  const float unweighted_yafrsmooth_correction =
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
   * Add the Catmull-Rom baseline and the weighted YAFRSMOOTH correction:
   */
  const float newval =
    sharpening_over_two * unweighted_yafrsmooth_correction + catmull_rom;

  *out = newval;
}

static void
vips_interpolate_yafrsmooth_interpolate( VipsInterpolate *interpolate, 
	REGION *out, REGION *in, 
	int out_x, int out_y, double x, double y )
{
	VipsInterpolateYafrsmooth *yafrsmooth = 
		VIPS_INTERPOLATE_YAFRSMOOTH( interpolate );

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
  const gint ix = FLOOR (x);
  const gint iy = FLOOR (y);

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
  const float rite_width = x - ix;
  const float dow_height = y - iy;
  const float left_width = 1.f - rite_width;
  const float up__height = 1.f - dow_height;
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
  const float left_width_times_rite_width = left_width * rite_width;
  const float up__height_times_dow_height = up__height * dow_height;

  const float cardinal_two =
    left_width_times_rite_width * ( -1.5f * rite_width + 1.f )
    + left_width;
  const float cardinal_dos =
    up__height_times_dow_height * ( -1.5f * dow_height + 1.f )
    + up__height;

  const float minus_half_left_width_times_rite_width =
    -.5f * left_width_times_rite_width;
  const float minus_half_up__height_times_dow_height =
    -.5f * up__height_times_dow_height;

  const float left_width_times_up__height_times_rite_width =
    left_width_times_rite_width * up__height;
  const float left_width_times_dow_height_times_rite_width =
    left_width_times_rite_width * dow_height;
  const float left_width_times_up__height_times_dow_height =
    up__height_times_dow_height * left_width;
  const float rite_width_times_up__height_times_dow_height =
    up__height_times_dow_height * rite_width;

  const float cardinal_one =
    minus_half_left_width_times_rite_width * left_width;
  const float cardinal_uno =
    minus_half_up__height_times_dow_height * up__height;

  const float cardinal_fou =
    minus_half_left_width_times_rite_width * rite_width;
  const float cardinal_qua =
    minus_half_up__height_times_dow_height * dow_height;

  const float cardinal_thr =
    1.f - ( minus_half_left_width_times_rite_width + cardinal_two );
  const float cardinal_tre =
    1.f - ( minus_half_up__height_times_dow_height + cardinal_dos );

  /*
   * Set the tile pointer to the first relevant value. Since the
   * pointer initially points to dos_two, we need to rewind it one
   * tile row, then go back one additional pixel.
   */
  const PEL *p = (PEL *) IM_REGION_ADDR( in, ix - 1, iy - 1 ); 

	/* Pel size and line size.
	 */
	const int channels = in->im->Bands; 
	const int pixels_per_buffer_row = 
		IM_REGION_LSKIP( in ) / (sizeof( float ) * channels); 

	/* Where we write the result.
	 */
	PEL *q = (PEL *) IM_REGION_ADDR( out, out_x, out_y ); 
	int z;

	for( z = 0; z < channels; z++ ) 
		catrom_yafrsmooth ((float *) q + z, (float *) p + z,
			   channels, pixels_per_buffer_row,
			   yafrsmooth->sharpening,
			   cardinal_one,
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
                           rite_width_times_up__height_times_dow_height);
}

static void
vips_interpolate_yafrsmooth_class_init( VipsInterpolateYafrsmoothClass *class )
{
	VipsInterpolateClass *interpolate_class = 
		VIPS_INTERPOLATE_CLASS( class );

	vips_interpolate_yafrsmooth_parent_class = 
		g_type_class_peek_parent( class );

	interpolate_class->interpolate = 
		vips_interpolate_yafrsmooth_interpolate;
	interpolate_class->window_size = 4;
}

static void
vips_interpolate_yafrsmooth_init( VipsInterpolateYafrsmooth *yafrsmooth )
{
#ifdef DEBUG
	printf( "vips_interpolate_yafrsmooth_init: " );
	vips_object_print( VIPS_OBJECT( yafrsmooth ) );
#endif /*DEBUG*/

	yafrsmooth->sharpening = 1.0;
}

GType
vips_interpolate_yafrsmooth_get_type( void )
{
	static GType type = 0;

	if( !type ) {
		static const GTypeInfo info = {
			sizeof( VipsInterpolateYafrsmoothClass ),
			NULL,           /* base_init */
			NULL,           /* base_finalize */
			(GClassInitFunc) vips_interpolate_yafrsmooth_class_init,
			NULL,           /* class_finalize */
			NULL,           /* class_data */
			sizeof( VipsInterpolateYafrsmooth ),
			32,             /* n_preallocs */
			(GInstanceInitFunc) vips_interpolate_yafrsmooth_init,
		};

		type = g_type_register_static( VIPS_TYPE_INTERPOLATE, 
			"VipsInterpolateYafrsmooth", &info, 0 );
	}

	return( type );
}

VipsInterpolate *
vips_interpolate_yafrsmooth_new( void )
{
	return( VIPS_INTERPOLATE( g_object_new( 
		VIPS_TYPE_INTERPOLATE_YAFRSMOOTH, NULL ) ) );
}

void
vips_interpolate_yafrsmooth_set_sharpening( 
	VipsInterpolateYafrsmooth *yafrsmooth, 
	double sharpening )
{
	yafrsmooth->sharpening = sharpening; 
}

/* Convenience: return a static yafrsmooth you don't need to free.
 */
VipsInterpolate *
vips_interpolate_yafrsmooth_static( void )
{
	static VipsInterpolate *interpolate = NULL;

	if( !interpolate )
		interpolate = vips_interpolate_yafrsmooth_new();

	return( interpolate );
}


