/* @(#) Generate an image where the value of each pixel represents the
 * @(#) contrast within a window of half_win_size from the corresponsing
 * @(#) point in the input image. Sub-sample by a factor of spacing.
 * @(#)
 * @(#) Pixels beyond the edges of the image are considered to be have the
 * @(#) value zero (black).
 * @(#)
 * @(#) Input must be single-band uncoded uchar, WIO or PIO.
 * @(#)
 * @(#) Output is single-band uncoded uint, WIO or PIO.
 * @(#)
 * @(#) int
 * @(#) im_contrast_surface(
 * @(#)   IMAGE *in,
 * @(#)   IMAGE *out,
 * @(#)   int    half_win_size,
 * @(#)   int    spacing
 * @(#) );
 * @(#)
 * @(#) Returns either 0 (success) or -1 (fail)
 * @(#)
 * @(#) Also: im_contrast_surface_raw(). As above, but pixels within
 * @(#) half_win_size of the edge are not calculated, and output is smaller
 * @(#) accordingly.
 *
 * Copyright: 2006, The Nottingham Trent University
 *
 * Author: Tom Vajzovic
 * (based on algorithm by Nicos Dessipris & John Cupitt)
 *
 * Written on: 2006-03-13
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

/** HEADERS **/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H */

#ifdef NOT_IN_VIPS
#define _(s) (s)
#else
#include <vips/intl.h>
#endif

#include <stdlib.h>

#include <vips/vips.h>
#include <vips/region.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC */

/** MACROS **/

/* from simple_macros.h */
#define LESSER(a,b)  ((a)<(b)?(a):(b))
#define DOUBLE(a)                ( (a)<<1 )
#define DOUBLE_ADD_ONE(a)  ( 1 | ( (a)<<1 ) )

/** LOCAL TYPES **/

typedef struct cont_surf_params_s
{
  int half_win_size;
  int spacing;

} cont_surf_params_t;

/** LOCAL FUNCTIONS DECLARATIONS **/

int
im_contrast_surface (IMAGE * in, IMAGE * out, int half_win_size, int spacing);

int
im_contrast_surface_raw (IMAGE * in, IMAGE * out, int half_win_size,
			 int spacing);

static int cont_surf_gen (REGION * to_make, REGION * make_from,
			  void *unrequired, cont_surf_params_t * params);

static unsigned int calc_cont (REGION * reg, int win_size_less_one,
			       int x_left, int y_top);

/** EXPORTED FUNCTIONS **/

int
im_contrast_surface (IMAGE * in, IMAGE * out, int half_win_size, int spacing)
{
  IMAGE *t1 = im_open_local (out, "im_contrast_surface intermediate", "p");

  if (!t1
      || im_embed (in, t1, 1, half_win_size, half_win_size,
		   in->Xsize + DOUBLE (half_win_size),
		   in->Ysize + DOUBLE (half_win_size))
      || im_contrast_surface_raw (t1, out, half_win_size, spacing))

    return -1;

  out->Xoffset = 0;
  out->Yoffset = 0;

  return 0;
}

int
im_contrast_surface_raw (IMAGE * in, IMAGE * out, int half_win_size,
			 int spacing)
{
#define FUNCTION_NAME "im_contrast_surface_raw"

  cont_surf_params_t *params;

  if (im_piocheck (in, out))
    return -1;

  if (IM_CODING_NONE != in->Coding || IM_BANDFMT_UCHAR != in->BandFmt
      || 1 != in->Bands)
    {
      im_error (FUNCTION_NAME, _("one band uncoded uchar only"));
      return -1;
    }

  if (half_win_size < 1 || spacing < 1)
    {
      im_error (FUNCTION_NAME, _("bad parameters"));
      return -1;
    }

  if (DOUBLE (half_win_size) >= LESSER (in->Xsize, in->Ysize))
    {
      im_error (FUNCTION_NAME,
		_("parameters would result in zero size output image"));
      return -1;
    }

  params = IM_NEW (out, cont_surf_params_t);

  if (!params)
    return -1;

  params->half_win_size = half_win_size;
  params->spacing = spacing;

  if (im_cp_desc (out, in))
    return -1;

  out->BandFmt = IM_BANDFMT_UINT;
  out->Bbits = sizeof (unsigned int) << 3;

  out->Xsize = 1 + ((in->Xsize - DOUBLE_ADD_ONE (half_win_size)) / spacing);
  out->Ysize = 1 + ((in->Ysize - DOUBLE_ADD_ONE (half_win_size)) / spacing);

  out->Xoffset = -half_win_size;
  out->Yoffset = -half_win_size;

  if (im_demand_hint (out, IM_FATSTRIP, in, NULL))
    return -1;

  return im_generate (out, im_start_one, cont_surf_gen, im_stop_one, in,
		      params);

#undef FUNCTION_NAME
}

/** LOCAL FUNCTIONS DEFINITIONS **/
static int
cont_surf_gen (REGION * to_make, REGION * make_from, void *unrequired,
	       cont_surf_params_t * params)
{
  /* I don't need *in, but I will recieve it anyway since im_start_one() needs it */

  unsigned int *row =
    (unsigned int *) IM_REGION_ADDR (to_make, to_make->valid.left,
				     to_make->valid.top);
  int xoff;
  int y;
  int bottom = to_make->valid.top + to_make->valid.height;
  size_t lskip = IM_REGION_LSKIP (to_make) / sizeof (unsigned int);

  Rect area = {
    params->spacing * to_make->valid.left,
    params->spacing * to_make->valid.top,
    DOUBLE_ADD_ONE (params->half_win_size) +
      (params->spacing * (to_make->valid.width - 1)),
    DOUBLE_ADD_ONE (params->half_win_size) +
      (params->spacing * (to_make->valid.height - 1))
  };

  if (im_prepare (make_from, &area)
      || !im_rect_equalsrect (&make_from->valid, &area))
    return -1;

  for (y = to_make->valid.top; y < bottom; ++y, row += lskip)

    for (xoff = 0; xoff < to_make->valid.width; ++xoff)

      row[xoff] =
	calc_cont (make_from, DOUBLE (params->half_win_size),
		   (xoff + to_make->valid.left) * params->spacing,
		   y * params->spacing);

  return 0;
}

static unsigned int
calc_cont (REGION * reg, int win_size_less_one, int x_left, int y_top)
{
  unsigned char val;
  unsigned char all_black = 1;
  unsigned char *row;
  unsigned int contrast = 0;
  int xoff;
  int yoff;
  size_t lskip = IM_REGION_LSKIP (reg) / sizeof (unsigned char);

  row = (unsigned char *) IM_REGION_ADDR (reg, x_left, y_top);
  val = *row;

  for (yoff = 0; yoff <= win_size_less_one && all_black; ++yoff, row += lskip)
    for (xoff = 0; xoff <= win_size_less_one; ++xoff)
      if (row[xoff] != val)
	{
	  all_black = 0;
	  break;
	}

  if (all_black)
    return contrast;

  row = (unsigned char *) IM_REGION_ADDR (reg, x_left, y_top);

  for (yoff = 0; yoff < win_size_less_one; ++yoff, row += lskip)
    {
      for (xoff = 0; xoff < win_size_less_one; ++xoff)
	contrast +=
	  abs (row[xoff + 1] - row[xoff]) + abs (row[xoff + lskip] -
						 row[xoff]);

      contrast += abs (row[xoff + lskip] - row[xoff]);
    }

  for (xoff = 0; xoff < win_size_less_one; ++xoff)
    contrast += abs (row[xoff + 1] - row[xoff]);

  return contrast;
}
