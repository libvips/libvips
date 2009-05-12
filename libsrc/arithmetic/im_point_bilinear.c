/* @(#) Find the value at (x,y) in given band of image.
 * @(#) Use bilinear interpolation if x or y are non-integral.
 * @(#) 
 * @(#) int im_maxpos_vec(
 * @(#)   IMAGE *im,
 * @(#)   double x,
 * @(#)   double y,
 * @(#)   int band,
 * @(#)   double *val
 * @(#) );
 * @(#) 
 *
 * Copyright: 2006, The Nottingham Trent University
 *
 * Author: Tom Vajzovic
 *
 * Written on: 2006-09-26
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
#endif /* HAVE_CONFIG_H */
#include <vips/intl.h>

#include <vips/vips.h>
#include <vips/r_access.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC */


/** EXPORTED FUNCTION **/

int im_point_bilinear( IMAGE *im, double x, double y, int band, double *val ){
#define FUNCTION_NAME "im_point_bilinear"

  double x_frac= x - (int) x;
  double y_frac= y - (int) y;
  Rect need= { x, y, ( x_frac ? 2 : 1 ), ( y_frac ? 2 : 1 ) };
  REGION *reg;

  if( im_pincheck( im ) )
    return -1;

  if( im-> Coding ){
    im_error( FUNCTION_NAME, "%s", _("uncoded images only") );
    return -1;
  }
  if( !( im_isint( im ) || im_isfloat( im ) ) ){
    im_error( FUNCTION_NAME, "%s", _("scalar images only") );
    return -1;
  }
  if( band >= im-> Bands || x < 0.0 || y < 0.0 || x > im-> Xsize || y > im-> Ysize ){
    im_error( FUNCTION_NAME, "%s", _("coords outside image") );
    return -1;
  }
  if( ! val ){
    im_error( FUNCTION_NAME, "%s", _("invalid arguments") );
    return -1;
  }

  reg= im_region_create( im );

  if( ! reg || im_prepare( reg, &need ) )
    return -1;

  if( ! im_rect_includesrect( &reg-> valid, &need ) ){
    im_error( FUNCTION_NAME, "%s", _("coords outside image") );
    im_region_free( reg );
    return -1;
  }

  if( x_frac )
    if( y_frac )
      *val=      x_frac      *      y_frac      * (double) IM_REGION_VALUE( reg, ((int)x + 1), ((int)y + 1), band )
          +      x_frac      * ( 1.0 - y_frac ) * (double) IM_REGION_VALUE( reg, ((int)x + 1),    (int)y   , band )
          + ( 1.0 - x_frac ) *      y_frac      * (double) IM_REGION_VALUE( reg,    (int)x,    ((int)y + 1), band )
          + ( 1.0 - x_frac ) * ( 1.0 - y_frac ) * (double) IM_REGION_VALUE( reg,    (int)x,       (int)y   , band );

    else
      *val=      x_frac      * IM_REGION_VALUE( reg, ((int)x + 1), (int)y, band )
          + ( 1.0 - x_frac ) * IM_REGION_VALUE( reg,    (int)x,    (int)y, band );

  else
    if( y_frac )
      *val=      y_frac      * IM_REGION_VALUE( reg, (int)x, ((int)y + 1), band )
          + ( 1.0 - y_frac ) * IM_REGION_VALUE( reg, (int)x,    (int)y   , band );

    else
      *val= IM_REGION_VALUE( reg, (int)x, (int)y, band );

  im_region_free( reg );

  return 0;

#undef FUNCTION_NAME
}

