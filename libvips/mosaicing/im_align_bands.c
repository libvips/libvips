/*
 * Brute force align the bands of an image.
 *
 * Copyright: Nottingham Trent University
 * Author: Tom Vajzovic
 * Written on: 2008-02-04
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/

#include <vips/intl.h>
#include <vips/vips.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/**
 * im_align_bands:
 * @in: image to align
 * @out: output image
 *
 * This operation uses im_phasecor_fft() to find an integer displacement to
 * align all image bands band 0. It is very slow and not very accurate. 
 *
 * Use im_estpar() in preference: it's fast and accurate.
 * 
 * See also: im_global_balancef(), im_remosaic().
 *
 * Returns: 0 on success, -1 on error
 */
int im_align_bands( IMAGE *in, IMAGE *out ){
#define FUNCTION_NAME "im_align_bands"
  if( im_piocheck( in, out ))
    return -1;

  if( 1 == in-> Bands )
    return im_copy( in, out );
  {
    IMAGE **bands= IM_ARRAY( out, 2 * in-> Bands, IMAGE* );
    IMAGE **wrapped_bands= bands + in-> Bands;
    double x= 0.0;
    double y= 0.0;
    int i;

    if( ! bands || im_open_local_array( out, bands, in-> Bands, FUNCTION_NAME ": bands", "p" )
        || im_open_local_array( out, wrapped_bands + 1, in-> Bands - 1, FUNCTION_NAME ": wrapped_bands", "p" ))
      return -1;

    for( i= 0; i < in-> Bands; ++i )
      if( im_extract_band( in, bands[i], i ))
        return -1;

    wrapped_bands[ 0 ]= bands[0];

    for( i= 1; i < in-> Bands; ++i ){
      IMAGE *temp= im_open( FUNCTION_NAME ": temp", "t" );
      double this_x, this_y, val;

      if( ! temp || im_phasecor_fft( bands[i-1], bands[i], temp )
          || im_maxpos_avg( temp, & this_x, & this_y, & val ) || im_close( temp ))
        return -1;

      x+= this_x;
      y+= this_y;

      if( im_wrap( bands[i], wrapped_bands[i], (int) x, (int) y ))
        return -1;
    }
    return im_gbandjoin( wrapped_bands, out, in-> Bands );
  }
#undef FUNCTION_NAME
}
