/* Like im_spcor(), but calculates phase correlation in the Fourier domain.
 *
 * Copyright: 2008, Nottingham Trent University
 *
 * Author: Tom Vajzovic
 * Written on: 2008-01-16
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

int im_phasecor_fft( IMAGE *in1, IMAGE *in2, IMAGE *out ){
#define FUNCTION_NAME "im_fft_phasecor"
  IMAGE *temp1= im_open_local( out, FUNCTION_NAME ": temp1", "t" );
  IMAGE *temp2= im_open_local( out, FUNCTION_NAME ": temp2", "t" );
  IMAGE *temp3= im_open_local( out, FUNCTION_NAME ": temp3", "t" );

  if( ! temp1 || ! temp2 || ! temp3 )
    return -1;

  return im_incheck( in1 )
    || im_incheck( in2 )
    || im_outcheck( out )
    || im_fwfft( in1, temp1 )
    || im_fwfft( in2, temp2 )
    || im_cross_phase( temp1, temp2, temp3 )
    || im_invfftr( temp3, out );
#undef FUNCTION_NAME
}
