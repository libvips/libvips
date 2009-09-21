/* @(#) Creates a vasari fractal surface of a given dimension by
 * @(#) filtering white gaussian noise (function im_gaussnoise(3X))
 * @(#) using the function im_fltimage_freq(3X)
 * @(#) 
 * @(#) Usage:
 * @(#) int im_fractsurf(im, frd, size)
 * @(#) double frd;
 * @(#) int size;
 * @(#) 
 * @(#) Returns 0 on sucess and -1 on error
 * @(#) 
 *
 * Copyright: 1991, N. Dessipris.
 *
 * Author: N. Dessipris
 * Written on: 10/09/1991
 * Modified on:
 * 20/9/95 JC
 *	 - modernised, a little
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

#include <stdio.h>
#include <stdarg.h>
#include <math.h>

#include <vips/vips.h>
#include <vips/fmask.h> /* for MASK_FRACTAL_FLT */

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

int 
im_fractsurf( IMAGE *out, int size, double frd )
{
	IMAGE *noise = im_open_local( out, "noise.v", "p" );

	if( !noise )
		return( -1 );
	if( frd <= 2.0 || frd >= 3.0 ) {
		im_error( "im_fractsurf", "%s", 
			_( "dimension shuld be in (2,3)" ) );
		return( -1 );
	}

	if( im_gaussnoise( noise, size, size, 0.0, 1.0 ) ) 
		return( -1 );

	/* create the fractal filter mask, and perform filtering on noise
	 * Note that the result is in im, stored as float since
	 * the original noise is in float.  It needs scaling for display
	 */
	if( im_flt_image_freq( noise, out, MASK_FRACTAL_FLT, frd ) )
		return( -1 );

	return( 0 );
}
