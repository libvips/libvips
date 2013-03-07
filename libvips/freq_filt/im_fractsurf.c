/* im_fractsurf
 *
 * Copyright: 1991, N. Dessipris.
 *
 * Author: N. Dessipris
 * Written on: 10/09/1991
 * Modified on:
 * 20/9/95 JC
 *	 - modernised, a little
 * 7/2/10
 * 	- cleanups
 * 	- gtkdoc
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
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
    02110-1301  USA

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

/**
 * im_fractsurf:
 * @out: output image
 * @size: size of image to generate
 * @frd: fractal dimension
 *
 * Generate an image of size @size and fractal dimension @frd. The dimension
 * should be between 2 and 3.
 *
 * See also: im_gaussnoise(), im_flt_image_freq().
 *
 * Returns: 0 on success, -1 on error.
 */
int 
im_fractsurf( IMAGE *out, int size, double frd )
{
	IMAGE *noise;

	if( frd <= 2.0 || frd >= 3.0 ) {
		im_error( "im_fractsurf", "%s", 
			_( "dimension should be in (2,3)" ) );
		return( -1 );
	}

	if( !(noise = im_open_local( out, "im_fractsurf", "p" )) ||
		im_gaussnoise( noise, size, size, 0.0, 1.0 ) || 
		im_flt_image_freq( noise, out, VIPS_MASK_FRACTAL_FLT, frd ) )
		return( -1 );

	return( 0 );
}
