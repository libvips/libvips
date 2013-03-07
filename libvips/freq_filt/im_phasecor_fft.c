/* Like im_spcor(), but calculates phase correlation in the Fourier domain.
 *
 * Copyright: 2008, Nottingham Trent University
 *
 * Author: Tom Vajzovic
 * Written on: 2008-01-16
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

#include <vips/vips.h>

/**
 * im_phasecor_fft:
 * @in1: first input image
 * @in2: second input image
 * @out: output image
 *
 * Convert the two input images to Fourier space, calculate phase-correlation,
 * back to real space.
 *
 * See also: im_fwfft(), im_cross_phase(), 
 *
 * Returns: 0 on success, -1 on error
 */
int 
im_phasecor_fft( IMAGE *in1, IMAGE *in2, IMAGE *out )
{
	IMAGE *t[3];

	if( im_open_local_array( out, t, 3, "im_phasecor_fft", "p" ) ||
		im_fwfft( in1, t[0] ) ||
		im_fwfft( in2, t[1] ) ||
		im_cross_phase( t[0], t[1], t[2] ) ||
		im_invfftr( t[2], out ) )
		return( -1 );

	return( 0 );
}
