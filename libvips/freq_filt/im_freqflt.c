/* @(#)  Functions which takes as input a valid image and filters it
 * @(#) in the fourier domain with the filter mask
 * @(#)   Input can have any format ; output is the same as input
 * @(#)  imin can be char uchar, short, ushort, int, uint, float, double
 * @(#)  or complex float; result is the same as input, clipped if necessary.
 * @(#)  mask can have any format but the sizes of input and mask are equal
 * @(#)  The function performs float fft and if the input is not complex float
 * @(#) the output is casted to the type of input according to im_clip2..()
 * @(#)  Since buffer images are involved the size, is restricted to 512x512
 * @(#) for the SUN4 SPARC workstation
 * @(#)
 * @(#) int im_freqflt(imin, mask, imout)
 * @(#) IMAGE *imin, *mask, *imout;
 * @(#)
 * @(#) Returns 0 on success and -1 on error
 *
 * Copyright: 1990, N. Dessipris.
 *
 * Author: Nicos Dessipris
 * Written on: 02/05/1990
 * Modified on : 08/03/1991
 * 16/6/93 J.Cupitt
 *	- im_multiply() called, rather than im_cmultim()
 * 27/10/93 JC
 *	- im_clip2*() called, rather than im_any2*()
 * 20/9/95 JC
 *	- rewritten
 * 10/9/98 JC
 *	- frees memory more quickly
 * 4/3/03 JC
 *	- use im_invfftr() to get real back for speedup
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
#include <math.h>

#include <vips/vips.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

int 
im_freqflt( IMAGE *in, IMAGE *mask, IMAGE *out )
{
	IMAGE *dummy;

	/* Placeholder for memory free.
	 */
	if( !(dummy = im_open( "memory-1", "p" )) )
		return( -1 );

	if( vips_bandfmt_iscomplex( in->BandFmt ) ) {
		/* Easy case! Assume it has already been transformed.
		 */
		IMAGE *t1 = im_open_local( dummy, "im_freqflt-1", "p" );

		if( !t1 ||
			im_multiply( in, mask, t1 ) ||
			im_invfftr( t1, out ) ) {
			im_close( dummy );
			return( -1 );
		}
	}
	else {
		/* Harder - fft first, then mult, then force back to start
		 * type.
		 * 
		 * Optimisation: output of im_invfft() is float buffer, we 
		 * will usually chagetype to char, so rather than keeping a
		 * large float buffer and partial to char from that, do
		 * changetype to a memory buffer, and copy to out from that.
		 */
		IMAGE *t[3];
		IMAGE *t3;

		if( im_open_local_array( dummy, t, 3, "im_freqflt-1", "p" ) ||
			!(t3 = im_open_local( out, "im_freqflt-3", "t" )) ||
			im_fwfft( in, t[0] ) ||
			im_multiply( t[0], mask, t[1] ) ||
			im_invfftr( t[1], t[2] ) ||
			im_clip2fmt( t[2], t3, in->BandFmt ) ||
			im_copy( t3, out ) ) {
			im_close( dummy );
			return( -1 );
		}	
	}

	im_close( dummy );

	return( 0 );
}

