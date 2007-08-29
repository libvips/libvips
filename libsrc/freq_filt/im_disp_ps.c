/* @(#)  Makes a displayable uchar power spectrum of an input one band image
 * @(#) Input should be float complex
 * @(#) All images are kept in RAM; so only square arrays of powers of 
 * @(#) 2 as inputs.
 * @(#) Functions im_fwfft, im_c2ps, im_scaleps and im_rotquad are used
 * @(#)  Image descriptors should have been set properly by the calling program
 * @(#)
 * @(#)  int im_disp_ps(in, out)
 * @(#)  IMAGE *in, *out;
 * @(#)  int bandno;
 * @(#)
 * @(#)  Returns 0 on sucess and -1 on error
 * @(#)
 *
 * Copyright: 1991, N. Dessipris.
 *
 * Author: Nicos Dessipris
 * Written on: 27/03/1991
 * Modified on : 
 * 16/6/93 J.Cupitt
 *	- im_ioflag() changed to im_iocheck()
 * 23/2/95 JC
 *	- rewritten for partials
 * 10/9/98 JC
 *	- frees memory more quickly
 * 2/4/02 JC
 *	- any number of bands
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

static int 
disp_ps( IMAGE *dummy, IMAGE *in, IMAGE *out )
{
	IMAGE *t[3];

	if( im_open_local_array( out, t, 3, "im_disp_ps temp 1", "p" ) )
		return( -1 );

	if( in->BandFmt == IM_BANDFMT_COMPLEX ) {
		if( im_c2ps( in, t[1] ) )
			return( -1 );
	}
	else {
		if( im_fwfft( in, t[0] ) || im_c2ps( t[0], t[1] ) )
			return( -1 );
	}

	if( im_scaleps( t[1], t[2] ) || im_rotquad( t[2], out ) )
		return( -1 );

	return( 0 );
}

int 
im_disp_ps( IMAGE *in, IMAGE *out )
{
	IMAGE *dummy = im_open( "memory:1", "p" );

	if( !dummy )
		return( -1 );
	if( disp_ps( dummy, in, out ) ) {
		im_close( dummy );
		return( -1 );
	}
	im_close( dummy );

	return( 0 );
}
