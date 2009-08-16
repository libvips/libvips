/* @(#) Shifts the four quadrants of a fourier transform for display
 * @(#) Any number of bands, any coding, any band format
 * @(#) Works on images with even sizes
 * @(#) Output is the same as the input
 * @(#) 
 * @(#) Usage:
 * @(#) 
 * @(#) 	int 
 * @(#) 	im_rotquad( in, out )
 * @(#) 	IMAGE *in, *out;
 * @(#)
 *
 * Copyright: 1990, N. Dessipris.
 *
 * Author: Nicos Dessipris 
 * Written on: 12/04/1990
 * Modified on : 09/05/1991
 * Modified on : 09/06/1992, J.Cupitt. 
 *	- now works for any type, any number of bands.
 *	- uses bcopy instead of a loop: mucho faster.
 * now uses memcpy - for Sys5 compat K.Martinez 29/4/92
 * 5/8/93 JC
 *	- some ANSIfication
 * 28/6/95 JC
 *	- some more modernisation
 * 11/7/02 JC
 *	- redone in term of extract()/insert(), for great partialisation
 * 14/4/04
 *	- sets Xoffset / Yoffset
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
#include <stdlib.h>
#include <string.h>

#include <vips/vips.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

int
im_rotquad( IMAGE *in, IMAGE *out )
{
	IMAGE *t[6];
	int xd = in->Xsize / 2;
	int yd = in->Ysize / 2;

	if( in->Xsize < 2 || in->Ysize < 2 )
		return( im_copy( in, out ) );

	if( im_open_local_array( out, t, 6, "im_rotquad-1", "p" ) ||
		/* Extract 4 areas.
		 */
		im_extract_area( in, t[0], 0, 0, xd, yd ) ||
		im_extract_area( in, t[1], xd, 0, in->Xsize - xd, yd ) ||
		im_extract_area( in, t[2], 0, yd, xd, in->Ysize - yd ) ||
		im_extract_area( in, t[3], xd, yd, 
			in->Xsize - xd, in->Ysize - yd ) ||
	
		/* Reassemble, rotated.
		 */
		im_insert( t[3], t[2], t[4], in->Xsize - xd, 0 ) ||
		im_insert( t[1], t[0], t[5], in->Xsize - xd, 0 ) ||
		im_insert( t[4], t[5], out, 0, in->Ysize - yd ) )
		return( -1 );

	out->Xoffset = xd;
	out->Yoffset = yd;

	return( 0 );
}
