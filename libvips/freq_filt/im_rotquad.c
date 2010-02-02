/* im_rotquad
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
 * 2/2/10
 * 	- redone in terms of im_wrap()
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

/**
 * im_rotquad:
 * @in: input image
 * @out: output image
 *
 * Rotate the quadrants of the image so that the point that was at the
 * top-left is now in the centre. Handy for moving Fourier images to optical
 * space.
 *
 * See also: im_wrap().
 *
 * Returns: 0 on success, -1 on error
 */
int
im_rotquad( IMAGE *in, IMAGE *out )
{
	return( im_wrap( in, out, in->Xsize / 2, in->Ysize / 2 ) );
}
