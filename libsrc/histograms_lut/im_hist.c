/* @(#) Creates a displayable historam of in result in hist
 * @(#) If bandno=0 histogram of all bands is created
 * @(#) else the histogram of bandno only is created.
 * @(#)
 * @(#)  Usage:
 * @(#)  int im_hist(in, out, bandno)
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
 *	- im_ioflag() call changed to im_iocheck()
 * 24/5/95 JC
 *	- ANSIfied and tidied up
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

#include <vips/vips.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

int 
im_hist( IMAGE *in, IMAGE *out, int bandno )
{
	IMAGE *hist = im_open_local( out, "im_hist:#1", "p" );

	if( !hist || 
		im_iocheck( in, out ) ||
		im_histgr( in, hist, bandno ) ||
		im_histplot( hist, out ) )
		return( -1 );

	return( 0 );
}
