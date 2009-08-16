/* @(#) Function which returns an int.  This integer is the threshold 
 * @(#) above which there are percent values of the input images
 * @(#)  If for instance precent=.1, the number of pels of the input image
 * @(#) with values greater than the returned int will correspond to
 * @(#) 10% of all pels of the image.
 * @(#) One band IM_BANDFMT_UCHAR images only.
 * @(#)
 * @(#) Function im_mpercent() assumes that input
 * @(#) is either memory mapped or in a buffer.
 * @(#)
 * @(#) int im_percent(in, percent)
 * @(#) IMAGE *in;
 * @(#) double percent;
 * @(#)
 * @(#) Returns 0 on success and -1 on error
 *
 * Copyright: 1990, N. Dessipris
 *
 * Author: N. Dessipris
 * Written on: 02/08/1990
 * Modified on : 29/4/93 K.Martinez   for Sys5
 * 20/2/95 JC
 *	- now returns result through parameter
 *	- ANSIfied a little
 * 19/1/07
 * 	- redone with the vips hist operators
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
#include <string.h>

#include <vips/vips.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* What threshold will select a specified percentage of the pixels in the
 * image. 
 */
int
im_mpercent( IMAGE *in, double percent, int *out )
{	
	IMAGE *base;
	IMAGE *t[6];
	double pos;

	if( !(base = im_open( "im_mpercent1", "p" )) )
		return( -1 );
	if( im_open_local_array( base, t, 6, "im_mpercent", "p" ) ) {
		im_close( base );
		return( -1 );
	}

	if( im_histgr( in, t[0], -1 ) ||
		im_histcum( t[0], t[1] ) ||
		im_histnorm( t[1], t[2] ) ||
		im_lessconst( t[2], t[3], percent * t[2]->Xsize ) ||
		im_fliphor( t[3], t[4] ) ||
		im_profile( t[4], t[5], 1 ) ||
		im_avg( t[5], &pos ) ) {
		im_close( base );
		return( -1 );
	}
	im_close( base );

	*out = pos;

	return( 0 );
}
