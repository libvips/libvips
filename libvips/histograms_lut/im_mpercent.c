/* find percent of pixels
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
 * 25/3/10
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
#include <string.h>

#include <vips/vips.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/**
 * im_mpercent:
 * @in: input image
 * @percent: threshold percentage
 * @out: output threshold value
 *
 * im_mpercent() returns (through the @out parameter) the threshold above 
 * which there are @percent values of @in. If for example percent=.1, the
 * number of pels of the input image with values greater than the returned 
 * int will correspond to 10% of all pels of the image.
 *
 * The function works for uchar and ushort images only.  It can be used 
 * to threshold the scaled result of a filtering operation.
 *
 * See also: im_histgr(), im_profile().
 *
 * Returns: 0 on success, -1 on error
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
