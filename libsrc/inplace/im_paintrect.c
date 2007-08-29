/* @(#) Fill Rect r of image im with pels of colour ink. r can be any size and
 * @(#) any position, we clip against the image size.
 * @(#) 
 * @(#) int
 * @(#) im_paintrect( IMAGE *im, Rect *r, PEL *ink )
 * @(#) 
 * @(#) 
 *
 * Copyright: J. Cupitt
 * Written: 15/06/1992
 * 22/7/93 JC
 *	- im_incheck() added
 * 16/8/94 JC
 *	- im_incheck() changed to im_makerw()
 * 5/12/06
 * 	- im_invalidate() after paint
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

#include <vips/vips.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* Paint a rect of colour into an image.
 */
int
im_paintrect( IMAGE *im, Rect *r, PEL *ink )
{	
	int es = im->Bbits >> 3;
	int ps = es * im->Bands;
	int ls = ps * im->Xsize;
	Rect image, clipped;
	int x, y, b;
	PEL *to;
	PEL *q;

	if( im_rwcheck( im ) )
		return( -1 );

	/* Find area we plot.
	 */
	image.left = 0;
	image.top = 0;
	image.width = im->Xsize;
	image.height = im->Ysize;
	im_rect_intersectrect( r, &image, &clipped );

	/* Any points left to plot?
	 */
	if( im_rect_isempty( &clipped ) )
		return( 0 );

	/* Loop through image plotting where required.
	 */
	to = (PEL *) im->data + clipped.left * ps + clipped.top * ls;
	for( y = 0; y < clipped.height; y++ ) {
		q = to;

		for( x = 0; x < clipped.width; x++ )
			for( b = 0; b < ps; b++ )
				*q++ = ink[b];
		
		to += ls;
	}

	im_invalidate( im );

	return( 0 );
}

