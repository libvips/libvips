/* @(#) Read a pel out of an image and into a buffer, plot a pel back into
 * @(#) the image again.
 * @(#) 
 * @(#) int
 * @(#) im_readpoint( IMAGE *im, int x, int y, PEL *ink )
 * @(#) 
 * @(#) int
 * @(#) im_plotpoint( IMAGE *im, int x, int y, PEL *ink )
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

/* Read a colour from an image.
 */
int
im_readpoint( IMAGE *im, int x, int y, PEL *pel )
{	
	int es = IM_IMAGE_SIZEOF_ELEMENT( im ); 
	int ps = es * im->Bands;
	int ls = ps * im->Xsize;
	int b;
	PEL *from;

	if( im_rwcheck( im ) )
		return( -1 );

	/* Check coordinates in range.
	 */
	if(  x > im->Xsize || x < 0 || y > im->Ysize || y < 0 ) {
		im_error( "im_readpoint", "%s", _( "invalid cooordinates" ) ); 
		return( 1 ); 
	}

	/* Suck single pixel.
	 */
	from = (PEL *) im->data + x * ps + y * ls;
	for( b = 0; b < ps; b++ )
		*pel++ = *from++;
	
	return( 0 );
}

/* Plot a point in an image.
 */
int
im_plotpoint( IMAGE *im, int x, int y, PEL *pel )
{	
	int es = IM_IMAGE_SIZEOF_ELEMENT( im ); 
	int ps = es * im->Bands;
	int ls = ps * im->Xsize;
	int b;
	PEL *to;

	if( im_rwcheck( im ) )
		return( -1 );

	/* Check coordinates in range.
	 */
	if(  x > im->Xsize || x < 0 || y > im->Ysize || y < 0 )
		return( 0 );

	/* Paint single pixel.
	 */
	to = (PEL *) im->data + x * ps + y * ls;
	for( b = 0; b < ps; b++ )
		*to++ = *pel++;

	im_invalidate( im );

	return( 0 );
}
