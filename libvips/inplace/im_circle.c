/* @(#)  writes a circle in a vasari file
 * @(#) The circle is centred in the middle of the file (xsize/2, ysize/2)
 * @(#) im must be a valid image
 * @(#) int im_circle(pim, cx, cy, radius, intensity)
 * @(#) IMAGE *pim;
 * @(#) int cx, cy, radius, intensity;
 * @(#)
 * @(#) Return -1 on error 0 on sucess.
 *
 * Copyright 1990, N. Dessipris.
 *
 * Author N. Dessipris
 * Written on 30/05/1990
 * Updated on:
 * 22/7/93 JC
 *	- im_incheck() call added
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
#include <math.h>
#include <string.h>

#include <vips/vips.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

int 
im_circle( IMAGE *im, int cx, int cy, int radius, int intensity )
{
	PEL *start;
	int size = 0;
	int x, y, d, offset;

	if( im_rwcheck( im ) )
		return( -1 );

/* Check args */
	if ( (im->data == NULL)||(im->BandFmt != IM_BANDFMT_UCHAR)||
	   (im->Bands != 1))
		{
		im_error("im_circle: ", "%s", _( "able to write input image") );
		return(-1);
		}
	if ((intensity > 255)||(intensity <= 0))
		{
		im_error( "im_circle", "%s", _( "intensity between 0 and 255") );
		return(-1);
		}
/* Check if circle fits into image */
	if ( ((radius+cy)> im->Ysize - 1) || ((cy-radius)< 0 ) ||
	     ((radius+cx)> im->Xsize - 1) || ((cx-radius) < 0 )   )
		{
		im_error( "im_circle", "%s", _( "The circle doesnot fit in image") );
		return(-1);
		}
/* Draw the circle */
	size = im->Xsize;
	start = (PEL*)im->data;
	offset = cy * im->Xsize + cx; /* point at the center of the circle */
	x = 0;
	y = radius;
	d = 3 - 2 * radius;
	while ( x < y )
		{
		*(start + offset + size * y + x) = (PEL)intensity;
		*(start + offset + size * x + y) = (PEL)intensity;
		*(start + offset + size * y - x) = (PEL)intensity;
		*(start + offset + size * x - y) = (PEL)intensity;
		*(start + offset - size * y - x) = (PEL)intensity;
		*(start + offset - size * x - y) = (PEL)intensity;
		*(start + offset - size * y + x) = (PEL)intensity;
		*(start + offset - size * x + y) = (PEL)intensity;
		if (d < 0 )
			d += ( 4 * x + 6 );
		else
			{
			d += ( 4 * ( x - y ) + 10 );
			y--;
			}
		x++;
		}
	if ( x== y )
		{
		*(start + offset + size * y + x) = (PEL)intensity;
		*(start + offset + size * x + y) = (PEL)intensity;
		*(start + offset + size * y - x) = (PEL)intensity;
		*(start + offset + size * x - y) = (PEL)intensity;
		*(start + offset - size * y - x) = (PEL)intensity;
		*(start + offset - size * x - y) = (PEL)intensity;
		*(start + offset - size * y + x) = (PEL)intensity;
		*(start + offset - size * x + y) = (PEL)intensity;
		}

	im_invalidate( im );

        return(0);	
}
