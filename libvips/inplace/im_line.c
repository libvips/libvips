/* @#) line drawer. adapted to draw for graphics system
 * @(#) Modified to be compatible with the vasari library
 * @(#) In order to use this function, the input file should have been set by
 * @(#) im_mmapinrw()
 *
 * Copyright: N. Dessipris
 * Written: 02/01/1990
 * Modified :
 * 22/7/93 JC
 *	- im_incheck() added
 *	- externs removed
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
#include <math.h>

#include <vips/vips.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

int im_line(image, x1, y1, x2, y2, pelval)
IMAGE *image;
int   x1, x2, y1, y2, pelval;
{

double x, y, dx, dy, m;
long offset;
double signx, signy;

	if( im_rwcheck( image ) )
		return( -1 );
/* check coordinates */
if (  (x1 > image->Xsize)||(x1<0)||(y1 > image->Ysize)||(y1<0)
    ||(x2 > image->Xsize)||(x2<0)||(y2 > image->Ysize)||(y2<0) ) { 
	im_error( "im_line", "%s", _( "invalid line cooordinates") ); 
	return(-1); }
if ((pelval > 255)||(pelval < 0)) {
	im_error( "im_line", "%s", _( "line intensity between 0 and 255") ); 
	return(-1); }

if (image->Bands != 1) { 
	im_error( "im_line", "%s", _( "image should have one band only") );
	return(-1); } 

dx = (double)(x2 - x1);
dy = (double)(y2 - y1);

if (dx < 0.0) 
	signx = -1.0;
else 
	signx = 1.0;

if (dy < 0.0)
	signy = -1.0;
else 
	signy = 1.0;

if (dx == 0.0)
	{
	x = x1; y = y1;
	while (y != y2)
		{
		offset = (int)(x+.5) + ((int)(y +.5)) * image->Xsize;
		*(image->data + offset) = (PEL)pelval;
		y += signy;
		}
	/* Draw point (x2, y2) */
	offset = x2 + y2 * image->Xsize;
	*(image->data + offset) = (PEL)pelval;
	return(0);
	}

if (dy == 0.0)
	{
	y = y1; x = x1;
	while (x != x2)
		{
		offset = (int)(x+.5) + ((int)(y +.5)) * image->Xsize;
		*(image->data + offset) = (PEL)pelval;
		x += signx;
		}
	/* Draw point (x2, y2) */
	offset = x2 + y2 * image->Xsize;
	*(image->data + offset) = (PEL)pelval;
	return(0);
	}

if (fabs(dy) < fabs(dx))
	{
	m = fabs(dy/dx)*signy;
	y = y1;
	x = x1;
	while (x != x2)
		{
		offset = (int)(x+.5) + ((int)(y +.5)) * image->Xsize;
		*(image->data + offset) = (PEL)pelval;
		x += signx;
		y += m;
		}
	}
else
	{
	m = fabs(dx/dy)*signx;
	x = x1; y = y1;
	while (y != y2)
		{
		offset = (int)(x+.5) + ((int)(y +.5)) * image->Xsize;
		*(image->data + offset) = (PEL)pelval;
		x += m;
		y += signy;
		}
	}
/* Draw point (x2, y2) */
offset = x2 + y2 * image->Xsize;
*(image->data + offset) = (PEL)pelval;
	im_invalidate( image );
return(0);
}
