/* Fill Rect r of image im with pels of colour ink. 
 *
 * Copyright: J. Cupitt
 * Written: 15/06/1992
 * 22/7/93 JC
 *	- im_incheck() added
 * 16/8/94 JC
 *	- im_incheck() changed to im_makerw()
 * 5/12/06
 * 	- im_invalidate() after paint
 * 6/3/10
 * 	- don't im_invalidate() after paint, this now needs to be at a higher
 * 	  level
 * 22/9/10
 * 	- gtk-doc
 * 	- added 'fill'
 * 	- renamed as im_draw_rect() for consistency
 * 27/9/10
 * 	- memcpy() subsequent lines of the rect
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

#include "draw.h"

/**
 * im_draw_rect:
 * @image: image to draw on
 * @left: area to paint
 * @top: area to paint
 * @width: area to paint
 * @height: area to paint
 * @fill: fill the rect
 * @ink: paint with this colour
 *
 * Paint pixels within @left, @top, @width, @height in @image with @ink. If
 * @fill is zero, just paint a 1-pixel-wide outline.
 *
 * See also: im_draw_circle().
 *
 * Returns: 0 on success, or -1 on error.
 */
int
im_draw_rect( IMAGE *image, 
	int left, int top, int width, int height, int fill, VipsPel *ink )
{
	Rect im, rect, clipped;
	Draw draw;

	if( !fill ) 
		return( im_draw_rect( image, left, top, width, 1, 1, ink ) ||
			im_draw_rect( image, 
				left + width - 1, top, 1, height, 1, ink ) ||
			im_draw_rect( image, 
				left, top + height - 1, width, 1, 1, ink ) ||
			im_draw_rect( image, left, top, 1, height, 1, ink ) );

	int x, y;
	VipsPel *to;
	VipsPel *q;

	/* Find area we plot.
	 */
	im.left = 0;
	im.top = 0;
	im.width = image->Xsize;
	im.height = image->Ysize;
	rect.left = left;
	rect.top = top;
	rect.width = width;
	rect.height = height;
	im_rect_intersectrect( &rect, &im, &clipped );

	/* Any points left to plot?
	 */
	if( im_rect_isempty( &clipped ) )
		return( 0 );

	if( im_check_coding_known( "im_draw_rect", image ) ||
		!im__draw_init( &draw, image, ink ) )
		return( -1 );

	/* We plot the first line pointwise, then memcpy() it for the
	 * subsequent lines.
	 */
	to = IM_IMAGE_ADDR( image, clipped.left, clipped.top );

	q = to;
	for( x = 0; x < clipped.width; x++ ) {
		im__draw_pel( &draw, q );
		q += draw.psize;
	}

	q = to + draw.lsize;
	for( y = 1; y < clipped.height; y++ ) {
		memcpy( q, to, clipped.width * draw.psize );
		q += draw.lsize;
	}

	im__draw_free( &draw );

	return( 0 );
}
