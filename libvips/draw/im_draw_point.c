/* draw / read single points
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
 * 29/9/10
 * 	- gtk-doc
 * 	- use Draw base class
 * 	- read_point partial-ised
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
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
    02110-1301  USA

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

#include "old_draw.h"

/**
 * im_read_point:
 * @image: image to read from
 * @x: position to read
 * @y: position to read
 * @ink: read value here
 *
 * Reads a single point on an image. 
 *
 * @ink is an array of bytes to contain a valid pixel for the image's format.
 * It must have at least IM_IMAGE_SIZEOF_PEL( @im ) bytes.
 *
 * See also: im_draw_point().
 *
 * Returns: 0 on success, or -1 on error.
 */
int
im_read_point( VipsImage *image, int x, int y, VipsPel *ink )
{
	REGION *reg;
	Rect area;

	if( im_check_coding_known( "im_draw_point", image ) ||
		!(reg = im_region_create( image )) )
		return( -1 );

	area.left = x;
	area.top = y;
	area.width = 1;
	area.height = 1;
	if( im_prepare( reg, &area ) ) {
		im_region_free( reg );
		return( -1 );
	}

	memcpy( ink, IM_REGION_ADDR( reg, x, y ), 
		IM_IMAGE_SIZEOF_PEL( image ) );

	im_region_free( reg );

	return( 0 );
}
