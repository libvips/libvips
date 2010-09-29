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

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

typedef struct _Point {
	Draw draw;
} Point;

/**
 * im_draw_point:
 * @image: image to draw on
 * @x: position to draw
 * @y: position to draw
 * @ink: value to draw
 *
 * Draws a single point on an image. 
 *
 * @ink is an array of bytes containing a valid pixel for the image's format.
 * It must have at least IM_IMAGE_SIZEOF_PEL( @im ) bytes.
 *
 * This an inplace operation, so @im is changed. It does not thread and will
 * not work well as part of a pipeline. On 32-bit machines it will be limited
 * to 2GB images.
 *
 * See also: im_draw_line().
 *
 * Returns: 0 on success, or -1 on error.
 */
int
im_draw_point( VipsImage *image, int x, int y, PEL *ink )
{	
	Point point;

	if( im_check_coding_known( "im_draw_point", image ) ||
		im__draw_init( DRAW( &point ), image, NULL ) )
		return( -1 );

	/* Check coordinates.
	 */
	if( x >= 0 && x < image->Xsize && y >= 0 && y < image->Ysize ) 
		memcpy( IM_IMAGE_ADDR( image, x, y ), ink, 
			DRAW( image )->psize );

	im__draw_free( DRAW( &point ) );

	return( 0 );
}

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
im_read_point( VipsImage *image, int x, int y, PEL *ink )
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
