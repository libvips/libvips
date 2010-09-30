/* draw a circle on an image
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
 * 6/3/10
 * 	- don't im_invalidate() after paint, this now needs to be at a higher
 * 	  level
 * 18/8/10
 *	- gtkdoc
 *	- rewritten: clips, fills, any bands, any format
 * 27/9/10
 * 	- break base out to Draw
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

#include <string.h>

#include <vips/vips.h>

#include "draw.h"

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* Our state.
 */
typedef struct {
	Draw draw;

	/* Parameters.
	 */
	int cx, cy;
	int radius;
	gboolean fill;

	/* Derived stuff.
	 */
	PEL *centre;
} Circle;

static void
circle_octants( Circle *circle, int x, int y )
{
	Draw *draw = DRAW( circle );

	if( circle->fill ) {
		const int cx = circle->cx;
		const int cy = circle->cy;

		im__draw_scanline( draw, cy + y, cx - x, cx + x );
		im__draw_scanline( draw, cy - y, cx - x, cx + x );
		im__draw_scanline( draw, cy + x, cx - y, cx + y );
		im__draw_scanline( draw, cy - x, cx - y, cx + y );
	}
	else if( DRAW( circle )->noclip ) {
		const size_t lsize = draw->lsize;
		const size_t psize = draw->psize;
		PEL *centre = circle->centre;

		im__draw_pel( draw, centre + lsize * y - psize * x );
		im__draw_pel( draw, centre + lsize * y + psize * x );
		im__draw_pel( draw, centre - lsize * y - psize * x );
		im__draw_pel( draw, centre - lsize * y + psize * x );
		im__draw_pel( draw, centre + lsize * x - psize * y );
		im__draw_pel( draw, centre + lsize * x + psize * y );
		im__draw_pel( draw, centre - lsize * x - psize * y );
		im__draw_pel( draw, centre - lsize * x + psize * y );
	}
	else {
		const int cx = circle->cx;
		const int cy = circle->cy;

		im__draw_pel_clip( draw, cx + y, cy - x );
		im__draw_pel_clip( draw, cx + y, cy + x );
		im__draw_pel_clip( draw, cx - y, cy - x );
		im__draw_pel_clip( draw, cx - y, cy + x );
		im__draw_pel_clip( draw, cx + x, cy - y );
		im__draw_pel_clip( draw, cx + x, cy + y );
		im__draw_pel_clip( draw, cx - x, cy - y );
		im__draw_pel_clip( draw, cx - x, cy + y );
	}
}

static void
circle_free( Circle *circle )
{
	im__draw_free( DRAW( circle ) );
	im_free( circle );
}

static Circle *
circle_new( IMAGE *im, int cx, int cy, int radius, gboolean fill, PEL *ink )
{
	Circle *circle;

	if( !(circle = IM_NEW( NULL, Circle )) )
		return( NULL );
	if( !im__draw_init( DRAW( circle ), im, ink ) ) {
		circle_free( circle );
		return( NULL );
	}

	circle->cx = cx;
	circle->cy = cy;
	circle->radius = radius;
	circle->fill = fill;
	circle->centre = (PEL *) IM_IMAGE_ADDR( im, cx, cy );

	if( cx - radius >= 0 && cx + radius < im->Xsize &&
		cy - radius >= 0 && cy + radius < im->Ysize )
		DRAW( circle )->noclip = TRUE;

	return( circle );
}

static void
circle_draw( Circle *circle )
{
	int x, y, d;

	y = circle->radius;
	d = 3 - 2 * circle->radius;

	for( x = 0; x < y; x++ ) {
		circle_octants( circle, x, y );

		if( d < 0 )
			d += 4 * x + 6;
		else {
			d += 4 * (x - y) + 10;
			y--;
		}
	}

	if( x == y ) 
		circle_octants( circle, x, y );
}

/**
 * im_draw_circle:
 * @image: image to draw on
 * @x: centre of circle
 * @y: centre of circle
 * @radius: circle radius
 * @fill: fill the circle
 * @ink: value to draw
 *
 * Draws a circle on @image. If @fill is %TRUE then the circle is filled,
 * otherwise a 1-pixel-wide perimeter is drawn.
 *
 * @ink is an array of bytes containing a valid pixel for the image's format.
 * It must have at least IM_IMAGE_SIZEOF_PEL( @image ) bytes.
 *
 * See also: im_draw_line().
 *
 * Returns: 0 on success, or -1 on error.
 */
int
im_draw_circle( VipsImage *image, 
	int x, int y, int radius, gboolean fill, PEL *ink )
{
	if( x + radius >= 0 && x - radius < image->Xsize &&
		y + radius >= 0 && y - radius < image->Ysize ) {
		Circle *circle;

		if( im_check_coding_known( "im_draw_circle", image ) ||
			!(circle = circle_new( image, 
				x, y, radius, fill, ink )) )
			return( -1 );
		circle_draw( circle );

		circle_free( circle );
	}

	return( 0 );
}

