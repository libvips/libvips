/* replicate an image x times horizontally and vertically
 *
 * JC, 30 sep 03 
 *
 * 15/4/04
 *	- some optimisations for some cases
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

/* Turn on debugging output.
#define DEBUG
#define DEBUG_PAINT
#define DEBUG_MAKE
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <vips/vips.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

static int
replicate_gen( REGION *or, void *seq, void *a, void *b )
{
	REGION *ir = (REGION *) seq;
	IMAGE *in = (IMAGE *) a;
	Rect *r = &or->valid;
	int twidth = in->Xsize;
	int theight = in->Ysize;
	int x, y;
	Rect tile;

	/* Find top left of tiles we need.
	 */
	int xs = (r->left / twidth) * twidth;
	int ys = (r->top / theight) * theight;

	/* The tile enclosing the top-left corner of the requested area.
	 */
	tile.left = xs;
	tile.top = ys;
	tile.width = twidth;
	tile.height = theight;

	/* If the request fits inside a single tile, we can just pointer-copy.
	 */
	if( im_rect_includesrect( &tile, r ) ) {
		Rect irect;

		/* Translate request to input space.
		 */
		irect = *r;
		irect.left -= xs;
		irect.top -= ys;
		if( im_prepare( ir, &irect ) )
			return( -1 );

		if( im_region_region( or, ir, r, irect.left, irect.top ) )
			return( -1 );

		return( 0 );
	}

	for( y = ys; y < IM_RECT_BOTTOM( r ); y += theight )
		for( x = xs; x < IM_RECT_RIGHT( r ); x += twidth ) {
			Rect paint;

			/* Whole tile at x, y
			 */
			tile.left = x;
			tile.top = y;
			tile.width = twidth;
			tile.height = theight;

			/* Which parts touch the area of the output we are
			 * building.
			 */
			im_rect_intersectrect( &tile, r, &paint );

			/* Translate back to ir coordinates.
			 */
			paint.left -= x;
			paint.top -= y;

			assert( !im_rect_isempty( &paint ) );

			/* Render into or.
			 */
			if( im_prepare_to( ir, or, &paint,
				paint.left + x,
				paint.top + y ) )
				return( -1 );
		}

	return( 0 );
}

int
im_replicate( IMAGE *in, IMAGE *out, int across, int down )
{
	if( across <= 0 || down <= 0 ) {
		im_errormsg( "im_replicate: bad parameters" );
		return( -1 );
	}
	if( im_piocheck( in, out ) )
		return( -1 );
	if( im_cp_desc( out, in ) )
		return( -1 );
	out->Xsize *= across;
	out->Ysize *= down;

	/* We can render small tiles with pointer copies.
	 */
	if( im_demand_hint( out, IM_SMALLTILE, in, NULL ) )
		return( -1 );

	if( im_generate( out, 
		im_start_one, replicate_gen, im_stop_one, in, NULL ) )
		return( -1 );

	return( 0 );
}

