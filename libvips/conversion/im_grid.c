/* chop a tall thin image up into a grid ... useful for displaying volumetric
 * images
 *
 * 4/8/05
 * 7/9/05
 * 	- oops, clipping was wrong
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

typedef struct _Grid {
	IMAGE *in;
	IMAGE *out;
	int tile_height;
	int across;
	int down;
} Grid;

static int
grid_gen( REGION *or, void *seq, void *a, void *b )
{
	REGION *ir = (REGION *) seq;
	Grid *grid = (Grid *) b;
	Rect *r = &or->valid;
	int twidth = grid->in->Xsize;
	int theight = grid->tile_height;
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
		irect.top += grid->across * ys + theight * (xs / twidth);

		if( im_prepare( ir, &irect ) ||
			im_region_region( or, ir, r, irect.left, irect.top ) )
			return( -1 );

		return( 0 );
	}

	for( y = ys; y < IM_RECT_BOTTOM( r ); y += theight )
		for( x = xs; x < IM_RECT_RIGHT( r ); x += twidth ) {
			Rect paint;
			Rect input;

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

			assert( !im_rect_isempty( &paint ) );

			/* Translate back to ir coordinates.
			 */
			input = paint;
			input.left -= x;
			input.top -= y;
			input.top += grid->across * y + theight * (x / twidth);

			/* Render into or.
			 */
			if( im_prepare_to( ir, or, &input,
				paint.left, paint.top ) )
				return( -1 );
		}

	return( 0 );
}

int
im_grid( IMAGE *in, IMAGE *out, int tile_height, int across, int down )
{
	Grid *grid = IM_NEW( out, Grid );

	if( !grid || im_piocheck( in, out ) )
		return( -1 );
	if( across <= 0 || down <= 0 ) {
		im_error( "im_grid", "%s", _( "bad parameters" ) );
		return( -1 );
	}
	if( in->Ysize % tile_height != 0 ||
		in->Ysize / tile_height != across * down ) {
		im_error( "im_grid", "%s", _( "bad grid geometry" ) );
		return( -1 );
	}

	grid->in = in;
	grid->out = out;
	grid->tile_height = tile_height;
	grid->across = across;
	grid->down = down;

	if( im_cp_desc( out, in ) )
		return( -1 );
	out->Xsize = in->Xsize * across;
	out->Ysize = tile_height * down;

	/* We can render small tiles with pointer copies.
	 */
	if( im_demand_hint( out, IM_SMALLTILE, in, NULL ) )
		return( -1 );

	if( im_generate( out, 
		im_start_one, grid_gen, im_stop_one, in, grid ) )
		return( -1 );

	return( 0 );
}

