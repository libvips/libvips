/* im_grid
 *
 * 4/8/05
 * 7/9/05
 * 	- oops, clipping was wrong
 * 30/1/10
 * 	- gtkdoc
 * 	- small cleanups
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

#include "conversion.h"

typedef struct _VipsGrid {
	VipsConversion parent_instance;

	VipsImage *in;

	int tile_height;
	int across;
	int down;

} VipsGrid;

typedef VipsConversionClass VipsGridClass;

G_DEFINE_TYPE( VipsGrid, vips_grid, VIPS_TYPE_CONVERSION );

static int
vips_grid_gen( VipsRegion *or, void *vseq, void *a, void *b,
	gboolean *stop )
{
	VipsRegion *ir = (VipsRegion *) vseq;
	VipsGrid *grid = (VipsGrid *) b;
	VipsRect *r = &or->valid;
	int twidth = grid->in->Xsize;
	int theight = grid->tile_height;

	int x, y;
	VipsRect tile;

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
	if( vips_rect_includesrect( &tile, r ) ) {
		Rect irect;

		/* Translate request to input space.
		 */
		irect = *r;
		irect.left -= xs;
		irect.top -= ys;
		irect.top += grid->across * ys + theight * (xs / twidth);

		if( vips_region_prepare( ir, &irect ) ||
			vips_region_region( or, ir, r, irect.left, irect.top ) )
			return( -1 );

		return( 0 );
	}

	for( y = ys; y < VIPS_RECT_BOTTOM( r ); y += theight )
		for( x = xs; x < VIPS_RECT_RIGHT( r ); x += twidth ) {
			VipsRect paint;
			VipsRect input;

			/* Whole tile at x, y
			 */
			tile.left = x;
			tile.top = y;
			tile.width = twidth;
			tile.height = theight;

			/* Which parts touch the area of the output we are
			 * building.
			 */
			vips_rect_intersectrect( &tile, r, &paint );

			g_assert( !vips_rect_isempty( &paint ) );

			/* Translate back to ir coordinates.
			 */
			input = paint;
			input.left -= x;
			input.top -= y;
			input.top += grid->across * y + theight * (x / twidth);

			/* Render into or.
			 */
			if( vips_region_prepare_to( ir, or, &input,
				paint.left, paint.top ) )
				return( -1 );
		}

	return( 0 );
}

static int
vips_grid_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsConversion *conversion = VIPS_CONVERSION( object );
	VipsGrid *grid = (VipsGrid *) object;

	if( VIPS_OBJECT_CLASS( vips_grid_parent_class )->build( object ) )
		return( -1 );

	if( vips_check_coding_known( class->nickname, grid->in ) ||
		vips_image_pio_input( grid->in ) )
		return( -1 );

	if( grid->in->Ysize % grid->tile_height != 0 ||
		grid->in->Ysize / grid->tile_height != 
			grid->across * grid->down ) {
		vips_error( class->nickname, "%s", _( "bad grid geometry" ) );
		return( -1 );
	}

	if( vips_image_copy_fields( conversion->out, grid->in ) )
		return( -1 );
	/* We can render small tiles with pointer copies.
	 */
	vips_demand_hint( conversion->out, 
		VIPS_DEMAND_STYLE_SMALLTILE, grid->in, NULL );
	conversion->out->Xsize = grid->in->Xsize * grid->across;
	conversion->out->Ysize = grid->tile_height * grid->down;

	if( vips_image_generate( conversion->out,
		vips_start_one, vips_grid_gen, vips_stop_one, 
		grid->in, grid ) )
		return( -1 );

	return( 0 );
}

static void
vips_grid_class_init( VipsGridClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "grid";
	vobject_class->description = _( "grid an image" );
	vobject_class->build = vips_grid_build;

	VIPS_ARG_IMAGE( class, "in", 1, 
		_( "Input" ), 
		_( "Input image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsGrid, in ) );

	VIPS_ARG_INT( class, "tile_height", 3, 
		_( "Tile height" ), 
		_( "chop into tiles this high" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsGrid, tile_height ),
		1, 10000000, 128 );

	VIPS_ARG_INT( class, "across", 4, 
		_( "Across" ), 
		_( "number of tiles across" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsGrid, across ),
		1, 10000000, 1 );

	VIPS_ARG_INT( class, "down", 5, 
		_( "Down" ), 
		_( "number of tiles down" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsGrid, down ),
		1, 10000000, 1 );

}

static void
vips_grid_init( VipsGrid *grid )
{
	grid->tile_height = 128;
	grid->across = 1;
	grid->down = 1;
}

/**
 * vips_grid:
 * @in: input image
 * @out: output image
 * @tile_height: chop into tiles this high
 * @across: tiles across
 * @down: tiles down
 * @...: %NULL-terminated list of optional named arguments
 *
 * Chop a tall thin image up into a set of tiles, lay the tiles out in a grid. 
 *
 * The input image should be a very tall, thin image containing a list of
 * smaller images. Volumetric or time-sequence images are often laid out like
 * this. This image is chopped into a series of tiles, each @tile_height
 * pixels high and the width of @in. The tiles are then rearranged into a grid
 * @across tiles across and @down tiles down in row-major order.
 *
 * Supplying @tile_height, @across and @down is not strictly necessary, we
 * only really need two of these. Requiring three is a double-check that the
 * image has the expected geometry. 
 *
 * See also: vips_embed(), vips_insert(), vips_join().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_grid( VipsImage *in, VipsImage **out, 
	int tile_height, int across, int down, ... )
{
	va_list ap;
	int result;

	va_start( ap, down );
	result = vips_call_split( "grid", ap, 
		in, out, tile_height, across, down );
	va_end( ap );

	return( result );
}
