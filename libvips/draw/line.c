/* draw straight lines
 *
 * Copyright: J. Cupitt
 * Written: 15/06/1992
 * Modified : 22/10/92 - clipping constraints changed
 * 22/7/93 JC
 *	- im_incheck() added
 * 16/8/94 JC
 *	- im_incheck() changed to im_makerw()
 * 5/12/06
 * 	- im_invalidate() after paint
 * 1/3/10
 * 	- oops, lineset needs to ask for WIO of mask and ink
 * 6/3/10
 * 	- don't im_invalidate() after paint, this now needs to be at a higher
 * 	  level
 * 27/9/10
 * 	- gtk-doc
 * 	- use draw.c base class
 * 	- do pointwise clipping
 * 	- rename as im_draw_line() for consistency
 * 	- cleanups!
 * 6/2/14
 * 	- redo as a class
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

#include <vips/vips.h>

#include "pdraw.h"
#include "line.h"

G_DEFINE_TYPE( VipsLine, vips_line, VIPS_TYPE_DRAW );

static int
vips_line_draw( VipsLine *line )
{
	VipsLineClass *class = VIPS_LINE_GET_CLASS( line );
	VipsLinePlotPoint plot_point = class->plot_point; 

	int x, y, err;

	/* Start point and offset.
	 */
	x = line->x1; 
	y = line->y1;

	/* Special case: zero width and height is single point.
	 */
	if( line->dx == 0 && line->dy == 0 ) {
		if( plot_point( line, x, y ) ) 
			return( -1 );
	}
	/* Special case vertical and horizontal lines for speed.
	 */
	else if( line->dx == 0 ) {
		/* Vertical line going down.
		 */
		for( ; y <= line->y2; y++ ) {
			if( plot_point( line, x, y ) )
				return( -1 );
		}
	}
	else if( line->dy == 0 ) {
		/* Horizontal line to the right.
		 */
		for( ; x <= line->x2; x++ ) {
			if( plot_point( line, x, y ) )
				return( -1 );
		}
	}
	/* Special case diagonal lines.
	 */
	else if( abs( line->dy ) == abs( line->dx ) && line->dy > 0 ) {
		/* Diagonal line going down and right.
		 */
		for( ; x <= line->x2; x++, y++ ) {
			if( plot_point( line, x, y ) )
				return( -1 );
		}
	}
	else if( abs( line->dy ) == abs( line->dx ) && line->dy < 0 ) {
		/* Diagonal line going up and right.
		 */
		for( ; x <= line->x2; x++, y-- ) {
			if( plot_point( line, x, y ) )
				return( -1 );
		}
	}
	else if( abs( line->dy ) < abs( line->dx ) && line->dy > 0 ) {
		/* Between -45 and 0 degrees.
		 */
		for( err = 0; x <= line->x2; x++ ) {
			if( plot_point( line, x, y ) )
				return( -1 );

			err += line->dy;
			if( err >= line->dx ) {
				err -= line->dx;
				y++;
			}
		}
	}
	else if( abs( line->dy ) < abs( line->dx ) && line->dy < 0 ) {
		/* Between 0 and 45 degrees.
		 */
		for( err = 0; x <= line->x2; x++ ) {
			if( plot_point( line, x, y ) )
				return( -1 );

			err -= line->dy;
			if( err >= line->dx ) {
				err -= line->dx;
				y--;
			}
		}
	}
	else if( abs( line->dy ) > abs( line->dx ) && line->dx > 0 ) {
		/* Between -45 and -90 degrees.
		 */
		for( err = 0; y <= line->y2; y++ ) {
			if( plot_point( line, x, y ) )
				return( -1 );

			err += line->dx;
			if( err >= line->dy ) {
				err -= line->dy;
				x++;
			}
		}
	}
	else if( abs( line->dy ) > abs( line->dx ) && line->dx < 0 ) {
		/* Between -90 and -135 degrees.
		 */
		for( err = 0; y <= line->y2; y++ ) {
			if( plot_point( line, x, y ) )
				return( -1 );

			err -= line->dx;
			if( err >= line->dy ) {
				err -= line->dy;
				x--;
			}
		}
	}
	else
		g_assert( 0 );

	return( 0 );
}

static int
vips_line_build( VipsObject *object )
{
	VipsDraw *draw = VIPS_DRAW( object );
	VipsLine *line = (VipsLine *) object;

	if( VIPS_OBJECT_CLASS( vips_line_parent_class )->build( object ) )
		return( -1 );

	/* Find offsets.
	 */
	line->dx = line->x2 - line->x1;
	line->dy = line->y2 - line->y1;

	/* Swap endpoints to reduce number of cases. 
	 */
	if( abs( line->dx ) >= abs( line->dy ) && line->dx < 0 ) {
		/* Swap to get all x greater or equal cases going to the 
		 * right. Do diagonals here .. just have up and right and down
		 * and right now.
		 */
		VIPS_SWAP( int, line->x1, line->x2 );
		VIPS_SWAP( int, line->y1, line->y2 );
	}
	else if( abs( line->dx ) < abs( line->dy ) && line->dy < 0 ) {
		/* Swap to get all y greater cases going down the screen.
		 */
		VIPS_SWAP( int, line->x1, line->x2 );
		VIPS_SWAP( int, line->y1, line->y2 );
	}

	/* Recalculate dx, dy.
	 */
	line->dx = line->x2 - line->x1;
	line->dy = line->y2 - line->y1;

	if( line->x1 < draw->image->Xsize && 
		line->x1 >= 0 &&
		line->x2 < draw->image->Xsize && 
		line->x2 >= 0 &&
		line->y1 < draw->image->Ysize && 
		line->y1 >= 0 &&
		line->y2 < draw->image->Ysize && 
		line->y2 >= 0 )
		VIPS_DRAW( line )->noclip = TRUE;

	if( vips_line_draw( line ) ) 
		return( -1 );

	return( 0 );
}

static int
vips_line_plot_point( VipsLine *line, int x, int y ) 
{
	VipsDraw *draw = (VipsDraw *) line;

	if( draw->noclip )
		vips__draw_pel( draw, VIPS_IMAGE_ADDR( draw->image, x, y ) );
	else
		vips__draw_pel_clip( draw, x, y );

	return( 0 );
}

static void
vips_line_class_init( VipsLineClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "line";
	vobject_class->description = _( "draw a line on an image" );
	vobject_class->build = vips_line_build;

	class->plot_point = vips_line_plot_point; 

	VIPS_ARG_INT( class, "x1", 3, 
		_( "x1" ), 
		_( "Start of line" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsLine, x1 ),
		-1000000000, 1000000000, 0 );

	VIPS_ARG_INT( class, "y1", 4, 
		_( "y1" ), 
		_( "Start of line" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsLine, y1 ),
		-1000000000, 1000000000, 0 );

	VIPS_ARG_INT( class, "x2", 5, 
		_( "x2" ), 
		_( "End of line" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsLine, x2 ),
		-1000000000, 1000000000, 0 );

	VIPS_ARG_INT( class, "y2", 6, 
		_( "y2" ), 
		_( "End of line" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsLine, y2 ),
		-1000000000, 1000000000, 0 );

}

static void
vips_line_init( VipsLine *line )
{
}

static int
vips_linev( VipsImage *image, 
	double *ink, int n, int x1, int y1, int x2, int y2, va_list ap )
{
	VipsArea *area_ink;
	int result;

	area_ink = (VipsArea *) vips_array_double_new( ink, n );
	result = vips_call_split( "line", ap, 
		image, area_ink, x1, y1, x2, y2 );
	vips_area_unref( area_ink );

	return( result );
}

/**
 * vips_line:
 * @image: image to draw on
 * @ink: (array length=n): value to draw
 * @n length of ink array
 *
 * Draws a 1-pixel-wide line on an image. Subclass and override ::plot to draw
 * lines made of other objects. See vips_draw_mask(). 
 *
 * @ink is an array of double containing values to draw. 
 *
 * See also: vips_line1(), vips_circle(), vips_draw_mask(). 
 *
 * Returns: 0 on success, or -1 on error.
 */
int
vips_line( VipsImage *image, 
	double *ink, int n, int x1, int y1, int x2, int y2, ... )
{
	va_list ap;
	int result;

	va_start( ap, y2 );
	result = vips_linev( image, ink, n, x1, y1, x2, y2, ap );
	va_end( ap );

	return( result );
}

/**
 * vips_line1:
 * @image: image to draw on
 * @ink: value to draw
 *
 * As vips_line(), but just takes a single double for @ink. 
 *
 * See also: vips_line(), vips_circle().
 *
 * Returns: 0 on success, or -1 on error.
 */
int
vips_line1( VipsImage *image, double ink, int x1, int y1, int x2, int y2, ... )
{
	double array_ink[1];
	va_list ap;
	int result;

	array_ink[0] = ink; 

	va_start( ap, y2 );
	result = vips_linev( image, array_ink, 1, x1, y1, x2, y2, ap );
	va_end( ap );

	return( result );
}
