/* draw a draw_circle on an image
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
 * 3/2/14
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

#include <string.h>

#include <vips/vips.h>

#include "pdraw.h"

typedef struct _VipsDrawCircle {
	VipsDraw parent_object;

	int cx;
	int cy;
	int radius;
	gboolean fill;

	VipsPel *centre;
} VipsDrawCircle;

typedef VipsDrawClass VipsDrawCircleClass;

G_DEFINE_TYPE( VipsDrawCircle, vips_draw_circle, VIPS_TYPE_DRAW );

static void
vips_draw_circle_octants( VipsDrawCircle *circle, int x, int y )
{
	VipsDraw *draw = VIPS_DRAW( circle );
	const int cx = circle->cx;
	const int cy = circle->cy;

	if( circle->fill ) {
		vips__draw_scanline( draw, cy + y, cx - x, cx + x );
		vips__draw_scanline( draw, cy - y, cx - x, cx + x );
		vips__draw_scanline( draw, cy + x, cx - y, cx + y );
		vips__draw_scanline( draw, cy - x, cx - y, cx + y );
	}
	else if( draw->noclip ) {
		const size_t lsize = draw->lsize;
		const size_t psize = draw->psize;
		VipsPel *centre = circle->centre;

		vips__draw_pel( draw, centre + lsize * y - psize * x );
		vips__draw_pel( draw, centre + lsize * y + psize * x );
		vips__draw_pel( draw, centre - lsize * y - psize * x );
		vips__draw_pel( draw, centre - lsize * y + psize * x );
		vips__draw_pel( draw, centre + lsize * x - psize * y );
		vips__draw_pel( draw, centre + lsize * x + psize * y );
		vips__draw_pel( draw, centre - lsize * x - psize * y );
		vips__draw_pel( draw, centre - lsize * x + psize * y );
	}
	else {
		vips__draw_pel_clip( draw, cx + y, cy - x );
		vips__draw_pel_clip( draw, cx + y, cy + x );
		vips__draw_pel_clip( draw, cx - y, cy - x );
		vips__draw_pel_clip( draw, cx - y, cy + x );
		vips__draw_pel_clip( draw, cx + x, cy - y );
		vips__draw_pel_clip( draw, cx + x, cy + y );
		vips__draw_pel_clip( draw, cx - x, cy - y );
		vips__draw_pel_clip( draw, cx - x, cy + y );
	}
}

static int
vips_draw_circle_build( VipsObject *object )
{
	VipsDraw *draw = VIPS_DRAW( object );
	VipsDrawCircle *circle = (VipsDrawCircle *) object;

	int x, y, d;

	if( VIPS_OBJECT_CLASS( vips_draw_circle_parent_class )->build( object ) )
		return( -1 );

	circle->centre = VIPS_IMAGE_ADDR( draw->image, circle->cx, circle->cy );

	if( circle->cx - circle->radius >= 0 && 
		circle->cx + circle->radius < draw->image->Xsize &&
		circle->cy - circle->radius >= 0 && 
		circle->cy + circle->radius < draw->image->Ysize )
		draw->noclip = TRUE;

	y = circle->radius;
	d = 3 - 2 * circle->radius;

	for( x = 0; x < y; x++ ) {
		vips_draw_circle_octants( circle, x, y );

		if( d < 0 )
			d += 4 * x + 6;
		else {
			d += 4 * (x - y) + 10;
			y--;
		}
	}

	if( x == y ) 
		vips_draw_circle_octants( circle, x, y );

	return( 0 );
}

static void
vips_draw_circle_class_init( VipsDrawCircleClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "draw_circle";
	vobject_class->description = _( "draw a draw_circle on an image" );
	vobject_class->build = vips_draw_circle_build;

	VIPS_ARG_INT( class, "cx", 3, 
		_( "cx" ), 
		_( "Centre of draw_circle" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsDrawCircle, cx ),
		-1000000000, 1000000000, 0 );

	VIPS_ARG_INT( class, "cy", 4, 
		_( "cy" ), 
		_( "Centre of draw_circle" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsDrawCircle, cy ),
		-1000000000, 1000000000, 0 );

	VIPS_ARG_INT( class, "radius", 5, 
		_( "Radius" ), 
		_( "Radius in pixels" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsDrawCircle, radius ),
		0, 1000000000, 0 );

	VIPS_ARG_BOOL( class, "fill", 6, 
		_( "Fill" ), 
		_( "Draw a solid object" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsDrawCircle, fill ),
		FALSE ); 

}

static void
vips_draw_circle_init( VipsDrawCircle *circle )
{
	circle->fill = FALSE;
}

static int
vips_draw_circlev( VipsImage *image, 
	double *ink, int n, int cx, int cy, int radius, va_list ap )
{
	VipsArea *area_ink;
	int result;

	area_ink = (VipsArea *) vips_array_double_new( ink, n );
	result = vips_call_split( "draw_circle", ap, 
		image, area_ink, cx, cy, radius );
	vips_area_unref( area_ink );

	return( result );
}

/**
 * vips_draw_circle:
 * @image: image to draw on
 * @ink: (array length=n): value to draw
 * @n: length of ink array
 * @cx: centre of draw_circle
 * @cy: centre of draw_circle
 * @radius: draw_circle radius
 *
 * Optional arguments:
 *
 * @fill: fill the draw_circle
 *
 * Draws a circle on @image. If @fill is %TRUE then the circle is filled,
 * otherwise a 1-pixel-wide perimeter is drawn.
 *
 * @ink is an array of double containing values to draw. 
 *
 * See also: vips_draw_circle1(), vips_line().
 *
 * Returns: 0 on success, or -1 on error.
 */
int
vips_draw_circle( VipsImage *image, 
	double *ink, int n, int cx, int cy, int radius, ... )
{
	va_list ap;
	int result;

	va_start( ap, radius );
	result = vips_draw_circlev( image, ink, n, cx, cy, radius, ap );
	va_end( ap );

	return( result );
}

/**
 * vips_draw_circle1:
 * @image: image to draw on
 * @ink: value to draw
 * @cx: centre of draw_circle
 * @cy: centre of draw_circle
 * @radius: draw_circle radius
 *
 * Optional arguments:
 *
 * @fill: fill the draw_circle
 *
 * As vips_draw_circle(), but just takes a single double for @ink. 
 *
 * See also: vips_draw_circle().
 *
 * Returns: 0 on success, or -1 on error.
 */
int
vips_draw_circle1( VipsImage *image, 
	double ink, int cx, int cy, int radius, ... )
{
	double array_ink[1];
	va_list ap;
	int result;

	array_ink[0] = ink; 

	va_start( ap, radius );
	result = vips_draw_circlev( image, array_ink, 1, cx, cy, radius, ap );
	va_end( ap );

	return( result );
}

