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
#include <vips/internal.h>

#include "drawink.h"

typedef struct _VipsDrawCircle {
	VipsDrawink parent_object;

	int cx;
	int cy;
	int radius;
	gboolean fill;

} VipsDrawCircle;

typedef struct _VipsDrawCircleClass {
	VipsDrawinkClass parent_class;

} VipsDrawCircleClass; 

G_DEFINE_TYPE( VipsDrawCircle, vips_draw_circle, VIPS_TYPE_DRAWINK );

void
vips__draw_circle_direct( VipsImage *image, int cx, int cy, int r,
	VipsDrawScanline draw_scanline, void *client )
{
	int x, y, d;

	y = r;
	d = 3 - 2 * r;

	for( x = 0; x < y; x++ ) {
		draw_scanline( image, cy + y, cx - x, cx + x, client );
		draw_scanline( image, cy - y, cx - x, cx + x, client );
		draw_scanline( image, cy + x, cx - y, cx + y, client );
		draw_scanline( image, cy - x, cx - y, cx + y, client );

		if( d < 0 )
			d += 4 * x + 6;
		else {
			d += 4 * (x - y) + 10;
			y--;
		}
	}

	if( x == y ) 
		draw_scanline( image, cy + y, cx - x, cx + x, client );
		draw_scanline( image, cy - y, cx - x, cx + x, client );
		draw_scanline( image, cy + x, cx - y, cx + y, client );
		draw_scanline( image, cy - x, cx - y, cx + y, client );
}

static inline void
vips_draw_circle_draw_point( VipsImage *image, int x, int y, void *client )
{
	VipsPel *ink = (VipsPel *) client; 
	VipsPel *q = VIPS_IMAGE_ADDR( image, x, y );
	int psize = VIPS_IMAGE_SIZEOF_PEL( image ); 

 	int j;

	/* Faster than memcopy() for n < about 20.
	 */
	for( j = 0; j < psize; j++ ) 
		q[j] = ink[j];
}

/* Paint endpoints, with clip.
 */
static void 
vips_draw_circle_draw_endpoints_clip( VipsImage *image,
	int y, int x1, int x2, void *client )
{
	if( y >= 0 &&
		y < image->Ysize ) {
		if( x1 >=0 &&
			x1 < image->Xsize )
			vips_draw_circle_draw_point( image, x1, y, client );
		if( x2 >=0 &&
			x2 < image->Xsize )
			vips_draw_circle_draw_point( image, x2, y, client );
	}
}

/* Paint endpoints, no clip.
 */
static void 
vips_draw_circle_draw_endpoints_noclip( VipsImage *image,
	int y, int x1, int x2, void *client )
{
	vips_draw_circle_draw_point( image, x1, y, client );
	vips_draw_circle_draw_point( image, x2, y, client );
}

/* Paint scanline.
 */
static void 
vips_draw_circle_draw_scanline( VipsImage *image,
	int y, int x1, int x2, void *client )
{
	VipsPel *ink = (VipsPel *) client; 
	int psize = VIPS_IMAGE_SIZEOF_PEL( image ); 

	VipsPel *q;
	int len;
	int i, j;

	g_assert( x1 <= x2 );

	if( y < 0 || 
		y >= image->Ysize )
		return;
	if( x1 < 0 && 
		x2 < 0 )
		return;
	if( x1 >= image->Xsize && 
		x2 >= image->Xsize )
		return;
	x1 = VIPS_CLIP( 0, x1, image->Xsize - 1 );
	x2 = VIPS_CLIP( 0, x2, image->Xsize - 1 );

	q = VIPS_IMAGE_ADDR( image, x1, y );
	len = x2 - x1 + 1;

	for( i = 0; i < len; i++ ) {
		for( j = 0; j < psize; j++ )
			q[j] = ink[j];

		q += psize;
	}
}

static int
vips_draw_circle_build( VipsObject *object )
{
	VipsDraw *draw = VIPS_DRAW( object );
	VipsDrawink *drawink = VIPS_DRAWINK( object );
	VipsDrawCircle *circle = (VipsDrawCircle *) object;

	VipsDrawScanline draw_scanline;

	if( VIPS_OBJECT_CLASS( vips_draw_circle_parent_class )->
		build( object ) )
		return( -1 );

	if( circle->fill )
		draw_scanline = vips_draw_circle_draw_scanline;
	else if( circle->cx - circle->radius >= 0 && 
		circle->cx + circle->radius < draw->image->Xsize &&
		circle->cy - circle->radius >= 0 && 
		circle->cy + circle->radius < draw->image->Ysize )
		draw_scanline = vips_draw_circle_draw_endpoints_noclip; 
		else
		draw_scanline = vips_draw_circle_draw_endpoints_clip; 

	vips__draw_circle_direct( draw->image, 
		circle->cx, circle->cy, circle->radius,
		draw_scanline, drawink->pixel_ink );

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
 * @...: %NULL-terminated list of optional named arguments
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
 * @...: %NULL-terminated list of optional named arguments
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

