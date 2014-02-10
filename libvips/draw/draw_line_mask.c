/* draw a mask along a line
 *
 * Copyright: J. Cupitt
 * Written: 15/06/1992
 * 22/7/93 JC
 *	- im_incheck() added
 * 16/8/94 JC
 *	- im_incheck() changed to im_makerw()
 * 24/10/03 JC
 *	- now blends with 0-255 mask
 * 5/12/06
 * 	- im_invalidate() after paint
 * 6/3/10
 * 	- don't im_invalidate() after paint, this now needs to be at a higher
 * 	  level
 * 28/9/10
 * 	- gtk-doc
 * 	- renamed as im_draw_mask()
 * 	- use Draw base class
 * 6/2/14
 * 	- now a subclass of VipsDrawLine
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
#include "draw_line.h"

typedef struct _VipsDrawLineMask {
	VipsDrawLine parent_object;

	VipsImage *mask;

} VipsDrawLineMask;

typedef VipsDrawLineClass VipsDrawLineMaskClass;

G_DEFINE_TYPE( VipsDrawLineMask, vips_draw_line_mask, VIPS_TYPE_DRAW_LINE );

static int
vips_draw_line_mask_plot_point( VipsDrawLine *line, int x, int y ) 
{
	VipsDraw *draw = (VipsDraw *) line;
	VipsDrawLineMask *mask = (VipsDrawLineMask *) line;

	return( vips_draw_mask( draw->image, 
		draw->ink->data, draw->ink->n, mask->mask, x, y, NULL ) ); 
}

static void
vips_draw_line_mask_class_init( VipsDrawLineMaskClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "draw_line_mask";
	vobject_class->description = _( "draw a mask along a line" );

	class->plot_point = vips_draw_line_mask_plot_point; 

	VIPS_ARG_IMAGE( class, "mask", 7, 
		_( "Mask" ), 
		_( "Mask image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsDrawLineMask, mask ) ); 

}

static void
vips_draw_line_mask_init( VipsDrawLineMask *draw_line_mask )
{
}

static int
vips_draw_line_maskv( VipsImage *image, 
	double *ink, int n, int x1, int y1, int x2, int y2, VipsImage *mask,
	va_list ap )
{
	VipsArea *area_ink;
	int result;

	area_ink = (VipsArea *) vips_array_double_new( ink, n );
	result = vips_call_split( "draw_line_mask", ap, 
		image, area_ink, x1, y1, x2, y2, mask );
	vips_area_unref( area_ink );

	return( result );
}

/**
 * vips_draw_line_mask:
 * @image: image to draw on
 * @ink: (array length=n): value to draw
 * @n: length of ink array
 * @x1: start of line
 * @y1: start of line
 * @x2: end of line
 * @y2: end of line
 * @mask: mask to draw along line
 *
 * Draws @mask at every point along a line. 
 *
 * @ink is an array of double containing values to draw. 
 *
 * See also: vips_draw_line_mask1(), vips_draw_line(), vips_draw_mask(). 
 *
 * Returns: 0 on success, or -1 on error.
 */
int
vips_draw_line_mask( VipsImage *image, 
	double *ink, int n, int x1, int y1, int x2, int y2, 
	VipsImage *mask, ... )
{
	va_list ap;
	int result;

	va_start( ap, mask );
	result = vips_draw_line_maskv( image, ink, n, x1, y1, x2, y2, mask, ap );
	va_end( ap );

	return( result );
}

/**
 * vips_draw_line_mask1:
 * @image: image to draw on
 * @ink: value to draw
 * @x1: start of line
 * @y1: start of line
 * @x2: end of line
 * @y2: end of line
 * @mask: mask to draw along line
 *
 * As vips_draw_line_mask(), but just takes a single double for @ink. 
 *
 * See also: vips_draw_line_mask(), vips_circle().
 *
 * Returns: 0 on success, or -1 on error.
 */
int
vips_draw_line_mask1( VipsImage *image, 
	double ink, int x1, int y1, int x2, int y2, VipsImage *mask, ... )
{
	double array_ink[1];
	va_list ap;
	int result;

	array_ink[0] = ink; 

	va_start( ap, mask );
	result = vips_draw_line_maskv( image, 
		array_ink, 1, x1, y1, x2, y2, mask, ap );
	va_end( ap );

	return( result );
}
