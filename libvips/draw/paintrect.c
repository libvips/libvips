/* Fill Rect r of image im with pels of colour ink. 
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
 * 22/9/10
 * 	- gtk-doc
 * 	- added 'fill'
 * 	- renamed as im_draw_rect() for consistency
 * 27/9/10
 * 	- memcpy() subsequent lines of the rect
 * 10/2/14	
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
#include <string.h>

#include <vips/vips.h>
#include <vips/internal.h>

#include "pdraw.h"

typedef struct _VipsPaintrect {
	VipsDraw parent_object;

	/* Parameters.
	 */
	int left;
	int top;
	int width;
	int height;
	gboolean fill; 

} VipsPaintrect;

typedef struct _VipsPaintrectClass {
	VipsDrawClass parent_class;

} VipsPaintrectClass; 

G_DEFINE_TYPE( VipsPaintrect, vips_paintrect, VIPS_TYPE_DRAW );

static int
vips_paintrect_build( VipsObject *object )
{
	VipsDraw *draw = VIPS_DRAW( object );
	VipsPaintrect *paintrect = (VipsPaintrect *) object;
	int left = paintrect->left;
	int top = paintrect->top;
	int width = paintrect->width;
	int height = paintrect->height;

	VipsRect image;
	VipsRect rect; 
	VipsRect clip;

	if( VIPS_OBJECT_CLASS( vips_paintrect_parent_class )->build( object ) )
		return( -1 );

	/* Also use a solid fill for very narrow unfilled rects.
	 */
	if( !paintrect->fill &&
		width > 2 &&
		height > 2 ) 
		return( vips_paintrect( draw->image, 
				draw->ink->data, draw->ink->n, 
				left, top, width, 1, NULL ) ||
			vips_paintrect( draw->image, 
				draw->ink->data, draw->ink->n, 
				left + width - 1, top, 1, height, NULL ) ||
			vips_paintrect( draw->image, 
				draw->ink->data, draw->ink->n, 
				left, top + height - 1, width, 1, NULL ) ||
			vips_paintrect( draw->image, 
				draw->ink->data, draw->ink->n, 
				left, top, 1, height, NULL ) );

	image.left = 0;
	image.top = 0;
	image.width = draw->image->Xsize;
	image.height = draw->image->Ysize;
	rect.left = left;
	rect.top = top;
	rect.width = width;
	rect.height = height;
	vips_rect_intersectrect( &rect, &image, &clip );

	if( !vips_rect_isempty( &clip ) ) {
		VipsPel *to = 
			VIPS_IMAGE_ADDR( draw->image, clip.left, clip.top );

		VipsPel *q;
		int x, y;

		/* We plot the first line pointwise, then memcpy() it for the
		 * subsequent lines.
		 */

		q = to;
		for( x = 0; x < clip.width; x++ ) {
			vips__draw_pel( draw, q );
			q += draw->psize;
		}

		q = to + draw->lsize;
		for( y = 1; y < clip.height; y++ ) {
			memcpy( q, to, clip.width * draw->psize );
			q += draw->lsize;
		}
	}

	return( 0 );
}

static void
vips_paintrect_class_init( VipsPaintrectClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "paintrect";
	vobject_class->description = _( "paint a rectangle on an image" );
	vobject_class->build = vips_paintrect_build;

	VIPS_ARG_INT( class, "left", 6, 
		_( "Left" ), 
		_( "Rect to fill" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsPaintrect, left ),
		-1000000000, 1000000000, 0 );

	VIPS_ARG_INT( class, "top", 7, 
		_( "top" ), 
		_( "Rect to fill" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsPaintrect, top ),
		-1000000000, 1000000000, 0 );

	VIPS_ARG_INT( class, "width", 8, 
		_( "width" ), 
		_( "Rect to fill" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsPaintrect, width ),
		-1000000000, 1000000000, 0 );

	VIPS_ARG_INT( class, "height", 9, 
		_( "height" ), 
		_( "Rect to fill" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsPaintrect, height ),
		-1000000000, 1000000000, 0 );

	VIPS_ARG_BOOL( class, "fill", 10, 
		_( "Fill" ), 
		_( "Draw a solid object" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsPaintrect, fill ),
		FALSE ); 

}

static void
vips_paintrect_init( VipsPaintrect *paintrect )
{
}

static int
vips_paintrectv( VipsImage *image, 
	double *ink, int n, int left, int top, int width, int height, 
	va_list ap )
{
	VipsArea *area_ink;
	int result;

	area_ink = (VipsArea *) vips_array_double_new( ink, n );
	result = vips_call_split( "paintrect", ap, 
		image, area_ink, left, top, width, height ); 
	vips_area_unref( area_ink );

	return( result );
}

/**
 * vips_paintrect:
 * @image: image to draw on
 * @ink: (array length=n): value to draw
 * @n: length of ink array
 * @left: area to paint
 * @top: area to paint
 * @width: area to paint
 * @height: area to paint
 *
 * Optional arguments:
 *
 * @fill: fill the rect
 *
 * Paint pixels within @left, @top, @width, @height in @image with @ink. If
 * @fill is zero, just paint a 1-pixel-wide outline.
 *
 * See also: vips_circle().
 *
 * Returns: 0 on success, or -1 on error.
 */
int
vips_paintrect( VipsImage *image, 
	double *ink, int n, int left, int top, int width, int height, ... ) 
{
	va_list ap;
	int result;

	va_start( ap, height );
	result = vips_paintrectv( image, 
		ink, n, left, top, width, height, ap ); 
	va_end( ap );

	return( result );
}

/**
 * vips_paintrect1:
 * @image: image to draw on
 * @ink: (array length=n): value to draw
 * @n: length of ink array
 * @left: area to paint
 * @top: area to paint
 * @width: area to paint
 * @height: area to paint
 *
 * Optional arguments:
 *
 * @fill: fill the rect
 *
 * As vips_painrect(), but just takes a single double for @ink. 
 *
 * See also: vips_paintrect().
 *
 * Returns: 0 on success, or -1 on error.
 */
int
vips_paintrect1( VipsImage *image, 
	double ink, int left, int top, int width, int height, ... ) 
{
	double array_ink[1];
	va_list ap;
	int result;

	array_ink[0] = ink; 

	va_start( ap, height );
	result = vips_paintrectv( image, 
		array_ink, 1, left, top, width, height, ap );
	va_end( ap );

	return( result );
}

