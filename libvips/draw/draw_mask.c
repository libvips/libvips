/* Draw a mask on an image.
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
 * 7/2/14
 * 	- redo as a class
 * 	- now it's VipsDrawMask
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
#include <vips/internal.h>

#include "drawink.h"

typedef struct _VipsDrawMask {
	VipsDrawink parent_object;

	/* Parameters.
	 */
	VipsImage *mask;
	int x;
	int y;

	/* Derived.
	 */
	VipsRect image_clip;
	VipsRect mask_clip;
} VipsDrawMask;

typedef struct _VipsDrawMaskClass {
	VipsDrawinkClass parent_class;

} VipsDrawMaskClass; 

G_DEFINE_TYPE( VipsDrawMask, vips_draw_mask, VIPS_TYPE_DRAWINK );

/* Paint ink into an 8 or 16 bit integer image.
 */
#define IBLEND( TYPE, TO, INK ) { \
	TYPE *tto = (TYPE *) (TO); \
	TYPE *tink = (TYPE *) (INK); \
 	\
	int x, i, j; \
 	\
	for( j = 0, x = 0; x < width; x++ ) \
		for( i = 0; i < bands; i++, j++ ) \
			tto[j] = (tink[i] * m[x] + \
				tto[j] * (255 - m[x])) / 255; \
}

/* Do the blend with doubles.
 */
#define DBLEND( TYPE, TO, INK ) { \
	TYPE *tto = (TYPE *) (TO); \
	TYPE *tink = (TYPE *) (INK); \
 	\
	int x, i, j; \
 	\
	for( j = 0, x = 0; x < width; x++ ) \
		for( i = 0; i < bands; i++, j++ ) \
			tto[j] = ((double) tink[i] * m[x] + \
				(double) tto[j] * (255 - m[x])) / 255; \
}

/* Blend of complex.
 */
#define CBLEND( TYPE, TO, INK ) { \
	TYPE *tto = (TYPE *) (TO); \
	TYPE *tink = (TYPE *) (INK); \
 	\
	int x, i, j; \
 	\
	for( j = 0, x = 0; x < width; x++ ) \
		for( i = 0; i < bands * 2; i += 2, j += 2 ) { \
			tto[j] = ((double) tink[i] * m[x] + \
				(double) tto[j] * (255 - m[x])) / 255;\
			tto[j + 1] = ((double) tink[i + 1] * m[x] + \
				(double) tto[j + 1] * (255 - m[x])) / \
				255;\
		} \
}

static int
vips_draw_mask_draw_labq( VipsImage *image, VipsImage *mask, VipsPel *ink, 
	VipsRect *image_clip, VipsRect *mask_clip )
{
	int width = image_clip->width;
	int height = image_clip->height;
	int bands = image->Bands; 

	float *lab_buffer;
	int y;

	if( !(lab_buffer = VIPS_ARRAY( NULL, width * 3, float )) )
		return( -1 );

	for( y = 0; y < height; y++ ) {
		VipsPel *to = VIPS_IMAGE_ADDR( image, 
			image_clip->left, 
			y + image_clip->top );
		VipsPel *m = VIPS_IMAGE_ADDR( mask, 
			mask_clip->left, 
			y + mask_clip->top );

		vips__LabQ2Lab_vec( lab_buffer, to, width );
		DBLEND( float, lab_buffer, (double *) ink );
		vips__Lab2LabQ_vec( to, lab_buffer, width );
	}

	g_free( lab_buffer );

	return( 0 );
}

static int
vips_draw_mask_draw( VipsImage *image, VipsImage *mask, VipsPel *ink, 
	VipsRect *image_clip, VipsRect *mask_clip )
{
	int width = image_clip->width;
	int height = image_clip->height;
	int bands = image->Bands; 

	int y;

	for( y = 0; y < height; y++ ) {
		VipsPel *to = VIPS_IMAGE_ADDR( image, 
			image_clip->left, y + image_clip->top );
		VipsPel *m = VIPS_IMAGE_ADDR( mask, 
			mask_clip->left, y + mask_clip->top );

		switch( image->BandFmt ) {
		case VIPS_FORMAT_UCHAR: 
			IBLEND( unsigned char, to, ink );
			break;

		case VIPS_FORMAT_CHAR: 
			IBLEND( signed char, to, ink );
			break;

		case VIPS_FORMAT_USHORT: 
			IBLEND( unsigned short, to, ink );
			break;

		case VIPS_FORMAT_SHORT: 
			IBLEND( signed short, to, ink );
			break;

		case VIPS_FORMAT_UINT: 
			DBLEND( unsigned int, to, ink );
			break;

		case VIPS_FORMAT_INT: 
			DBLEND( signed int, to, ink );
			break;

		case VIPS_FORMAT_FLOAT:  
			DBLEND( float, to, ink );
			break;

		case VIPS_FORMAT_DOUBLE:
			DBLEND( double, to, ink );
			break;

		case VIPS_FORMAT_COMPLEX:
			CBLEND( float, to, ink );
			break;

		case VIPS_FORMAT_DPCOMPLEX:
			CBLEND( double, to, ink );
			break;

		default:
			g_assert( 0 ); 
		}
	}

	return( 0 );
}

/* Direct path for draw-mask-along-line or draw-mask-along-circle. We want to
 * avoid function dispatch overhead.
 *
 * The vips7 im_draw_mask() wrapper calls this as well.
 */
int
vips__draw_mask_direct( VipsImage *image, VipsImage *mask, 
	VipsPel *ink, int x, int y )
{
	VipsRect image_rect;
	VipsRect area_rect;
	VipsRect image_clip;
	VipsRect mask_clip;

	if( vips_check_coding_noneorlabq( "draw_mask_direct", image ) ||
		vips_image_wio_input( mask ) ||
		vips_check_mono( "draw_mask_direct", mask ) ||
		vips_check_uncoded( "draw_mask_direct", mask ) ||
		vips_check_format( "draw_mask_direct", 
			mask, VIPS_FORMAT_UCHAR ) )
		return( -1 );

	/* Find the area we draw on the image.
	 */
	area_rect.left = x;
	area_rect.top = y;
	area_rect.width = mask->Xsize;
	area_rect.height = mask->Ysize;
	image_rect.left = 0;
	image_rect.top = 0;
	image_rect.width = image->Xsize;
	image_rect.height = image->Ysize;
	vips_rect_intersectrect( &area_rect, &image_rect, &image_clip );

	/* And the area of the mask image we use.
	 */
	mask_clip = image_clip;
	mask_clip.left -= x;
	mask_clip.top -= y;

	if( !vips_rect_isempty( &image_clip ) ) 
		switch( image->Coding ) {
		case VIPS_CODING_LABQ:
			if( vips_draw_mask_draw_labq( image, mask, ink, 
				&image_clip, &mask_clip ) )
				return( -1 );
			break;

		case VIPS_CODING_NONE:
			if( vips_draw_mask_draw( image, mask, ink, 
				&image_clip, &mask_clip ) )
				return( -1 );
			break;

		default:
			g_assert( 0 );
		}

	return( 0 );
}

static int
vips_draw_mask_build( VipsObject *object )
{
	VipsDraw *draw = VIPS_DRAW( object );
	VipsDrawink *drawink = VIPS_DRAWINK( object );
	VipsDrawMask *mask = (VipsDrawMask *) object;

	if( VIPS_OBJECT_CLASS( vips_draw_mask_parent_class )->build( object ) )
		return( -1 );

	if( vips__draw_mask_direct( draw->image, mask->mask, drawink->pixel_ink,
		mask->x, mask->y  ) )
		return( -1 ) ;

	return( 0 );
}

static void
vips_draw_mask_class_init( VipsDrawMaskClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "draw_mask";
	vobject_class->description = _( "draw a mask on an image" );
	vobject_class->build = vips_draw_mask_build;

	VIPS_ARG_IMAGE( class, "mask", 5, 
		_( "Mask" ), 
		_( "Mask of pixels to draw" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsDrawMask, mask ) ); 

	VIPS_ARG_INT( class, "x", 6, 
		_( "x" ), 
		_( "Draw mask here" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsDrawMask, x ),
		-1000000000, 1000000000, 0 );

	VIPS_ARG_INT( class, "y", 7, 
		_( "y" ), 
		_( "Draw mask here" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsDrawMask, y ),
		-1000000000, 1000000000, 0 );

}

static void
vips_draw_mask_init( VipsDrawMask *draw_mask )
{
}

static int
vips_draw_maskv( VipsImage *image, 
	double *ink, int n, VipsImage *mask, int x, int y, va_list ap )
{
	VipsArea *area_ink;
	int result;

	area_ink = (VipsArea *) vips_array_double_new( ink, n );
	result = vips_call_split( "draw_mask", ap, 
		image, area_ink, mask, x, y );
	vips_area_unref( area_ink );

	return( result );
}

/**
 * vips_draw_mask:
 * @image: image to draw on
 * @ink: value to draw
 * @mask: mask of 0/255 values showing where to plot
 * @x: draw mask here
 * @y: draw mask here
 *
 * Draw @mask on the image. @mask is a monochrome 8-bit image with 0/255
 * for transparent or @ink coloured points. Intermediate values blend the ink
 * with the pixel. Use with vips_text() to draw text on an image. Use in a 
 * vips_line() subclass to draw an object along a line. 
 *
 * @ink is an array of double containing values to draw. 
 *
 * See also: vips_text(), vips_line().
 *
 * Returns: 0 on success, or -1 on error.
 */
int
vips_draw_mask( VipsImage *image, 
	double *ink, int n, VipsImage *mask, int x, int y, ... )
{
	va_list ap;
	int result;

	va_start( ap, y );
	result = vips_draw_maskv( image, ink, n, mask, x, y, ap );
	va_end( ap );

	return( result );
}

/**
 * vips_draw_mask1:
 * @image: image to draw on
 * @ink: value to draw
 * @mask: mask of 0/255 values showing where to plot
 * @x: draw mask here
 * @y: draw mask here
 *
 * As vips_draw_mask(), but just takes a single double for @ink. 
 *
 * See also: vips_draw_mask().
 *
 * Returns: 0 on success, or -1 on error.
 */
int
vips_draw_mask1( VipsImage *image, 
	double ink, VipsImage *mask, int x, int y, ... )
{
	double array_ink[1];
	va_list ap;
	int result;

	array_ink[0] = ink; 

	va_start( ap, y );
	result = vips_draw_maskv( image, array_ink, 1, mask, x, y, ap );
	va_end( ap );

	return( result );
}
