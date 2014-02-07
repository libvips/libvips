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
 * 	- now it's VipsPaintmask
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

#include "pdraw.h"

typedef struct _VipsPaintmask {
	VipsDraw parent_object;

	/* Parameters.
	 */
	VipsImage *mask;
	int x;
	int y;

	/* Derived.
	 */
	VipsRect image_clip;
	VipsRect mask_clip;
} VipsPaintmask;

typedef struct _VipsPaintmaskClass {
	VipsDrawClass parent_class;

} VipsPaintmaskClass; 

G_DEFINE_TYPE( VipsPaintmask, vips_paintmask, VIPS_TYPE_DRAW );

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
			tto[j] = (tink[i] * mask[x] + \
				tto[j] * (255 - mask[x])) / 255; \
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
			tto[j] = ((double) tink[i] * mask[x] + \
				(double) tto[j] * (255 - mask[x])) / 255; \
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
			tto[j] = ((double) tink[i] * mask[x] + \
				(double) tto[j] * (255 - mask[x])) / 255;\
			tto[j + 1] = ((double) tink[i + 1] * mask[x] + \
				(double) tto[j + 1] * (255 - mask[x])) / \
				255;\
		} \
}

static int
vips_paintmask_draw_labq( VipsPaintmask *paintmask )
{
	VipsDraw *draw = VIPS_DRAW( paintmask );
	int width = paintmask->image_clip.width;
	int height = paintmask->image_clip.height;
	int bands = draw->image->Bands; 

	float *lab_buffer;
	int y;

	if( !(lab_buffer = VIPS_ARRAY( NULL, width * 3, float )) )
		return( -1 );

	for( y = 0; y < height; y++ ) {
		VipsPel *to = VIPS_IMAGE_ADDR( draw->image, 
			paintmask->image_clip.left, 
			y + paintmask->image_clip.top );
		VipsPel *mask = VIPS_IMAGE_ADDR( paintmask->mask, 
			paintmask->mask_clip.left, 
			y + paintmask->mask_clip.top );

		vips__LabQ2Lab_vec( lab_buffer, to, width );
		DBLEND( float, lab_buffer, (double *) draw->ink->data );
		vips__Lab2LabQ_vec( to, lab_buffer, width );
	}

	g_free( lab_buffer );

	return( 0 );
}

static int
vips_paintmask_draw( VipsPaintmask *paintmask )
{
	VipsDraw *draw = VIPS_DRAW( paintmask );
	int width = paintmask->image_clip.width;
	int height = paintmask->image_clip.height;
	int bands = draw->image->Bands; 

	int y;

	for( y = 0; y < height; y++ ) {
		VipsPel *to = VIPS_IMAGE_ADDR( draw->image, 
			paintmask->image_clip.left, 
			y + paintmask->image_clip.top );
		VipsPel *mask = VIPS_IMAGE_ADDR( paintmask->mask, 
			paintmask->mask_clip.left, 
			y + paintmask->mask_clip.top );

		switch( draw->image->BandFmt ) {
		case VIPS_FORMAT_UCHAR: 
			IBLEND( unsigned char, to, draw->pixel_ink );
			break;

		case VIPS_FORMAT_CHAR: 
			IBLEND( signed char, to, draw->pixel_ink );
			break;

		case VIPS_FORMAT_USHORT: 
			IBLEND( unsigned short, to, draw->pixel_ink );
			break;

		case VIPS_FORMAT_SHORT: 
			IBLEND( signed short, to, draw->pixel_ink );
			break;

		case VIPS_FORMAT_UINT: 
			DBLEND( unsigned int, to, draw->pixel_ink );
			break;

		case VIPS_FORMAT_INT: 
			DBLEND( signed int, to, draw->pixel_ink );
			break;

		case VIPS_FORMAT_FLOAT:  
			DBLEND( float, to, draw->pixel_ink );
			break;

		case VIPS_FORMAT_DOUBLE:
			DBLEND( double, to, draw->pixel_ink );
			break;

		case VIPS_FORMAT_COMPLEX:
			CBLEND( float, to, draw->pixel_ink );
			break;

		case VIPS_FORMAT_DPCOMPLEX:
			CBLEND( double, to, draw->pixel_ink );
			break;

		default:
			g_assert( 0 ); 
		}
	}

	return( 0 );
}

static int
vips_paintmask_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsDraw *draw = VIPS_DRAW( object );
	VipsPaintmask *paintmask = (VipsPaintmask *) object;

	VipsRect area;
	VipsRect image;

	if( VIPS_OBJECT_CLASS( vips_paintmask_parent_class )->build( object ) )
		return( -1 );

	if( vips_check_coding_noneorlabq( class->nickname, draw->image ) ||
		vips_image_wio_input( paintmask->mask ) ||
		vips_check_mono( class->nickname, paintmask->mask ) ||
		vips_check_uncoded( class->nickname, paintmask->mask ) ||
		vips_check_format( class->nickname, 
			paintmask->mask, VIPS_FORMAT_UCHAR ) )
		return( -1 );

	/* Find the area we draw on the image.
	 */
	area.left = paintmask->x;
	area.top = paintmask->y;
	area.width = paintmask->mask->Xsize;
	area.height = paintmask->mask->Ysize;
	image.left = 0;
	image.top = 0;
	image.width = draw->image->Xsize;
	image.height = draw->image->Ysize;
	vips_rect_intersectrect( &area, &image, &paintmask->image_clip );

	/* And the area of the mask image we use.
	 */
	paintmask->mask_clip = paintmask->image_clip;
	paintmask->mask_clip.left -= paintmask->x;
	paintmask->mask_clip.top -= paintmask->y;

	/* Any points to plot?
	 */
	if( vips_rect_isempty( &paintmask->image_clip ) ) 
		return( 0 );

	/* Loop through image plotting where required.
	 */
	switch( draw->image->Coding ) {
	case VIPS_CODING_LABQ:
		if( vips_paintmask_draw_labq( paintmask ) ) 
			return( -1 );
		break;

	case VIPS_CODING_NONE:
		if( vips_paintmask_draw( paintmask ) ) 
			return( -1 );
		break;

	default:
		g_assert( 0 );
	}

	return( 0 );
}

static void
vips_paintmask_class_init( VipsPaintmaskClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "paintmask";
	vobject_class->description = _( "draw a mask on an image" );
	vobject_class->build = vips_paintmask_build;

	VIPS_ARG_IMAGE( class, "mask", 5, 
		_( "Mask" ), 
		_( "Mask of pixels to draw" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsPaintmask, mask ) ); 

	VIPS_ARG_INT( class, "x", 6, 
		_( "x" ), 
		_( "Draw mask here" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsPaintmask, x ),
		-1000000000, 1000000000, 0 );

	VIPS_ARG_INT( class, "y", 7, 
		_( "y" ), 
		_( "Draw mask here" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsPaintmask, y ),
		-1000000000, 1000000000, 0 );

}

static void
vips_paintmask_init( VipsPaintmask *paintmask )
{
}

static int
vips_paintmaskv( VipsImage *image, 
	double *ink, int n, VipsImage *mask, int x, int y, va_list ap )
{
	VipsArea *area_ink;
	int result;

	area_ink = (VipsArea *) vips_array_double_new( ink, n );
	result = vips_call_split( "paintmask", ap, 
		image, area_ink, mask, x, y );
	vips_area_unref( area_ink );

	return( result );
}

/**
 * vips_paintmask:
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
vips_paintmask( VipsImage *image, 
	double *ink, int n, VipsImage *mask, int x, int y, ... )
{
	va_list ap;
	int result;

	va_start( ap, y );
	result = vips_paintmaskv( image, ink, n, mask, x, y, ap );
	va_end( ap );

	return( result );
}

/**
 * vips_paintmask1:
 * @image: image to draw on
 * @ink: value to draw
 * @mask: mask of 0/255 values showing where to plot
 * @x: draw mask here
 * @y: draw mask here
 *
 * As vips_paintmask(), but just takes a single double for @ink. 
 *
 * See also: vips_paintmask().
 *
 * Returns: 0 on success, or -1 on error.
 */
int
vips_paintmask1( VipsImage *image, 
	double ink, VipsImage *mask, int x, int y, ... )
{
	double array_ink[1];
	va_list ap;
	int result;

	array_ink[0] = ink; 

	va_start( ap, y );
	result = vips_paintmaskv( image, array_ink, 1, mask, x, y, ap );
	va_end( ap );

	return( result );
}
