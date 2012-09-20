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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <stdlib.h>

#include <vips/vips.h>
#include <vips/internal.h>

#include "draw.h"

typedef struct _Mask {
	Draw draw;

	/* Parameters.
	 */
	int x;
	int y;
	VipsImage *mask_im;

	/* Derived.
	 */
	Rect image_clip;
	Rect mask_clip;
} Mask;

static void
mask_free( Mask *mask )
{
	im__draw_free( DRAW( mask ) );
	im_free( mask );
}

static Mask *
mask_new( VipsImage *im, int x, int y, VipsPel *ink, VipsImage *mask_im )
{
	Mask *mask;
	Rect area, image;

	if( im_check_coding_noneorlabq( "im_draw_mask", im ) ||
		im_incheck( mask_im ) ||
		im_check_mono( "im_draw_mask", mask_im ) ||
		im_check_uncoded( "im_draw_mask", mask_im ) ||
		im_check_format( "im_draw_mask", mask_im, IM_BANDFMT_UCHAR ) ||
		!(mask = IM_NEW( NULL, Mask )) )
		return( NULL );
	if( !im__draw_init( DRAW( mask ), im, ink ) ) {
		mask_free( mask );
		return( NULL );
	}

	mask->x = x;
	mask->y = y;
	mask->mask_im = mask_im;

	/* Find the area we draw on the image.
	 */
	area.left = x;
	area.top = y;
	area.width = mask_im->Xsize;
	area.height = mask_im->Ysize;
	image.left = 0;
	image.top = 0;
	image.width = im->Xsize;
	image.height = im->Ysize;
	im_rect_intersectrect( &area, &image, &mask->image_clip );

	/* And the area of the mask image we use.
	 */
	mask->mask_clip = mask->image_clip;
	mask->mask_clip.left -= x;
	mask->mask_clip.top -= y;

	return( mask );
}

/* Paint ink into an 8 or 16 bit integer image.
 */
#define IBLEND( TYPE, TO, INK ) { \
	TYPE *tto = (TYPE *) (TO); \
	TYPE *tink = (TYPE *) (INK); \
 	\
	int x, i, j; \
 	\
	for( j = 0, x = 0; x < mask->image_clip.width; x++ ) \
		for( i = 0; i < DRAW( mask )->im->Bands; i++, j++ ) \
			tto[j] = (tink[i] * mask_line[x] + \
				tto[j] * (255 - mask_line[x])) / 255; \
}

/* Do the blend with doubles.
 */
#define DBLEND( TYPE, TO, INK ) { \
	TYPE *tto = (TYPE *) (TO); \
	TYPE *tink = (TYPE *) (INK); \
 	\
	int x, i, j; \
 	\
	for( j = 0, x = 0; x < mask->image_clip.width; x++ ) \
		for( i = 0; i < DRAW( mask )->im->Bands; i++, j++ ) \
			tto[j] = ((double) tink[i] * mask_line[x] + \
				(double) tto[j] * (255 - mask_line[x])) / 255;\
}

/* Blend of complex.
 */
#define CBLEND( TYPE, TO, INK ) { \
	TYPE *tto = (TYPE *) (TO); \
	TYPE *tink = (TYPE *) (INK); \
 	\
	int x, i, j; \
 	\
	for( j = 0, x = 0; x < mask->image_clip.width; x++ ) \
		for( i = 0; i < DRAW( mask )->im->Bands * 2; i += 2, j += 2 ) { \
			tto[j] = ((double) tink[i] * mask_line[x] + \
				(double) tto[j] * (255 - mask_line[x])) / 255;\
			tto[j + 1] = ((double) tink[i + 1] * mask_line[x] + \
				(double) tto[j + 1] * (255 - mask_line[x])) / \
				255;\
		} \
}

static int
mask_draw_labq( Mask *mask )
{
	float *lab_buffer;
	float ink_buffer[3];
	int y;

	if( !(lab_buffer = IM_ARRAY( NULL, 
		mask->image_clip.width * 3, float )) )
		return( -1 );

	vips__LabQ2Lab_vec( ink_buffer, DRAW( mask )->ink, 1 );

	for( y = 0; y < mask->image_clip.height; y++ ) {
		VipsPel *to = IM_IMAGE_ADDR( DRAW( mask )->im, 
			mask->image_clip.left, y + mask->image_clip.top );
		VipsPel *mask_line = IM_IMAGE_ADDR( mask->mask_im, 
			mask->mask_clip.left, y + mask->mask_clip.top );

		vips__LabQ2Lab_vec( lab_buffer, to, mask->image_clip.width );
		DBLEND( float, lab_buffer, ink_buffer );
		vips__Lab2LabQ_vec( to, lab_buffer, mask->image_clip.width );
	}

	im_free( lab_buffer );

	return( 0 );
}

static int
mask_draw( Mask *mask )
{
	int y;

	for( y = 0; y < mask->image_clip.height; y++ ) {
		VipsPel *to = IM_IMAGE_ADDR( DRAW( mask )->im, 
			mask->image_clip.left, 
			y + mask->image_clip.top );
		VipsPel *mask_line = IM_IMAGE_ADDR( mask->mask_im, 
			mask->mask_clip.left, 
			y + mask->mask_clip.top );

		switch( DRAW( mask )->im->BandFmt ) {
		case IM_BANDFMT_UCHAR: 		
			IBLEND( unsigned char, to, DRAW( mask )->ink );
			break;

		case IM_BANDFMT_CHAR:  
			IBLEND( signed char, to, DRAW( mask )->ink );
			break;

		case IM_BANDFMT_USHORT: 
			IBLEND( unsigned short, to, DRAW( mask )->ink );
			break;

		case IM_BANDFMT_SHORT: 
			IBLEND( signed short, to, DRAW( mask )->ink );
			break;

		case IM_BANDFMT_UINT: 
			DBLEND( unsigned int, to, DRAW( mask )->ink );
			break;

		case IM_BANDFMT_INT: 
			DBLEND( signed int, to, DRAW( mask )->ink );
			break;

		case IM_BANDFMT_FLOAT:  
			DBLEND( float, to, DRAW( mask )->ink );
			break;

		case IM_BANDFMT_DOUBLE:
			DBLEND( double, to, DRAW( mask )->ink );
			break;

		case IM_BANDFMT_COMPLEX:
			CBLEND( float, to, DRAW( mask )->ink );
			break;

		case IM_BANDFMT_DPCOMPLEX:
			CBLEND( double, to, DRAW( mask )->ink );
			break;

		default:
			g_assert( 0 ); 
		}
	}

	return( 0 );
}

/**
 * im_draw_mask:
 * @image: image to draw on
 * @x: draw mask here
 * @y: draw mask here
 * @ink: value to draw
 * @mask_im: mask of 0/255 values showing where to plot
 *
 * Draw a mask on the image. @mask_im is a monochrome 8-bit image with 0/255
 * for transparent or @ink coloured points. Intermediate values blend the ink
 * with the pixel. Use with im_text() to draw text on an image.
 *
 * @ink is an array of bytes 
 * containing a valid pixel for the image's format.
 * It must have at least IM_IMAGE_SIZEOF_PEL( @image ) bytes.
 *
 * See also: im_draw_circle(), im_text(), im_draw_line_user().
 *
 * Returns: 0 on success, or -1 on error.
 */
int
im_draw_mask( VipsImage *image, VipsImage *mask_im, int x, int y, VipsPel *ink )
{
	Mask *mask;

	if( !(mask = mask_new( image, x, y, ink, mask_im )) )
		return( -1 );

	/* Any points to plot?
	 */
	if( im_rect_isempty( &mask->image_clip ) ) {
		mask_free( mask );
		return( 0 );
	}

	/* Loop through image plotting where required.
	 */
	switch( image->Coding ) {
	case IM_CODING_LABQ:
		if( mask_draw_labq( mask ) ) {
			mask_free( mask );
			return( 0 );
		}
		break;

	case IM_CODING_NONE:
		if( mask_draw( mask ) ) {
			mask_free( mask );
			return( 0 );
		}
		break;

	default:
		g_assert( 0 );
	}

	mask_free( mask );

	return( 0 );
}

