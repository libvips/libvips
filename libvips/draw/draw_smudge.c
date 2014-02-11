/* Smudge a piece of image. 
 *
 * Copyright: J. Cupitt
 * Written: 15/06/1992
 * 22/7/93 JC
 *	- im_incheck() added
 * 16/8/94 JC
 *	- im_incheck() changed to im_makerw()
 * ? JC
 *	- im_makerw() changed to im_rwcheck()
 * 5/12/06
 * 	- im_invalidate() after paint
 * 6/3/10
 * 	- don't im_invalidate() after paint, this now needs to be at a higher
 * 	  level
 * 30/9/10
 * 	- gtk-doc
 * 	- deprecate im_smear()
 * 30/1/12
 * 	- back to the custom smear, the conv one was too slow
 * 11/2/14
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
#include <vips/internal.h>

#include "pdraw.h"

typedef struct _VipsDrawSmudge {
	VipsDraw parent_object;

	/* Parameters.
	 */
	int left;
	int top;
	int width;
	int height;

} VipsDrawSmudge;

typedef struct _VipsDrawSmudgeClass {
	VipsDrawClass parent_class;

} VipsDrawSmudgeClass; 

G_DEFINE_TYPE( VipsDrawSmudge, vips_draw_smudge, VIPS_TYPE_DRAW );

static int
vips_draw_smudge_build( VipsObject *object )
{
	VipsDraw *draw = VIPS_DRAW( object );
	VipsImage *im = draw->image; 
	VipsDrawSmudge *smudge = (VipsDrawSmudge *) object;
	int left = smudge->left;
	int top = smudge->top;
	int width = smudge->width;
	int height = smudge->height;

	/* Double bands for complex images.
	 */
	int bands = vips_image_get_bands( draw->image ) * 
		(vips_band_format_iscomplex( vips_image_get_format( im ) ) ? 
		 	2 : 1);
	int elements = bands * vips_image_get_width( im );

	VipsRect area, image, clipped;
	double *total;
	int x, y, i, j, b;

	if( VIPS_OBJECT_CLASS( vips_draw_smudge_parent_class )->
		build( object ) )
		return( -1 );

	area.left = left;
	area.top = top;
	area.width = width;
	area.height = height;

	/* Don't do the margins.
	 */
	image.left = 0;
	image.top = 0;
	image.width = im->Xsize;
	image.height = im->Ysize;
	vips_rect_marginadjust( &image, -1 );

	vips_rect_intersectrect( &area, &image, &clipped );
	if( vips_rect_isempty( &clipped ) )
		return( 0 );

	if( !(total = VIPS_ARRAY( im, bands, double )) )
		return( -1 );

/* What we do for each type.
 */
#define SMUDGE( TYPE ) \
	for( y = 0; y < clipped.height; y++ ) { \
		TYPE *q; \
		TYPE *p; \
		\
		q = (TYPE *) VIPS_IMAGE_ADDR( im, \
			clipped.left, clipped.top + y ); \
		p = q - elements - bands; \
		for( x = 0; x < clipped.width; x++ ) { \
			TYPE *p1, *p2; \
 			\
			for( b = 0; b < bands; b++ ) \
				total[b] = 0.0; \
			\
			p1 = p; \
			for( i = 0; i < 3; i++ ) { \
				p2 = p1; \
				for( j = 0; j < 3; j++ ) \
					for( b = 0; b < bands; b++ ) \
						total[b] += *p2++; \
				\
				p1 += elements; \
			} \
 			\
			for( b = 0; b < bands; b++ ) \
				q[b] = (16 * (double) q[b] + total[b]) / 25.0; \
			\
			p += bands; \
			q += bands; \
		} \
	}

	switch( vips_image_get_format( im ) ) { 
	case VIPS_FORMAT_UCHAR: 	SMUDGE( unsigned char ); break; 
	case VIPS_FORMAT_CHAR: 		SMUDGE( char ); break; 
	case VIPS_FORMAT_USHORT: 	SMUDGE( unsigned short ); break; 
	case VIPS_FORMAT_SHORT: 	SMUDGE( short ); break; 
	case VIPS_FORMAT_UINT: 		SMUDGE( unsigned int ); break; 
	case VIPS_FORMAT_INT: 		SMUDGE( int ); break; 
	case VIPS_FORMAT_FLOAT: 	SMUDGE( float ); break; 
	case VIPS_FORMAT_DOUBLE: 	SMUDGE( double ); break; 
	case VIPS_FORMAT_COMPLEX: 	SMUDGE( float ); break;
	case VIPS_FORMAT_DPCOMPLEX: 	SMUDGE( double ); break;

	default:
		g_assert( 0 );
	}

	return( 0 );
}

static void
vips_draw_smudge_class_init( VipsDrawSmudgeClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "draw_smudge";
	vobject_class->description = _( "blur a rectangle on an image" );
	vobject_class->build = vips_draw_smudge_build;

	VIPS_ARG_INT( class, "left", 6, 
		_( "Left" ), 
		_( "Rect to fill" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsDrawSmudge, left ),
		-1000000000, 1000000000, 0 );

	VIPS_ARG_INT( class, "top", 7, 
		_( "top" ), 
		_( "Rect to fill" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsDrawSmudge, top ),
		-1000000000, 1000000000, 0 );

	VIPS_ARG_INT( class, "width", 8, 
		_( "width" ), 
		_( "Rect to fill" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsDrawSmudge, width ),
		-1000000000, 1000000000, 0 );

	VIPS_ARG_INT( class, "height", 9, 
		_( "height" ), 
		_( "Rect to fill" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsDrawSmudge, height ),
		-1000000000, 1000000000, 0 );

}

static void
vips_draw_smudge_init( VipsDrawSmudge *draw_smudge )
{
}

/**
 * vips_draw_smudge:
 * @image: image to draw on
 * @left: point to paint
 * @top: point to paint
 * @width: area to paint
 * @height: area to paint
 *
 * Smudge a section of @image. Each pixel in the area @left, @top, @width,
 * @height is replaced by the average of the surrounding 3x3 pixels. 
 *
 * See also: vips_draw_line().
 *
 * Returns: 0 on success, or -1 on error.
 */
int
vips_draw_smudge( VipsImage *image, 
	int left, int top, int width, int height, ... ) 
{
	va_list ap;
	int result;

	va_start( ap, height );
	result = vips_call_split( "draw_smudge", ap, 
		image, left, top, width, height ); 
	va_end( ap );

	return( result );
}
