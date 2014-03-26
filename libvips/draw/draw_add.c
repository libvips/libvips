/* in-place add, ie. a = a + b
 *
 * 26/3/14
 * 	- from draw_add.c
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

typedef struct _VipsDrawAdd {
	VipsDraw parent_object;

	/* Parameters.
	 */
	VipsImage *sub;
	int x;
	int y;

} VipsDrawAdd;

typedef struct _VipsDrawAddClass {
	VipsDrawClass parent_class;

} VipsDrawAddClass; 

G_DEFINE_TYPE( VipsDrawAdd, vips_draw_add, VIPS_TYPE_DRAW );

#define LOOP( TYPE ) { \
	TYPE * restrict pt = (TYPE *) p; \
	TYPE * restrict qt = (TYPE *) q; \
	\
	for( x = 0; x < sz; x++ ) \
		qt[x] += pt[x]; \
}

static int
vips_draw_add_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsDraw *draw = VIPS_DRAW( object );
	VipsDrawAdd *image = (VipsDrawAdd *) object;
	VipsImage **t = (VipsImage **) vips_object_local_array( object, 3 );

	VipsImage *im;
	VipsRect image_rect;
	VipsRect sub_rect; 
	VipsRect clip_rect;

	if( VIPS_OBJECT_CLASS( vips_draw_add_parent_class )->build( object ) )
		return( -1 );

	if( vips_check_uncoded( class->nickname, draw->image ) ||
		vips_check_coding_same( class->nickname, 
			draw->image, image->sub ) ||
		vips_check_bands_1orn_unary( class->nickname, 
			image->sub, draw->image->Bands ) )
		return( -1 );

	/* Cast sub to match main in bands and format.
	 */
	im = image->sub;
	if( vips__bandup( class->nickname, 
		im, &t[0], draw->image->Bands ) ||
		vips_cast( t[0], &t[1], draw->image->BandFmt, NULL ) )
		return( -1 );
	im = t[1];

	/* Make rects for main and sub and clip.
	 */
	image_rect.left = 0;
	image_rect.top = 0;
	image_rect.width = draw->image->Xsize;
	image_rect.height = draw->image->Ysize;
	sub_rect.left = image->x;
	sub_rect.top = image->y;
	sub_rect.width = im->Xsize;
	sub_rect.height = im->Ysize;
	vips_rect_intersectrect( &image_rect, &sub_rect, &clip_rect );

	if( !vips_rect_isempty( &clip_rect ) ) {
		/* Complex just doubles the size.
		 */
		const int sz = clip_rect.width * im->Bands * 
			(vips_band_format_iscomplex( im->BandFmt ) ? 
		 	2 : 1);

		VipsPel *p, *q;
		int x, y;

		if( vips_image_wio_input( im ) )
			return( -1 ); 

		p = VIPS_IMAGE_ADDR( im, 
			clip_rect.left - image->x, clip_rect.top - image->y );
		q = VIPS_IMAGE_ADDR( draw->image, 
			clip_rect.left, clip_rect.top );

		for( y = 0; y < clip_rect.height; y++ ) {
			switch( im->BandFmt ) {
			case VIPS_FORMAT_UCHAR: 	
				LOOP( unsigned char ); break; 
			case VIPS_FORMAT_CHAR: 	
				LOOP( signed char ); break; 
			case VIPS_FORMAT_USHORT: 
				LOOP( unsigned short ); break; 
			case VIPS_FORMAT_SHORT: 	
				LOOP( signed short ); break; 
			case VIPS_FORMAT_UINT: 	
				LOOP( unsigned int ); break; 
			case VIPS_FORMAT_INT: 	
				LOOP( signed int ); break; 

			case VIPS_FORMAT_FLOAT: 		
			case VIPS_FORMAT_COMPLEX: 
				LOOP( float ); break; 

			case VIPS_FORMAT_DOUBLE:	
			case VIPS_FORMAT_DPCOMPLEX: 
				LOOP( double ); break;

			default:
				g_assert( 0 );
			}

			p += VIPS_IMAGE_SIZEOF_LINE( im );
			q += VIPS_IMAGE_SIZEOF_LINE( draw->image );
		}
	}

	return( 0 );
}

static void
vips_draw_add_class_init( VipsDrawAddClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "draw_add";
	vobject_class->description = _( "add an image into another image" );
	vobject_class->build = vips_draw_add_build;

	VIPS_ARG_IMAGE( class, "sub", 5, 
		_( "Sub-image" ), 
		_( "Sub-image to add to main image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsDrawAdd, sub ) );

	VIPS_ARG_INT( class, "x", 6, 
		_( "x" ), 
		_( "Add image here" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsDrawAdd, x ),
		-1000000000, 1000000000, 0 );

	VIPS_ARG_INT( class, "y", 7, 
		_( "y" ), 
		_( "Add image here" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsDrawAdd, y ),
		-1000000000, 1000000000, 0 );

}

static void
vips_draw_add_init( VipsDrawAdd *draw_add )
{
}

/**
 * vips_draw_add:
 * @image: image to add to
 * @sub: image to add from
 * @x: add @sub here
 * @y: add @sub here
 *
 * Add @sub to @image at position @x, @y. The two images must be uncoded.
 * If @sub has 1 band, the bands will be duplicated to match the
 * number of bands in @image. @sub will be converted to @image's format, see
 * vips_cast().
 *
 * See also: vips_draw_mask(), vips_draw_image(), vips_insert().
 *
 * Returns: 0 on success, or -1 on error.
 */
int
vips_draw_add( VipsImage *image, VipsImage *sub, int x, int y, ... )
{
	va_list ap;
	int result;

	va_start( ap, y );
	result = vips_call_split( "draw_add", ap, image, sub, x, y );
	va_end( ap );

	return( result );
}
