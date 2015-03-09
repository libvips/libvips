/* in-place insert
 *
 * Copyright: J. Cupitt
 * Written: 15/06/1992
 * 22/7/93 JC
 *	- im_incheck() added
 * 16/8/94 JC
 *	- im_incheck() changed to im_makerw()
 * 1/9/04 JC
 *	- checks bands/types/etc match (thanks Matt)
 *	- smarter pixel size calculations
 * 5/12/06
 * 	- im_invalidate() after paint
 * 24/3/09
 * 	- added IM_CODING_RAD support
 * 21/10/09
 * 	- allow sub to be outside main
 * 	- gtkdoc
 * 6/3/10
 * 	- don't im_invalidate() after paint, this now needs to be at a higher
 * 	  level
 * 25/8/10
 * 	- cast and bandalike sub to main
 * 22/9/10
 * 	- rename to im_draw_image()
 * 	- gtk-doc
 * 9/2/14
 * 	- redo as a class, based on draw_image
 * 28/3/14
 * 	- add "mode" param
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
#include <limits.h>

#include <vips/vips.h>
#include <vips/internal.h>

#include "pdraw.h"

typedef struct _VipsDrawImage {
	VipsDraw parent_object;

	/* Parameters.
	 */
	VipsImage *sub;
	int x;
	int y;
	VipsCombineMode mode; 

} VipsDrawImage;

typedef struct _VipsDrawImageClass {
	VipsDrawClass parent_class;

} VipsDrawImageClass; 

G_DEFINE_TYPE( VipsDrawImage, vips_draw_image, VIPS_TYPE_DRAW );

#define LOOP( TYPE, TEMP, MIN, MAX ) { \
	TYPE * restrict pt = (TYPE *) p; \
	TYPE * restrict qt = (TYPE *) q; \
	\
	for( x = 0; x < sz; x++ ) { \
		TEMP v; \
		\
		v = pt[x] + qt[x]; \
		\
		qt[x] = VIPS_CLIP( MIN, v, MAX ); \
	} \
}

#define LOOPF( TYPE ) { \
	TYPE * restrict pt = (TYPE *) p; \
	TYPE * restrict qt = (TYPE *) q; \
	\
	for( x = 0; x < sz; x++ ) \
		qt[x] += pt[x]; \
}

static void
vips_draw_image_mode_add( VipsDrawImage *draw_image, VipsImage *im, 
	VipsPel *q, VipsPel *p, int n )
{
	/* Complex just doubles the size.
	 */
	const int sz = n * im->Bands * 
		(vips_band_format_iscomplex( im->BandFmt ) ?  2 : 1);

	int x;

	switch( im->BandFmt ) {
	case VIPS_FORMAT_UCHAR: 	
		LOOP( unsigned char, int, 0, UCHAR_MAX ); break; 
	case VIPS_FORMAT_CHAR: 	
		LOOP( signed char, int, SCHAR_MIN, SCHAR_MAX ); break; 
	case VIPS_FORMAT_USHORT: 
		LOOP( unsigned short, int, 0, USHRT_MAX ); break; 
	case VIPS_FORMAT_SHORT: 	
		LOOP( signed short, int, SCHAR_MIN, SCHAR_MAX ); break; 
	case VIPS_FORMAT_UINT: 	
		LOOP( unsigned int, gint64, 0, UINT_MAX ); break; 
	case VIPS_FORMAT_INT: 	
		LOOP( signed int, gint64, INT_MIN, INT_MAX ); break; 

	case VIPS_FORMAT_FLOAT: 		
	case VIPS_FORMAT_COMPLEX: 
		LOOPF( float ); break; 

	case VIPS_FORMAT_DOUBLE:	
	case VIPS_FORMAT_DPCOMPLEX: 
		LOOPF( double ); break;

	default:
		g_assert( 0 );
	}
}

static int
vips_draw_image_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsDraw *draw = VIPS_DRAW( object );
	VipsDrawImage *draw_image = (VipsDrawImage *) object;
	VipsImage **t = (VipsImage **) vips_object_local_array( object, 3 );

	VipsImage *im;
	VipsRect image_rect;
	VipsRect sub_rect; 
	VipsRect clip_rect;

	if( VIPS_OBJECT_CLASS( vips_draw_image_parent_class )->build( object ) )
		return( -1 );

	if( vips_check_coding_known( class->nickname, draw->image ) ||
		vips_check_coding_same( class->nickname, 
			draw->image, draw_image->sub ) ||
		vips_check_bands_1orn_unary( class->nickname, 
			draw_image->sub, draw->image->Bands ) )
		return( -1 );

	/* SET will work for any matching coding, but every other mode needs 
	 * uncoded images. 
	 */
	if( draw_image->mode != VIPS_COMBINE_MODE_SET &&
		vips_check_uncoded( class->nickname, draw->image ) )
		return( -1 ); 

	/* Cast sub to match main in bands and format.
	 */
	im = draw_image->sub;
	if( im->Coding == VIPS_CODING_NONE ) {
		if( vips__bandup( class->nickname, 
			im, &t[0], draw->image->Bands ) ||
			vips_cast( t[0], &t[1], draw->image->BandFmt, NULL ) )
			return( -1 );

		im = t[1];
	}

	/* Make rects for main and sub and clip.
	 */
	image_rect.left = 0;
	image_rect.top = 0;
	image_rect.width = draw->image->Xsize;
	image_rect.height = draw->image->Ysize;
	sub_rect.left = draw_image->x;
	sub_rect.top = draw_image->y;
	sub_rect.width = im->Xsize;
	sub_rect.height = im->Ysize;
	vips_rect_intersectrect( &image_rect, &sub_rect, &clip_rect );

	if( !vips_rect_isempty( &clip_rect ) ) {
		VipsPel *p, *q;
		int y;

		if( vips_image_wio_input( im ) )
			return( -1 ); 

		p = VIPS_IMAGE_ADDR( im, 
			clip_rect.left - draw_image->x, 
			clip_rect.top - draw_image->y );
		q = VIPS_IMAGE_ADDR( draw->image, 
			clip_rect.left, clip_rect.top );

		for( y = 0; y < clip_rect.height; y++ ) {
			switch( draw_image->mode ) {
			case VIPS_COMBINE_MODE_SET:
				memcpy( (char *) q, (char *) p, 
					clip_rect.width * 
						VIPS_IMAGE_SIZEOF_PEL( im ) );
				break;

			case VIPS_COMBINE_MODE_ADD:
				vips_draw_image_mode_add( draw_image, 
					im, q, p, clip_rect.width ); 
				break;

			default:
				g_assert( 0 );
				break;

			}

			p += VIPS_IMAGE_SIZEOF_LINE( im );
			q += VIPS_IMAGE_SIZEOF_LINE( draw->image );
		}
	}

	return( 0 );
}

static void
vips_draw_image_class_init( VipsDrawImageClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "draw_image";
	vobject_class->description = _( "paint an image into another image" );
	vobject_class->build = vips_draw_image_build;

	VIPS_ARG_IMAGE( class, "sub", 5, 
		_( "Sub-image" ), 
		_( "Sub-image to insert into main image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsDrawImage, sub ) );

	VIPS_ARG_INT( class, "x", 6, 
		_( "x" ), 
		_( "Draw image here" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsDrawImage, x ),
		-1000000000, 1000000000, 0 );

	VIPS_ARG_INT( class, "y", 7, 
		_( "y" ), 
		_( "Draw image here" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsDrawImage, y ),
		-1000000000, 1000000000, 0 );

	VIPS_ARG_ENUM( class, "mode", 8, 
		_( "Mode" ), 
		_( "Combining mode" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsDrawImage, mode ),
		VIPS_TYPE_COMBINE_MODE, VIPS_COMBINE_MODE_SET ); 

}

static void
vips_draw_image_init( VipsDrawImage *draw_image )
{
	draw_image->mode = VIPS_COMBINE_MODE_SET;
}

/**
 * vips_draw_image:
 * @image: image to draw on
 * @sub: image to paint
 * @x: draw @sub here
 * @y: draw @sub here
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * @mode: how to combine pixels 
 *
 * Draw @sub on top of @image at position @x, @y. The two images must have the 
 * same Coding. If @sub has 1 band, the bands will be duplicated to match the
 * number of bands in @image. @sub will be converted to @image's format, see
 * vips_cast().
 *
 * Use @mode to set how pixels are combined. If you use 
 * #VIPS_COMBINE_MODE_ADD, both images muct be uncoded. 
 *
 * See also: vips_draw_mask(), vips_insert().
 *
 * Returns: 0 on success, or -1 on error.
 */
int
vips_draw_image( VipsImage *image, VipsImage *sub, int x, int y, ... )
{
	va_list ap;
	int result;

	va_start( ap, y );
	result = vips_call_split( "draw_image", ap, image, sub, x, y );
	va_end( ap );

	return( result );
}
