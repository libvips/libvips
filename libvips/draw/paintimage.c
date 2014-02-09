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
 * 	- redo as a class, based on paintimage
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

typedef struct _VipsPaintimage {
	VipsDraw parent_object;

	/* Parameters.
	 */
	VipsImage *sub;
	int x;
	int y;

} VipsPaintimage;

typedef struct _VipsPaintimageClass {
	VipsDrawClass parent_class;

} VipsPaintimageClass; 

G_DEFINE_TYPE( VipsPaintimage, vips_paintimage, VIPS_TYPE_DRAW );

static int
vips_paintimage_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsDraw *draw = VIPS_DRAW( object );
	VipsPaintimage *paintimage = (VipsPaintimage *) object;
	VipsImage **t = (VipsImage **) vips_object_local_array( object, 3 );

	VipsImage *im;
	VipsRect image;
	VipsRect sub; 
	VipsRect clip;

	if( VIPS_OBJECT_CLASS( vips_paintimage_parent_class )->build( object ) )
		return( -1 );

	if( vips_check_coding_known( class->nickname, draw->image ) ||
		vips_check_coding_same( class->nickname, 
			draw->image, paintimage->sub ) ||
		vips_check_bands_1orn_unary( class->nickname, 
			paintimage->sub, draw->image->Bands ) )
		return( -1 );

	/* Cast sub to match main in bands and format.
	 */
	im = paintimage->sub;
	if( im->Coding == VIPS_CODING_NONE ) {
		if( vips__bandup( class->nickname, 
			im, &t[0], draw->image->Bands ) ||
			vips_cast( t[0], &t[1], draw->image->BandFmt, NULL ) )
			return( -1 );

		im = t[1];
	}

	/* Make rects for main and sub and clip.
	 */
	image.left = 0;
	image.top = 0;
	image.width = draw->image->Xsize;
	image.height = draw->image->Ysize;
	sub.left = paintimage->x;
	sub.top = paintimage->y;
	sub.width = im->Xsize;
	sub.height = im->Ysize;
	vips_rect_intersectrect( &image, &sub, &clip );

	if( !vips_rect_isempty( &clip ) ) {
		VipsPel *p, *q;
		int y;

		if( vips_image_wio_input( im ) )
			return( -1 ); 

		p = VIPS_IMAGE_ADDR( im, 
			clip.left - paintimage->x, clip.top - paintimage->y );
		q = VIPS_IMAGE_ADDR( draw->image, clip.left, clip.top );
		for( y = 0; y < clip.height; y++ ) {
			memcpy( (char *) q, (char *) p, 
				clip.width * VIPS_IMAGE_SIZEOF_PEL( im ) );
			p += VIPS_IMAGE_SIZEOF_LINE( im );
			q += VIPS_IMAGE_SIZEOF_LINE( draw->image );
		}
	}

	return( 0 );
}

static void
vips_paintimage_class_init( VipsPaintimageClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "paintimage";
	vobject_class->description = _( "paint an image into another image" );
	vobject_class->build = vips_paintimage_build;

	VIPS_ARG_IMAGE( class, "sub", 5, 
		_( "Sub-image" ), 
		_( "Sub-image to insert into main image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsPaintimage, sub ) );

	VIPS_ARG_INT( class, "x", 6, 
		_( "x" ), 
		_( "Draw image here" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsPaintimage, x ),
		-1000000000, 1000000000, 0 );

	VIPS_ARG_INT( class, "y", 7, 
		_( "y" ), 
		_( "Draw image here" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsPaintimage, y ),
		-1000000000, 1000000000, 0 );

}

static void
vips_paintimage_init( VipsPaintimage *paintimage )
{
}

/**
 * vips_paintimage1:
 * @image: image to draw on
 * @sub: image to paint
 * @x: draw @sub here
 * @y: draw @sub here
 *
 * Draw @sub on top of @image at position @x, @y. The two images must have the 
 * same
 * Coding. If @sub has 1 band, the bands will be duplicated to match the
 * number of bands in @image. @sub will be converted to @image's format, see
 * vips_cast().
 *
 * See also: vips_paintmask(), vips_insert().
 *
 * Returns: 0 on success, or -1 on error.
 */
int
vips_paintimage( VipsImage *image, VipsImage *sub, int x, int y, ... )
{
	va_list ap;
	int result;

	va_start( ap, y );
	result = vips_call_split( "paintimage", ap, 
		image, NULL, sub, x, y );
	va_end( ap );

	return( result );
}
