/* base class for drawing operations
 *
 * 27/9/10
 *	- from im_draw_circle()
 * 17/11/10
 * 	- oops, scanline clipping was off by 1
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

#include "draw.h"

/** 
 * SECTION: inplace
 * @short_description: in-place paintbox operations: flood, paste, line,
 * circle
 * @stability: Stable
 * @include: vips/vips.h
 *
 * These operations directly modify the image. They do not thread, on 32-bit
 * machines they will be limited to 2GB images, and a little care needs to be
 * taken if you use them as part of an image pipeline. 
 *
 * They are mostly supposed to be useful 
 * for paintbox-style programs.
 *
 */

G_DEFINE_ABSTRACT_TYPE( VipsDraw, vips_draw, VIPS_TYPE_OPERATION );

static int
vips_draw_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsDraw *draw = VIPS_DRAW( object );

#ifdef DEBUG
	printf( "vips_draw_build: " );
	vips_object_print_name( object );
	printf( "\n" );
#endif /*DEBUG*/

	if( VIPS_OBJECT_CLASS( vips_draw_parent_class )->build( object ) )
		return( -1 );

	if( vips_image_inplace( draw->im ) )
		return( NULL );

	draw->lsize = VIPS_IMAGE_SIZEOF_LINE( draw->im );
	draw->psize = VIPS_IMAGE_SIZEOF_PEL( draw->im );
	draw->noclip = FALSE;

	if( !(draw->pixel_ink = vips__vector_to_ink( 
		class->nickname, draw->im,
		draw->ink->data, draw->ink->n )) )
		return( -1 );

	return( 0 );
}

static void
vips_draw_class_init( VipsDrawClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "draw";
	vobject_class->description = _( "Draw operations" );
	vobject_class->build = vips_draw_build;

	VIPS_ARG_IMAGE( class, "im", 1, 
		_( "Image" ), 
		_( "Image to draw on" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsDraw, im ) );

	VIPS_ARG_BOXED( class, "ink", 12, 
		_( "Ink" ), 
		_( "Colour for pixels" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsDraw, ink ),
		VIPS_TYPE_ARRAY_DOUBLE );

}

static void
vips_draw_init( VipsDraw *draw )
{
	draw->ink = vips_area_new_array( G_TYPE_DOUBLE, sizeof( double ), 1 ); 
	((double *) (draw->ink->data))[0] = 0;
}

void
vips_draw_operation_init( void )
{
	extern GType vips_copy_get_type( void ); 

	vips_copy_get_type();
}

/* Fill a scanline between points x1 and x2 inclusive. x1 < x2.
 */
void 
vips__draw_scanline( VipsDraw *draw, int y, int x1, int x2 )
{
	VipsPel *mp;
	int i;
	int len;

	g_assert( x1 <= x2 );

	if( y < 0 || 
		y >= draw->im->Ysize )
		return;
	if( x1 < 0 && 
		x2 < 0 )
		return;
	if( x1 >= draw->im->Xsize && 
		x2 >= draw->im->Xsize )
		return;
	x1 = VIPS_CLIP( 0, x1, draw->im->Xsize - 1 );
	x2 = VIPS_CLIP( 0, x2, draw->im->Xsize - 1 );

	mp = VIPS_IMAGE_ADDR( draw->im, x1, y );
	len = x2 - x1 + 1;

	for( i = 0; i < len; i++ ) {
		vips__draw_pel( draw, mp );
		mp += draw->psize;
	}
}

