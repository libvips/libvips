/* drawink with a constant ink
 *
 * 27/9/10
 *	- from im_drawink_circle()
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
#include <glib/gi18n-lib.h>

#include <string.h>

#include <vips/vips.h>
#include <vips/internal.h>

#include "drawink.h"

G_DEFINE_ABSTRACT_TYPE( VipsDrawink, vips_drawink, VIPS_TYPE_DRAW );

static int
vips_drawink_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsDraw *draw = VIPS_DRAW( object );
	VipsDrawink *drawink = VIPS_DRAWINK( object );

#ifdef DEBUG
	printf( "vips_drawink_build: " );
	vips_object_print_name( object );
	printf( "\n" );
#endif /*DEBUG*/

	if( VIPS_OBJECT_CLASS( vips_drawink_parent_class )->build( object ) )
		return( -1 );

	if( drawink->ink &&
		!(drawink->pixel_ink = vips__vector_to_ink( class->nickname, 
			draw->image,
			VIPS_ARRAY_ADDR( drawink->ink, 0 ), NULL, 
			VIPS_AREA( drawink->ink )->n )) )
		return( -1 );

	return( 0 );
}

static void
vips_drawink_class_init( VipsDrawinkClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "drawink";
	vobject_class->description = _( "draw with ink operations" );
	vobject_class->build = vips_drawink_build;

	VIPS_ARG_BOXED( class, "ink", 2, 
		_( "Ink" ), 
		_( "Color for pixels" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsDrawink, ink ),
		VIPS_TYPE_ARRAY_DOUBLE );

}

static void
vips_drawink_init( VipsDrawink *drawink )
{
	drawink->ink = vips_array_double_newv( 1, 0.0 ); 
}

/* Fill a scanline between points x1 and x2 inclusive. x1 < x2.
 */
int
vips__drawink_scanline( VipsDrawink *drawink, int y, int x1, int x2 )
{
	VipsDraw *draw = (VipsDraw *) drawink;

	VipsPel *mp;
	int i;
	int len;

	g_assert( x1 <= x2 );

	if( y < 0 || 
		y >= draw->image->Ysize )
		return( 0 );
	if( x1 < 0 && 
		x2 < 0 )
		return( 0 );
	if( x1 >= draw->image->Xsize && 
		x2 >= draw->image->Xsize )
		return( 0 );
	x1 = VIPS_CLIP( 0, x1, draw->image->Xsize - 1 );
	x2 = VIPS_CLIP( 0, x2, draw->image->Xsize - 1 );

	mp = VIPS_IMAGE_ADDR( draw->image, x1, y );
	len = x2 - x1 + 1;

	for( i = 0; i < len; i++ ) {
		vips__drawink_pel( drawink, mp );
		mp += draw->psize;
	}

	return( 0 );
}


