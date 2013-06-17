/* im_wrap
 *
 * Copyright: 2008, Nottingham Trent University
 * Author: Tom Vajzovic
 * Written on: 2008-01-15
 * 2/2/10
 * 	- rewritten in terms of im_replicate()/im_extract_area()
 * 	- gtkdoc
 * 	- allows any x/y 
 * 31/5/13
 * 	- redone as a class
 * 	- added rotquad behaviour if x/y not set
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

#include <vips/vips.h>

#include "pconversion.h"

typedef struct _VipsWrap {
	VipsConversion parent_instance;

	VipsImage *in;

	int x;
	int y;

} VipsWrap;

typedef VipsConversionClass VipsWrapClass;

G_DEFINE_TYPE( VipsWrap, vips_wrap, VIPS_TYPE_CONVERSION );

static int
vips_wrap_build( VipsObject *object )
{
	VipsConversion *conversion = VIPS_CONVERSION( object );
	VipsWrap *wrap = (VipsWrap *) object;
	VipsImage **t = (VipsImage **) vips_object_local_array( object, 7 );

	int x;
	int y;

	if( VIPS_OBJECT_CLASS( vips_wrap_parent_class )->build( object ) )
		return( -1 );

	if( !vips_object_argument_isset( object, "x" ) )
		wrap->x = wrap->in->Xsize / 2;
	if( !vips_object_argument_isset( object, "y" ) )
		wrap->y = wrap->in->Ysize / 2;

	/* Clock arithmetic: we want negative x/y to wrap around
	 * nicely.
	 */
	x = wrap->x < 0 ? 
		-wrap->x % wrap->in->Xsize : 
		wrap->in->Xsize - wrap->x % wrap->in->Xsize;
	y = wrap->y < 0 ? 
		-wrap->y % wrap->in->Ysize : 
		wrap->in->Ysize - wrap->y % wrap->in->Ysize;

	if( vips_replicate( wrap->in, &t[0], 2, 2, NULL ) ||
		vips_extract_area( t[0], &t[1], 
			x, y, wrap->in->Xsize, wrap->in->Ysize, NULL ) ||
		vips_image_write( t[1], conversion->out ) )
		return( -1 );

	conversion->out->Xoffset = x;
	conversion->out->Yoffset = y;

	return( 0 );
}

static void
vips_wrap_class_init( VipsWrapClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "wrap";
	vobject_class->description = _( "wrap image origin" );
	vobject_class->build = vips_wrap_build;

	VIPS_ARG_IMAGE( class, "in", 1, 
		_( "Input" ), 
		_( "Input image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsWrap, in ) );

	VIPS_ARG_INT( class, "x", 3, 
		_( "x" ), 
		_( "Left edge of input in output" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsWrap, x ),
		-1000000, 1000000, 0 );

	VIPS_ARG_INT( class, "y", 4, 
		_( "y" ), 
		_( "Top edge of input in output" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsWrap, y ),
		-1000000, 1000000, 0 );

}

static void
vips_wrap_init( VipsWrap *wrap )
{
}

/**
 * vips_wrap:
 * @in: input image
 * @out: output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * @x: horizontal displacement
 * @y: vertical displacement
 *
 * Slice an image up and move the segments about so that the pixel that was
 * at 0, 0 is now at @x, @y. If @x and @y are not set, they default to the
 * centre of the image. 
 *
 * See also: vips_embed(), vips_replicate().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_wrap( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "wrap", ap, in, out );
	va_end( ap );

	return( result );
}

