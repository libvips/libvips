/* shrink with a box filter
 *
 * 30/10/15
 * 	- from shrink.c (now renamed as shrink2.c)
 * 	- split to h and v shrinks for a large memory saving
 * 	- now handles complex
 * 15/8/16
 * 	- more accurate resize
 * 	- rename xshrink -> hshrink for greater consistency 
 * 9/2/17
 * 	- use reduce, not affine, for any residual shrink
 * 	- expand cache hint
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

/*
#define DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <stdlib.h>
#include <math.h>

#include <vips/vips.h>
#include <vips/debug.h>
#include <vips/internal.h>

#include "presample.h"

typedef struct _VipsShrink {
	VipsResample parent_instance;

	double hshrink;		/* Shrink factors */
	double vshrink;

} VipsShrink;

typedef VipsResampleClass VipsShrinkClass;

G_DEFINE_TYPE( VipsShrink, vips_shrink, VIPS_TYPE_RESAMPLE );

static int
vips_shrink_build( VipsObject *object )
{
	VipsResample *resample = VIPS_RESAMPLE( object );
	VipsShrink *shrink = (VipsShrink *) object;
	VipsImage **t = (VipsImage **) 
		vips_object_local_array( object, 3 );

	int hshrink_int;
	int vshrink_int;

	if( VIPS_OBJECT_CLASS( vips_shrink_parent_class )->build( object ) )
		return( -1 );

	hshrink_int = (int) shrink->hshrink;
	vshrink_int = (int) shrink->vshrink;

	if( hshrink_int != shrink->hshrink || 
		vshrink_int != shrink->vshrink ) {
		/* Shrink by int factors, reduce to final size.
		 */
		double xresidual = shrink->hshrink / hshrink_int; 
		double yresidual = shrink->vshrink / vshrink_int;

		if( vips_shrinkv( resample->in, &t[0], vshrink_int, NULL ) ||
			vips_shrinkh( t[0], &t[1], hshrink_int, NULL ) )
			return( -1 ); 

		if( vips_reduce( t[1], &t[2], xresidual, yresidual, NULL ) ||
			vips_image_write( t[2], resample->out ) )
			return( -1 );
	}
	else {
		if( vips_shrinkv( resample->in, &t[0], shrink->vshrink, NULL ) ||
			vips_shrinkh( t[0], &t[1], shrink->hshrink, NULL ) ||
			vips_image_write( t[1], resample->out ) )
			return( -1 );
	}

	return( 0 );
}

static void
vips_shrink_class_init( VipsShrinkClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );
	VipsOperationClass *operation_class = VIPS_OPERATION_CLASS( class );

	VIPS_DEBUG_MSG( "vips_shrink_class_init\n" );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "shrink";
	vobject_class->description = _( "shrink an image" );
	vobject_class->build = vips_shrink_build;

	operation_class->flags = VIPS_OPERATION_SEQUENTIAL;

	VIPS_ARG_DOUBLE( class, "vshrink", 9, 
		_( "Vshrink" ), 
		_( "Vertical shrink factor" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsShrink, vshrink ),
		1.0, 1000000.0, 1.0 );

	VIPS_ARG_DOUBLE( class, "hshrink", 8, 
		_( "Hshrink" ), 
		_( "Horizontal shrink factor" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsShrink, hshrink ),
		1.0, 1000000.0, 1.0 );

	/* The old names .. now use h and v everywhere. 
	 */
	VIPS_ARG_DOUBLE( class, "xshrink", 8, 
		_( "Xshrink" ), 
		_( "Horizontal shrink factor" ),
		VIPS_ARGUMENT_REQUIRED_INPUT | VIPS_ARGUMENT_DEPRECATED,
		G_STRUCT_OFFSET( VipsShrink, hshrink ),
		1.0, 1000000.0, 1.0 );

	VIPS_ARG_DOUBLE( class, "yshrink", 9, 
		_( "Yshrink" ), 
		_( "Vertical shrink factor" ),
		VIPS_ARGUMENT_REQUIRED_INPUT | VIPS_ARGUMENT_DEPRECATED,
		G_STRUCT_OFFSET( VipsShrink, vshrink ),
		1.0, 1000000.0, 1.0 );

}

static void
vips_shrink_init( VipsShrink *shrink )
{
}

/**
 * vips_shrink:
 * @in: input image
 * @out: output image
 * @hshrink: horizontal shrink
 * @vshrink: vertical shrink
 * @...: %NULL-terminated list of optional named arguments
 *
 * Shrink @in by a pair of factors with a simple box filter. For non-integer
 * factors, vips_shrink() will first shrink by the integer part with a box
 * filter, then use vips_reduce() to shrink by the
 * remaining fractional part. 
 *
 * This is a very low-level operation: see vips_resize() for a more
 * convenient way to resize images. 
 *
 * This operation does not change xres or yres. The image resolution needs to
 * be updated by the application. 
 *
 * See also: vips_resize(), vips_reduce().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_shrink( VipsImage *in, VipsImage **out, 
	double hshrink, double vshrink, ... )
{
	va_list ap;
	int result;

	va_start( ap, vshrink );
	result = vips_call_split( "shrink", ap, in, out, hshrink, vshrink );
	va_end( ap );

	return( result );
}
