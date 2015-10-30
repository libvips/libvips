/* shrink with a box filter
 *
 * 30/10/15
 * 	- from shrink.c
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

typedef struct _VipsShrink2 {
	VipsResample parent_instance;

	int xshrink;		/* Shrink factors */
	int yshrink;

} VipsShrink2;

typedef VipsResampleClass VipsShrink2Class;

G_DEFINE_TYPE( VipsShrink2, vips_shrink2, VIPS_TYPE_RESAMPLE );

static int
vips_shrink2_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsResample *resample = VIPS_RESAMPLE( object );
	VipsShrink2 *shrink = (VipsShrink2 *) object;
	VipsImage **t = (VipsImage **) 
		vips_object_local_array( object, 1 );

	VipsImage *in;

	if( VIPS_OBJECT_CLASS( vips_shrink2_parent_class )->build( object ) )
		return( -1 );

	in = resample->in; 

	if( vips_shrinkh( in, &t[0], shrink->xshrink, NULL ) ||
		vips_shrinkv( t[0], &t[1], shrink->yshrink, NULL ) )
		return( -1 );
	in = t[1];

	return( 0 );
}

static void
vips_shrink2_class_init( VipsShrink2Class *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );
	VipsOperationClass *operation_class = VIPS_OPERATION_CLASS( class );

	VIPS_DEBUG_MSG( "vips_shrink2_class_init\n" );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "shrink2";
	vobject_class->description = _( "shrink an image" );
	vobject_class->build = vips_shrink2_build;

	operation_class->flags = VIPS_OPERATION_SEQUENTIAL;

	VIPS_ARG_INT( class, "xshrink", 8, 
		_( "Xshrink" ), 
		_( "Horizontal shrink factor" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsShrink2, xshrink ),
		1.0, 1000000, 1 );

	VIPS_ARG_INT( class, "yshrink", 9, 
		_( "Yshrink" ), 
		_( "Vertical shrink factor" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsShrink2, yshrink ),
		1.0, 1000000, 1 );

}

static void
vips_shrink2_init( VipsShrink2 *shrink )
{
}

/**
 * vips_shrink2:
 * @in: input image
 * @out: output image
 * @xshrink: horizontal shrink
 * @yshrink: vertical shrink
 * @...: %NULL-terminated list of optional named arguments
 *
 * Shrink @in by a pair of factors with a simple box filter. 
 *
 * You will get aliasing for non-integer shrinks. In this case, shrink with
 * this function to the nearest integer size above the target shrink, then
 * downsample to the exact size with vips_affine() and your choice of
 * interpolator. See vips_resize() for a convenient way to do this.
 *
 * This operation does not change xres or yres. The image resolution needs to
 * be updated by the application. 
 *
 * See also: vips_resize(), vips_affine().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_shrink2( VipsImage *in, VipsImage **out, 
	int xshrink, int yshrink, ... )
{
	va_list ap;
	int result;

	va_start( ap, yshrink );
	result = vips_call_split( "shrink2", ap, in, out, xshrink, yshrink );
	va_end( ap );

	return( result );
}
