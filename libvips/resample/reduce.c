/* 2D reduce ... call reduceh and reducev
 *
 * 27/1/16
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

typedef struct _VipsReduce {
	VipsResample parent_instance;

	double xshrink;		/* Shrink factors */
	double yshrink;

} VipsReduce;

typedef VipsResampleClass VipsReduceClass;

G_DEFINE_TYPE( VipsReduce, vips_reduce, VIPS_TYPE_RESAMPLE );

static int
vips_reduce_build( VipsObject *object )
{
	VipsResample *resample = VIPS_RESAMPLE( object );
	VipsReduce *reduce = (VipsReduce *) object;
	VipsImage **t = (VipsImage **) 
		vips_object_local_array( object, 3 );

	if( VIPS_OBJECT_CLASS( vips_reduce_parent_class )->build( object ) )
		return( -1 );

	/*
	if( vips_reduceh( resample->in, &t[0], reduce->xshrink, NULL ) ||
		vips_linecache( t[0], &t[1], 
			"tile_height", 4,
			NULL ) ||
		vips_reducev( t[1], &t[2], reduce->yshrink, NULL ) ||
		vips_image_write( t[2], resample->out ) )
		return( -1 );
	*/

	/*
	if( vips_reducev( resample->in, &t[0], reduce->yshrink, NULL ) ||
		vips_linecache( t[0], &t[1], 
			"tile_height", 4,
			NULL ) ||
		vips_reduceh( t[1], &t[2], reduce->xshrink, NULL ) ||
		vips_image_write( t[2], resample->out ) )
		return( -1 );
	*/

	if( vips_reducev( resample->in, &t[0], reduce->yshrink, NULL ) ||
		vips_reduceh( t[0], &t[1], reduce->xshrink, NULL ) ||
		vips_image_write( t[1], resample->out ) )
		return( -1 );

	/*
	if( vips_reduceh( resample->in, &t[0], reduce->xshrink, NULL ) ||
		vips_reducev( t[0], &t[1], reduce->yshrink, NULL ) ||
		vips_image_write( t[1], resample->out ) )
		return( -1 );
	 */

	return( 0 );
}

static void
vips_reduce_class_init( VipsReduceClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );
	VipsOperationClass *operation_class = VIPS_OPERATION_CLASS( class );

	VIPS_DEBUG_MSG( "vips_reduce_class_init\n" );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "reduce";
	vobject_class->description = _( "reduce an image" );
	vobject_class->build = vips_reduce_build;

	operation_class->flags = VIPS_OPERATION_SEQUENTIAL;

	VIPS_ARG_DOUBLE( class, "xshrink", 8, 
		_( "Xshrink" ), 
		_( "Horizontal shrink factor" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsReduce, xshrink ),
		1.0, 1000000.0, 1.0 );

	VIPS_ARG_DOUBLE( class, "yshrink", 9, 
		_( "Yshrink" ), 
		_( "Vertical shrink factor" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsReduce, yshrink ),
		1.0, 1000000.0, 1.0 );

}

static void
vips_reduce_init( VipsReduce *reduce )
{
}

/**
 * vips_reduce:
 * @in: input image
 * @out: output image
 * @xshrink: horizontal shrink
 * @shrinke: vertical shrink
 * @...: %NULL-terminated list of optional named arguments
 *
 * Reduce @in by a pair of factors with a pair of 1D cubic interpolators. This 
 * will not work well for shrink factors greater than two.
 *
 * This is a very low-level operation: see vips_resize() for a more
 * convenient way to resize images. 
 *
 * This operation does not change xres or yres. The image resolution needs to
 * be updated by the application. 
 *
 * See also: vips_resize(), vips_affine().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_reduce( VipsImage *in, VipsImage **out, 
	double xshrink, double yshrink, ... )
{
	va_list ap;
	int result;

	va_start( ap, yshrink );
	result = vips_call_split( "reduce", ap, in, out, xshrink, yshrink );
	va_end( ap );

	return( result );
}
