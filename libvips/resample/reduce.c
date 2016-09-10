/* 2D reduce ... call reduceh and reducev
 *
 * 27/1/16
 * 	- from shrink.c 
 * 15/8/16
 * 	- rename xshrink -> hshrink for greater consistency 
 * 9/9/16
 * 	- add @centre option
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

/**
 * VipsKernel: 
 * @VIPS_KERNEL_NEAREST: The nearest pixel to the point.
 * @VIPS_KERNEL_LINEAR: Calculate a pixel value using linear interpolation.
 * @VIPS_KERNEL_CUBIC: Calculate using a 4-element cubic kernel.
 * @VIPS_KERNEL_LANCZOS2: Calculate with a two-lobe Lanczos kernel.
 * @VIPS_KERNEL_LANCZOS3: Calculate with a three-lobe Lanczos kernel.
 *
 * The resampling kernels vips supports. See vips_reduce(), for example.  
 *
 * The Lanczos kernels vary in size with the downsampling ratio. 
 */

typedef struct _VipsReduce {
	VipsResample parent_instance;

	double hshrink;		/* Shrink factors */
	double vshrink;

	/* The thing we use to make the kernel.
	 */
	VipsKernel kernel;

	/* Use centre rather than corner sampling convention.
	 */
	gboolean centre;

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

	if( vips_reducev( resample->in, &t[0], reduce->vshrink, 
		"kernel", reduce->kernel, 
		"centre", reduce->centre, 
		NULL ) ||
		vips_reduceh( t[0], &t[1], reduce->hshrink, 
			"kernel", reduce->kernel, 
			"centre", reduce->centre, 
			NULL ) ||
		vips_image_write( t[1], resample->out ) )
		return( -1 );

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

	VIPS_ARG_DOUBLE( class, "hshrink", 8, 
		_( "Hshrink" ), 
		_( "Horizontal shrink factor" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsReduce, hshrink ),
		1.0, 1000000.0, 1.0 );

	VIPS_ARG_DOUBLE( class, "vshrink", 9, 
		_( "Vshrink" ), 
		_( "Vertical shrink factor" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsReduce, vshrink ),
		1.0, 1000000.0, 1.0 );

	VIPS_ARG_ENUM( class, "kernel", 3, 
		_( "Kernel" ), 
		_( "Resampling kernel" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsReduce, kernel ),
		VIPS_TYPE_KERNEL, VIPS_KERNEL_LANCZOS3 );

	VIPS_ARG_BOOL( class, "centre", 7, 
		_( "Centre" ), 
		_( "Use centre sampling convention" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsReduce, centre ),
		FALSE );

	/* The old names .. now use h and v everywhere. 
	 */
	VIPS_ARG_DOUBLE( class, "xshrink", 8, 
		_( "Xshrink" ), 
		_( "Horizontal shrink factor" ),
		VIPS_ARGUMENT_REQUIRED_INPUT | VIPS_ARGUMENT_DEPRECATED,
		G_STRUCT_OFFSET( VipsReduce, hshrink ),
		1.0, 1000000.0, 1.0 );

	VIPS_ARG_DOUBLE( class, "yshrink", 9, 
		_( "Yshrink" ), 
		_( "Vertical shrink factor" ),
		VIPS_ARGUMENT_REQUIRED_INPUT | VIPS_ARGUMENT_DEPRECATED,
		G_STRUCT_OFFSET( VipsReduce, vshrink ),
		1.0, 1000000.0, 1.0 );

}

static void
vips_reduce_init( VipsReduce *reduce )
{
	reduce->kernel = VIPS_KERNEL_LANCZOS3;
}

/**
 * vips_reduce:
 * @in: input image
 * @out: output image
 * @hshrink: horizontal shrink
 * @vshrink: vertical shrink
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @kernel: #VipsKernel to use to interpolate (default: lanczos3)
 * * @centre: %gboolean use centre rather than corner sampling convention
 *
 * Reduce @in by a pair of factors with a pair of 1D kernels. This 
 * will not work well for shrink factors greater than three.
 *
 * Set @centre to use centre rather than corner sampling convention. Centre
 * convention can be useful to match the behaviour of other systems. 
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
	double hshrink, double vshrink, ... )
{
	va_list ap;
	int result;

	va_start( ap, vshrink );
	result = vips_call_split( "reduce", ap, in, out, hshrink, vshrink );
	va_end( ap );

	return( result );
}
