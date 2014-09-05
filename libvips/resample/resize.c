/* resize an image ... a simple wrapper over affine
 *
 * 13/8/14
 * 	- from affine.c
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
#define DEBUG_VERBOSE
#define DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <limits.h>

#include <vips/vips.h>
#include <vips/debug.h>
#include <vips/internal.h>
#include <vips/transform.h>

#include "presample.h"

typedef struct _VipsResize {
	VipsResample parent_instance;

	double h_scale;
	double v_scale;
	VipsInterpolate *interpolate;
	double idx;
	double idy;

} VipsResize;

typedef VipsResampleClass VipsResizeClass;

G_DEFINE_TYPE( VipsResize, vips_resize, VIPS_TYPE_RESAMPLE ); 

static int
vips_resize_build( VipsObject *object )
{
	VipsResample *resample = VIPS_RESAMPLE( object );
	VipsResize *resize = (VipsResize *) object;

	VipsImage **t = (VipsImage **) 
		vips_object_local_array( object, 4 );

	double a, b, c, d; 

	if( VIPS_OBJECT_CLASS( vips_resize_parent_class )->build( object ) )
		return( -1 );

	a = resize->h_scale;
	b = 0.0;
	c = 0.0;
	d = resize->v_scale;

	if( vips_affine( resample->in, &t[0], a, b, c, d, 
		"interpolate", resize->interpolate,
		"idx", resize->idx,
		"idy", resize->idy,
		NULL ) ||
		vips_image_write( t[0], resample->out ) )
		return( -1 ); 

	return( 0 );
}

static void
vips_resize_class_init( VipsResizeClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );
	VipsOperationClass *operation_class = VIPS_OPERATION_CLASS( class );

	VIPS_DEBUG_MSG( "vips_resize_class_init\n" );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "resize";
	vobject_class->description = _( "resize an image" );
	vobject_class->build = vips_resize_build;

	operation_class->flags = VIPS_OPERATION_SEQUENTIAL;

	VIPS_ARG_DOUBLE( class, "h_scale", 113, 
		_( "Horizontal scale factor" ), 
		_( "Scale image by this factor in the horizontal axis" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsResize, h_scale ),
		0, 10000000, 0 );

	VIPS_ARG_DOUBLE( class, "v_scale", 114, 
		_( "Vertical scale factor" ), 
		_( "Scale image by this factor in the vertical axis" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsResize, v_scale ),
		0, 10000000, 0 );

	VIPS_ARG_INTERPOLATE( class, "interpolate", 2, 
		_( "Interpolate" ), 
		_( "Interpolate pixels with this" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT, 
		G_STRUCT_OFFSET( VipsResize, interpolate ) );

	VIPS_ARG_DOUBLE( class, "idx", 115, 
		_( "Input offset" ), 
		_( "Horizontal input displacement" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsResize, idx ),
		-10000000, 10000000, 0 );

	VIPS_ARG_DOUBLE( class, "idy", 116, 
		_( "Input offset" ), 
		_( "Vertical input displacement" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsResize, idy ),
		-10000000, 10000000, 0 );
}

static void
vips_resize_init( VipsResize *resize )
{
}

/**
 * vips_resize:
 * @in: input image
 * @out: output image
 * @h_scale: horizontal scale factor
 * @v_scale: vertical scale factor
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * @interpolate: interpolate pixels with this
 * @idx: input horizontal offset
 * @idy: input vertical offset
 *
 * @interpolate defaults to bilinear. 
 *
 * @idx, @idy default to zero.
 *
 * See also: vips_shrink(), vips_affine(), #VipsInterpolate.
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_resize( VipsImage *in, VipsImage **out, 
	double h_scale, double v_scale, ... )
{
	va_list ap;
	int result;

	va_start( ap, v_scale );
	result = vips_call_split( "affine", ap, in, out, h_scale, v_scale );
	va_end( ap );

	return( result );
}



