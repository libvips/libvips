/* read a single getpoint
 *
 * Copyright: J. Cupitt
 * Written: 15/06/1992
 * 22/7/93 JC
 *	- im_incheck() added
 * 16/8/94 JC
 *	- im_incheck() changed to im_makerw()
 * 5/12/06
 * 	- im_invalidate() after paint
 * 6/3/10
 * 	- don't im_invalidate() after paint, this now needs to be at a higher
 * 	  level
 * 29/9/10
 * 	- gtk-doc
 * 	- use Draw base class
 * 	- read_getpoint partial-ised
 * 10/2/14
 * 	- redo as a class
 * 16/12/14
 * 	- free the input region much earlier
 * 14/10/16
 * 	- crop to a memory image rather than using a region ... this means we
 * 	  use workers to calculate pixels and therefore use per-thread caching
 * 	  in the revised buffer system
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
#define VIPS_DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#include <vips/vips.h>
#include <vips/internal.h>

#include "statistic.h"

typedef struct _VipsGetpoint {
	VipsOperation parent_instance;

	VipsImage *in;
	int x;
	int y;
	VipsArrayDouble *out_array;

} VipsGetpoint;

typedef VipsOperationClass VipsGetpointClass;

G_DEFINE_TYPE( VipsGetpoint, vips_getpoint, VIPS_TYPE_OPERATION );

static int
vips_getpoint_build( VipsObject *object )
{
	VipsGetpoint *getpoint = (VipsGetpoint *) object;
	VipsImage **t = (VipsImage **) vips_object_local_array( object, 4 );

	double *vector;
	VipsArrayDouble *out_array;

	if( VIPS_OBJECT_CLASS( vips_getpoint_parent_class )->build( object ) )
		return( -1 );

	/* Crop, decode and unpack to double.
	 */
	if( vips_crop( getpoint->in, &t[0], 
		getpoint->x, getpoint->y, 1, 1, NULL ) ||
		vips_image_decode( t[0], &t[1] ) ||
		vips_cast( t[1], &t[2], VIPS_FORMAT_DOUBLE, NULL ) )
		return( -1 );

	/* To a mem buffer, then copy to out. 
	 */
	vips_image_set_int( t[2], "hide-progress", 1 );
	if( !(t[3] = vips_image_new_memory()) ||
		vips_image_write( t[2], t[3] ) )
		return( -1 );

	if( !(vector = VIPS_ARRAY( getpoint->in, t[3]->Bands, double )) )
		return( -1 );
	memcpy( vector, t[3]->data, VIPS_IMAGE_SIZEOF_PEL( t[3] ) );

	out_array = vips_array_double_new( vector, t[3]->Bands );
	g_object_set( object, 
		"out_array", out_array,
		NULL );
	vips_area_unref( VIPS_AREA( out_array ) );

	return( 0 );
}

static void
vips_getpoint_class_init( VipsGetpointClass *class )
{
	GObjectClass *gobject_class = (GObjectClass *) class;
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "getpoint";
	object_class->description = _( "read a point from an image" );
	object_class->build = vips_getpoint_build;

	VIPS_ARG_IMAGE( class, "in", 1,
		_( "in" ), 
		_( "Input image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsGetpoint, in ) );

	VIPS_ARG_BOXED( class, "out_array", 2, 
		_( "Output array" ), 
		_( "Array of output values" ),
		VIPS_ARGUMENT_REQUIRED_OUTPUT,
		G_STRUCT_OFFSET( VipsGetpoint, out_array ),
		VIPS_TYPE_ARRAY_DOUBLE );

	VIPS_ARG_INT( class, "x", 5, 
		_( "x" ), 
		_( "Point to read" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsGetpoint, x ),
		0, VIPS_MAX_COORD, 0 );

	VIPS_ARG_INT( class, "y", 6, 
		_( "y" ), 
		_( "Point to read" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsGetpoint, y ),
		0, VIPS_MAX_COORD, 0 );

}

static void
vips_getpoint_init( VipsGetpoint *getpoint )
{
}

/**
 * vips_getpoint: (method)
 * @in: image to read from
 * @vector: (out)(array length=n): output pixel value here
 * @n: length of output vector
 * @x: position to read
 * @y: position to read
 * @...: %NULL-terminated list of optional named arguments
 *
 * Reads a single pixel on an image. 
 *
 * The pixel values are returned in @vector, the length of the
 * array in @n. You must free the array with g_free() when you are done with
 * it.
 *
 * See also: vips_draw_point().
 *
 * Returns: 0 on success, or -1 on error.
 */
int
vips_getpoint( VipsImage *in, double **vector, int *n, int x, int y, ... )
{
	va_list ap;
	VipsArrayDouble *out_array;
	VipsArea *area;
	int result;

	va_start( ap, y );
	result = vips_call_split( "getpoint", ap, in, &out_array, x, y );
	va_end( ap );

	if( result )
		return( -1 ); 

	area = VIPS_AREA( out_array );
	*vector = VIPS_ARRAY( NULL, area->n, double );
	if( !*vector ) {
		vips_area_unref( area );
		return( -1 );
	}
	memcpy( *vector, area->data, area->n * area->sizeof_type ); 
	*n = area->n;
        vips_area_unref( area );

	return( 0 );
}
