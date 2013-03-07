/* join left-right and up-down
 *
 * Copyright 1990, 1991: Kirk Martinez, N. Dessipris
 * Author: Kirk Martinez, N. Dessipris
 * Written on: 9/6/90
 * Modified on: 17/04/1991
 * 31/8/93 JC
 *	- args to memcpy() were reversed
 * 14/11/94 JC
 *	- tided up and ANSIfied
 * 	- now accepts IM_CODING_LABQ
 *	- memory leaks removed
 *	- bug in calculation of output Xsize removed (thanks Thomson!)
 *	- bug in checking of image compatibility fixed
 * 23/10/95 JC
 *	- rewritten in terms of im_insert()
 * 14/4/04 
 *	- sets Xoffset / Yoffset
 * 1/2/10
 * 	- gtkdoc
 * 	- cleanups
 * 19/10/11
 * 	- redone as a class
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
#include <string.h>
#include <stdlib.h>

#include <vips/vips.h>
#include <vips/internal.h>
#include <vips/debug.h>

#include "conversion.h"

typedef struct _VipsJoin {
	VipsConversion parent_instance;

	/* Params.
	 */
	VipsImage *in1;
	VipsImage *in2;
	VipsDirection direction;
	gboolean expand;
	int shim;
	VipsArea *background;
	VipsAlign align;
} VipsJoin;

typedef VipsConversionClass VipsJoinClass;

G_DEFINE_TYPE( VipsJoin, vips_join, VIPS_TYPE_CONVERSION );

static int
vips_join_build( VipsObject *object )
{
	VipsConversion *conversion = VIPS_CONVERSION( object );
	VipsJoin *join = (VipsJoin *) object;

	int x, y;
	VipsImage *t;

	if( VIPS_OBJECT_CLASS( vips_join_parent_class )->build( object ) )
		return( -1 );

	switch( join->direction ) {
	case VIPS_DIRECTION_HORIZONTAL:
		x = join->in1->Xsize + join->shim;

		switch( join->align ) {
		case VIPS_ALIGN_LOW:
			y = 0;
			break;

		case VIPS_ALIGN_CENTRE:
			y = join->in1->Ysize / 2 - join->in2->Ysize / 2;
			break;

		case VIPS_ALIGN_HIGH:
			y = join->in1->Ysize - join->in2->Ysize;
			break;

		default:
			g_assert( 0 );

			/* Keep -Wall happy.
			 */
			return( 0 );
		}

		break;

	case VIPS_DIRECTION_VERTICAL:
		y = join->in1->Ysize + join->shim;

		switch( join->align ) {
		case VIPS_ALIGN_LOW:
			x = 0;
			break;

		case VIPS_ALIGN_CENTRE:
			x = join->in1->Xsize / 2 - join->in2->Xsize / 2;
			break;

		case VIPS_ALIGN_HIGH:
			x = join->in1->Xsize - join->in2->Xsize;
			break;

		default:
			g_assert( 0 );

			/* Keep -Wall happy.
			 */
			return( 0 );
		}

		break;

	default:
		g_assert( 0 );

		/* Keep -Wall happy.
		 */
		return( 0 );
	}

	if( vips_insert( join->in1, join->in2, &t, x, y,
		"expand", TRUE,
		"background", join->background,
		NULL ) )
		return( -1 );

	if( !join->expand ) {
		VipsImage *t2;
		int left, top, width, height;

		switch( join->direction ) {
		case VIPS_DIRECTION_HORIZONTAL:
			left = 0;
			top = VIPS_MAX( 0, y ) - y;
			width = t->Xsize;
			height = VIPS_MIN( join->in1->Ysize, join->in2->Ysize );
			break;

		case VIPS_DIRECTION_VERTICAL:
			left = VIPS_MAX( 0, x ) - x;
			top = 0;
			width = VIPS_MIN( join->in1->Xsize, join->in2->Xsize );
			height = t->Ysize; 
			break;

		default:
			g_assert( 0 );

			/* Keep -Wall happy.
			 */
			return( 0 );
		}

		if( vips_extract_area( t, &t2, 
			left, top, width, height, NULL ) ) {
			g_object_unref( t );
			return( -1 );
		}
		g_object_unref( t );

		t = t2;
	}

	if( vips_image_write( t, conversion->out ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

static void
vips_join_class_init( VipsJoinClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );
	VipsOperationClass *operation_class = VIPS_OPERATION_CLASS( class );

	VIPS_DEBUG_MSG( "vips_join_class_init\n" );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "join";
	vobject_class->description = _( "join a pair of images" );
	vobject_class->build = vips_join_build;

	operation_class->flags = VIPS_OPERATION_SEQUENTIAL;

	VIPS_ARG_IMAGE( class, "in1", -1, 
		_( "in1" ), 
		_( "First input image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsJoin, in1 ) );

	VIPS_ARG_IMAGE( class, "in2", 0, 
		_( "in2" ), 
		_( "Second input image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsJoin, in2 ) );

	VIPS_ARG_ENUM( class, "direction", 2, 
		_( "direction" ), 
		_( "Join left-right or up-down" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsJoin, direction ),
		VIPS_TYPE_DIRECTION, VIPS_DIRECTION_HORIZONTAL ); 

	VIPS_ARG_BOOL( class, "expand", 4, 
		_( "Expand" ), 
		_( "Expand output to hold all of both inputs" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsJoin, expand ),
		FALSE );

	VIPS_ARG_INT( class, "shim", 5, 
		_( "Shim" ), 
		_( "Pixels between images" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsJoin, shim ),
		0, 1000000, 0 );

	VIPS_ARG_BOXED( class, "background", 6, 
		_( "Background" ), 
		_( "Colour for new pixels" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsJoin, background ),
		VIPS_TYPE_ARRAY_DOUBLE );

	VIPS_ARG_ENUM( class, "align", 2, 
		_( "Align" ), 
		_( "Align on the low, centre or high coordinate edge" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsJoin, align ),
		VIPS_TYPE_ALIGN, VIPS_ALIGN_LOW ); 
}

static void
vips_join_init( VipsJoin *join )
{
	/* Init our instance fields.
	 */
	join->background = 
		vips_area_new_array( G_TYPE_DOUBLE, sizeof( double ), 1 ); 
	((double *) (join->background->data))[0] = 0.0;
}

/**
 * vips_join:
 * @in1: first input image 
 * @in2: second input image 
 * @out: output image
 * @direction: join horizontally or vertically
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * @expand: %TRUE to expand the output image to hold all of the input pixels
 * @shim: space between images, in pixels
 * @background: background ink colour
 * @align: low, centre or high alignment
 *
 * Join @in1 and @in2 together, left-right or up-down depending on the value 
 * of @direction.
 *
 * If one is taller or wider than the
 * other, @out will be has high as the smaller. If @expand is %TRUE, then
 * the output will be expanded to contain all of the input pixels.
 *
 * Use @align to set the edge that the images align on. By default, they align
 * on the edge with the lower value coordinate.
 *
 * Use @background to set the colour of any pixels in @out which are not
 * present in either @in1 or @in2.
 *
 * Use @shim to set the spacing between the images. By default this is 0.
 * 
 * If the number of bands differs, one of the images 
 * must have one band. In this case, an n-band image is formed from the 
 * one-band image by joining n copies of the one-band image together, and then
 * the two n-band images are operated upon.
 *
 * The two input images are cast up to the smallest common type (see table 
 * Smallest common format in 
 * <link linkend="VIPS-arithmetic">arithmetic</link>).
 *
 * See also: vips_insert().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_join( VipsImage *in1, VipsImage *in2, VipsImage **out, 
	VipsDirection direction, ... )
{
	va_list ap;
	int result;

	va_start( ap, direction );
	result = vips_call_split( "join", ap, in1, in2, out, direction );
	va_end( ap );

	return( result );
}
