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
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

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

/**
 * VipsJoin:
 * @in1: first input image 
 * @in2: second input image 
 * @out: output image
 * @direction: join horizontally or vertically
 * @expand: TRUE to expand the output image to hold all of the input pixels
 * @shim: space between images, in pixels
 * @background: background ink colour
 * @align: low, centre or high alignment
 *
 * Join @left and @right together, left-right. If one is taller than the
 * other, @out will be has high as the smaller.
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

typedef struct _VipsJoin {
	VipsConversion parent_instance;

	/* Params.
	 */
	VipsImage *main;
	VipsImage *sub;
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

	if( VIPS_OBJECT_CLASS( vips_join_parent_class )->build( object ) )
		return( -1 );

	switch( join->direction ) {
	case VIPS_DIRECTION_HORIZONTAL:
		x = join->main->Xsize + join->shim;

		switch( join->align ) {
		case VIPS_ALIGN_LOW:
			y = 0;
			break;

		case VIPS_ALIGN_CENTRE:
			mx = VIPS_MAX( join->main->Ysize, join->sub->Ysize );
			y = 
			break;

		case VIPS_ALIGN_HIGH:
			y = 0;
			break;


	case VIPS_DIRECTION_VERTICAL:

	default:
		g_asert( 0 );
	}
	

	return( 0 );
}

static void
vips_join_class_init( VipsJoinClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	VIPS_DEBUG_MSG( "vips_join_class_init\n" );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "join";
	vobject_class->description = _( "join an image" );
	vobject_class->build = vips_join_build;

	VIPS_ARG_IMAGE( class, "main", -1, 
		_( "Main" ), 
		_( "Main input image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsJoin, main ) );

	VIPS_ARG_IMAGE( class, "sub", 0, 
		_( "Sub-image" ), 
		_( "Sub-image to join into main image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsJoin, sub ) );

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
		G_STRUCT_OFFSET( VipsInsert, shim ),
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
		VIPS_ARGUMENT_REQUIRED_INPUT,
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

int
vips_join( VipsImage *main, VipsImage *sub, VipsImage **out, 
	VipsDirection direction, ... )
{
	va_list ap;
	int result;

	va_start( ap, y );
	result = vips_call_split( "join", ap, main, sub, out, direction );
	va_end( ap );

	return( result );
}
