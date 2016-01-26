/* count lines 
 *
 * Copyright: 1990, N. Dessipris.
 *
 * Author: Nicos Dessipris
 * Written on: 02/05/1990
 * Modified on : 
 *
 * 19/9/95 JC
 *	- tidied up
 * 23/10/10
 * 	- gtk-doc
 * 17/1/14
 * 	- redone as a class, now just a convenience function
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

#include "pmorphology.h"

typedef struct _VipsCountlines {
	VipsMorphology parent_instance;

	double nolines;
	VipsDirection direction;
} VipsCountlines;

typedef VipsMorphologyClass VipsCountlinesClass;

G_DEFINE_TYPE( VipsCountlines, vips_countlines, VIPS_TYPE_MORPHOLOGY );

static int
vips_countlines_build( VipsObject *object )
{
	VipsMorphology *morphology = VIPS_MORPHOLOGY( object );
	VipsCountlines *countlines = (VipsCountlines *) object;
	VipsImage *in = morphology->in;
	VipsImage **t = (VipsImage **) vips_object_local_array( object, 7 );

	double nolines;

	if( VIPS_OBJECT_CLASS( vips_countlines_parent_class )->build( object ) )
		return( -1 );

	/* Compiler warnings.
	 */
	nolines = 1;

	switch( countlines->direction ) {
	case VIPS_DIRECTION_HORIZONTAL:
		if( !(t[0] = vips_image_new_matrixv( 1, 2, -1.0, 1.0 )) ||
			vips_moreeq_const1( in, &t[1], 128, NULL ) ||
			vips_conv( t[1], &t[2], t[0], NULL ) ||
			vips_project( t[2], &t[3], &t[4], NULL ) ||
			vips_avg( t[3], &nolines, NULL ) )
			return( -1 ); 
		break;

	case VIPS_DIRECTION_VERTICAL:
		if( !(t[0] = vips_image_new_matrixv( 2, 1, -1.0, 1.0 )) ||
			vips_moreeq_const1( in, &t[1], 128, NULL ) ||
			vips_conv( t[1], &t[2], t[0], NULL ) ||
			vips_project( t[2], &t[3], &t[4], NULL ) ||
			vips_avg( t[4], &nolines, NULL ) )
			return( -1 ); 
		break;

	default:
		g_assert_not_reached();
	}

	g_object_set( object, "nolines", nolines / 255.0, NULL );

	return( 0 );
}

static void
vips_countlines_class_init( VipsCountlinesClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	VIPS_DEBUG_MSG( "vips_countlines_class_init\n" );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "countlines";
	vobject_class->description = _( "count lines in an image" ); 
	vobject_class->build = vips_countlines_build;

	VIPS_ARG_DOUBLE( class, "nolines", 2, 
		_( "Nolines" ), 
		_( "Number of lines" ),
		VIPS_ARGUMENT_REQUIRED_OUTPUT,
		G_STRUCT_OFFSET( VipsCountlines, nolines ),
		0, 10000000, 0.0 );

	VIPS_ARG_ENUM( class, "direction", 3, 
		_( "direction" ), 
		_( "Countlines left-right or up-down" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsCountlines, direction ),
		VIPS_TYPE_DIRECTION, VIPS_DIRECTION_HORIZONTAL ); 

}

static void
vips_countlines_init( VipsCountlines *countlines )
{
}

/**
 * vips_countlines:
 * @in: input image
 * @nolines: output average number of lines
 * @direction: count lines horizontally or vertically
 * @...: %NULL-terminated list of optional named arguments
 *
 * Function which calculates the number of transitions
 * between black and white for the horizontal or the vertical
 * direction of an image.  black<128 , white>=128
 * The function calculates the number of transitions for all
 * Xsize or Ysize and returns the mean of the result
 * Input should be one band, 8-bit.
 *
 * See also: vips_morph(), vips_conv().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_countlines( VipsImage *in, double *nolines, 
	VipsDirection direction, ... )
{
	va_list ap;
	int result;

	va_start( ap, direction );
	result = vips_call_split( "countlines", ap, in, nolines, direction );
	va_end( ap );

	return( result );
}
