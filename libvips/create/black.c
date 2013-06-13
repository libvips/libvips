/* im_black.c
 *
 * Copyright: 1990, J. Cupitt
 *
 * Author: J. Cupitt
 * Written on: 02/08/1990
 * Modified on : 16/04/1991 by N. Dessipris to work on a line by line basis
 * 15/8/94 JC
 *	- adapted for partials
 *	- ANSIfied
 * 	- memory leaks fixed!
 * 2/3/98 JC
 *	- IM_ANY added
 * 18/1/09
 * 	- gtkdoc
 * 31/10/11
 * 	- redo as a class
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

#include "create.h"

typedef struct _VipsBlack {
	VipsCreate parent_instance;

	int width;
	int height;
	int bands;

} VipsBlack;

typedef VipsCreateClass VipsBlackClass;

G_DEFINE_TYPE( VipsBlack, vips_black, VIPS_TYPE_CREATE );

static int
vips_black_gen( VipsRegion *or, void *seq, void *a, void *b,
	gboolean *stop )
{
	vips_region_black( or );

	return( 0 );
}

static int
vips_black_build( VipsObject *object )
{
	VipsCreate *create = VIPS_CREATE( object );
	VipsBlack *black = (VipsBlack *) object;

	if( VIPS_OBJECT_CLASS( vips_black_parent_class )->build( object ) )
		return( -1 );

	vips_image_init_fields( create->out,
		black->width, black->height, black->bands, 
		VIPS_FORMAT_UCHAR, VIPS_CODING_NONE,
                black->bands == 1 ? 
			VIPS_INTERPRETATION_B_W : VIPS_INTERPRETATION_MULTIBAND,
		1.0, 1.0 );
	vips_demand_hint( create->out, 
		VIPS_DEMAND_STYLE_ANY, NULL );

	if( vips_image_generate( create->out, 
		NULL, vips_black_gen, NULL, NULL, NULL ) )
		return( -1 );

	return( 0 );
}

static void
vips_black_class_init( VipsBlackClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	VIPS_DEBUG_MSG( "vips_black_class_init\n" );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "black";
	vobject_class->description = _( "make a black image" );
	vobject_class->build = vips_black_build;

	VIPS_ARG_INT( class, "width", 4, 
		_( "Width" ), 
		_( "Image width in pixels" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsBlack, width ),
		1, 1000000, 1 );

	VIPS_ARG_INT( class, "height", 5, 
		_( "Height" ), 
		_( "Image height in pixels" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsBlack, height ),
		1, 1000000, 1 );

	VIPS_ARG_INT( class, "bands", 6, 
		_( "Bands" ), 
		_( "Number of bands in image" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsBlack, bands ),
		1, 1000000, 1 );
}

static void
vips_black_init( VipsBlack *black )
{
	black->bands = 1;
}

/**
 * vips_black:
 * @out: output image
 * @width: output width
 * @height: output height
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * @bands: output bands
 *
 * Make a black unsigned char image of a specified size.
 *
 * See also: im_make_xy(), im_text(), im_gaussnoise().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_black( VipsImage **out, int width, int height, ... )
{
	va_list ap;
	int result;

	va_start( ap, height );
	result = vips_call_split( "black", ap, out, width, height );
	va_end( ap );

	return( result );
}
