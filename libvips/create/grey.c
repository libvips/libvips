/* grey ramps
 *
 * Copyright: 1990, N. Dessipris.
 *
 * Author: Nicos Dessipris
 * Written on: 02/02/1990
 * Modified on:
 * 22/7/93 JC
 *	- im_outcheck() added
 *	- externs removed
 * 8/2/95 JC
 *	- ANSIfied
 *	- im_fgrey() made from im_grey()
 * 31/8/95 JC
 *	- now makes [0,1], rather than [0,256)
 *	- im_grey() now defined in terms of im_fgrey()
 * 2/3/98 JC
 *	- partialed
 * 1/2/11
 * 	- gtk-doc
 * 13/6/13
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
#include <math.h>

#include <vips/vips.h>

#include "create.h"

typedef struct _VipsGrey {
	VipsCreate parent_instance;

	int width;
	int height;

	gboolean uchar;

} VipsGrey;

typedef VipsCreateClass VipsGreyClass;

G_DEFINE_TYPE( VipsGrey, vips_grey, VIPS_TYPE_CREATE );

static int
vips_grey_build( VipsObject *object )
{
	VipsCreate *create = VIPS_CREATE( object );
	VipsGrey *grey = (VipsGrey *) object;
	VipsImage **t = (VipsImage **) vips_object_local_array( object, 7 );
	VipsImage *in;

	if( VIPS_OBJECT_CLASS( vips_grey_parent_class )->build( object ) )
		return( -1 );

	if( vips_xyz( &t[0], grey->width, grey->height, NULL ) ||
		vips_extract_band( t[0], &t[1], 0, NULL ) )
		return( -1 );
	
	if( grey->uchar ) {
		if( vips_linear1( t[1], &t[2], 
				255.0 / (grey->width - 1), 0.0, NULL ) ||
			vips_cast( t[2], &t[3], VIPS_FORMAT_UCHAR, NULL ) )
			return( -1 );
		in = t[3];
	}
	else {
		if( vips_linear1( t[1], &t[2], 
			1.0 / (grey->width - 1), 0, NULL ) )
			return( -1 );
		in = t[2];
	}
	
	if( vips_image_write( in, create->out ) )
		return( -1 );

	return( 0 );
}

static void
vips_grey_class_init( VipsGreyClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "grey";
	vobject_class->description = _( "make a grey ramp image" );
	vobject_class->build = vips_grey_build;

	VIPS_ARG_INT( class, "width", 4, 
		_( "Width" ), 
		_( "Image width in pixels" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsGrey, width ),
		1, 1000000, 1 );

	VIPS_ARG_INT( class, "height", 5, 
		_( "Height" ), 
		_( "Image height in pixels" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsGrey, height ),
		1, 1000000, 1 );

	VIPS_ARG_BOOL( class, "uchar", 7, 
		_( "Uchar" ), 
		_( "Output an unsigned char image" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsGrey, uchar ),
		FALSE );

}

static void
vips_grey_init( VipsGrey *grey )
{
}

/**
 * vips_grey:
 * @out: output image
 * @xsize: image size
 * @ysize: image size
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * @uchar: output a uchar image
 *
 * Create a one-band float image with the left-most column zero and the
 * right-most 1. Intermediate pixels are a linear ramp.
 *
 * Set @uchar to output a uchar image with the leftmost pixel 0 and the
 * rightmost 255. 
 *
 * See also: vips_xyz(), vips_identity().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_grey( VipsImage **out, int width, int height, ... )
{
	va_list ap;
	int result;

	va_start( ap, height );
	result = vips_call_split( "grey", ap, out, width, height );
	va_end( ap );

	return( result );
}
