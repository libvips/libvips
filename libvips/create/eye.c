/* make a test pattern to show the eye's frequency response
 *
 * Copyright: 1990, 1991, N.Dessipris.
 *
 * Author N. Dessipris
 * Written on 30/05/1990
 * Updated on: 27/01/1991, 07/03/1991,
 * 22/7/93 JC
 *	- im_outcheck() added
 * 30/8/95 JC
 *	- modernized
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

#include "pcreate.h"
#include "point.h"

typedef struct _VipsEye {
	VipsPoint parent_instance;

	double factor;

} VipsEye;

typedef VipsPointClass VipsEyeClass;

G_DEFINE_TYPE( VipsEye, vips_eye, VIPS_TYPE_POINT );

static float
vips_eye_point( VipsPoint *point, int x, int y ) 
{
	VipsEye *eye = (VipsEye *) point;

	double c = eye->factor * VIPS_PI / (2 * (point->width - 1));
	double h = ((point->height - 1) * (point->height - 1));

	return( y * y * cos( c * x * x ) / h );
}

static void
vips_eye_class_init( VipsEyeClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );
	VipsPointClass *point_class = VIPS_POINT_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "eye";
	vobject_class->description = 
		_( "make an image showing the eye's spatial response" );

	point_class->point = vips_eye_point;

	VIPS_ARG_DOUBLE( class, "factor", 6, 
		_( "Factor" ), 
		_( "Maximum spatial frequency" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsEye, factor ),
		0.0, 1.0, 0.5 );
}

static void
vips_eye_init( VipsEye *eye )
{
	eye->factor = 0.5;
}


/**
 * vips_eye:
 * @out: output image
 * @width: image size
 * @height: image size
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @factor: maximum spatial frequency
 * * @uchar: output a uchar image
 *
 * Create a test pattern with increasing spatial frequence in X and 
 * amplitude in Y. @factor should be between 0 and 1 and determines the 
 * maximum spatial frequency.
 *
 * Set @uchar to output a uchar image. 
 *
 * See also: vips_zone().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_eye( VipsImage **out, int width, int height, ... )
{
	va_list ap;
	int result;

	va_start( ap, height );
	result = vips_call_split( "eye", ap, out, width, height );
	va_end( ap );

	return( result );
}
