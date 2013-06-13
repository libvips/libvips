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

#include "create.h"

typedef struct _VipsEye {
	VipsCreate parent_instance;

	int width;
	int height;

	double factor;
	gboolean uchar;

} VipsEye;

typedef VipsCreateClass VipsEyeClass;

G_DEFINE_TYPE( VipsEye, vips_eye, VIPS_TYPE_CREATE );

static int
vips_eye_gen( VipsRegion *or, void *seq, void *a, void *b,
	gboolean *stop )
{
	VipsEye *eye = (VipsEye *) a;
	VipsRect *r = &or->valid;
	int le = r->left;
	int to = r->top;
	int ri = VIPS_RECT_RIGHT( r );
	int bo = VIPS_RECT_BOTTOM( r );

	double c = eye->factor * VIPS_PI / (2 * (eye->width - 1));
	double h = ((eye->height - 1) * (eye->height - 1));

	int x, y;

	for( y = to; y < bo; y++ ) {
		float *q = (float *) VIPS_REGION_ADDR( or, le, y );

		for( x = le; x < ri; x++ ) 
			q[x] = y * y * cos( c * x * x ) / h; 
	}

	return( 0 );
}

static int
vips_eye_build( VipsObject *object )
{
	VipsCreate *create = VIPS_CREATE( object );
	VipsEye *eye = (VipsEye *) object;
	VipsImage **t = (VipsImage **) vips_object_local_array( object, 7 );
	VipsImage *in;

	if( VIPS_OBJECT_CLASS( vips_eye_parent_class )->build( object ) )
		return( -1 );

	t[0] = vips_image_new();
	vips_image_init_fields( t[0],
		eye->width, eye->height, 1,
		VIPS_FORMAT_FLOAT, VIPS_CODING_NONE, VIPS_INTERPRETATION_B_W,
		1.0, 1.0 );
	vips_demand_hint( t[0], 
		VIPS_DEMAND_STYLE_ANY, NULL );
	if( vips_image_generate( t[0], 
		NULL, vips_eye_gen, NULL, eye, NULL ) )
		return( -1 );

	in = t[0];
	if( eye->uchar ) {
		if( vips_linear1( in, &t[1], 127.5, 127.5, NULL ) ||
			vips_cast( t[1], &t[2], VIPS_FORMAT_UCHAR, NULL ) )
			return( -1 );
		in = t[2];
	}

	if( vips_image_write( in, create->out ) )
		return( -1 );

	return( 0 );
}

static void
vips_eye_class_init( VipsEyeClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "eye";
	vobject_class->description = _( "make a eye image" );
	vobject_class->build = vips_eye_build;

	VIPS_ARG_INT( class, "width", 4, 
		_( "Width" ), 
		_( "Image width in pixels" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsEye, width ),
		1, 1000000, 1 );

	VIPS_ARG_INT( class, "height", 5, 
		_( "Height" ), 
		_( "Image height in pixels" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsEye, height ),
		1, 1000000, 1 );

	VIPS_ARG_DOUBLE( class, "factor", 6, 
		_( "Factor" ), 
		_( "Maximum spatial frequency" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsEye, factor ),
		0.0, 1.0, 0.5 );

	VIPS_ARG_BOOL( class, "uchar", 7, 
		_( "Uchar" ), 
		_( "Output an unsigned char image" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsEye, uchar ),
		FALSE );

}

static void
vips_eye_init( VipsEye *eye )
{
	eye->factor = 0.5;
}


/**
 * vips_eye:
 * @out: output image
 * @xsize: image size
 * @ysize: image size
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * @factor: maximum spatial frequency
 * @uchar: output a uchar image
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
