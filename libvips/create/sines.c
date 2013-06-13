/* creates a 2d sinewave 
 *
 * Copyright: 1990, N. Dessipris.
 *
 * Author: Nicos Dessipris
 * Written on: 02/02/1990
 * Modified on:
 * 22/7/93 JC
 *	- externs removed
 *	- im_outcheck() added
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

typedef struct _VipsSines {
	VipsCreate parent_instance;

	int width;
	int height;

	double hfreq;
	double vfreq;
	gboolean uchar;

} VipsSines;

typedef VipsCreateClass VipsSinesClass;

G_DEFINE_TYPE( VipsSines, vips_sines, VIPS_TYPE_CREATE );

static int
vips_sines_gen( VipsRegion *or, void *seq, void *a, void *b,
	gboolean *stop )
{
	VipsSines *sines = (VipsSines *) a;
	VipsRect *r = &or->valid;
	int le = r->left;
	int to = r->top;
	int ri = VIPS_RECT_RIGHT( r );
	int bo = VIPS_RECT_BOTTOM( r );

	double theta = sines->hfreq == 0.0 ? 
		VIPS_PI / 2.0 : atan( sines->vfreq / sines->hfreq );
	double costheta = cos( theta ); 
	double sintheta = sin( theta );
	double factor = sqrt( sines->hfreq * sines->hfreq + 
		sines->vfreq * sines->vfreq );
	double cons = factor * VIPS_PI * 2.0 / sines->width;

	int x, y;

	for( y = to; y < bo; y++ ) {
		float *q = (float *) VIPS_REGION_ADDR( or, le, y );
		double ysintheta = y * sintheta;

		for( x = le; x < ri; x++ ) 
			*q++ = cos( cons * (x * costheta - ysintheta) );
	}

	return( 0 );
}

static int
vips_sines_build( VipsObject *object )
{
	VipsCreate *create = VIPS_CREATE( object );
	VipsSines *sines = (VipsSines *) object;
	VipsImage **t = (VipsImage **) vips_object_local_array( object, 7 );
	VipsImage *in;

	if( VIPS_OBJECT_CLASS( vips_sines_parent_class )->build( object ) )
		return( -1 );

	t[0] = vips_image_new();
	vips_image_init_fields( t[0],
		sines->width, sines->height, 1,
		VIPS_FORMAT_FLOAT, VIPS_CODING_NONE, VIPS_INTERPRETATION_B_W,
		1.0, 1.0 );
	vips_demand_hint( t[0], 
		VIPS_DEMAND_STYLE_ANY, NULL );
	if( vips_image_generate( t[0], 
		NULL, vips_sines_gen, NULL, sines, NULL ) )
		return( -1 );

	in = t[0];
	if( sines->uchar ) {
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
vips_sines_class_init( VipsSinesClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "sines";
	vobject_class->description = _( "make a 2D sine wave" );
	vobject_class->build = vips_sines_build;

	VIPS_ARG_INT( class, "width", 4, 
		_( "Width" ), 
		_( "Image width in pixels" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsSines, width ),
		1, 1000000, 1 );

	VIPS_ARG_INT( class, "height", 5, 
		_( "Height" ), 
		_( "Image height in pixels" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsSines, height ),
		1, 1000000, 1 );

	VIPS_ARG_DOUBLE( class, "hfreq", 6, 
		_( "hfreq" ), 
		_( "Horizontal spatial frequency" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsSines, hfreq ),
		0.0, 10000.0, 0.5 );

	VIPS_ARG_DOUBLE( class, "vfreq", 7, 
		_( "vfreq" ), 
		_( "Vertical spatial frequency" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsSines, vfreq ),
		0.0, 10000.0, 0.5 );

	VIPS_ARG_BOOL( class, "uchar", 8, 
		_( "Uchar" ), 
		_( "Output an unsigned char image" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsSines, uchar ),
		FALSE );

}

static void
vips_sines_init( VipsSines *sines )
{
	sines->hfreq = 0.5;
	sines->vfreq = 0.5;
}


/**
 * vips_sines:
 * @out: output image
 * @xsize: image size
 * @ysize: image size
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * @hfreq: horizontal frequency
 * @vreq: vertical frequency
 * @uchar: output a uchar image
 *
 * Creates a float one band image of the a sine waveform in two
 * dimensions.  
 *
 * The number of horizontal and vertical spatial frequencies are
 * determined by the variables @hfreq and @vfreq respectively.  The
 * function is useful for creating displayable sine waves and
 * square waves in two dimensions.
 *
 * If horfreq and verfreq are integers the resultant image is periodical
 * and therfore the Fourier transform does not present spikes
 *
 * Pixels are normally in [-1, +1], set @uchar to output [0, 255]. 
 * 
 * See also: vips_grey(), vips_xyz(). 
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_sines( VipsImage **out, int width, int height, ... )
{
	va_list ap;
	int result;

	va_start( ap, height );
	result = vips_call_split( "sines", ap, out, width, height );
	va_end( ap );

	return( result );
}
