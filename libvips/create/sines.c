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

#include "pcreate.h"
#include "point.h"

typedef struct _VipsSines {
	VipsPoint parent_instance;

	double hfreq;
	double vfreq;

	double c;
	double sintheta;
	double costheta;

} VipsSines;

typedef VipsPointClass VipsSinesClass;

G_DEFINE_TYPE( VipsSines, vips_sines, VIPS_TYPE_POINT );

static float
vips_sines_point( VipsPoint *point, int x, int y ) 
{
	VipsSines *sines = (VipsSines *) point;

	return( cos( sines->c * (x * sines->costheta - y * sines->sintheta) ) );
}

static int
vips_sines_build( VipsObject *object )
{
	VipsPoint *point = VIPS_POINT( object );
	VipsSines *sines = (VipsSines *) object;

	double theta;
	double factor;

	if( VIPS_OBJECT_CLASS( vips_sines_parent_class )->build( object ) )
		return( -1 );

	theta = sines->hfreq == 0.0 ? 
		VIPS_PI / 2.0 : atan( sines->vfreq / sines->hfreq );
	factor = sqrt( sines->hfreq * sines->hfreq + 
		sines->vfreq * sines->vfreq );
	sines->costheta = cos( theta ); 
	sines->sintheta = sin( theta );
	sines->c = factor * VIPS_PI * 2.0 / point->width;

	return( 0 );
}

static void
vips_sines_class_init( VipsSinesClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );
	VipsPointClass *point_class = VIPS_POINT_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "sines";
	vobject_class->description = _( "make a 2D sine wave" );
	vobject_class->build = vips_sines_build;

	point_class->point = vips_sines_point;

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
