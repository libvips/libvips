/* im_scale
 *
 * Author: John Cupitt
 * Written on: 22/4/93
 * Modified on: 
 * 30/6/93 JC
 *	- adapted for partial v2
 * 	- ANSI
 * 31/8/93 JC
 *	- calculation of offset now includes scale
 * 8/5/06
 * 	- set Type on output too
 * 16/10/06
 * 	- what? no, don't set Type, useful to be able to scale histograms, for
 * 	  example
 * 1/2/10
 * 	- gtkdoc
 * 30/5/13
 * 	- redo as a class
 * 	- add log scale and exponent as an option
 * 14/1/14
 * 	- use linear uchar mode
 * 14/7/14
 * 	- round to nearest on uchar output
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <stdlib.h>
#include <math.h>

#include <vips/vips.h>

#include "pconversion.h"

typedef struct _VipsScale {
	VipsConversion parent_instance;

	VipsImage *in;

	gboolean log;
	double exp;

} VipsScale;

typedef VipsConversionClass VipsScaleClass;

G_DEFINE_TYPE( VipsScale, vips_scale, VIPS_TYPE_CONVERSION );

static int
vips_scale_build( VipsObject *object )
{
	VipsConversion *conversion = VIPS_CONVERSION( object );
	VipsScale *scale = (VipsScale *) object;
	VipsImage **t = (VipsImage **) vips_object_local_array( object, 7 );

	double mx;
	double mn;

	if( VIPS_OBJECT_CLASS( vips_scale_parent_class )->build( object ) )
		return( -1 );

	if( vips_stats( scale->in, &t[0], NULL ) )
		return( -1 );
	mn = *VIPS_MATRIX( t[0], 0, 0 );
	mx = *VIPS_MATRIX( t[0], 1, 0 );

	if( mn == mx ) {
		/* Range of zero: just return black.
		 */
		if( vips_black( &t[1], scale->in->Xsize, scale->in->Ysize, 
			"bands", scale->in->Bands,
			NULL ) ||
			vips_image_write( t[1], conversion->out ) )
			return( -1 );
	}
	else if( scale->log ) { 
		double f = 255.0 / log10( 1.0 + pow( mx, scale->exp ) );

		if( vips_pow_const1( scale->in, &t[2], scale->exp, NULL ) ||
			vips_linear1( t[2], &t[3], 1.0, 1.0, NULL ) ||
			vips_log10( t[3], &t[4], NULL ) ||
			vips_linear1( t[4], &t[5], f, 0.0, 
				"uchar", TRUE, 
				NULL ) ||
			vips_image_write( t[5], conversion->out ) )
			return( -1 );
	}
	else {
		double f = 255.0 / (mx - mn);

		/* Add .5 to get round-to-nearest.
		 */
		double a = -(mn * f) + 0.5;

		if( vips_linear1( scale->in, &t[2], f, a, 
			"uchar", TRUE, 
			NULL ) ||
			vips_image_write( t[2], conversion->out ) )
			return( -1 );
	}

	return( 0 );
}

static void
vips_scale_class_init( VipsScaleClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "scale";
	vobject_class->description = _( "scale an image to uchar" );
	vobject_class->build = vips_scale_build;

	VIPS_ARG_IMAGE( class, "in", 1, 
		_( "Input" ), 
		_( "Input image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsScale, in ) );

	VIPS_ARG_BOOL( class, "log", 3, 
		_( "Log" ), 
		_( "Log scale" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsScale, log ),
		FALSE );

	VIPS_ARG_DOUBLE( class, "exp", 3, 
		_( "Exponent" ), 
		_( "Exponent for log scale" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsScale, exp ),
		0.00001, 10000, 0.25 );

}

static void
vips_scale_init( VipsScale *scale )
{
	scale->exp = 0.25;
}

/**
 * vips_scale:
 * @in: input image
 * @out: output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @log: log scale pixels
 * * @exp: exponent for log scale
 *
 * Search the image for the maximum and minimum value, then return the image
 * as unsigned 8-bit, scaled so that the maximum value is 255 and the
 * minimum is zero.
 *
 * If @log is set, transform with log10(1.0 + pow(x, @exp)) + .5, 
 * then scale so max == 255. By default, @exp is 0.25.
 *
 * See also: vips_cast().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_scale( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "scale", ap, in, out );
	va_end( ap );

	return( result );
}
