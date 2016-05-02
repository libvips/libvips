/* laplacian of logmatian
 *
 * Written on: 30/11/1989
 * Updated on: 6/12/1991
 * 7/8/96 JC
 *	- ansified, mem leaks plugged
 * 20/11/98 JC
 *	- mask too large check added
 * 26/3/02 JC
 *	- ahem, was broken since '96, thanks matt
 * 16/7/03 JC
 *	- makes mask out to zero, not out to minimum, thanks again matt
 * 22/10/10
 * 	- gtkdoc
 * 20/10/13
 * 	- redone as a class from logmat.c
 * 16/12/14
 * 	- default to int output to match vips_conv()
 * 	- use @precision, not @integer
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

typedef struct _VipsLogmat {
	VipsCreate parent_instance;

	double sigma;
	double min_ampl;

	gboolean separable;
	gboolean integer;		/* Deprecated */
	VipsPrecision precision; 

} VipsLogmat;

typedef struct _VipsLogmatClass {
	VipsCreateClass parent_class;

} VipsLogmatClass;

G_DEFINE_TYPE( VipsLogmat, vips_logmat, VIPS_TYPE_CREATE );

static int
vips_logmat_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsCreate *create = VIPS_CREATE( object );
	VipsLogmat *logmat = (VipsLogmat *) object;
	double sig2 = logmat->sigma * logmat->sigma; 

	double last; 
	int x, y;
	int width, height; 
	double sum; 

	if( VIPS_OBJECT_CLASS( vips_logmat_parent_class )->build( object ) )
		return( -1 );

	/* The old, deprecated @integer property has been deliberately set to
	 * FALSE and they've not used the new @precision property ... switch
	 * to float to help them out.
	 */
	if( vips_object_argument_isset( object, "integer" ) &&
		!vips_object_argument_isset( object, "precision" ) &&
		!logmat->integer ) 
		logmat->precision = VIPS_PRECISION_FLOAT;

	if( vips_check_precision_intfloat( class->nickname, 
		logmat->precision ) )
		return( -1 ); 

	/* Find the size of the mask. We want to eval the mask out to the 
	 * flat zero part, ie. beyond the minimum and to the point where it 
	 * comes back up towards zero.
	 */
	last = 0.0;
	for( x = 0; x < 5000; x++ ) {
		const double distance = x * x;
		double val;

		/* Handbook of Pattern Recognition and image processing
		 * by Young and Fu AP 1986 pp 220-221
		 * temp =  (1.0 / (2.0 * IM_PI * sig4)) *
			(2.0 - (distance / sig2)) * 
			exp( (-1.0) * distance / (2.0 * sig2) )

		   .. use 0.5 to normalise
		 */
		val = 0.5 * 
			(2.0 - (distance / sig2)) * 
			exp( -distance / (2.0 * sig2) );

		/* Stop when change in value (ie. difference from the last
		 * point) is positive (ie. we are going up) and absolute value 
		 * is less than the min.
		 */
		if( val - last >= 0 &&
			VIPS_FABS( val ) < logmat->min_ampl )
			break;

		last = val;
	}
	if( x == 5000 ) {
		vips_error( class->nickname, "%s", _( "mask too large" ) );
		return( -1 );
	}

	width = x * 2 + 1;
	height = logmat->separable ? 1 : width; 

	vips_image_init_fields( create->out,
		width, height, 1, 
		VIPS_FORMAT_DOUBLE, VIPS_CODING_NONE, VIPS_INTERPRETATION_B_W,
		1.0, 1.0 ); 
	vips_image_pipelinev( create->out, 
		VIPS_DEMAND_STYLE_ANY, NULL );
	if( vips_image_write_prepare( create->out ) )
		return( -1 );

	sum = 0.0;
	for( y = 0; y < height; y++ ) {
		for( x = 0; x < width; x++ ) {
			int xo = x - width / 2;
			int yo = y - height / 2;
			double distance = xo * xo + yo * yo;
			double v = 0.5 *
				(2.0 - (distance / sig2)) *
				exp( -distance / (2.0 * sig2) );

			if( logmat->precision == VIPS_PRECISION_INTEGER )
				v = VIPS_RINT( 20 * v );

			*VIPS_MATRIX( create->out, x, y ) = v;
			sum += v; 
		}
	}

	vips_image_set_double( create->out, "scale", sum ); 
	vips_image_set_double( create->out, "offset", 0.0 ); 

	return( 0 );
}

static void
vips_logmat_class_init( VipsLogmatClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "logmat";
	vobject_class->description = _( "make a laplacian of gaussian image" );
	vobject_class->build = vips_logmat_build;

	VIPS_ARG_DOUBLE( class, "sigma", 2, 
		_( "Radius" ), 
		_( "Radius of Logmatian" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsLogmat, sigma ),
		0.000001, 10000.0, 1.0 );

	VIPS_ARG_DOUBLE( class, "min_ampl", 3, 
		_( "Width" ), 
		_( "Minimum amplitude of Logmatian" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsLogmat, min_ampl ),
		0.000001, 10000.0, 0.1 );

	VIPS_ARG_BOOL( class, "separable", 4, 
		_( "Separable" ), 
		_( "Generate separable Logmatian" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsLogmat, separable ),
		FALSE );

	VIPS_ARG_BOOL( class, "integer", 5, 
		_( "Integer" ), 
		_( "Generate integer Logmatian" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT | VIPS_ARGUMENT_DEPRECATED,
		G_STRUCT_OFFSET( VipsLogmat, integer ),
		FALSE );

	VIPS_ARG_ENUM( class, "precision", 6, 
		_( "Precision" ), 
		_( "Generate with this precision" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT, 
		G_STRUCT_OFFSET( VipsLogmat, precision ), 
		VIPS_TYPE_PRECISION, VIPS_PRECISION_INTEGER ); 

}

static void
vips_logmat_init( VipsLogmat *logmat )
{
	logmat->sigma = 1;
	logmat->min_ampl = 0.1;
	logmat->precision = VIPS_PRECISION_INTEGER;
}

/**
 * vips_logmat:
 * @out: output image
 * @sigma: standard deviation of mask
 * @min_ampl: minimum amplitude
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @separable: generate a separable mask
 * * @precision: #VipsPrecision for @out
 *
 * Creates a circularly symmetric Laplacian of Gaussian mask 
 * of radius 
 * @sigma.  The size of the mask is determined by the variable @min_ampl; 
 * if for instance the value .1 is entered this means that the produced mask 
 * is clipped at values within 10 persent of zero, and where the change 
 * between mask elements is less than 10%.
 *
 * The program uses the following equation: (from Handbook of Pattern 
 * Recognition and image processing by Young and Fu, AP 1986 pages 220-221):
 *
 *  H(r) = (1 / (2 * M_PI * s4)) *
 * 	(2 - (r2 / s2)) * 
 * 	exp(-r2 / (2 * s2))
 *
 * where s2 = @sigma * @sigma, s4 = s2 * s2, r2 = r * r.  
 *
 * The generated mask has odd size and its maximum value is normalised to 
 * 1.0, unless @precision is #VIPS_PRECISION_INTEGER.
 *
 * If @separable is set, only the centre horizontal is generated. This is
 * useful for separable convolutions. 
 *
 * If @precision is #VIPS_PRECISION_INTEGER, an integer mask is generated. 
 * This is useful for integer convolutions. 
 *
 * "scale" is set to the sum of all the mask elements.
 *
 * See also: vips_gaussmat(), vips_conv().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_logmat( VipsImage **out, double sigma, double min_ampl, ... )
{
	va_list ap;
	int result;

	va_start( ap, min_ampl );
	result = vips_call_split( "logmat", ap, out, sigma, min_ampl );
	va_end( ap );

	return( result );
}
