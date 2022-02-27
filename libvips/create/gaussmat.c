/* generate gaussian images
 *
 * Written on: 30/11/1989 by Nicos
 * Updated on: 6/12/1991
 * 7/8/96 JC
 *	- ansified, mem leaks plugged
 * 20/11/98 JC
 *	- mask too large check added
 * 18/3/09
 * 	- bumped max mask size *40
 * 	- added _sep variant
 * 30/3/09
 * 	- set scale in _sep variant, why not
 * 21/10/10
 * 	- gtkdoc
 * 20/10/13
 * 	- redone as a class 
 * 16/12/14
 * 	- default to int output to match vips_conv()
 * 	- use @precision, not @integer
 * 10/3/16
 * 	- allow 1x1 masks
 * 	- better size calc
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
#include <glib/gi18n-lib.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>

#include <vips/vips.h>

#include "pcreate.h"

typedef struct _VipsGaussmat {
	VipsCreate parent_instance;

	double sigma;
	double min_ampl;

	gboolean separable;
	gboolean integer;		/* Deprecated */
	VipsPrecision precision; 

} VipsGaussmat;

typedef struct _VipsGaussmatClass {
	VipsCreateClass parent_class;

} VipsGaussmatClass;

G_DEFINE_TYPE( VipsGaussmat, vips_gaussmat, VIPS_TYPE_CREATE );

/* Don't allow mask radius to go over this.
 */
#define MASK_SANITY (5000)

static int
vips_gaussmat_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsCreate *create = VIPS_CREATE( object );
	VipsGaussmat *gaussmat = (VipsGaussmat *) object;
	double sig2 =  2. * gaussmat->sigma * gaussmat->sigma;
	int max_x = VIPS_CLIP( 0, 8 * gaussmat->sigma, MASK_SANITY ); 

	int x, y;
	int width, height; 
	double sum; 

	if( VIPS_OBJECT_CLASS( vips_gaussmat_parent_class )->build( object ) )
		return( -1 );

	/* The old, deprecated @integer property has been deliberately set to
	 * FALSE and they've not used the new @precision property ... switch
	 * to float to help them out.
	 */
	if( vips_object_argument_isset( object, "integer" ) &&
		!vips_object_argument_isset( object, "precision" ) &&
		!gaussmat->integer ) 
		gaussmat->precision = VIPS_PRECISION_FLOAT;

	/* Find the size of the mask. Limit the mask size to 10k x 10k for 
	 * sanity. We allow x == 0, meaning a 1x1 mask.
	 */
	for( x = 0; x < max_x; x++ ) {
		double v = exp( - ((double)(x * x)) / sig2 );

		if( v < gaussmat->min_ampl ) 
			break;
	}
	if( x >= MASK_SANITY ) {
		vips_error( class->nickname, "%s", _( "mask too large" ) );
		return( -1 );
	}
	width = 2 * VIPS_MAX( x - 1, 0 ) + 1;
	height = gaussmat->separable ? 1 : width; 

	vips_image_init_fields( create->out,
		width, height, 1, 
		VIPS_FORMAT_DOUBLE, VIPS_CODING_NONE, 
		VIPS_INTERPRETATION_MULTIBAND,
		1.0, 1.0 ); 
	if( vips_image_pipelinev( create->out, VIPS_DEMAND_STYLE_ANY, NULL ) ||
		vips_image_write_prepare( create->out ) )
		return( -1 );

	sum = 0.0;
	for( y = 0; y < height; y++ ) {
		for( x = 0; x < width; x++ ) {
			int xo = x - width / 2;
			int yo = y - height / 2;
			double distance = xo * xo + yo * yo;
			double v = exp( -distance / sig2 );

			if( gaussmat->precision != VIPS_PRECISION_FLOAT )
				v = VIPS_RINT( 20 * v );

			*VIPS_MATRIX( create->out, x, y ) = v;
			sum += v; 
		}
	}

	/* Make sure we can't make sum == 0: it'd certainly cause /0 later. 
	 */
	if( sum == 0 )
		sum = 1;

	vips_image_set_double( create->out, "scale", sum ); 
	vips_image_set_double( create->out, "offset", 0.0 ); 

	return( 0 );
}

static void
vips_gaussmat_class_init( VipsGaussmatClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "gaussmat";
	vobject_class->description = _( "make a gaussian image" );
	vobject_class->build = vips_gaussmat_build;

	VIPS_ARG_DOUBLE( class, "sigma", 2, 
		_( "Sigma" ), 
		_( "Sigma of Gaussian" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsGaussmat, sigma ),
		0.000001, 10000.0, 1.0 );

	VIPS_ARG_DOUBLE( class, "min_ampl", 3, 
		_( "Minimum amplitude" ), 
		_( "Minimum amplitude of Gaussian" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsGaussmat, min_ampl ),
		0.000001, 10000.0, 0.1 );

	VIPS_ARG_BOOL( class, "separable", 4, 
		_( "Separable" ), 
		_( "Generate separable Gaussian" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsGaussmat, separable ),
		FALSE );

	VIPS_ARG_BOOL( class, "integer", 5, 
		_( "Integer" ), 
		_( "Generate integer Gaussian" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT | VIPS_ARGUMENT_DEPRECATED,
		G_STRUCT_OFFSET( VipsGaussmat, integer ),
		FALSE );

	VIPS_ARG_ENUM( class, "precision", 6, 
		_( "Precision" ), 
		_( "Generate with this precision" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT, 
		G_STRUCT_OFFSET( VipsGaussmat, precision ), 
		VIPS_TYPE_PRECISION, VIPS_PRECISION_INTEGER ); 

}

static void
vips_gaussmat_init( VipsGaussmat *gaussmat )
{
	gaussmat->sigma = 1;
	gaussmat->min_ampl = 0.1;
	gaussmat->precision = VIPS_PRECISION_INTEGER;
}

/**
 * vips_gaussmat:
 * @out: (out): output image
 * @sigma: standard deviation of mask
 * @min_ampl: minimum amplitude
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @separable: generate a separable gaussian
 * * @precision: #VipsPrecision for @out
 *
 * Creates a circularly symmetric Gaussian image of radius 
 * @sigma.  The size of the mask is determined by the variable @min_ampl; 
 * if for instance the value .1 is entered this means that the produced mask 
 * is clipped at values less than 10 percent of the maximum amplitude.
 *
 * The program uses the following equation:
 *
 *   H(r) = exp( -(r * r) / (2 * @sigma * @sigma) )
 *
 * The generated image has odd size and its maximum value is normalised to
 * 1.0, unless @precision is #VIPS_PRECISION_INTEGER.
 *
 * If @separable is set, only the centre horizontal is generated. This is
 * useful for separable convolutions. 
 *
 * If @precision is #VIPS_PRECISION_INTEGER, an integer gaussian is generated. 
 * This is useful for integer convolutions. 
 *
 * "scale" is set to the sum of all the mask elements.
 *
 * See also: vips_logmat(), vips_conv().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_gaussmat( VipsImage **out, double sigma, double min_ampl, ... )
{
	va_list ap;
	int result;

	va_start( ap, min_ampl );
	result = vips_call_split( "gaussmat", ap, out, sigma, min_ampl );
	va_end( ap );

	return( result );
}
