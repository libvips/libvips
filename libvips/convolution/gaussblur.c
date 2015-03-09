/* Gaussian blur. 
 * 
 * 15/11/13
 * 	- from vips_sharpen()
 * 19/11/14
 * 	- change parameters to be more imagemagick-like
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
#define DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <stdlib.h>
#include <math.h>

#include <vips/vips.h>

typedef struct _VipsGaussblur {
	VipsOperation parent_instance;

	VipsImage *in;
	VipsImage *out;

	gdouble sigma; 
	gdouble min_ampl; 
	VipsPrecision precision; 

} VipsGaussblur;

typedef VipsOperationClass VipsGaussblurClass;

G_DEFINE_TYPE( VipsGaussblur, vips_gaussblur, VIPS_TYPE_OPERATION );

static int
vips_gaussblur_build( VipsObject *object )
{
	VipsGaussblur *gaussblur = (VipsGaussblur *) object;
	VipsImage **t = (VipsImage **) vips_object_local_array( object, 2 );

	if( VIPS_OBJECT_CLASS( vips_gaussblur_parent_class )->build( object ) )
		return( -1 );

	if( vips_gaussmat( &t[0], gaussblur->sigma, gaussblur->min_ampl, 
		"separable", TRUE,
		"precision", gaussblur->precision,
		NULL ) )
		return( -1 ); 

#ifdef DEBUG
	printf( "gaussblur: blurring with:\n" ); 
	vips_matrixprint( t[0], NULL ); 
#endif /*DEBUG*/

	if( vips_convsep( gaussblur->in, &t[1], t[0], 
		"precision", gaussblur->precision,
		NULL ) )
		return( -1 );

	g_object_set( object, "out", vips_image_new(), NULL ); 

	if( vips_image_write( t[1], gaussblur->out ) )
		return( -1 );

	return( 0 );
}

static void
vips_gaussblur_class_init( VipsGaussblurClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsOperationClass *operation_class = VIPS_OPERATION_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "gaussblur";
	object_class->description = _( "gaussian blur" );
	object_class->build = vips_gaussblur_build;

	operation_class->flags = VIPS_OPERATION_SEQUENTIAL;

	VIPS_ARG_IMAGE( class, "in", 1, 
		_( "Input" ), 
		_( "Input image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsGaussblur, in ) );

	VIPS_ARG_IMAGE( class, "out", 2, 
		_( "Output" ), 
		_( "Output image" ),
		VIPS_ARGUMENT_REQUIRED_OUTPUT, 
		G_STRUCT_OFFSET( VipsGaussblur, out ) );

	VIPS_ARG_DOUBLE( class, "sigma", 3, 
		_( "Sigma" ), 
		_( "Sigma of Gaussian" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsGaussblur, sigma ),
		0.01, 1000, 1.5 );

	VIPS_ARG_DOUBLE( class, "min_ampl", 3, 
		_( "Minimum amplitude" ), 
		_( "Minimum amplitude of Gaussian" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsGaussblur, min_ampl ),
		0.001, 1.0, 0.2 );

	VIPS_ARG_ENUM( class, "precision", 4, 
		_( "Precision" ), 
		_( "Convolve with this precision" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT, 
		G_STRUCT_OFFSET( VipsGaussblur, precision ), 
		VIPS_TYPE_PRECISION, VIPS_PRECISION_INTEGER ); 

}

static void
vips_gaussblur_init( VipsGaussblur *gaussblur )
{
	gaussblur->sigma = 1.5; 
	gaussblur->min_ampl = 0.2;
	gaussblur->precision = VIPS_PRECISION_INTEGER; 
}

/**
 * vips_gaussblur:
 * @in: input image
 * @out: output image
 * @sigma: how large a mask to use
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * @precision: #VipsPrecision for blur, default VIPS_PRECISION_INTEGER
 * @min_ampl: minimum amplitude, default 0.2
 *
 * This operator runs vips_gaussmat() and vips_convsep() for you on an image.
 * Set @min_ampl smaller to generate a larger, more accurate mask. Set @sigma
 * larger to make the blur more blurry. 
 *
 * See also: vips_gaussmat(), vips_convsep().
 * 
 * Returns: 0 on success, -1 on error.
 */
int 
vips_gaussblur( VipsImage *in, VipsImage **out, double sigma, ... )
{
	va_list ap;
	int result;

	va_start( ap, sigma );
	result = vips_call_split( "gaussblur", ap, in, out, sigma );  
	va_end( ap );

	return( result );
}
