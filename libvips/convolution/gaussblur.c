/* Gaussian blur. 
 * 
 * 15/11/13
 * 	- from vips_sharpen()
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

	int radius; 
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

	/* Stop at 20% of max ... bit mean, but means mask radius is roughly
	 * right.
	 */
	if( vips_gaussmat( &t[0], gaussblur->radius / 2.0, 0.2, 
		"separable", TRUE,
		"integer", gaussblur->precision != VIPS_PRECISION_FLOAT,
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

	VIPS_ARG_INT( class, "radius", 3, 
		_( "radius" ), 
		_( "Mask radius" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsGaussblur, radius ),
		1, 1000000, 3 );

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
	gaussblur->radius = 3; 
	gaussblur->precision = VIPS_PRECISION_INTEGER; 
}

/**
 * vips_gaussblur:
 * @in: input image
 * @out: output image
 * @radius: how large a mask to use
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * @precision: #VipsPrecision for blur
 *
 * This operator runs vips_gaussmat() and vips_convsep() for you on an image. 
 *
 * @radius is not used directly. Instead the standard deviation of
 * vips_gaussmat() is set to @radius / 2.0 and the minimum amplitude set to 
 * 20%. This gives a mask radius of approximately @radius pixels.
 *
 * See also: vips_gaussmat(), vips_conv().
 * 
 * Returns: 0 on success, -1 on error.
 */
int 
vips_gaussblur( VipsImage *in, VipsImage **out, int radius, ... )
{
	va_list ap;
	int result;

	va_start( ap, radius );
	result = vips_call_split( "gaussblur", ap, in, out, radius );  
	va_end( ap );

	return( result );
}
