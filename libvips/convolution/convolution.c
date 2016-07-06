/* base class for all convolution operations
 *
 * properties:
 * 	- one input image
 * 	- one output image
 * 	- one input mask
 */

/*

    Copyright (C) 1991-2005 The National Gallery

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License as published by the Free Software Foundation; either
    version 2.1 of the License, or (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU 
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this library; if not, write to the Free Software
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
#include <vips/internal.h>

#include "pconvolution.h"

/** 
 * SECTION: convolution
 * @short_description: convolve and correlate images
 * @stability: Stable
 * @include: vips/vips.h
 *
 * These operations convolve an image in some way, or are operations based on
 * simple convolution, or are useful with convolution.
 *
 */

/** 
 * VipsPrecision:
 * @VIPS_PRECISION_INTEGER: int everywhere
 * @VIPS_PRECISION_FLOAT: float everywhere
 * @VIPS_PRECISION_APPROXIMATE: approximate integer output
 *
 * How accurate an operation should be. 
 */

/** 
 * VipsCombine:
 * @VIPS_COMBINE_MAX: take the maximum of the possible values
 * @VIPS_COMBINE_SUM: sum all the values
 *
 * How to combine values. 
 */

G_DEFINE_ABSTRACT_TYPE( VipsConvolution, vips_convolution, 
	VIPS_TYPE_OPERATION );

static int
vips_convolution_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsConvolution *convolution = VIPS_CONVOLUTION( object );
	VipsImage **t = (VipsImage **) vips_object_local_array( object, 2 );

#ifdef DEBUG
	printf( "vips_convolution_build: " );
	vips_object_print_name( object );
	printf( "\n" );
#endif /*DEBUG*/

	if( VIPS_OBJECT_CLASS( vips_convolution_parent_class )->
		build( object ) )
		return( -1 );

	if( vips_check_matrix( class->nickname, convolution->mask, &t[0] ) )
		return( -1 ); 
	convolution->M = t[0];

	return( 0 );
}

static void
vips_convolution_class_init( VipsConvolutionClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );
	VipsOperationClass *operation_class = VIPS_OPERATION_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "convolution";
	vobject_class->description = _( "convolution operations" );
	vobject_class->build = vips_convolution_build;

	operation_class->flags = VIPS_OPERATION_SEQUENTIAL;

	/* Inputs set by subclassess.
	 */

	VIPS_ARG_IMAGE( class, "in", 0, 
		_( "Input" ), 
		_( "Input image argument" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsConvolution, in ) );

	VIPS_ARG_IMAGE( class, "out", 10, 
		_( "Output" ), 
		_( "Output image" ),
		VIPS_ARGUMENT_REQUIRED_OUTPUT, 
		G_STRUCT_OFFSET( VipsConvolution, out ) );

	VIPS_ARG_IMAGE( class, "mask", 20, 
		_( "Mask" ), 
		_( "Input matrix image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsConvolution, mask ) );

}

static void
vips_convolution_init( VipsConvolution *convolution )
{
}

/* Called from iofuncs to init all operations in this dir. Use a plugin system
 * instead?
 */
void
vips_convolution_operation_init( void )
{
	extern int vips_conv_get_type( void ); 
	extern int vips_convf_get_type( void ); 
	extern int vips_convi_get_type( void ); 
	extern int vips_convsep_get_type( void ); 
	extern int vips_convasep_get_type( void ); 
	extern int vips_compass_get_type( void ); 
	extern int vips_fastcor_get_type( void ); 
	extern int vips_spcor_get_type( void ); 
	extern int vips_sharpen_get_type( void ); 
	extern int vips_gaussblur_get_type( void ); 

	vips_conv_get_type(); 
	vips_convf_get_type(); 
	vips_convi_get_type(); 
	vips_compass_get_type(); 
	vips_convsep_get_type(); 
	vips_convasep_get_type(); 
	vips_fastcor_get_type(); 
	vips_spcor_get_type(); 
	vips_sharpen_get_type(); 
	vips_gaussblur_get_type(); 
}
