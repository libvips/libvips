/* repeatedly convolve with a rotating mask
 *
 * 23/10/13	
 * 	- from vips_conv()
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

#include <vips/vips.h>

#include "pconvolution.h"

typedef struct {
	VipsConvolution parent_instance;

	int times; 
	VipsAngle45 angle; 
	VipsCombine combine; 
	VipsPrecision precision; 
	int layers; 
	int cluster; 
} VipsCompass;

typedef VipsConvolutionClass VipsCompassClass;

G_DEFINE_TYPE( VipsCompass, vips_compass, VIPS_TYPE_CONVOLUTION );

static int
vips_compass_build( VipsObject *object )
{
	VipsConvolution *convolution = (VipsConvolution *) object;
	VipsCompass *compass = (VipsCompass *) object;
	VipsImage **masks;
	VipsImage *mask;
	VipsImage **images;
	int i; 
	VipsImage **abs;
	VipsImage **combine;
	VipsImage *x;

	g_object_set( compass, "out", vips_image_new(), NULL ); 

	if( VIPS_OBJECT_CLASS( vips_compass_parent_class )->build( object ) )
		return( -1 );

	masks = (VipsImage **) 
		vips_object_local_array( object, compass->times );
	images = (VipsImage **) 
		vips_object_local_array( object, compass->times );
	abs = (VipsImage **) 
		vips_object_local_array( object, compass->times );
	combine = (VipsImage **) 
		vips_object_local_array( object, compass->times );

	mask = convolution->M;
	for( i = 0; i < compass->times; i++ ) {
		if( vips_conv( convolution->in, &images[i], mask, 
			"precision", compass->precision,
			"layers", compass->layers,
			"cluster", compass->cluster,
			NULL ) )
			return( -1 ); 
		if( vips_rot45( mask, &masks[i],
			"angle", compass->angle,
			NULL ) )
			return( -1 ); 

		mask = masks[i];
	}

	for( i = 0; i < compass->times; i++ )
		if( vips_abs( images[i], &abs[i], NULL ) )
			return( -1 ); 

	switch( compass->combine ) { 
	case VIPS_COMBINE_MAX:
		if( vips_bandrank( abs, &combine[0], compass->times,
			"index", compass->times - 1,
			NULL ) )
			return( -1 ); 
		x = combine[0];
		break;

	case VIPS_COMBINE_SUM:
		x = abs[0];
		for( i = 1; i < compass->times; i++ ) {
			if( vips_add( x, abs[i], &combine[i], NULL ) )
				return( -1 );
			x = combine[i];
		}
		break;

	default:
		/* Silence compiler wrning.
		 */
		x = NULL;
		g_assert( 0 );
	}

	if( vips_image_write( x, convolution->out ) )
		return( -1 ); 

	return( 0 );
}

static void
vips_compass_class_init( VipsCompassClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "compass";
	object_class->description = _( "convolve with rotating mask" );
	object_class->build = vips_compass_build;

	VIPS_ARG_INT( class, "times", 101, 
		_( "Times" ), 
		_( "Rotate and convolve this many times" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT, 
		G_STRUCT_OFFSET( VipsCompass, times ), 
		1, 1000, 2 ); 

	VIPS_ARG_ENUM( class, "angle", 103, 
		_( "Angle" ), 
		_( "Rotate mask by this much between convolutions" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT, 
		G_STRUCT_OFFSET( VipsCompass, angle ), 
		VIPS_TYPE_ANGLE45, VIPS_ANGLE45_90 ); 

	VIPS_ARG_ENUM( class, "combine", 104, 
		_( "Combine" ), 
		_( "Combine convolution results like this" ), 
		VIPS_ARGUMENT_OPTIONAL_INPUT, 
		G_STRUCT_OFFSET( VipsCompass, combine ), 
		VIPS_TYPE_COMBINE, VIPS_COMBINE_MAX ); 

	VIPS_ARG_ENUM( class, "precision", 203, 
		_( "Precision" ), 
		_( "Convolve with this precision" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT, 
		G_STRUCT_OFFSET( VipsCompass, precision ), 
		VIPS_TYPE_PRECISION, VIPS_PRECISION_INTEGER ); 

	VIPS_ARG_INT( class, "layers", 204, 
		_( "Layers" ), 
		_( "Use this many layers in approximation" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT, 
		G_STRUCT_OFFSET( VipsCompass, layers ), 
		1, 1000, 5 ); 

	VIPS_ARG_INT( class, "cluster", 205, 
		_( "Cluster" ), 
		_( "Cluster lines closer than this in approximation" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT, 
		G_STRUCT_OFFSET( VipsCompass, cluster ), 
		1, 100, 1 ); 

}

static void
vips_compass_init( VipsCompass *compass )
{
	compass->times = 2;
	compass->angle = VIPS_ANGLE45_90;
	compass->combine = VIPS_COMBINE_MAX;
	compass->precision = VIPS_PRECISION_INTEGER;
	compass->layers = 5;
	compass->cluster = 1;
}

int 
vips_compass( VipsImage *in, VipsImage **out, VipsImage *mask, ... )
{
	va_list ap;
	int result;

	va_start( ap, mask );
	result = vips_call_split( "compass", ap, in, out, mask );
	va_end( ap );

	return( result );
}
