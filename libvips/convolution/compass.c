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

/* This is a simple wrapper over the old vips7 functions. At some point we
 * should rewrite this as a pure vips8 class and redo the vips7 functions as
 * wrappers over this.
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
	VipsRotate45 angle; 
	int join; 
} VipsCompass;

typedef VipsConvolutionClass VipsCompassClass;

G_DEFINE_TYPE( VipsCompass, vips_compass, VIPS_TYPE_CONVOLUTION );

static int
vips_compass_build( VipsObject *object )
{
	VipsConvolution *convolution = (VipsConvolution *) object;
	VipsCompass *compass = (VipsCompass *) object;

	g_object_set( compass, "out", vips_image_new(), NULL ); 

	if( VIPS_OBJECT_CLASS( vips_compass_parent_class )->build( object ) )
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
	object_class->description = _( "convolution operation" );
	object_class->build = vips_compass_build;

	VIPS_ARG_ENUM( class, "precision", 103, 
		_( "Precision" ), 
		_( "Convolve with this precision" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT, 
		G_STRUCT_OFFSET( VipsCompass, precision ), 
		VIPS_TYPE_PRECISION, VIPS_PRECISION_INTEGER ); 

	VIPS_ARG_INT( class, "layers", 104, 
		_( "Layers" ), 
		_( "Use this many layers in approximation" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT, 
		G_STRUCT_OFFSET( VipsCompass, layers ), 
		1, 1000, 5 ); 

	VIPS_ARG_INT( class, "cluster", 105, 
		_( "Cluster" ), 
		_( "Cluster lines closer than this in approximation" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT, 
		G_STRUCT_OFFSET( VipsCompass, cluster ), 
		1, 100, 1 ); 

}

static void
vips_compass_init( VipsCompass *compass )
{
	compass->times = 1;
	compass->angle = 5;
	compass->join = 1;
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
