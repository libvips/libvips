/* convolve twice, rotating the mask
 *
 * 23/10/13	
 * 	- from vips_convsep()
 * 8/5/17
 *      - default to float ... int will often lose precision and should not be
 *        the default
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
#include <glib/gi18n-lib.h>

#include <stdio.h>

#include <vips/vips.h>

#include "pconvolution.h"

typedef struct {
	VipsConvolution parent_instance;

	VipsPrecision precision; 
	int layers; 
	int cluster; 
} VipsConvsep;

typedef VipsConvolutionClass VipsConvsepClass;

G_DEFINE_TYPE( VipsConvsep, vips_convsep, VIPS_TYPE_CONVOLUTION );

static int
vips_convsep_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsConvolution *convolution = (VipsConvolution *) object;
	VipsConvsep *convsep = (VipsConvsep *) object;
	VipsImage **t = (VipsImage **) 
		vips_object_local_array( object, 4 );

	VipsImage *in;

	g_object_set( convsep, "out", vips_image_new(), NULL ); 

	if( VIPS_OBJECT_CLASS( vips_convsep_parent_class )->build( object ) )
		return( -1 );

	if( vips_check_separable( class->nickname, convolution->M ) ) 
                return( -1 );

	in = convolution->in;

	if( convsep->precision == VIPS_PRECISION_APPROXIMATE ) {
		if( vips_convasep( in, &t[0], convolution->M,
			"layers", convsep->layers,
			NULL ) )
			return( -1 ); 
		in = t[0];
	}
	else { 
		/* Take a copy, since we must set the offset.
		 */
		if( vips_rot( convolution->M, &t[0], VIPS_ANGLE_D90, NULL ) ||
			vips_copy( t[0], &t[3], NULL ) )
			return( -1 ); 
		vips_image_set_double( t[3], "offset", 0 );

		if( vips_conv( in, &t[1], convolution->M, 
				"precision", convsep->precision,
				"layers", convsep->layers,
				"cluster", convsep->cluster,
				NULL ) ||
			vips_conv( t[1], &t[2], t[3], 
				"precision", convsep->precision,
				"layers", convsep->layers,
				"cluster", convsep->cluster,
				NULL ) )
			return( -1 ); 
		in = t[2];
	}

	if( vips_image_write( in, convolution->out ) )
		return( -1 ); 

	return( 0 );
}

static void
vips_convsep_class_init( VipsConvsepClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "convsep";
	object_class->description = _( "seperable convolution operation" );
	object_class->build = vips_convsep_build;

	VIPS_ARG_ENUM( class, "precision", 203, 
		_( "Precision" ), 
		_( "Convolve with this precision" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT, 
		G_STRUCT_OFFSET( VipsConvsep, precision ), 
		VIPS_TYPE_PRECISION, VIPS_PRECISION_FLOAT ); 

	VIPS_ARG_INT( class, "layers", 204, 
		_( "Layers" ), 
		_( "Use this many layers in approximation" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT, 
		G_STRUCT_OFFSET( VipsConvsep, layers ), 
		1, 1000, 5 ); 

	VIPS_ARG_INT( class, "cluster", 205, 
		_( "Cluster" ), 
		_( "Cluster lines closer than this in approximation" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT, 
		G_STRUCT_OFFSET( VipsConvsep, cluster ), 
		1, 100, 1 ); 

}

static void
vips_convsep_init( VipsConvsep *convsep )
{
	convsep->precision = VIPS_PRECISION_FLOAT;
	convsep->layers = 5;
	convsep->cluster = 1;
}

/**
 * vips_convsep: (method)
 * @in: input image
 * @out: (out): output image
 * @mask: convolution mask
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @precision: calculation accuracy
 * * @layers: number of layers for approximation
 * * @cluster: cluster lines closer than this distance
 *
 * Perform a separable convolution of @in with @mask.
 * See vips_conv() for a detailed description.
 *
 * The mask must be 1xn or nx1 elements. 
 *
 * The image is convolved twice: once with @mask and then again with @mask 
 * rotated by 90 degrees. This is much faster for certain types of mask
 * (gaussian blur, for example) than doing a full 2D convolution.
 *
 * See also: vips_conv(), vips_gaussmat().
 *
 * Returns: 0 on success, -1 on error
 */
int 
vips_convsep( VipsImage *in, VipsImage **out, VipsImage *mask, ... )
{
	va_list ap;
	int result;

	va_start( ap, mask );
	result = vips_call_split( "convsep", ap, in, out, mask );
	va_end( ap );

	return( result );
}
