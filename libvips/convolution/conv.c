/* convolution
 *
 * 12/8/13	
 * 	- from vips_hist_cum()
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
#include <vips/internal.h>

#include "pconvolution.h"

typedef struct {
	VipsConvolution parent_instance;

	VipsPrecision precision; 
	int layers; 
	int cluster; 
} VipsConv;

typedef VipsConvolutionClass VipsConvClass;

G_DEFINE_TYPE( VipsConv, vips_conv, VIPS_TYPE_CONVOLUTION );

static int
vips_conv_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsConvolution *convolution = (VipsConvolution *) object;
	VipsConv *conv = (VipsConv *) object;
	VipsImage **t = (VipsImage **) 
		vips_object_local_array( object, 4 );

	VipsImage *in;
	INTMASK *imsk;
	DOUBLEMASK *dmsk;

	g_object_set( conv, "out", vips_image_new(), NULL ); 

	if( VIPS_OBJECT_CLASS( vips_conv_parent_class )->build( object ) )
		return( -1 );

	in = convolution->in;

	/*
	printf( "vips_conv_build: convolving with:\n" );
	vips_matrixprint( convolution->M, NULL ); 
 	 */

	if( !(imsk = im_vips2imask( convolution->M, class->nickname )) || 
		!im_local_imask( convolution->out, imsk ) )
		return( -1 ); 
	if( !(dmsk = im_vips2mask( convolution->M, class->nickname )) || 
		!im_local_dmask( convolution->out, dmsk ) )
		return( -1 ); 

	/* Unpack for processing.
	 */
	if( vips_image_decode( in, &t[0] ) )
		return( -1 );
	in = t[0];

	switch( conv->precision ) { 
	case VIPS_PRECISION_INTEGER:
		if( im_conv( in, convolution->out, imsk ) )
			return( -1 ); 
		break;

	case VIPS_PRECISION_FLOAT:
		if( im_conv_f( in, convolution->out, dmsk ) )
			return( -1 ); 
		break;

	case VIPS_PRECISION_APPROXIMATE:
		if( im_aconv( in, convolution->out, dmsk, 
			conv->layers, conv->cluster ) )
			return( -1 ); 
		break;

	default:
		g_assert_not_reached();
	}

	return( 0 );
}

static void
vips_conv_class_init( VipsConvClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "conv";
	object_class->description = _( "convolution operation" );
	object_class->build = vips_conv_build;

	VIPS_ARG_ENUM( class, "precision", 103, 
		_( "Precision" ), 
		_( "Convolve with this precision" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT, 
		G_STRUCT_OFFSET( VipsConv, precision ), 
		VIPS_TYPE_PRECISION, VIPS_PRECISION_INTEGER ); 

	VIPS_ARG_INT( class, "layers", 104, 
		_( "Layers" ), 
		_( "Use this many layers in approximation" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT, 
		G_STRUCT_OFFSET( VipsConv, layers ), 
		1, 1000, 5 ); 

	VIPS_ARG_INT( class, "cluster", 105, 
		_( "Cluster" ), 
		_( "Cluster lines closer than this in approximation" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT, 
		G_STRUCT_OFFSET( VipsConv, cluster ), 
		1, 100, 1 ); 

}

static void
vips_conv_init( VipsConv *conv )
{
	conv->precision = VIPS_PRECISION_INTEGER;
	conv->layers = 5;
	conv->cluster = 1;
}

/**
 * vips_conv:
 * @in: input image
 * @out: output image
 * @mask: convolve with this mask
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @precision: calculation accuracy
 * * @layers: number of layers for approximation
 * * @cluster: cluster lines closer than this distance
 *
 * Convolution. 
 *
 * Perform a convolution of @in with @mask.
 * Each output pixel is
 * calculated as sigma[i]{pixel[i] * mask[i]} / scale + offset, where scale
 * and offset are part of @mask. 
 *
 * If @precision is #VIPS_PRECISION_INTEGER then the convolution is performed
 * with integer arithmetic and the output image 
 * always has the same #VipsBandFormat as the input image. 
 *
 * Convolutions on unsigned 8-bit images are calculated with the 
 * processor's vector unit, if possible. Disable this with `--vips-novector` or 
 * `VIPS_NOVECTOR`.
 *
 * If @precision is #VIPS_PRECISION_FLOAT then the convolution is performed
 * with floating-point arithmetic. The output image 
 * is always #VIPS_FORMAT_FLOAT unless @in is #VIPS_FORMAT_DOUBLE, in which case
 * @out is also #VIPS_FORMAT_DOUBLE. 
 *
 * If @precision is #VIPS_PRECISION_APPROXIMATE then the output image 
 * always has the same #VipsBandFormat as the input image. 
 *
 * Larger values for @layers give more accurate
 * results, but are slower. As @layers approaches the mask radius, the
 * accuracy will become close to exact convolution and the speed will drop to 
 * match. For many large masks, such as Gaussian, @n_layers need be only 10% of
 * this value and accuracy will still be good.
 *
 * Smaller values of @cluster will give more accurate results, but be slower
 * and use more memory. 10% of the mask radius is a good rule of thumb.
 *
 * Returns: 0 on success, -1 on error
 */
int 
vips_conv( VipsImage *in, VipsImage **out, VipsImage *mask, ... )
{
	va_list ap;
	int result;

	va_start( ap, mask );
	result = vips_call_split( "conv", ap, in, out, mask );
	va_end( ap );

	return( result );
}
