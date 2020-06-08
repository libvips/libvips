/* resize an image ... up and down resampling.
 *
 * 13/8/14
 * 	- from affine.c
 * 18/11/14
 * 	- add the fancier algorithm from vipsthumbnail
 * 11/11/15
 * 	- smarter cache sizing
 * 29/2/16
 * 	- shrink more affine less, now we have better anti-alias settings
 * 10/3/16
 * 	- revise again, using new vips_reduce() code
 * 1/5/16
 * 	- allow >1 on one axis, <1 on the other
 * 	- expose @kernel setting
 * 16/6/16
 * 	- better quality for linear/cubic kernels ... do more shrink and less
 * 	  reduce
 * 22/6/16
 * 	- faster and better upsizing
 * 15/8/16
 * 	- more accurate resizing
 * 9/9/16
 * 	- add @centre option
 * 6/3/17	
 * 	- moved the cache to shrinkv
 * 15/10/17
 * 	- make LINEAR and CUBIC adaptive
 * 25/11/17
 * 	- deprecate --centre ... it's now always on, thanks tback
 * 3/12/18 [edwjusti]
 * 	- disable the centre sampling offset for nearest upscale, since the
 * 	  affine nearest interpolator is always centre 
 * 7/7/19 [lovell]
 * 	- don't let either axis drop below 1px
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
#define DEBUG_VERBOSE
#define DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <limits.h>

#include <vips/vips.h>
#include <vips/debug.h>
#include <vips/internal.h>
#include <vips/transform.h>

#include "presample.h"

typedef struct _VipsAlphaResize {
	VipsOperation parent_instance;

	VipsImage *in;
	VipsImage *out;

	double scale;
	double vscale;
} VipsAlphaResize;

typedef VipsOperationClass VipsAlphaResizeClass;

G_DEFINE_TYPE( VipsAlphaResize, vips_alpha_resize, VIPS_TYPE_OPERATION );

/* How much of a scale should be by an integer shrink factor?
 */
static int
vips_alpha_resize_int_shrink( double scale )
{
	return VIPS_MAX( 1, VIPS_FLOOR( 1.0 / (scale * 2) ) );
}

static int
vips_alpha_resize_build( VipsObject *object )
{
	VipsAlphaResize *resize = (VipsAlphaResize *) object;

	VipsImage **t = (VipsImage **) vips_object_local_array( object, 9 );

	VipsImage *in = resize->in;
	double hscale = resize->scale;
	double vscale = vips_object_argument_isset( object, "vscale" ) ?
		resize->vscale : resize->scale;
	int int_hshrink = vips_alpha_resize_int_shrink( hscale );
	int int_vshrink = vips_alpha_resize_int_shrink( vscale );

	g_object_set( resize, "out", vips_image_new(), NULL );

	//temp temp temp
//	int_hshrink = 1;
//	int_vshrink = 1;
	//temp temp temp

	/* Unpack for processing.
	 */
	if( vips_image_decode( in, &t[5] ) )
		return( -1 );
	in = t[5];

	if( int_vshrink > 1 || int_hshrink > 1) {
		if( vips_premultiply( in, &t[7], NULL ) )
			return (-1);
		in = t[7];
	}

	if( int_vshrink > 1 ) { 
		g_info( "shrinkv by %d", int_vshrink );
		if( vips_shrinkv( in, &t[0], int_vshrink, NULL ) )
			return( -1 );
		in = t[0];

		vscale *= int_vshrink;
	}

	if( int_hshrink > 1 ) { 
		g_info( "shrinkh by %d", int_hshrink );
		if( vips_shrinkh( in, &t[1], int_hshrink, NULL ) )
			return( -1 );
		in = t[1];

		hscale *= int_hshrink;
	}

	if( int_vshrink > 1 || int_hshrink > 1) {
		if( vips_unpremultiply( in, &t[8], NULL ) )
			return (-1);
		in = t[8];
	}

	/* Don't let either axis drop below 1 px.
	 */
	hscale = VIPS_MAX( hscale, 1.0 / in->Xsize );
	vscale = VIPS_MAX( vscale, 1.0 / in->Ysize );

	if( vips_colourspace( in, &t[6], VIPS_INTERPRETATION_RGB16, NULL) )
		return( -1 );
	in = t[6];

	/* Any residual downsizing.
	 */
	if (hscale > vscale) {
		if( hscale < 1.0 ) {
			g_info( "residual reduceh by %g",
			        hscale );
			if( vips_alpha_reduceh( in, &t[3], 1.0 / hscale, NULL ) )
				return (-1);
			in = t[3];
		}

		if( vscale < 1.0 ) {
			g_info( "residual reducev by %g", vscale );
			if( vips_alpha_reducev( in, &t[2], 1.0 / vscale, NULL ) )
				return (-1);
			in = t[2];
		}
	} else {
		if( vscale < 1.0 ) {
			g_info( "residual reducev by %g", vscale );
			if( vips_alpha_reducev( in, &t[2], 1.0 / vscale, NULL ) )
				return (-1);
			in = t[2];
		}

		if( hscale < 1.0 ) {
			g_info( "residual reduceh by %g",
			        hscale );
			if( vips_alpha_reduceh( in, &t[3], 1.0 / hscale, NULL ) )
				return (-1);
			in = t[3];
		}
	}

	/* upsizing is not supported
	 */
	if( hscale > 1.0 ||
		vscale > 1.0 ) {
		vips_error( VIPS_OBJECT_GET_CLASS( vips_alpha_resize_parent_class )->nickname,
			"alpha_resize doesn't support upsizing");
		return( -1 );
	}

	if( vips_image_write( in, resize->out ) )
		return( -1 ); 

	return( 0 );
}

static void
vips_alpha_resize_class_init( VipsAlphaResizeClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );
	VipsOperationClass *operation_class = VIPS_OPERATION_CLASS( class );

	VIPS_DEBUG_MSG( "vips_alpha_resize_class_init\n" );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "alpha_resize";
	vobject_class->description = _( "resize an image with alpha" );
	vobject_class->build = vips_alpha_resize_build;

	operation_class->flags = VIPS_OPERATION_SEQUENTIAL;

	VIPS_ARG_IMAGE( class, "in", 1,
	                _( "Input" ),
	                _( "Input image" ),
	                VIPS_ARGUMENT_REQUIRED_INPUT,
	                G_STRUCT_OFFSET( VipsAlphaResize, in ) );

	VIPS_ARG_IMAGE( class, "out", 2,
	                _( "Output" ),
	                _( "Output image" ),
	                VIPS_ARGUMENT_REQUIRED_OUTPUT,
	                G_STRUCT_OFFSET( VipsAlphaResize, out ) );

	VIPS_ARG_DOUBLE( class, "scale", 3,
		_( "Scale factor" ), 
		_( "Scale image by this factor" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsAlphaResize, scale ),
		0, 10000000, 0 );

	VIPS_ARG_DOUBLE( class, "vscale", 4,
		_( "Vertical scale factor" ), 
		_( "Vertical scale image by this factor" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsAlphaResize, vscale ),
		0, 10000000, 0 );

}

static void
vips_alpha_resize_init( VipsAlphaResize *resize )
{
}

/**
 * vips_alpha_resize: (method)
 * @in: input image
 * @out: (out): output image
 * @scale: scale factor
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @vscale: %gdouble vertical scale factor
 * * @kernel: #VipsKernel to reduce with 
 *
 * Resize an image. 
 *
 * When downsizing, the
 * image is block-shrunk with vips_shrink(), 
 * then the image is shrunk again to the 
 * target size with vips_reduce(). How much is done by vips_shrink() vs.
 * vips_reduce() varies with the @kernel setting. Downsizing is done with
 * centre convention. 
 *
 * vips_resize() normally uses #VIPS_KERNEL_LANCZOS3 for the final reduce, you
 * can change this with @kernel.
 *
 * When upsizing (@scale > 1), the operation uses vips_affine() with
 * a #VipsInterpolate selected depending on @kernel. It will use
 * #VipsInterpolateBicubic for #VIPS_KERNEL_CUBIC and above. It adds a
 * 0.5 pixel displacement to the input pixels to get centre convention scaling.
 *
 * vips_resize() normally maintains the image aspect ratio. If you set
 * @vscale, that factor is used for the vertical scale and @scale for the
 * horizontal.
 *
 * If either axis would drop below 1px in size, the shrink in that dimension
 * is limited. This breaks the image aspect ratio, but prevents errors due to
 * fractional pixel sizes.
 *
 * This operation does not change xres or yres. The image resolution needs to
 * be updated by the application. 
 *
 * See also: vips_shrink(), vips_reduce().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_alpha_resize( VipsImage *in, VipsImage **out,
	double scale, ... )
{
	va_list ap;
	int result;

	va_start( ap, scale );
	result = vips_call_split( "alpha_resize", ap, in, out, scale );
	va_end( ap );

	return( result );
}
