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
 * 12/7/20
 * 	- much better handling of "nearest"
 * 22/4/22 kleisauke
 * 	- add @gap option
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
#include <glib/gi18n-lib.h>

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

typedef struct _VipsResize {
	VipsResample parent_instance;

	double scale;
	double vscale;
	double gap;
	VipsKernel kernel;

	/* Deprecated.
	 */
	VipsInterpolate *interpolate;
	double idx;
	double idy;
	gboolean centre;

} VipsResize;

typedef VipsResampleClass VipsResizeClass;

G_DEFINE_TYPE( VipsResize, vips_resize, VIPS_TYPE_RESAMPLE ); 

/* Suggest a VipsInterpolate which corresponds to a VipsKernel. We use
 * this to pick a thing for affine().
 */
static const char *
vips_resize_interpolate( VipsKernel kernel )
{
	switch( kernel ) {
	case VIPS_KERNEL_NEAREST:
	     return( "nearest" ); 

	case VIPS_KERNEL_LINEAR:
	     return( "bilinear" ); 

	/* Use cubic for everything else. There are other interpolators, like
	 * nohalo, but they don't really correspond well to any kernel.
	 */
	default:
	     return( "bicubic" ); 
	}
}

static int
vips_resize_build( VipsObject *object )
{
	VipsResample *resample = VIPS_RESAMPLE( object );
	VipsResize *resize = (VipsResize *) object;

	VipsImage **t = (VipsImage **) vips_object_local_array( object, 5 );

	VipsImage *in;
	double hscale;
	double vscale;
	int int_hshrink;
	int int_vshrink;

	if( VIPS_OBJECT_CLASS( vips_resize_parent_class )->build( object ) )
		return( -1 );

	in = resample->in;

	/* Updated below when we do the int part of our shrink.
	 */
	hscale = resize->scale;
	if( vips_object_argument_isset( object, "vscale" ) ) 
		vscale = resize->vscale;
	else
		vscale = resize->scale;

	/* Unpack for processing.
	 */
	if( vips_image_decode( in, &t[0] ) )
		return( -1 );
	in = t[0];

	if( resize->kernel == VIPS_KERNEL_NEAREST ) {
		int target_width;
		int target_height;

		/* The int part of our scale.
		 */
		if( resize->gap < 1.0 ) {
			int_hshrink = VIPS_FLOOR( 1.0 / hscale );
			int_vshrink = VIPS_FLOOR( 1.0 / vscale );
		}
		else {
			target_width = VIPS_ROUND_UINT( in->Xsize * hscale );
			target_height = VIPS_ROUND_UINT( in->Ysize * vscale );

			int_hshrink = VIPS_FLOOR( 
				(double) in->Xsize / target_width / 
					resize->gap );
			int_vshrink = VIPS_FLOOR( 
				(double) in->Ysize / target_height / 
					resize->gap );
		}

		int_hshrink = VIPS_MAX( 1, int_hshrink );
		int_vshrink = VIPS_MAX( 1, int_vshrink );

		if( int_vshrink > 1 ||
			int_hshrink > 1 ) { 
			g_info( "subsample by %d, %d", 
				int_hshrink, int_vshrink );
			if( vips_subsample( in, &t[1], 
				int_hshrink, int_vshrink, NULL ) )
				return( -1 );
			in = t[1];

			hscale *= int_hshrink;
			vscale *= int_vshrink;
		}
	}

	/* Don't let either axis drop below 1 px.
	 */
	hscale = VIPS_MAX( hscale, 1.0 / in->Xsize );
	vscale = VIPS_MAX( vscale, 1.0 / in->Ysize );

	/* Any residual downsizing.
	 */
	if( vscale < 1.0 ) { 
		g_info( "residual reducev by %g", vscale );
		if( vips_reducev( in, &t[2], 1.0 / vscale, 
			"kernel", resize->kernel, 
			"gap", resize->gap,
			NULL ) )  
			return( -1 );
		in = t[2];
	}

	if( hscale < 1.0 ) { 
		g_info( "residual reduceh by %g", hscale );
		if( vips_reduceh( in, &t[3], 1.0 / hscale, 
			"kernel", resize->kernel, 
			"gap", resize->gap,
			NULL ) )  
			return( -1 );
		in = t[3];
	}

	/* Any upsizing.
	 */
	if( hscale > 1.0 ||
		vscale > 1.0 ) { 
		const char *nickname = 
			vips_resize_interpolate( resize->kernel );

		/* Input displacement. For centre sampling, shift by 0.5 down
		 * and right. Except if this is nearest, which is always
		 * centre.
		 */
		const double id = 
			resize->kernel == VIPS_KERNEL_NEAREST ? 
			0.0 : 0.5;

		VipsInterpolate *interpolate;

		if( !(interpolate = vips_interpolate_new( nickname )) )
			return( -1 ); 
		vips_object_local( object, interpolate );

		if( resize->kernel == VIPS_KERNEL_NEAREST &&
			hscale == VIPS_FLOOR( hscale ) &&
			vscale == VIPS_FLOOR( vscale ) ) {
			/* Fast, integral nearest neighbour enlargement
			 */
			if( vips_zoom( in, &t[4], VIPS_FLOOR( hscale ),
				VIPS_FLOOR( vscale ), NULL ) )
				return( -1 );
			in = t[4];
		}
		else if( hscale > 1.0 &&
			vscale > 1.0 ) { 
			g_info( "residual scale %g x %g", hscale, vscale );
			if( vips_affine( in, &t[4], 
				hscale, 0.0, 0.0, vscale, 
				"interpolate", interpolate, 
				"idx", id, 
				"idy", id, 
				"extend", VIPS_EXTEND_COPY, 
				"premultiplied", TRUE, 
				NULL ) )  
				return( -1 );
			in = t[4];
		}
		else if( hscale > 1.0 ) { 
			g_info( "residual scale %g", hscale );
			if( vips_affine( in, &t[4], hscale, 0.0, 0.0, 1.0, 
				"interpolate", interpolate, 
				"idx", id, 
				"idy", id, 
				"extend", VIPS_EXTEND_COPY, 
				"premultiplied", TRUE, 
				NULL ) )  
				return( -1 );
			in = t[4];
		}
		else { 
			g_info( "residual scale %g", vscale );
			if( vips_affine( in, &t[4], 1.0, 0.0, 0.0, vscale, 
				"interpolate", interpolate, 
				"idx", id, 
				"idy", id, 
				"extend", VIPS_EXTEND_COPY, 
				"premultiplied", TRUE, 
				NULL ) )  
				return( -1 );
			in = t[4];
		}
	}

	if( vips_image_write( in, resample->out ) )
		return( -1 ); 

	return( 0 );
}

static void
vips_resize_class_init( VipsResizeClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );
	VipsOperationClass *operation_class = VIPS_OPERATION_CLASS( class );

	VIPS_DEBUG_MSG( "vips_resize_class_init\n" );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "resize";
	vobject_class->description = _( "resize an image" );
	vobject_class->build = vips_resize_build;

	operation_class->flags = VIPS_OPERATION_SEQUENTIAL;

	VIPS_ARG_DOUBLE( class, "scale", 113, 
		_( "Scale factor" ), 
		_( "Scale image by this factor" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsResize, scale ),
		0.0, 10000000.0, 0.0 );

	VIPS_ARG_DOUBLE( class, "vscale", 113, 
		_( "Vertical scale factor" ), 
		_( "Vertical scale image by this factor" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsResize, vscale ),
		0.0, 10000000.0, 0.0 );

	VIPS_ARG_ENUM( class, "kernel", 3, 
		_( "Kernel" ), 
		_( "Resampling kernel" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsResize, kernel ),
		VIPS_TYPE_KERNEL, VIPS_KERNEL_LANCZOS3 );

	VIPS_ARG_DOUBLE( class, "gap", 4, 
		_( "Gap" ), 
		_( "Reducing gap" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsResize, gap ),
		0.0, 1000000.0, 2.0 );

	/* We used to let people set the input offset so you could pick centre
	 * or corner interpolation, but it's not clear this was useful. 
	 */
	VIPS_ARG_DOUBLE( class, "idx", 115, 
		_( "Input offset" ), 
		_( "Horizontal input displacement" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT | VIPS_ARGUMENT_DEPRECATED,
		G_STRUCT_OFFSET( VipsResize, idx ),
		-10000000.0, 10000000.0, 0.0 );

	VIPS_ARG_DOUBLE( class, "idy", 116, 
		_( "Input offset" ), 
		_( "Vertical input displacement" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT | VIPS_ARGUMENT_DEPRECATED,
		G_STRUCT_OFFSET( VipsResize, idy ),
		-10000000.0, 10000000.0, 0.0 );

	/* It's a kernel now we use vips_reduce() not vips_affine().
	 */
	VIPS_ARG_INTERPOLATE( class, "interpolate", 2, 
		_( "Interpolate" ), 
		_( "Interpolate pixels with this" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT | VIPS_ARGUMENT_DEPRECATED, 
		G_STRUCT_OFFSET( VipsResize, interpolate ) );

	/* We used to let people pick centre or corner, but it's automatic now.
	 */
	VIPS_ARG_BOOL( class, "centre", 7, 
		_( "Centre" ), 
		_( "Use centre sampling convention" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT | VIPS_ARGUMENT_DEPRECATED,
		G_STRUCT_OFFSET( VipsResize, centre ),
		FALSE );

}

static void
vips_resize_init( VipsResize *resize )
{
	resize->gap = 2.0;
	resize->kernel = VIPS_KERNEL_LANCZOS3;
}

/**
 * vips_resize: (method)
 * @in: input image
 * @out: (out): output image
 * @scale: scale factor
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @vscale: %gdouble vertical scale factor
 * * @kernel: #VipsKernel to reduce with 
 * * @gap: reducing gap to use (default: 2.0)
 *
 * Resize an image. 
 *
 * Set @gap to speed up downsizing by having vips_shrink() to shrink
 * with a box filter first. The bigger @gap, the closer the result
 * to the fair resampling. The smaller @gap, the faster resizing.
 * The default value is 2.0 (very close to fair resampling
 * while still being faster in many cases).
 *
 * vips_resize() normally uses #VIPS_KERNEL_LANCZOS3 for the final reduce, you
 * can change this with @kernel. Downsizing is done with centre convention. 
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
 * This operation does not premultiply alpha. If your image has an alpha
 * channel, you should use vips_premultiply() on it first.
 *
 * See also: vips_premultiply(), vips_shrink(), vips_reduce().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_resize( VipsImage *in, VipsImage **out, 
	double scale, ... )
{
	va_list ap;
	int result;

	va_start( ap, scale );
	result = vips_call_split( "resize", ap, in, out, scale );
	va_end( ap );

	return( result );
}
