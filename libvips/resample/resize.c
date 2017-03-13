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

typedef struct _VipsResize {
	VipsResample parent_instance;

	double scale;
	double vscale;
	VipsKernel kernel;
	gboolean centre;

	/* Deprecated.
	 */
	VipsInterpolate *interpolate;
	double idx;
	double idy;

} VipsResize;

typedef VipsResampleClass VipsResizeClass;

G_DEFINE_TYPE( VipsResize, vips_resize, VIPS_TYPE_RESAMPLE ); 

/* How much of a scale should be by an integer shrink factor?
 *
 * This depends on the scale and the kernel we will use for residual resizing.
 * For upsizing and nearest-neighbour downsize, we want no shrinking. 
 *
 * Linear and cubic are fixed-size kernels and for a 0 offset are point
 * samplers. We will get aliasing if we do more than a x2 shrink with them.
 *
 * Lanczos is adaptive: the size of the kernel changes with the shrink factor.
 * We will get the best quality (but be the slowest) if we let reduce do all
 * the work. Leave it the final 200 - 300% to do as a compromise for
 * efficiency. 
 *
 * FIXME: this is rather ugly. Kernel should be a class and this info should be
 * stored in there. 
 */
static int
vips_resize_int_shrink( VipsResize *resize, double scale )
{
	if( scale > 1.0 )
		return( 1 ); 

	switch( resize->kernel ) { 
	case VIPS_KERNEL_NEAREST:
	     return( 1 ); 

	case VIPS_KERNEL_LINEAR:
	case VIPS_KERNEL_CUBIC:
	default:
		return( VIPS_FLOOR( 1.0 / scale ) );

	case VIPS_KERNEL_LANCZOS2:
	case VIPS_KERNEL_LANCZOS3:
		return( VIPS_MAX( 1, VIPS_FLOOR( 1.0 / (scale * 2) ) ) );
	}
}

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

	VipsImage **t = (VipsImage **) vips_object_local_array( object, 7 );

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

	/* The int part of our scale.
	 */
	int_hshrink = vips_resize_int_shrink( resize, hscale );
	int_vshrink = vips_resize_int_shrink( resize, vscale );

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

	/* We will get overcomputation on vips_shrink() from the vips_reduce() 
	 * coming later, so read into a cache where tiles are scanlines, and 
	 * make sure we keep enough scanlines.
	 *
	 * We use a threaded tilecache to avoid a deadlock: suppose thread1,
	 * evaluating the top block of the output, is delayed, and thread2, 
	 * evaluating the second block, gets here first (this can happen on 
	 * a heavily-loaded system). 
	 *
	 * With an unthreaded tilecache, thread2 will get
	 * the cache lock and start evaling the second block of the shrink. 
	 * When it reaches the png reader it will stall until the first block 
	 * has been used ... but it never will, since thread1 will block on 
	 * this cache lock. 
	 *
	 * Cache sizing: we double-buffer writes, so threads can be up to one 
	 * line of tiles behind. For example, one thread could be allocated
	 * tile (0,0) and then stall, the whole write system won't stall until
	 * it tries to allocate tile (0, 2).
	 *
	 * We reduce down after this, which can be a scale of up to @residual, 
	 * perhaps 0.5 or down as low as 0.3. So the number of scanlines we 
	 * need to keep for the worst case is 2 * @tile_height / @residual, 
	 * plus a little extra.
	 */
	if( int_vshrink > 1 ) { 
		int tile_width;
		int tile_height;
		int n_lines;
		int need_lines;

		vips_get_tile_size( in, 
			&tile_width, &tile_height, &n_lines );
		need_lines = 1.2 * n_lines / vscale;
		if( vips_tilecache( in, &t[6], 
			"tile_width", in->Xsize,
			"tile_height", 10,
			"max_tiles", 1 + need_lines / 10,
			"access", VIPS_ACCESS_SEQUENTIAL,
			"threaded", TRUE, 
			NULL ) )
			return( -1 );
		in = t[6];
	}

	/* Any residual downsizing.
	 */
	if( vscale < 1.0 ) { 
		g_info( "residual reducev by %g", vscale );
		if( vips_reducev( in, &t[2], 1.0 / vscale, 
			"kernel", resize->kernel, 
			"centre", resize->centre, 
			NULL ) )  
			return( -1 );
		in = t[2];
	}

	if( hscale < 1.0 ) { 
		g_info( "residual reduceh by %g", 
			hscale );
		if( vips_reduceh( in, &t[3], 1.0 / hscale, 
			"kernel", resize->kernel, 
			"centre", resize->centre, 
			NULL ) )  
			return( -1 );
		in = t[3];
	}

	/* Any upsizing.
	 */
	if( hscale > 1.0 ||
		vscale > 1.0 ) { 
		const char *nickname = vips_resize_interpolate( resize->kernel );
		VipsInterpolate *interpolate;

		if( !(interpolate = vips_interpolate_new( nickname )) )
			return( -1 ); 
		vips_object_local( object, interpolate );

		if( hscale > 1.0 && 
			vscale > 1.0 ) { 
			g_info( "residual scale %g x %g", hscale, vscale );
			if( vips_affine( in, &t[4], 
				hscale, 0.0, 0.0, vscale, 
				"interpolate", interpolate, 
				NULL ) )  
				return( -1 );
			in = t[4];
		}
		else if( hscale > 1.0 ) { 
			g_info( "residual scale %g", hscale );
			if( vips_affine( in, &t[4], hscale, 0.0, 0.0, 1.0, 
				"interpolate", interpolate, 
				NULL ) )  
				return( -1 );
			in = t[4];
		}
		else { 
			g_info( "residual scale %g", vscale );
			if( vips_affine( in, &t[4], 1.0, 0.0, 0.0, vscale, 
				"interpolate", interpolate, 
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
		0, 10000000, 0 );

	VIPS_ARG_DOUBLE( class, "vscale", 113, 
		_( "Vertical scale factor" ), 
		_( "Vertical scale image by this factor" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsResize, vscale ),
		0, 10000000, 0 );

	VIPS_ARG_ENUM( class, "kernel", 3, 
		_( "Kernel" ), 
		_( "Resampling kernel" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsResize, kernel ),
		VIPS_TYPE_KERNEL, VIPS_KERNEL_LANCZOS3 );

	VIPS_ARG_BOOL( class, "centre", 7, 
		_( "Centre" ), 
		_( "Use centre sampling convention" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsResize, centre ),
		FALSE );

	/* We used to let people set the input offset so you could pick centre
	 * or corner interpolation, but it's not clear this was useful. 
	 */
	VIPS_ARG_DOUBLE( class, "idx", 115, 
		_( "Input offset" ), 
		_( "Horizontal input displacement" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT | VIPS_ARGUMENT_DEPRECATED,
		G_STRUCT_OFFSET( VipsResize, idx ),
		-10000000, 10000000, 0 );

	VIPS_ARG_DOUBLE( class, "idy", 116, 
		_( "Input offset" ), 
		_( "Vertical input displacement" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT | VIPS_ARGUMENT_DEPRECATED,
		G_STRUCT_OFFSET( VipsResize, idy ),
		-10000000, 10000000, 0 );

	/* It's a kernel now we use vips_reduce() not vips_affine().
	 */
	VIPS_ARG_INTERPOLATE( class, "interpolate", 2, 
		_( "Interpolate" ), 
		_( "Interpolate pixels with this" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT | VIPS_ARGUMENT_DEPRECATED, 
		G_STRUCT_OFFSET( VipsResize, interpolate ) );

}

static void
vips_resize_init( VipsResize *resize )
{
	resize->kernel = VIPS_KERNEL_LANCZOS3;
}

/**
 * vips_resize:
 * @in: input image
 * @out: output image
 * @scale: scale factor
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @vscale: %gdouble vertical scale factor
 * * @kernel: #VipsKernel to reduce with 
 * * @centre: %gboolean use centre rather than corner sampling convention
 *
 * Resize an image. 
 *
 * When downsizing, the
 * image is block-shrunk with vips_shrink(), 
 * then the image is shrunk again to the 
 * target size with vips_reduce(). How much is done by vips_shrink() vs.
 * vips_reduce() varies with the @kernel setting. 
 *
 * vips_resize() normally uses #VIPS_KERNEL_LANCZOS3 for the final reduce, you
 * can change this with @kernel.
 *
 * Set @centre to use centre rather than corner sampling convention. Centre
 * convention can be useful to match the behaviour of other systems. 
 *
 * When upsizing (@scale > 1), the operation uses vips_affine() with
 * a #VipsInterpolate selected depending on @kernel. It will use
 * #VipsInterpolateBicubic for #VIPS_KERNEL_CUBIC and above.
 *
 * vips_resize() normally maintains the image apect ratio. If you set
 * @vscale, that factor is used for the vertical scale and @scale for the
 * horizontal.
 *
 * This operation does not change xres or yres. The image resolution needs to
 * be updated by the application. 
 *
 * See also: vips_shrink(), vips_reduce().
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
