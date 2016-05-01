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

	/* Deprecated.
	 */
	VipsInterpolate *interpolate;
	double idx;
	double idy;

} VipsResize;

typedef VipsResampleClass VipsResizeClass;

G_DEFINE_TYPE( VipsResize, vips_resize, VIPS_TYPE_RESAMPLE ); 

static int
vips_resize_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsResample *resample = VIPS_RESAMPLE( object );
	VipsResize *resize = (VipsResize *) object;

	VipsImage **t = (VipsImage **) vips_object_local_array( object, 7 );

	VipsImage *in;
	int target_width;
	int target_height;
	int int_hshrink;
	int int_vshrink;
	double hresidual;
	double vresidual;

	if( VIPS_OBJECT_CLASS( vips_resize_parent_class )->build( object ) )
		return( -1 );

	in = resample->in;

	/* The image size we are aiming for.
	 */
	target_width = in->Xsize * resize->scale;
	if( vips_object_argument_isset( object, "vscale" ) ) 
		target_height = in->Ysize * resize->vscale;
	else
		target_height = in->Ysize * resize->scale;

	/* If the factor is > 1.0, we need to zoom rather than shrink.
	 * Just set the int part to 1 in this case.
	 */

	/* We want the int part of the shrink to leave a bit to do with
	 * blur/reduce/sharpen, or we'll see strange changes in aliasing on int
	 * shrink boundaries as we resize.
	 */

	if( resize->scale > 1.0 )
		int_hshrink = 1;
	else
		int_hshrink = VIPS_FLOOR( 1.0 / (resize->scale * 2) );
	if( vips_object_argument_isset( object, "vscale" ) ) {
		if( resize->vscale > 1.0 )
			int_vshrink = 1;
		else
			int_vshrink = VIPS_FLOOR( 1.0 / (resize->vscale * 2) );
	}
	else
		int_vshrink = int_hshrink;

	if( int_vshrink > 1 ) { 
		vips_info( class->nickname, "shrinkv by %d", int_vshrink );
		if( vips_shrinkv( in, &t[0], int_vshrink, NULL ) )
			return( -1 );
		in = t[0];
	}

	if( int_hshrink > 1 ) { 
		vips_info( class->nickname, "shrinkh by %d", int_hshrink );
		if( vips_shrinkh( in, &t[1], int_hshrink, NULL ) )
			return( -1 );
		in = t[1];
	}

	/* Do we need a further size adjustment? It's the difference
	 * between our target size and the size we have after vips_shrink().
	 *
	 * This can break the aspect ratio slightly :/ but hopefully no one
	 * will notice.
	 */
	hresidual = (double) target_width / in->Xsize;
	vresidual = (double) target_height / in->Ysize;

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
		need_lines = 1.2 * n_lines / vresidual;
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
	if( vresidual < 1.0 ) { 
		vips_info( class->nickname, "residual reducev by %g", 
			vresidual );
		if( vips_reducev( in, &t[2], 1.0 / vresidual, NULL ) )  
			return( -1 );
		in = t[2];
	}

	if( hresidual < 1.0 ) { 
		vips_info( class->nickname, "residual reduceh by %g", 
			hresidual );
		if( vips_reduceh( in, &t[3], 1.0 / hresidual, NULL ) )  
			return( -1 );
		in = t[3];
	}

	/* Any upsizing.
	 */
	if( hresidual > 1.0 ) { 
		vips_info( class->nickname, "residual scaleh %g", 
			hresidual );
		if( vips_affine( in, &t[4], hresidual, 0.0, 0.0, 1.0, 
			"interpolate", vips_interpolate_nearest_static(), 
			NULL ) )  
			return( -1 );
		in = t[4];
	}

	if( vresidual > 1.0 ) { 
		vips_info( class->nickname, "residual scalev %g", vresidual );
		if( vips_affine( in, &t[5], 1.0, 0.0, 0.0, vresidual, 
			"interpolate", vips_interpolate_nearest_static(), 
			NULL ) )  
			return( -1 );
		in = t[5];
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

	/* We used to let people set the interpolator, but it's not clear this
	 * was useful. Anyway, vips_reduce() no longer has an interpolator
	 * param.
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
 * @vscale: vertical scale factor
 *
 * Resize an image. When upsizing (@scale > 1), the image is simply block
 * upsized. When downsizing, the
 * image is block-shrunk with vips_shrink(), then an anti-alias blur is
 * applied with vips_gaussblur(), then the image is shrunk again to the 
 * target size with vips_reduce(). 
 *
 * vips_resize() normally maintains the image apect ratio. If you set
 * @vscale, that factor is used for the vertical scale and @scale for the
 * horizontal.
 *
 * This operation does not change xres or yres. The image resolution needs to
 * be updated by the application. 
 *
 * See also: vips_shrink(), vips_reduce(), vips_gaussblur().
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
