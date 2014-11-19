/* resize an image ... up and down resampling.
 *
 * 13/8/14
 * 	- from affine.c
 * 18/11/14
 * 	- add the fancier algorithm from vipsthumbnail
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
	VipsInterpolate *interpolate;
	double idx;
	double idy;

} VipsResize;

typedef VipsResampleClass VipsResizeClass;

G_DEFINE_TYPE( VipsResize, vips_resize, VIPS_TYPE_RESAMPLE ); 

static int
vips_resize_build( VipsObject *object )
{
	VipsResample *resample = VIPS_RESAMPLE( object );
	VipsResize *resize = (VipsResize *) object;

	VipsImage **t = (VipsImage **) 
		vips_object_local_array( object, 6 );

	VipsImage *in;
	int window_size;
	int int_shrink;
	int int_shrink_width;
	double residual;
	double sigma;

	if( VIPS_OBJECT_CLASS( vips_resize_parent_class )->build( object ) )
		return( -1 );

	if( !vips_object_argument_isset( object, "interpolate" ) ) {
		char *nick;

		if( vips_type_find( "VipsInterpolate", "bicubic" ) )
			nick = "bicubic";
		else
			nick = "bilinear";
		g_object_set( object, 
			"interpolate", vips_interpolate_new( nick ),
			NULL ); 
	}

	in = resample->in;

	window_size = resize->interpolate ? 
		vips_interpolate_get_window_size( resize->interpolate ) : 2;

	/* If the factor is > 1.0, we need to zoom rather than shrink.
	 * Just set the int part to 1 in this case.
	 */
	int_shrink = resize->scale > 1.0 ? 1 : floor( 1.0 / resize->scale );

	/* We want to shrink by less for interpolators with larger windows.
	 */
	int_shrink = VIPS_MAX( 1,
		int_shrink / VIPS_MAX( 1, window_size / 2 ) );

	/* Size after int shrink.
	 */
	int_shrink_width = in->Xsize / int_shrink;

	/* Therefore residual scale factor is.
	 */
	residual = (in->Xsize * resize->scale) / int_shrink_width;

	/* A copy for enlarge resize.
	 */
	if( vips_shrink( in, &t[0], int_shrink, int_shrink, NULL ) )
		return( -1 );
	in = t[0];

	/* We want to make sure we read the image sequentially.
	 * However, the convolution we may be doing later will force us 
	 * into SMALLTILE or maybe FATSTRIP mode and that will break
	 * sequentiality.
	 *
	 * So ... read into a cache where tiles are scanlines, and make sure
	 * we keep enough scanlines to be able to serve a line of tiles.
	 *
	 * We use a threaded tilecache to avoid a deadlock: suppose thread1,
	 * evaluating the top block of the output, is delayed, and thread2, 
	 * evaluating the second block, gets here first (this can happen on 
	 * a heavily-loaded system). 
	 *
	 * With an unthreaded tilecache (as we had before), thread2 will get
	 * the cache lock and start evaling the second block of the shrink. 
	 * When it reaches the png reader it will stall until the first block 
	 * has been used ... but it never will, since thread1 will block on 
	 * this cache lock. 
	 */
	if( int_shrink > 1 ) { 
		int tile_width;
		int tile_height;
		int nlines;

		vips_get_tile_size( in, 
			&tile_width, &tile_height, &nlines );
		if( vips_tilecache( in, &t[6], 
			"tile_width", in->Xsize,
			"tile_height", 10,
			"max_tiles", 1 + (nlines * 2) / 10,
			"access", VIPS_ACCESS_SEQUENTIAL,
			"threaded", TRUE, 
			NULL ) )
			return( -1 );
		in = t[6];
	}

	/* If the final affine will be doing a large downsample, we can get 
	 * nasty aliasing on hard edges. Blur before affine to smooth this out.
	 *
	 * Don't blur for very small shrinks, blur with radius 1 for x1.5
	 * shrinks, blur radius 2 for x2.5 shrinks and above, etc.
	 */
	sigma = ((1.0 / residual) - 0.5) / 1.5;
	if( residual < 1.0 &&
		sigma > 0.1 ) { 
		if( vips_gaussblur( in, &t[2], sigma, NULL ) )
			return( -1 );
		in = t[2];
	}

	if( vips_affine( in, &t[3], residual, 0, 0, residual, 
		"interpolate", resize->interpolate,
		"idx", resize->idx,
		"idy", resize->idy,
		NULL ) )  
		return( -1 );
	in = t[3];

	/* If we are upsampling, don't sharpen.
	 */
	if( int_shrink > 1 ) { 
		t[5] = vips_image_new_matrixv( 3, 3,
			-1.0, -1.0, -1.0,
			-1.0, 32.0, -1.0,
			-1.0, -1.0, -1.0 );
		vips_image_set_double( t[5], "scale", 24 );

		if( vips_conv( in, &t[4], t[5], NULL ) ) 
			return( -1 );
		in = t[4];
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

	VIPS_ARG_INTERPOLATE( class, "interpolate", 2, 
		_( "Interpolate" ), 
		_( "Interpolate pixels with this" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT, 
		G_STRUCT_OFFSET( VipsResize, interpolate ) );

	VIPS_ARG_DOUBLE( class, "idx", 115, 
		_( "Input offset" ), 
		_( "Horizontal input displacement" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsResize, idx ),
		-10000000, 10000000, 0 );

	VIPS_ARG_DOUBLE( class, "idy", 116, 
		_( "Input offset" ), 
		_( "Vertical input displacement" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsResize, idy ),
		-10000000, 10000000, 0 );
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
 * @interpolate: interpolate pixels with this
 * @idx: input horizontal offset
 * @idy: input vertical offset
 *
 * Resize an image. When upsizing (@scale > 1), the image is simply resized
 * with vips_affine() and the supplied @interpolate. When downsizing, the
 * image is block-shrunk with vips_shrink() to roughly half the interpolator
 * window size above the target size, then blurred with an anti-alias filter,
 * then resampled with vips_affine() and the supplied interpolator, then
 * sharpened. 
 *
 * @interpolate defaults to bucubic, or bilinear if that is not available. 
 *
 * @idx, @idy default to zero. Offset them by 0.5 to get pixel-centre sampling. 
 *
 * See also: vips_shrink(), vips_affine(), #VipsInterpolate.
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
	result = vips_call_split( "affine", ap, in, out, scale );
	va_end( ap );

	return( result );
}
