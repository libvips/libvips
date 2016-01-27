/* horizontal reduce by a float factor
 *
 * 30/10/15
 * 	- from reduceh.c
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
#include <vips/debug.h>
#include <vips/internal.h>

#include "presample.h"

typedef struct _VipsReduceh {
	VipsResample parent_instance;

	double xreduce;		/* Reduce factor */
	VipsInterpolate *interpolate;

} VipsReduceh;

typedef VipsResampleClass VipsReducehClass;

G_DEFINE_TYPE( VipsReduceh, vips_reduceh, VIPS_TYPE_RESAMPLE );

static int
vips_reduceh_gen( VipsRegion *or, void *seq, 
	void *a, void *b, gboolean *stop )
{
	VipsImage *in = (VipsImage *) a;
	VipsReduceh *reduceh = (VipsReduceh *) b;
	int window_size = 
		vips_interpolate_get_window_size( reduceh->interpolate );
	int window_offset = 
		vips_interpolate_get_window_offset( reduceh->interpolate );
	const VipsInterpolateMethod interpolate = 
		vips_interpolate_get_method( reduceh->interpolate );
	int ps = VIPS_IMAGE_SIZEOF_PEL( in );
	VipsRegion *ir = (VipsRegion *) seq;
	VipsRect *r = &or->valid;

	VipsRect s;
	int y;

#ifdef DEBUG
	printf( "vips_reduceh_gen: generating %d x %d at %d x %d\n",
		r->width, r->height, r->left, r->top ); 
#endif /*DEBUG*/

	s.left = r->left * reduceh->xreduce - window_offset;
	s.top = r->top;
	s.width = r->width * reduceh->xreduce + window_size - 1;
	s.height = r->height;
	if( vips_region_prepare( ir, &s ) )
		return( -1 );

	VIPS_GATE_START( "vips_reduceh_gen: work" ); 

	for( y = 0; y < r->height; y ++ ) { 
		VipsPel *q = VIPS_REGION_ADDR( or, r->left, r->top + y ); 
		double Y = r->top + y; 

		int x;

		for( x = 0; x < r->width; x++ ) { 
			double X = window_offset + 
				(r->left + x) * reduceh->xreduce; 

			interpolate( reduceh->interpolate, q, ir, X, Y );

			q += ps;
		}
	}

	VIPS_GATE_STOP( "vips_reduceh_gen: work" ); 

	return( 0 );
}

static int
vips_reduceh_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsResample *resample = VIPS_RESAMPLE( object );
	VipsReduceh *reduceh = (VipsReduceh *) object;
	VipsImage **t = (VipsImage **) 
		vips_object_local_array( object, 1 );

	VipsImage *in;
	int window_size;
	int window_offset;

	if( VIPS_OBJECT_CLASS( vips_reduceh_parent_class )->build( object ) )
		return( -1 );

	in = resample->in; 

	/* We can't use vips_object_argument_isset(), since it may have been
	 * set to NULL, see vips_similarity().
	 */
	if( !reduceh->interpolate ) {
		VipsInterpolate *interpolate;

		interpolate = vips_interpolate_new( "cubich" );
		g_object_set( object, 
			"interpolate", interpolate,
			NULL ); 
		g_object_unref( interpolate );

		/* coverity gets confused by this, it thinks
		 * reduceh->interpolate may still be null. Assign ourselves,
		 * even though we don't need to.
		 */
		reduceh->interpolate = interpolate;
	}

	window_size = vips_interpolate_get_window_size( reduceh->interpolate );
	window_offset = 
		vips_interpolate_get_window_offset( reduceh->interpolate );

	if( reduceh->xreduce < 1 ) { 
		vips_error( class->nickname, 
			"%s", _( "reduce factors should be >= 1" ) );
		return( -1 );
	}
	if( reduceh->xreduce > 2 )  
		vips_warn( class->nickname, 
			"%s", _( "reduce factor greater than 2" ) );

	if( reduceh->xreduce == 1 ) 
		return( vips_image_write( in, resample->out ) );

	/* Unpack for processing.
	 */
	if( vips_image_decode( in, &t[0] ) )
		return( -1 );
	in = t[0];

	/* Add new pixels around the input so we can interpolate at the edges.
	 */
	if( vips_embed( in, &t[1], 
		window_offset, 0, 
		in->Xsize + window_size - 1, in->Ysize,
		"extend", VIPS_EXTEND_COPY,
		NULL ) )
		return( -1 );
	in = t[1];

	/* THINSTRIP will work, anything else will break seq mode. If you 
	 * combine reduce with conv you'll need to use a line cache to maintain
	 * sequentiality.
	 */
	if( vips_image_pipelinev( resample->out, 
		VIPS_DEMAND_STYLE_THINSTRIP, in, NULL ) )
		return( -1 );

	/* Size output. Note: we round the output width down!
	 *
	 * Don't change xres/yres, leave that to the application layer. For
	 * example, vipsthumbnail knows the true reduce factor (including the
	 * fractional part), we just see the integer part here.
	 */
	resample->out->Xsize = (in->Xsize - window_size + 1) / reduceh->xreduce;
	if( resample->out->Xsize <= 0 ) { 
		vips_error( class->nickname, 
			"%s", _( "image has shrunk to nothing" ) );
		return( -1 );
	}

#ifdef DEBUG
	printf( "vips_reduceh_build: reducing %d x %d image to %d x %d\n", 
		in->Xsize, in->Ysize, 
		resample->out->Xsize, resample->out->Ysize );  
#endif /*DEBUG*/

	if( vips_image_generate( resample->out,
		vips_start_one, vips_reduceh_gen, vips_stop_one, 
		in, reduceh ) )
		return( -1 );

	return( 0 );
}

static void
vips_reduceh_class_init( VipsReducehClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );
	VipsOperationClass *operation_class = VIPS_OPERATION_CLASS( class );

	VIPS_DEBUG_MSG( "vips_reduceh_class_init\n" );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "reduceh";
	vobject_class->description = _( "reduce an image horizontally" );
	vobject_class->build = vips_reduceh_build;

	operation_class->flags = VIPS_OPERATION_SEQUENTIAL_UNBUFFERED;

	VIPS_ARG_DOUBLE( class, "xreduce", 3, 
		_( "Xreduce" ), 
		_( "Horizontal reduce factor" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsReduceh, xreduce ),
		1, 1000000, 1 );

	VIPS_ARG_INTERPOLATE( class, "interpolate", 4, 
		_( "Interpolate" ), 
		_( "Interpolate pixels with this" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT, 
		G_STRUCT_OFFSET( VipsReduceh, interpolate ) );

}

static void
vips_reduceh_init( VipsReduceh *reduceh )
{
}

/**
 * vips_reduceh:
 * @in: input image
 * @out: output image
 * @xreduce: horizontal reduce
 * @...: %NULL-terminated list of optional named arguments
 *
 * Reduce @in horizontally by a float factor. The pixels in @out are
 * interpolated with a 1D cubic mask. This operation will not work well for
 * a reduction of more than a factor of two.
 *
 * This is a very low-level operation: see vips_resize() for a more
 * convenient way to resize images. 
 *
 * This operation does not change xres or yres. The image resolution needs to
 * be updated by the application. 
 *
 * See also: vips_shrink(), vips_resize(), vips_affine().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_reduceh( VipsImage *in, VipsImage **out, double xreduce, ... )
{
	va_list ap;
	int result;

	va_start( ap, xreduce );
	result = vips_call_split( "reduceh", ap, in, out, xreduce );
	va_end( ap );

	return( result );
}
