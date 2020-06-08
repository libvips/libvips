/* vertical reduce by a float factor with a kernel
 *
 * 29/1/16
 * 	- from shrinkv.c
 * 10/3/16
 * 	- add other kernels
 * 21/3/16
 * 	- add vector path
 * 2/4/16
 * 	- better int mask creation ... we now adjust the scale to keep the sum
 * 	  equal to the target scale
 * 15/6/16
 * 	- better accuracy with smarter multiplication
 * 15/8/16
 * 	- rename yshrink as vshrink for consistency
 * 9/9/16
 * 	- add @centre option
 * 7/3/17
 * 	- add a seq line cache
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
#define DEBUG_PIXELS
#define DEBUG_COMPILE
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
#include <vips/vector.h>

#include "presample.h"
#include "templates.h"
#include "alpha_reduce.h"

typedef struct _VipsAlphaReducev {
	VipsResample parent_instance;

	double vshrink;		/* Shrink factor */
} VipsAlphaReducev;

typedef VipsResampleClass VipsAlphaReducevClass;

/* We need C linkage for this.
 */
extern "C" {
G_DEFINE_TYPE( VipsAlphaReducev, vips_alpha_reducev, VIPS_TYPE_RESAMPLE );
}

#define EPSILON  (1.0e-12)

static int
vips_alpha_reducev_gen( VipsRegion *out_region, void *seq,
                        void *void_in, void *void_reducev, gboolean *stop )
{
	VipsImage *in = (VipsImage *) void_in;
	VipsAlphaReducev *reducev = (VipsAlphaReducev *) void_reducev;
	VipsRegion *ir = (VipsRegion *) seq;
	VipsRect *r = &out_region->valid;

	int resize_filter_support = 3;
	double support = reducev->vshrink * resize_filter_support;

	double first_bisect = (double)(r->top + 0 + 0.5) * reducev->vshrink + EPSILON;
	int first_start = VIPS_MAX( first_bisect - support + 0.5, 0.0 );

	double last_bisect = (double)(r->top + r->height - 1 + 0.5) * reducev->vshrink + EPSILON;
	int last_stop = VIPS_MIN( last_bisect + support + 0.5, in->Ysize);
	int filter_max_size = last_stop - first_start;
	VipsRect s = {
		.left = r->left,
		.top = first_start,
		.width = r->width,
		.height = filter_max_size,
	};

#ifdef DEBUG
	printf( "vips_alpha_reducev_gen: generating %d x %d at %d x %d\n",
		r->width, r->height, r->left, r->top );
#endif /*DEBUG*/

	if( vips_region_prepare( ir, &s ) )
		return( -1 );

	double *filter = (double*)alloca( sizeof(double) * filter_max_size );
	const int filter_stride = VIPS_REGION_LSKIP( ir );
	int source_inner_stride = VIPS_IMAGE_SIZEOF_PEL( in );
	int destination_inner_stride = VIPS_IMAGE_SIZEOF_PEL( out_region->im );

	VIPS_GATE_START( "vips_alpha_reducev_gen: work" );

	int outer_dimension_size = r->height;
	int max_source_size = in->Ysize;
	int destination_start = r->top;
	double factor = reducev->vshrink;
	int inner_dimension_size = r->width;
	int destination_outer_stride = VIPS_REGION_LSKIP( out_region );

	VipsPel* q = VIPS_REGION_ADDR(out_region, r->left, r->top);

	for( int i = 0; i < outer_dimension_size; i ++ ) {
		int filter_size;
		int filter_start;

		calculate_filter(
			factor, destination_start + i, max_source_size, filter,
			&filter_size, &filter_start );

		const VipsPel* p = VIPS_REGION_ADDR( ir, r->left, filter_start);

		reduce_inner_dimension<unsigned short, USHRT_MAX>(
			in, filter, filter_size, filter_stride, inner_dimension_size, p, q,
			source_inner_stride, destination_inner_stride );

		q += destination_outer_stride;
	}

	VIPS_GATE_STOP( "vips_alpha_reducev_gen: work" );

	VIPS_COUNT_PIXELS( out_region, "vips_alpha_reducev_gen" );

	return( 0 );
}

static int
vips_alpha_reducev_raw( VipsAlphaReducev *reducev, VipsImage *in, VipsImage **out )
{
	VipsObjectClass *object_class = VIPS_OBJECT_GET_CLASS( reducev );
	VipsResample *resample = VIPS_RESAMPLE( reducev );

	*out = vips_image_new();
	if( vips_image_pipelinev( *out,
		VIPS_DEMAND_STYLE_FATSTRIP, in, (void *) NULL ) )
		return( -1 );

	/* Size output. We need to always round to nearest, so round(), not
	 * rint().
	 *
	 * Don't change xres/yres, leave that to the application layer. For
	 * example, vipsthumbnail knows the true reduce factor (including the
	 * fractional part), we just see the integer part here.
	 */
	int out_height = VIPS_ROUND_UINT(
		resample->in->Ysize / reducev->vshrink );
	(*out)->Ysize = out_height;
	if( (*out)->Ysize <= 0 ) { 
		vips_error( object_class->nickname, 
			"%s", _( "image has shrunk to nothing" ) );
		return( -1 );
	}

#ifdef DEBUG
	printf( "vips_alpha_reducev_build: reducing %d x %d image to %d x %d\n",
		in->Xsize, in->Ysize, 
		(*out)->Xsize, (*out)->Ysize );  
#endif /*DEBUG*/

	if( vips_image_generate( *out,
		vips_start_one, vips_alpha_reducev_gen, vips_stop_one,
		in, reducev ) )
		return( -1 );

//	vips_reorder_margin_hint( *out, reducev->n_point );

	return( 0 );
}

static int
vips_alpha_reducev_build( VipsObject *object )
{
	VipsObjectClass *object_class = VIPS_OBJECT_GET_CLASS( object );
	VipsResample *resample = VIPS_RESAMPLE( object );
	VipsAlphaReducev *reducev = (VipsAlphaReducev *) object;
	VipsImage **t = (VipsImage **) vips_object_local_array( object, 4 );

	VipsImage *in;

	if( VIPS_OBJECT_CLASS( vips_alpha_reducev_parent_class )->build( object ) )
		return( -1 );

	in = resample->in; 

	if( reducev->vshrink < 1 ) { 
		vips_error( object_class->nickname, 
			"%s", _( "reduce factor should be >= 1" ) );
		return( -1 );
	}

	if( reducev->vshrink == 1 ) 
		return( vips_image_write( in, resample->out ) );

	/* Unpack for processing.
	 */
	if( vips_image_decode( in, &t[0] ) )
		return( -1 );
	in = t[0];

	if( vips_alpha_reducev_raw( reducev, in, &t[2] ) )
		return( -1 );
	in = t[2];

	/* Large reducev will throw off sequential mode. Suppose thread1 is
	 * generating tile (0, 0), but stalls. thread2 generates tile
	 * (0, 1), 128 lines further down the output. After it has done,
	 * thread1 tries to generate (0, 0), but by then the pixels it needs
	 * have gone from the input image line cache if the reducev is large.
	 *
	 * To fix this, put another seq on the output of reducev. Now we'll
	 * always have the previous XX lines of the shrunk image, and we won't
	 * fetch out of order. 
	 */
	if( vips_image_get_typeof( in, VIPS_META_SEQUENTIAL ) ) { 
		g_info( "reducev sequential line cache" ); 

		if( vips_sequential( in, &t[3], 
			"tile_height", 10,
			// "trace", TRUE,
			(void *) NULL ) )
			return( -1 );
		in = t[3];
	}

	if( vips_image_write( in, resample->out ) )
		return( -1 ); 

	return( 0 );
}

static void
vips_alpha_reducev_class_init( VipsAlphaReducevClass *reducev_class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( reducev_class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( reducev_class );
	VipsOperationClass *operation_class = 
		VIPS_OPERATION_CLASS( reducev_class );

	VIPS_DEBUG_MSG( "vips_alpha_reducev_class_init\n" );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "alpha_reducev";
	vobject_class->description = _( "shrink an image with alpha vertically" );
	vobject_class->build = vips_alpha_reducev_build;

	operation_class->flags = VIPS_OPERATION_SEQUENTIAL;

	VIPS_ARG_DOUBLE( reducev_class, "vshrink", 3, 
		_( "Vshrink" ), 
		_( "Vertical shrink factor" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsAlphaReducev, vshrink ),
		1, 1000000, 1 );
}

static void
vips_alpha_reducev_init( VipsAlphaReducev *reducev )
{
}

/* See reduce.c for the doc comment.
 */

int
vips_alpha_reducev( VipsImage *in, VipsImage **out, double vshrink, ... )
{
	va_list ap;
	int result;

	va_start( ap, vshrink );
	result = vips_call_split( "alpha_reducev", ap, in, out, vshrink );
	va_end( ap );

	return( result );
}
