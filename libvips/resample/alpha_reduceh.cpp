/* horizontal reduce by a float factor with a kernel
 *
 * 29/1/16
 * 	- from shrinkh.c
 * 10/3/16
 * 	- add other kernels
 * 15/8/16
 * 	- rename xshrink as hshrink for consistency
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
#include "templates.h"
#include "alpha_reduce.h"

typedef struct _VipsAlphaReduceh {
	VipsResample parent_instance;

	double hshrink;		/* Reduce factor */
} VipsAlphaReduceh;

typedef VipsResampleClass VipsAlphaReducehClass;

/* We need C linkage for this.
 */
extern "C" {
G_DEFINE_TYPE( VipsAlphaReduceh, vips_alpha_reduceh, VIPS_TYPE_RESAMPLE );
}

#define EPSILON  (1.0e-12)

static int
vips_alpha_reduceh_gen( VipsRegion *out_region, void *seq,
                  void *void_in, void *void_reduceh, gboolean *stop )
{
	VipsImage *in = (VipsImage *) void_in;
	VipsAlphaReduceh *reduceh = (VipsAlphaReduceh *) void_reduceh;
	VipsRegion *ir = (VipsRegion *) seq;
	VipsRect *r = &out_region->valid;

	/* Double bands for complex.
	 */
	const int num_bands = in->Bands *
	                      (vips_band_format_iscomplex( in->BandFmt ) ? 2 : 1);

	const int filter_support = 3;
	double support = reduceh->hshrink * filter_support;

	double first_bisect = (double) (r->left + 0 + 0.5) *
		reduceh->hshrink + EPSILON;
	int first_start = (int) VIPS_MAX( first_bisect - support + 0.5, 0.0 );

	double last_bisect = (double) (r->left + r->width - 1 + 0.5) *
		reduceh->hshrink + EPSILON;

	int last_stop = (int) VIPS_MIN( last_bisect + support + 0.5, in->Xsize );

	int filter_max_size = last_stop - first_start;
	VipsRect s = {
		.left = first_start,
		.top = r->top,
		.width = filter_max_size,
		.height = r->height,
	};

#ifdef DEBUG
	printf( "vips_alpha_reduceh_gen: generating %d x %d at %d x %d\n",
		r->width, r->height, r->left, r->top );
#endif /*DEBUG*/

	if( vips_region_prepare( ir, &s ) )
		return (-1);

	double *filter = (double*)alloca( sizeof(double) * filter_max_size );
	const int filter_stride = VIPS_IMAGE_SIZEOF_ELEMENT( in ) * num_bands;
	int source_inner_stride = VIPS_REGION_LSKIP( ir );
	int destination_inner_stride = VIPS_REGION_LSKIP( out_region );
	int destination_outer_stride = VIPS_IMAGE_SIZEOF_PEL( out_region->im );

	VIPS_GATE_START( "vips_alpha_reduceh_gen: work" );

	int max_source_size = in->Xsize;
	int outer_dimension_size = r->width;
	int destination_start = r->left;
	double factor = reduceh->hshrink;
	int inner_dimension_size = r->height;

	VipsPel* q = VIPS_REGION_ADDR( out_region, r->left, r->top);

	for( int i = 0; i < outer_dimension_size; i++ ) {
		int filter_size;
		int filter_start;

		calculate_filter(
			factor, destination_start + i, max_source_size, filter,
			&filter_size, &filter_start );

		const VipsPel* p = VIPS_REGION_ADDR( ir, filter_start, r->top);

		reduce_inner_dimension<unsigned short, USHRT_MAX>(
			in, filter, filter_size, filter_stride, inner_dimension_size, p, q,
			source_inner_stride, destination_inner_stride );

		q += destination_outer_stride;
	}

	VIPS_GATE_STOP( "vips_alpha_reduceh_gen: work" );

	VIPS_COUNT_PIXELS( out_region, "vips_alpha_reduceh_gen" );

	return( 0 );
}

static int
vips_alpha_reduceh_build( VipsObject *object )
{
	VipsObjectClass *object_class = VIPS_OBJECT_GET_CLASS( object );
	VipsResample *resample = VIPS_RESAMPLE( object );
	VipsAlphaReduceh *reduceh = (VipsAlphaReduceh *) object;
	VipsImage **t = (VipsImage **)
		vips_object_local_array( object, 2 );

	VipsImage *in;

	if( VIPS_OBJECT_CLASS( vips_alpha_reduceh_parent_class )->build( object ) )
		return( -1 );

	in = resample->in;

	if( reduceh->hshrink < 1 ) {
		vips_error( object_class->nickname,
			"%s", _( "reduce factors should be >= 1" ) );
		return( -1 );
	}

	if( reduceh->hshrink == 1 )
		return( vips_image_write( in, resample->out ) );

	/* Unpack for processing.
	 */
	if( vips_image_decode( in, &t[0] ) )
		return( -1 );
	in = t[0];

	if( vips_image_pipelinev( resample->out,
		VIPS_DEMAND_STYLE_THINSTRIP, in, (void *) NULL ) )
		return( -1 );

	/* Size output. We need to always round to nearest, so round(), not
	 * rint().
	 *
	 * Don't change xres/yres, leave that to the application layer. For
	 * example, vipsthumbnail knows the true reduce factor (including the
	 * fractional part), we just see the integer part here.
	 */
	resample->out->Xsize = VIPS_ROUND_UINT(
		resample->in->Xsize / reduceh->hshrink );
	if( resample->out->Xsize <= 0 ) {
		vips_error( object_class->nickname,
			"%s", _( "image has shrunk to nothing" ) );
		return( -1 );
	}

#ifdef DEBUG
	printf( "vips_alpha_reduceh_build: reducing %d x %d image to %d x %d\n",
		in->Xsize, in->Ysize,
		resample->out->Xsize, resample->out->Ysize );
#endif /*DEBUG*/

	if( vips_image_generate( resample->out,
		vips_start_one, vips_alpha_reduceh_gen, vips_stop_one,
		in, reduceh ) )
		return( -1 );

	//vips_reorder_margin_hint( resample->out, reduceh->n_point );

	return( 0 );
}

static void
vips_alpha_reduceh_class_init( VipsAlphaReducehClass *reduceh_class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( reduceh_class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( reduceh_class );
	VipsOperationClass *operation_class =
		VIPS_OPERATION_CLASS( reduceh_class );

	VIPS_DEBUG_MSG( "vips_reduceh_class_init\n" );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "alpha_reduceh";
	vobject_class->description = _( "shrink an image with alpha horizontally" );
	vobject_class->build = vips_alpha_reduceh_build;

	operation_class->flags = VIPS_OPERATION_SEQUENTIAL;

	VIPS_ARG_DOUBLE( reduceh_class, "hshrink", 3,
		_( "Hshrink" ),
		_( "Horizontal shrink factor" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsAlphaReduceh, hshrink ),
		1, 1000000, 1 );
}

static void
vips_alpha_reduceh_init( VipsAlphaReduceh *reduceh )
{
}

/* See reduce.c for the doc comment.
 */

int
vips_alpha_reduceh( VipsImage *in, VipsImage **out, double hshrink, ... )
{
	va_list ap;
	int result;

	va_start( ap, hshrink );
	result = vips_call_split( "alpha_reduceh", ap, in, out, hshrink );
	va_end( ap );

	return( result );
}
