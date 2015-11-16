/* resample with an index image
 *
 * 15/11/15
 * 	- from affine.c
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

typedef struct _VipsIndex {
	VipsResample parent_instance;

	VipsImage *image;
	VipsInterpolate *interpolate;

	/* Need an image vector for start_many / stop_many
	 */
	VipsImage *in_array[3];

} VipsIndex;

typedef VipsResampleClass VipsIndexClass;

G_DEFINE_TYPE( VipsIndex, vips_index, VIPS_TYPE_RESAMPLE );

/*
 * FAST_PSEUDO_FLOOR is a floor and floorf replacement which has been
 * found to be faster on several linux boxes than the library
 * version. It returns the floor of its argument unless the argument
 * is a negative integer, in which case it returns one less than the
 * floor. For example:
 *
 * FAST_PSEUDO_FLOOR(0.5) = 0
 *
 * FAST_PSEUDO_FLOOR(0.) = 0
 *
 * FAST_PSEUDO_FLOOR(-.5) = -1
 *
 * as expected, but
 *
 * FAST_PSEUDO_FLOOR(-1.) = -2
 *
 * The locations of the discontinuities of FAST_PSEUDO_FLOOR are the
 * same as floor and floorf; it is just that at negative integers the
 * function is discontinuous on the right instead of the left.
 */
#define FAST_PSEUDO_FLOOR(x) ( (int)(x) - ( (x) < 0. ) )

static int
vips_index_gen( VipsRegion *or, void *seq, void *a, void *b, gboolean *stop )
{
	VipsRegion **ir = (VipsRegion **) seq;
	const VipsImage **in_array = (VipsImage **) a;
	const VipsIndex *index = (VipsIndex *) b; 
	const VipsImage *in_array = (VipsImage **) a; 
	const VipsImage *in = in_array[0];
	const int window_size = 
		vips_interpolate_get_window_size( index->interpolate );
	const int window_offset = 
		vips_interpolate_get_window_offset( index->interpolate );
	const VipsInterpolateMethod interpolate = 
		vips_interpolate_get_method( index->interpolate );

	/* Area we generate in the output image.
	 */
	const VipsRect *r = &or->valid;
	const int le = r->left;
	const int ri = VIPS_RECT_RIGHT( r );
	const int to = r->top;
	const int bo = VIPS_RECT_BOTTOM( r );

	int ps = VIPS_IMAGE_SIZEOF_PEL( in );
	int x, y, z;
	
	VipsRect image, want, need, clipped;

#ifdef DEBUG_VERBOSE
	printf( "vips_index_gen: "
		"generating left=%d, top=%d, width=%d, height=%d\n", 
		r->left,
		r->top,
		r->width,
		r->height );
#endif /*DEBUG_VERBOSE*/

	/* Fetch the chunk of the index image we need, and find the max/min in
	 * x and y.
	 */
	if( vips_image_prepare( ir[1], r ) )
		return( -1 );


	want = *r;
	want.left += oarea->left;
	want.top += oarea->top;

	/* Find the area of the input image we need. This takes us to space 3. 
	 */
	vips__transform_invert_rect( &index->trn, &want, &need );

	/* That does round-to-nearest, because it has to stop rounding errors
	 * growing images unexpectedly. We need round-down, so we must
	 * add half a pixel along the left and top. But we are int :( so add 1
	 * pixel. 
	 *
	 * Add an extra line along the right and bottom as well, for rounding.
	 */
	vips_rect_marginadjust( &need, 1 );

	/* We need to fetch a larger area for the interpolator.
	 */
	need.left -= window_offset;
	need.top -= window_offset;
	need.width += window_size - 1;
	need.height += window_size - 1;

	/* Now go to space 2, the expanded input image. This is the one we
	 * read pixels from. 
	 */
	need.left += window_offset;
	need.top += window_offset;

	/* Clip against the size of (2).
	 */
	image.left = 0;
	image.top = 0;
	image.width = in->Xsize;
	image.height = in->Ysize;
	vips_rect_intersectrect( &need, &image, &clipped );

#ifdef DEBUG_VERBOSE
	printf( "vips_index_gen: "
		"preparing left=%d, top=%d, width=%d, height=%d\n", 
		clipped.left,
		clipped.top,
		clipped.width,
		clipped.height );
#endif /*DEBUG_VERBOSE*/

	if( vips_rect_isempty( &clipped ) ) {
		vips_region_black( or );
		return( 0 );
	}
	if( vips_region_prepare( ir, &clipped ) )
		return( -1 );

	VIPS_GATE_START( "vips_index_gen: work" ); 

	/* Resample! x/y loop over pixels in the output image (5).
	 */
	for( y = to; y < bo; y++ ) {
		/* Input clipping rectangle. We offset this so we can clip in
		 * space 2. 
		 */
		const int ile = iarea->left + window_offset;
		const int ito = iarea->top + window_offset;
		const int iri = ile + iarea->width;
		const int ibo = ito + iarea->height;

		/* Derivative of matrix.
		 */
		const double ddx = index->trn.ia;
		const double ddy = index->trn.ic;

		/* Continuous cods in transformed space.
		 */
		const double ox = le + oarea->left - index->trn.odx;
		const double oy = y + oarea->top - index->trn.ody;

		/* Continuous cods in input space.
		 */
		double ix, iy;

		VipsPel *q;

		/* To (3).
		 */
		ix = index->trn.ia * ox + index->trn.ib * oy;
		iy = index->trn.ic * ox + index->trn.id * oy;

		/* And the input offset in (3). 
		 */
		ix -= index->trn.idx;
		iy -= index->trn.idy;

		/* Finally to 2. 
		 */
		ix += window_offset;
		iy += window_offset;

		q = VIPS_REGION_ADDR( or, le, y );

		for( x = le; x < ri; x++ ) {
			int fx, fy; 	

			fx = FAST_PSEUDO_FLOOR( ix );
			fy = FAST_PSEUDO_FLOOR( iy );

			/* Clip against iarea.
			 */
			if( fx >= ile &&
				fx < iri &&
				fy >= ito &&
				fy < ibo ) {
				/* Verify that we can read the whole stencil.
				 * With DEBUG on this will range-check.
				 */
				g_assert( VIPS_REGION_ADDR( ir, 
					(int) ix - window_offset,
					(int) iy - window_offset ) );
				g_assert( VIPS_REGION_ADDR( ir, 
					(int) ix - window_offset + 
						window_size - 1,
					(int) iy - window_offset + 
						window_size - 1 ) );

				interpolate( index->interpolate, 
					q, ir, ix, iy );
			}
			else {
				for( z = 0; z < ps; z++ ) 
					q[z] = 0;
			}

			ix += ddx;
			iy += ddy;
			q += ps;
		}
	}

	VIPS_GATE_STOP( "vips_index_gen: work" ); 

	return( 0 );
}

static int
vips_index_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsResample *resample = VIPS_RESAMPLE( object );
	VipsIndex *index = (VipsIndex *) object;
	VipsImage **t = (VipsImage **) vips_object_local_array( object, 4 );

	VipsImage *in;
	VipsDemandStyle hint; 
	int window_size;
	int window_offset;
	double edge;

	if( VIPS_OBJECT_CLASS( vips_index_parent_class )->build( object ) )
		return( -1 );

	if( vips_check_coding_known( class->nickname, resample->in ) ||
		vips_check_complex( class->nickname, index->index ) )
		return( -1 );

	in = resample->in;

	if( vips_image_decode( in, &t[0] ) )
		return( -1 );
	in = t[0];

	if( vips_check_bands_1orn( class->nickname, in, index->index ) )
		return( -1 );

	/* We can't use vips_object_argument_isset(), since it may have been
	 * set to NULL, see vips_similarity().
	 */
	if( !index->interpolate ) {
		VipsInterpolate *interpolate;

		interpolate = vips_interpolate_new( "bilinear" );
		g_object_set( object, 
			"interpolate", interpolate,
			NULL ); 
		g_object_unref( interpolate );

		/* coverity gets confused by this, it thinks
		 * index->interpolate may still be null. Assign ourselves,
		 * even though we don't need to.
		 */
		index->interpolate = interpolate;
	}

	window_size = vips_interpolate_get_window_size( index->interpolate );
	window_offset = vips_interpolate_get_window_offset( index->interpolate );

	/* Add new pixels around the input so we can interpolate at the edges.
	 */
	if( vips_embed( in, &t[1], 
		window_offset, window_offset, 
		in->Xsize + window_size - 1, in->Ysize + window_size - 1,
		"extend", VIPS_EXTEND_COPY,
		NULL ) )
		return( -1 );
	in = t[1];

	if( vips_image_pipelinev( resample->out, VIPS_DEMAND_STYLE_SMALLTILE, 
		in, NULL ) )
		return( -1 );

	resample->out->Xsize = index->index->Xsize
	resample->out->Ysize = index->index->Xsize

	index->in_array[0] = in;
	index->in_array[1] = index->index;
	index->in_array[2] = NULL;
	if( vips_image_generate( resample->out, 
		vips_start_many, vips_index_gen, vips_stop_many, 
		index->in_array, index ) )
		return( -1 );

	return( 0 );
}

static void
vips_index_class_init( VipsIndexClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	VIPS_DEBUG_MSG( "vips_index_class_init\n" );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "index";
	vobject_class->description = _( "resample with an index image" );
	vobject_class->build = vips_index_build;

	VIPS_ARG_IMAGE( class, "index", 2, 
		_( "Index" ), 
		_( "Index pixels with this" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsIndex, index ) );

	VIPS_ARG_INTERPOLATE( class, "interpolate", 4, 
		_( "Interpolate" ), 
		_( "Interpolate pixels with this" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT, 
		G_STRUCT_OFFSET( VipsIndex, interpolate ) );

}

static void
vips_index_init( VipsIndex *index )
{
}

/**
 * vips_index:
 * @in: input image
 * @out: output image
 * @index: index image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * @interpolate: interpolate pixels with this
 *
 * This operator resamples @in using @index to look up pixels. @out is
 * the same size as @index, with each pixel being fetched from that position in
 * @in. That is:
 *
 * |[
 * out[x, y] = in[index[x, y]]
 * ]|
 *
 * If @index has one band, that band must be complex. Otherwise, @index must
 * have two bands of any format. 
 *
 * Coordinates in @index are in pixels, with (0, 0) being the top-left corner 
 * of @in, and with y increasing down the image. 
 *
 * @interpolate defaults to bilinear. 
 *
 * This operation does not change xres or yres. The image resolution needs to
 * be updated by the application. 
 *
 * See vips_maplut() for a 1D equivalent of this operation. 
 *
 * See also: vips_affine(), vips_resize(), vips_maplut(), #VipsInterpolate.
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_index( VipsImage *in, VipsImage **out, VipsImage *index, ... ) 
{
	va_list ap;
	int result;

	va_start( ap, index );
	result = vips_call_split( "index", ap, in, out, index );
	va_end( ap );

	return( result );
}
