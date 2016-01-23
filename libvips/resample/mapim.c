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

typedef struct _VipsMapim {
	VipsResample parent_instance;

	VipsImage *index;
	VipsInterpolate *interpolate;

	/* Need an image vector for start_many / stop_many
	 */
	VipsImage *in_array[3];

} VipsMapim;

typedef VipsResampleClass VipsMapimClass;

G_DEFINE_TYPE( VipsMapim, vips_mapim, VIPS_TYPE_RESAMPLE );

#define MINMAX( TYPE ) { \
	TYPE * restrict p1 = (TYPE *) p; \
	\
	for( x = 0; x < r->width; x++ ) { \
		TYPE px = p1[0]; \
		TYPE py = p1[1]; \
		\
		if( first ) { \
			min_x = px; \
			max_x = px; \
			min_y = py; \
			max_y = py; \
			\
			first = FALSE; \
		} \
		else { \
			if( px > max_x ) \
				max_x = px; \
			if( px < min_x ) \
				min_x = px; \
			if( py > max_y ) \
				max_y = py; \
			if( py < min_y ) \
				min_y = py; \
		} \
		\
		p1 += 2; \
	} \
}

/* Scan a region and find min/max in the two axes.
 */
static void
vips_mapim_region_minmax( VipsRegion *region, VipsRect *r, VipsRect *bounds )
{
	int min_x;
	int max_x;
	int min_y;
	int max_y;
	gboolean first;
	int x, y;

	first = TRUE;
	for( y = 0; y < r->height; y++ ) {
		VipsPel * restrict p = 
			VIPS_REGION_ADDR( region, r->left, y + r->top );

		switch( region->im->BandFmt ) {
		case VIPS_FORMAT_UCHAR: 	
			MINMAX( unsigned char ); break; 
		case VIPS_FORMAT_CHAR: 	
			MINMAX( signed char ); break; 
		case VIPS_FORMAT_USHORT: 
			MINMAX( unsigned short ); break; 
		case VIPS_FORMAT_SHORT: 	
			MINMAX( signed short ); break; 
		case VIPS_FORMAT_UINT: 	
			MINMAX( unsigned int ); break; 
		case VIPS_FORMAT_INT: 	
			MINMAX( signed int ); break; 

		case VIPS_FORMAT_FLOAT: 		
		case VIPS_FORMAT_COMPLEX: 
			MINMAX( float ); break; 

		case VIPS_FORMAT_DOUBLE:	
		case VIPS_FORMAT_DPCOMPLEX: 
			MINMAX( double ); break;

		default:
			g_assert( 0 );
		}
	}

	/* Add 1 to width/height, since we are rounding float down.
	 */
	bounds->left = min_x;
	bounds->top = min_y;
	bounds->width = 1 + max_x - min_x;
	bounds->height = 1 + max_y - min_y;
}

#define LOOKUP( TYPE ) { \
	TYPE * restrict p1 = (TYPE *) p; \
	\
	for( x = 0; x < r->width; x++ ) { \
		TYPE px = p1[0]; \
		TYPE py = p1[1]; \
		\
		if( px < 0 || \
			px >= resample->in->Xsize || \
			py < 0 || \
			py >= resample->in->Ysize ) { \
			for( z = 0; z < ps; z++ )  \
				q[z] = 0; \
		} \
		else \
			interpolate( mapim->interpolate, q, ir[0], \
				px + window_offset, py + window_offset ); \
		\
		p1 += 2; \
		q += ps; \
	} \
}

static int
vips_mapim_gen( VipsRegion *or, void *seq, void *a, void *b, gboolean *stop )
{
	VipsRect *r = &or->valid;
	VipsRegion **ir = (VipsRegion **) seq;
	const VipsImage **in_array = (const VipsImage **) a;
	const VipsMapim *mapim = (VipsMapim *) b; 
	const VipsResample *resample = VIPS_RESAMPLE( mapim );
	const VipsImage *in = in_array[0];
	const int window_size = 
		vips_interpolate_get_window_size( mapim->interpolate );
	const int window_offset = 
		vips_interpolate_get_window_offset( mapim->interpolate );
	const VipsInterpolateMethod interpolate = 
		vips_interpolate_get_method( mapim->interpolate );
	const int ps = VIPS_IMAGE_SIZEOF_PEL( in );

	VipsRect bounds, image, clipped;
	int x, y, z;
	
#ifdef DEBUG_VERBOSE
	printf( "vips_mapim_gen: "
		"generating left=%d, top=%d, width=%d, height=%d\n", 
		r->left,
		r->top,
		r->width,
		r->height );
#endif /*DEBUG_VERBOSE*/

	/* Fetch the chunk of the mapim image we need, and find the max/min in
	 * x and y.
	 */
	if( vips_region_prepare( ir[1], r ) )
		return( -1 );

	VIPS_GATE_START( "vips_mapim_gen: work" ); 

	vips_mapim_region_minmax( ir[1], r, &bounds ); 

	VIPS_GATE_STOP( "vips_mapim_gen: work" ); 

	/* The bounding box of that area is what we will need from @in. Add
	 * enough for the interpolation stencil as well.
	 */
	bounds.width += window_size - 1;
	bounds.height += window_size - 1;

	/* Clip against the source image.
	 */
	image.left = 0;
	image.top = 0;
	image.width = in->Xsize;
	image.height = in->Ysize;
	vips_rect_intersectrect( &bounds, &image, &clipped );

#ifdef DEBUG_VERBOSE
	printf( "vips_mapim_gen: "
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
	if( vips_region_prepare( ir[0], &clipped ) )
		return( -1 );

	VIPS_GATE_START( "vips_mapim_gen: work" ); 

	/* Resample! x/y loop over pixels in the output image (5).
	 */
	for( y = 0; y < r->height; y++ ) {
		VipsPel * restrict p = 
			VIPS_REGION_ADDR( ir[1], r->left, y + r->top );
		VipsPel * restrict q = 
			VIPS_REGION_ADDR( or, r->left, y + r->top );

		switch( ir[1]->im->BandFmt ) {
		case VIPS_FORMAT_UCHAR: 	
			LOOKUP( unsigned char ); break; 
		case VIPS_FORMAT_CHAR: 	
			LOOKUP( signed char ); break; 
		case VIPS_FORMAT_USHORT: 
			LOOKUP( unsigned short ); break; 
		case VIPS_FORMAT_SHORT: 	
			LOOKUP( signed short ); break; 
		case VIPS_FORMAT_UINT: 	
			LOOKUP( unsigned int ); break; 
		case VIPS_FORMAT_INT: 	
			LOOKUP( signed int ); break; 

		case VIPS_FORMAT_FLOAT: 		
		case VIPS_FORMAT_COMPLEX: 
			LOOKUP( float ); break; 
			break;

		case VIPS_FORMAT_DOUBLE:	
		case VIPS_FORMAT_DPCOMPLEX: 
			LOOKUP( double ); break;

		default:
			g_assert( 0 );
		}
	}

	VIPS_GATE_STOP( "vips_mapim_gen: work" ); 

	return( 0 );
}

static int
vips_mapim_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsResample *resample = VIPS_RESAMPLE( object );
	VipsMapim *mapim = (VipsMapim *) object;
	VipsImage **t = (VipsImage **) vips_object_local_array( object, 4 );

	VipsImage *in;
	int window_size;
	int window_offset;

	if( VIPS_OBJECT_CLASS( vips_mapim_parent_class )->build( object ) )
		return( -1 );

	if( vips_check_coding_known( class->nickname, resample->in ) ||
		vips_check_twocomponents( class->nickname, mapim->index ) )
		return( -1 );

	in = resample->in;

	if( vips_image_decode( in, &t[0] ) )
		return( -1 );
	in = t[0];

	/* We can't use vips_object_argument_isset(), since it may have been
	 * set to NULL, see vips_similarity().
	 */
	if( !mapim->interpolate ) {
		VipsInterpolate *interpolate;

		interpolate = vips_interpolate_new( "bilinear" );
		g_object_set( object, 
			"interpolate", interpolate,
			NULL ); 
		g_object_unref( interpolate );

		/* coverity gets confused by this, it thinks
		 * mapim->interpolate may still be null. Assign ourselves,
		 * even though we don't need to.
		 */
		mapim->interpolate = interpolate;
	}

	window_size = vips_interpolate_get_window_size( mapim->interpolate );
	window_offset = 
		vips_interpolate_get_window_offset( mapim->interpolate );

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

	resample->out->Xsize = mapim->index->Xsize;
	resample->out->Ysize = mapim->index->Ysize;

	mapim->in_array[0] = in;
	mapim->in_array[1] = mapim->index;
	mapim->in_array[2] = NULL;
	if( vips_image_generate( resample->out, 
		vips_start_many, vips_mapim_gen, vips_stop_many, 
		mapim->in_array, mapim ) )
		return( -1 );

	return( 0 );
}

static void
vips_mapim_class_init( VipsMapimClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	VIPS_DEBUG_MSG( "vips_mapim_class_init\n" );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "mapim";
	vobject_class->description = _( "resample with an mapim image" );
	vobject_class->build = vips_mapim_build;

	VIPS_ARG_IMAGE( class, "index", 3, 
		_( "Index" ), 
		_( "Index pixels with this" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsMapim, index ) );

	VIPS_ARG_INTERPOLATE( class, "interpolate", 4, 
		_( "Interpolate" ), 
		_( "Interpolate pixels with this" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT, 
		G_STRUCT_OFFSET( VipsMapim, interpolate ) );

}

static void
vips_mapim_init( VipsMapim *mapim )
{
}

/**
 * vips_mapim:
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
 * Coordinates in @index are in pixels, with (0, 0) being the top-left corner 
 * of @in, and with y increasing down the image. Use vips_xyz() to build index
 * images. 
 *
 * @interpolate defaults to bilinear. 
 *
 * This operation does not change xres or yres. The image resolution needs to
 * be updated by the application. 
 *
 * See vips_maplut() for a 1D equivalent of this operation. 
 *
 * See also: vips_xyz(), vips_affine(), vips_resize(), 
 * vips_maplut(), #VipsInterpolate.
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_mapim( VipsImage *in, VipsImage **out, VipsImage *index, ... ) 
{
	va_list ap;
	int result;

	va_start( ap, index );
	result = vips_call_split( "mapim", ap, in, out, index );
	va_end( ap );

	return( result );
}
