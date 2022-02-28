/* resample with an index image
 *
 * 15/11/15
 * 	- from affine.c
 * 12/8/18
 * 	- prevent float->int overflow
 * 	- a bit quicker
 * 17/12/18
 * 	- we were not offsetting pixel fetches by window_offset
 * 30/1/21 afontenot
 * 	- avoid NaN
 * 21/12/21
 * 	- improve edge antialiasing with "background" and "extend"
 * 	- add "premultiplied" param
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

typedef struct _VipsMapim {
	VipsResample parent_instance;

	VipsImage *index;
	VipsInterpolate *interpolate;

	/* How to generate extra edge pixels.
	 */
	VipsExtend extend;

	/* Background colour.
	 */
	VipsArrayDouble *background;

	/* The [double] converted to the input image format.
	 */
	VipsPel *ink;

	/* True if the input is already premultiplied (and we don't need to).
	 */
	gboolean premultiplied;

	/* Need an image vector for start_many / stop_many
	 */
	VipsImage *in_array[3];

} VipsMapim;

typedef VipsResampleClass VipsMapimClass;

G_DEFINE_TYPE( VipsMapim, vips_mapim, VIPS_TYPE_RESAMPLE );

/* Minmax of a line of pixels. 
 */
#define MINMAX( TYPE ) { \
	TYPE * restrict p1 = (TYPE *) p; \
	\
	TYPE t_max_x = max_x; \
	TYPE t_min_x = min_x; \
	TYPE t_max_y = max_y; \
	TYPE t_min_y = min_y; \
	\
	for( x = 0; x < r->width; x++ ) { \
		TYPE px = p1[0]; \
		TYPE py = p1[1]; \
		\
		if( first ) { \
			t_min_x = px; \
			t_max_x = px; \
			t_min_y = py; \
			t_max_y = py; \
			\
			first = FALSE; \
		} \
		else { \
			if( px > t_max_x ) \
				t_max_x = px; \
			else if( px < t_min_x ) \
				t_min_x = px; \
			\
			if( py > t_max_y ) \
				t_max_y = py; \
			else if( py < t_min_y ) \
				t_min_y = py; \
		} \
		\
		p1 += 2; \
	} \
	\
	min_x = t_min_x; \
	max_x = t_max_x; \
	min_y = t_min_y; \
	max_y = t_max_y; \
}

/* Scan a region and find min/max in the two axes.
 */
static void
vips_mapim_region_minmax( VipsRegion *region, VipsRect *r, VipsRect *bounds )
{
	double min_x;
	double max_x;
	double min_y;
	double max_y;
	gboolean first;
	int x, y;

	min_x = 0.0;
	max_x = 0.0;
	min_y = 0.0;
	max_y = 0.0;
	first = TRUE;
	for( y = 0; y < r->height; y++ ) {
		VipsPel * restrict p = 
			VIPS_REGION_ADDR( region, r->left, r->top + y );

		switch( region->im->BandFmt ) {
		case VIPS_FORMAT_UCHAR: 	
			MINMAX( unsigned char );
			break; 

		case VIPS_FORMAT_CHAR: 	
			MINMAX( signed char );
			break; 

		case VIPS_FORMAT_USHORT: 
			MINMAX( unsigned short );
			break; 

		case VIPS_FORMAT_SHORT: 	
			MINMAX( signed short );
			break; 

		case VIPS_FORMAT_UINT: 	
			MINMAX( unsigned int );
			break; 

		case VIPS_FORMAT_INT: 	
			MINMAX( signed int );
			break; 

		case VIPS_FORMAT_FLOAT: 		
		case VIPS_FORMAT_COMPLEX: 
			MINMAX( float );
			break; 

		case VIPS_FORMAT_DOUBLE:	
		case VIPS_FORMAT_DPCOMPLEX: 
			MINMAX( double );
			break;

		default:
			g_assert_not_reached();
		}
	}

	/* bounds is the bounding box -- we must round left/top down and round
	 * bottom/right up.
	 */
	min_x = floor( min_x );
	min_y = floor( min_y );
	max_x = ceil( max_x );
	max_y = ceil( max_y );

	/* bounds uses ints, so we must clip the range down from double.
	 * Coordinates can be negative for the antialias edges.
	 */
	min_x = VIPS_CLIP( -1, min_x, VIPS_MAX_COORD );
	min_y = VIPS_CLIP( -1, min_y, VIPS_MAX_COORD );
	max_x = VIPS_CLIP( -1, max_x, VIPS_MAX_COORD );
	max_y = VIPS_CLIP( -1, max_y, VIPS_MAX_COORD );

	bounds->left = min_x;
	bounds->top = min_y;
	bounds->width = (max_x - min_x) + 1;
	bounds->height = (max_y - min_y) + 1;
}

/* Unsigned int types.
 */
#define ULOOKUP( TYPE ) { \
	TYPE * restrict p1 = (TYPE *) p; \
	\
	for( x = 0; x < r->width; x++ ) { \
		TYPE px = p1[0]; \
		TYPE py = p1[1]; \
		\
		if( px >= clip_width || \
			py >= clip_height ) { \
			for( z = 0; z < ps; z++ )  \
				q[z] = mapim->ink[z]; \
		} \
		else \
			interpolate( mapim->interpolate, q, ir[0], \
				px + window_offset + 1, \
				py + window_offset + 1 ); \
		\
		p1 += 2; \
		q += ps; \
	} \
}

/* Signed int types. We allow -1 for x/y to get edge antialiasing.
 */
#define LOOKUP( TYPE ) { \
	TYPE * restrict p1 = (TYPE *) p; \
	\
	for( x = 0; x < r->width; x++ ) { \
		TYPE px = p1[0]; \
		TYPE py = p1[1]; \
		\
		if( px < -1 || \
			px >= clip_width || \
			py < -1 || \
			py >= clip_height ) { \
			for( z = 0; z < ps; z++ )  \
				q[z] = mapim->ink[z]; \
		} \
		else \
			interpolate( mapim->interpolate, q, ir[0], \
				px + window_offset + 1, \
				py + window_offset + 1 ); \
		\
		p1 += 2; \
		q += ps; \
	} \
}

/* Float types. We allow -1 for x/y to get edge antialiasing.
 */
#define FLOOKUP( TYPE ) { \
	TYPE * restrict p1 = (TYPE *) p; \
	\
	for( x = 0; x < r->width; x++ ) { \
		TYPE px = p1[0]; \
		TYPE py = p1[1]; \
		\
		if( VIPS_ISNAN( px ) || \
			VIPS_ISNAN( py ) || \
			px < -1 || \
			px >= clip_width || \
			py < -1 || \
			py >= clip_height ) { \
			for( z = 0; z < ps; z++ ) \
				q[z] = mapim->ink[z]; \
		} \
		else \
			interpolate( mapim->interpolate, q, ir[0], \
				px + window_offset + 1, \
				py + window_offset + 1 ); \
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
	const VipsImage *in = in_array[0];
	const int window_size = 
		vips_interpolate_get_window_size( mapim->interpolate );
	const int window_offset = 
		vips_interpolate_get_window_offset( mapim->interpolate );
	const VipsInterpolateMethod interpolate = 
		vips_interpolate_get_method( mapim->interpolate );
	const int ps = VIPS_IMAGE_SIZEOF_PEL( in );
	const int clip_width = in->Xsize - window_size;
	const int clip_height = in->Ysize - window_size;

	VipsRect bounds, need, image, clipped;
	int x, y, z;
	
#ifdef DEBUG_VERBOSE
	printf( "vips_mapim_gen: "
		"generating left=%d, top=%d, width=%d, height=%d\n", 
		r->left,
		r->top,
		r->width,
		r->height );
#endif /*DEBUG_VERBOSE*/

	/* Fetch the chunk of the index image we need, and find the max/min in
	 * x and y.
	 */
	if( vips_region_prepare( ir[1], r ) )
		return( -1 );

	VIPS_GATE_START( "vips_mapim_gen: work" ); 

	vips_mapim_region_minmax( ir[1], r, &bounds ); 

	VIPS_GATE_STOP( "vips_mapim_gen: work" ); 

	/* Enlarge by the stencil size.
	 */
	need.width = bounds.width + window_size - 1;
	need.height = bounds.height + window_size - 1;

	/* Offset for the antialias edge we have top and left.
	 */
	need.left = bounds.left + 1;
	need.top = bounds.top + 1;

	/* Clip against the expanded image.
	 */
	image.left = 0;
	image.top = 0;
	image.width = in->Xsize;
	image.height = in->Ysize;
	vips_rect_intersectrect( &need, &image, &clipped );

#ifdef DEBUG_VERBOSE
	printf( "vips_mapim_gen: "
		"preparing left=%d, top=%d, width=%d, height=%d\n", 
		clipped.left,
		clipped.top,
		clipped.width,
		clipped.height );
#endif /*DEBUG_VERBOSE*/

	if( vips_rect_isempty( &clipped ) ) {
		vips_region_paint_pel( or, r, mapim->ink );
		return( 0 );
	}
	if( vips_region_prepare( ir[0], &clipped ) )
		return( -1 );

	VIPS_GATE_START( "vips_mapim_gen: work" ); 

	/* Resample! x/y loop over pixels in the output (and index) images.
	 */
	for( y = 0; y < r->height; y++ ) {
		VipsPel * restrict p = 
			VIPS_REGION_ADDR( ir[1], r->left, y + r->top );
		VipsPel * restrict q = 
			VIPS_REGION_ADDR( or, r->left, y + r->top );

		switch( ir[1]->im->BandFmt ) {
		case VIPS_FORMAT_UCHAR: 	
			ULOOKUP( unsigned char ); break; 
		case VIPS_FORMAT_CHAR: 	
			LOOKUP( signed char ); break; 
		case VIPS_FORMAT_USHORT: 
			ULOOKUP( unsigned short ); break; 
		case VIPS_FORMAT_SHORT: 	
			LOOKUP( signed short ); break; 
		case VIPS_FORMAT_UINT: 	
			ULOOKUP( unsigned int ); break; 
		case VIPS_FORMAT_INT: 	
			LOOKUP( signed int ); break; 
		case VIPS_FORMAT_FLOAT: 		
		case VIPS_FORMAT_COMPLEX: 
			FLOOKUP( float ); break; 
		case VIPS_FORMAT_DOUBLE:	
		case VIPS_FORMAT_DPCOMPLEX: 
			FLOOKUP( double ); break;

		default:
			g_assert_not_reached();
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
	VipsImage **t = (VipsImage **) vips_object_local_array( object, 6 );

	VipsImage *in;
	int window_size;
	int window_offset;

	/* TRUE if we've premultiplied and need to unpremultiply.
	 */
	gboolean have_premultiplied;
	VipsBandFormat unpremultiplied_format;

	if( VIPS_OBJECT_CLASS( vips_mapim_parent_class )->build( object ) )
		return( -1 );

	if( vips_check_coding_known( class->nickname, resample->in ) ||
		vips_check_twocomponents( class->nickname, mapim->index ) )
		return( -1 );

	in = resample->in;

	if( vips_image_decode( in, &t[0] ) )
		return( -1 );
	in = t[0];

	window_size = vips_interpolate_get_window_size( mapim->interpolate );
	window_offset = 
		vips_interpolate_get_window_offset( mapim->interpolate );

	/* Add new pixels around the input so we can interpolate at the edges.
	 *
	 * We add the interpolate stencil, plus one extra pixel on all the
	 * edges. This means when we clip in generate (above) we can be sure 
	 * we clip outside the real pixels and don't get jaggies on edges.
	 *
	 * We allow for the +1 in the adjustment to window_offset in generate.
	 */
	if( vips_embed( in, &t[1], 
		window_offset + 1, window_offset + 1, 
		in->Xsize + window_size - 1 + 2, 
		in->Ysize + window_size - 1 + 2,
		"extend", mapim->extend,
		"background", mapim->background,
		NULL ) )
		return( -1 );
	in = t[1];

	/* If there's an alpha and we've not premultiplied, we have to 
	 * premultiply before resampling. 
	 */
	have_premultiplied = FALSE;
	if( vips_image_hasalpha( in ) &&
		!mapim->premultiplied ) { 
		if( vips_premultiply( in, &t[2], NULL ) ) 
			return( -1 );
		have_premultiplied = TRUE;

		/* vips_premultiply() makes a float image. When we
		 * vips_unpremultiply() below, we need to cast back to the
		 * pre-premultiply format.
		 */
		unpremultiplied_format = in->BandFmt;
		in = t[2];
	}

	/* Convert the background to the image's format.
	 */
	if( !(mapim->ink = vips__vector_to_ink( class->nickname, 
		in,
		VIPS_AREA( mapim->background )->data, NULL, 
		VIPS_AREA( mapim->background )->n )) )
		return( -1 );

	t[3] = vips_image_new();
	if( vips_image_pipelinev( t[3], VIPS_DEMAND_STYLE_SMALLTILE, 
		in, NULL ) )
		return( -1 );

	t[3]->Xsize = mapim->index->Xsize;
	t[3]->Ysize = mapim->index->Ysize;

	mapim->in_array[0] = in;
	mapim->in_array[1] = mapim->index;
	mapim->in_array[2] = NULL;
	if( vips_image_generate( t[3], 
		vips_start_many, vips_mapim_gen, vips_stop_many, 
		mapim->in_array, mapim ) )
		return( -1 );

	in = t[3];

	if( have_premultiplied ) {
		if( vips_unpremultiply( in, &t[4], NULL ) || 
			vips_cast( t[4], &t[5], unpremultiplied_format, NULL ) )
			return( -1 );
		in = t[5];
	}

	if( vips_image_write( in, resample->out ) )
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
	vobject_class->description = _( "resample with a map image" );
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

	VIPS_ARG_ENUM( class, "extend", 117, 
		_( "Extend" ), 
		_( "How to generate the extra pixels" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsMapim, extend ),
		VIPS_TYPE_EXTEND, VIPS_EXTEND_BACKGROUND );

	VIPS_ARG_BOXED( class, "background", 116, 
		_( "Background" ), 
		_( "Background value" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsMapim, background ),
		VIPS_TYPE_ARRAY_DOUBLE );

	VIPS_ARG_BOOL( class, "premultiplied", 117,
		_( "Premultiplied" ),
		_( "Images have premultiplied alpha" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsMapim, premultiplied ),
		FALSE );

}

static void
vips_mapim_init( VipsMapim *mapim )
{
	mapim->interpolate = vips_interpolate_new( "bilinear" );
	mapim->extend = VIPS_EXTEND_BACKGROUND;
	mapim->background = vips_array_double_newv( 1, 0.0 );
}

/**
 * vips_mapim: (method)
 * @in: input image
 * @out: (out): output image
 * @index: index image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @interpolate: interpolate pixels with this
 * * @extend: #VipsExtend how to generate new pixels 
 * * @background: #VipsArrayDouble colour for new pixels 
 * * @premultiplied: %gboolean, images are already premultiplied
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
 * of @in, and with y increasing down the image. Use vips_xyz() to build index
 * images. 
 *
 * @interpolate defaults to bilinear. 
 *
 * By default, new pixels are filled with @background. This defaults to 
 * zero (black). You can set other extend types with @extend. #VIPS_EXTEND_COPY 
 * is better for image upsizing.
 *
 * Image are normally treated as unpremultiplied, so this operation can be used
 * directly on PNG images. If your images have been through vips_premultiply(),
 * set @premultiplied. 
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
