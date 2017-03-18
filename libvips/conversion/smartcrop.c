/* crop an image down to a specified size by removing boring parts
 *
 * Copyright: 2017, J. Cupitt
 *
 * Adapted from sharp's smartcrop feature, with kind permission.
 *
 * 1/3/17
 * 	- first version, from sharp
 * 14/3/17
 * 	- revised attention smartcrop
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
#define VIPS_DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <vips/vips.h>
#include <vips/debug.h>

#include "pconversion.h"

#include "bandary.h"

typedef struct _VipsSmartcrop {
	VipsConversion parent_instance;

	VipsImage *in;
	int width;
	int height;
	VipsInteresting interesting;

} VipsSmartcrop;

typedef VipsConversionClass VipsSmartcropClass;

G_DEFINE_TYPE( VipsSmartcrop, vips_smartcrop, VIPS_TYPE_CONVERSION );

static int
vips_smartcrop_score( VipsSmartcrop *smartcrop, VipsImage *in, 
	int left, int top, int width, int height, double *score )
{
	VipsImage **t = (VipsImage **) 
		vips_object_local_array( VIPS_OBJECT( smartcrop ), 2 );

	if( vips_extract_area( in, &t[0], left, top, width, height, NULL ) ||
		vips_hist_find( t[0], &t[1], NULL ) ||
		vips_hist_entropy( t[1], score, NULL ) )
		return( -1 );

	return( 0 );
}

/* Entropy-style smartcrop. Repeatedly discard low interest areas. This should
 * be faster for very large images. 
 */
static int
vips_smartcrop_entropy( VipsSmartcrop *smartcrop, 
	VipsImage *in, int *left, int *top )
{
	int max_slice_size;
	int width;
	int height;

	*left = 0;
	*top = 0;
	width = in->Xsize;
	height = in->Ysize;

	/* How much do we trim by each iteration? Aim for 8 steps in the axis
	 * that needs trimming most.
	 */
	max_slice_size = VIPS_MAX( 
		ceil( (width - smartcrop->width) / 8.0 ),
		ceil( (height - smartcrop->height) / 8.0 ) );

	/* Repeatedly take a slice off width and height until we 
	 * reach the target.
	 */
	while( width > smartcrop->width || 
		height > smartcrop->height ) {
		const int slice_width = 
			VIPS_MIN( width - smartcrop->width, max_slice_size );
		const int slice_height = 
			VIPS_MIN( height - smartcrop->height, max_slice_size );

		if( slice_width > 0 ) { 
			double left_score;
			double right_score;

			if( vips_smartcrop_score( smartcrop, in, 
				*left, *top, slice_width, height, &left_score ) )
				return( -1 );

			if( vips_smartcrop_score( smartcrop, in, 
				*left + width - slice_width, *top, 
				slice_width, height, &right_score ) )
				return( -1 ); 

			width -= slice_width;
			if( left_score < right_score ) 
				*left += slice_width;
		}

		if( slice_height > 0 ) { 
			double top_score;
			double bottom_score;

			if( vips_smartcrop_score( smartcrop, in, 
				*left, *top, width, slice_height, &top_score ) )
				return( -1 );

			if( vips_smartcrop_score( smartcrop, in, 
				*left, *top + height - slice_height, 
				width, slice_height, &bottom_score ) )
				return( -1 ); 

			height -= slice_height;
			if( top_score < bottom_score ) 
				*top += slice_height;
		}
	}

	return( 0 );
}

static int
vips_smartcrop_attention( VipsSmartcrop *smartcrop, 
	VipsImage *in, int *left, int *top )
{
	/* ab ranges for skin colours. Trained with http://humanae.tumblr.com/
	 */
	static double ab_low[2] = { 3.0, 4.0 }; 
	static double ab_high[2] = { 22.0, 31.0 }; 

	VipsImage **t = (VipsImage **) 
		vips_object_local_array( VIPS_OBJECT( smartcrop ), 24 );

	double hshrink;
	double vshrink;
	double sigma;
	double max;
	int x_pos;
	int y_pos;

	if( !(t[21] = vips_image_new_matrixv( 3, 3,
		-1.0, 0.0, 1.0, -2.0, 0.0, 2.0, -1.0, 0.0, 1.0 )) )
		return( -1 );
	if( vips_rot( t[21], &t[22], VIPS_ANGLE_D90, NULL ) )
		return( -1 ); 

	/* Convert to LAB and just use the first three bands.
	 */
	if( vips_colourspace( in, &t[0], VIPS_INTERPRETATION_LAB, NULL ) ||
		vips_extract_band( t[0], &t[1], 0, "n", 3, NULL ) )
		return( -1 );

	/* Sobel edge-detect on L.
	 */
	if( vips_extract_band( t[1], &t[2], 0, NULL ) ||
		vips_conv( t[2], &t[3], t[21], NULL ) ||
		vips_conv( t[2], &t[4], t[22], NULL ) ||
		vips_abs( t[3], &t[5], NULL ) ||
		vips_abs( t[4], &t[6], NULL ) ||
		vips_add( t[5], t[6], &t[7], NULL ) )
		return( -1 );

	/* Look for skin colours, plus L > 15.
	 */
	if( vips_extract_band( t[1], &t[8], 1, "n", 2, NULL ) ||
		vips_moreeq_const( t[8], &t[9], ab_low, 2, NULL ) ||
		vips_lesseq_const( t[8], &t[10], ab_high, 2, NULL ) ||
		vips_andimage( t[9], t[10], &t[11], NULL ) ||
		vips_bandand( t[11], &t[12], NULL ) ||
		vips_moreeq_const1( t[2], &t[18], 15.0, NULL ) ||
		vips_andimage( t[12], t[18], &t[19], NULL ) )
		return( -1 ); 

	/* Look for saturated areas.
	 */
	if( vips_colourspace( t[1], &t[13], 
		VIPS_INTERPRETATION_LCH, NULL ) ||
		vips_extract_band( t[13], &t[14], 1, NULL ) ||
		vips_more_const1( t[14], &t[15], 60.0, NULL ) )
		return( -1 );

	/* Sum, shrink, blur and find maxpos. 
	 *
	 * The size we shrink to gives the precision with which we can place 
	 * the crop, the amount of blur is related to the size of the crop
	 * area: how large an area we want to consider for the scoring
	 * function.
	 */
	hshrink = in->Xsize / 32.0;
	vshrink = in->Ysize / 32.0;
	sigma = sqrt( pow( smartcrop->width / hshrink, 2 ) + 
			pow( smartcrop->height / vshrink, 2 ) ) / 6; 
	if( vips_add( t[7], t[19], &t[16], NULL ) ||
		vips_add( t[16], t[15], &t[17], NULL ) ||
		vips_shrink( t[17], &t[20], hshrink, vshrink, NULL ) ||
		vips_gaussblur( t[20], &t[23], sigma, NULL ) ||
		vips_max( t[23], &max, "x", &x_pos, "y", &y_pos, NULL ) )
		return( -1 ); 

	/* Centre the crop over the max.
	 */
	*left = VIPS_CLIP( 0, 
		hshrink * x_pos - smartcrop->width / 2, 
		in->Xsize - smartcrop->width );
	*top = VIPS_CLIP( 0, 
		vshrink * y_pos - smartcrop->height / 2, 
		in->Ysize - smartcrop->height ); 

	return( 0 ); 
}

static int
vips_smartcrop_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsConversion *conversion = VIPS_CONVERSION( object );
	VipsSmartcrop *smartcrop = (VipsSmartcrop *) object;
	VipsImage **t = (VipsImage **) vips_object_local_array( object, 2 );

	VipsImage *in;
	int left;
	int top;

	if( VIPS_OBJECT_CLASS( vips_smartcrop_parent_class )->
		build( object ) )
		return( -1 );

	if( smartcrop->width > smartcrop->in->Xsize ||
		smartcrop->height > smartcrop->in->Ysize ||
		smartcrop->width <= 0 || smartcrop->height <= 0 ) {
		vips_error( class->nickname, "%s", _( "bad extract area" ) );
		return( -1 );
	}

	in = smartcrop->in;

	/* If there's an alpha, we have to premultiply before searching for
	 * content. There could be stuff in transparent areas which we don't
	 * want to consider. 
	 */
	if( vips_image_hasalpha( in ) ) { 
		if( vips_premultiply( in, &t[0], NULL ) ) 
			return( -1 );
		in = t[0];
	}

	switch( smartcrop->interesting ) {
	case VIPS_INTERESTING_NONE:
		break;

	case VIPS_INTERESTING_CENTRE:
		left = (smartcrop->in->Xsize - smartcrop->width) / 2;
		top = (smartcrop->in->Ysize - smartcrop->height) / 2;
		break;

	case VIPS_INTERESTING_ENTROPY:
		if( vips_smartcrop_entropy( smartcrop, in, &left, &top ) )
			return( -1 );
		break;

	case VIPS_INTERESTING_ATTENTION:
		if( vips_smartcrop_attention( smartcrop, in, &left, &top ) )
			return( -1 );
		break;

	default:
		g_assert_not_reached();
		break;
	}

	if( vips_extract_area( smartcrop->in, &t[1], 
			left, top, smartcrop->width, smartcrop->height, NULL ) ||
		vips_image_write( t[1], conversion->out ) )
		return( -1 ); 

	return( 0 );
}

static void
vips_smartcrop_class_init( VipsSmartcropClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	VIPS_DEBUG_MSG( "vips_smartcrop_class_init\n" );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "smartcrop";
	vobject_class->description = _( "extract an area from an image" );
	vobject_class->build = vips_smartcrop_build;

	VIPS_ARG_IMAGE( class, "input", 0, 
		_( "Input" ), 
		_( "Input image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsSmartcrop, in ) );

	VIPS_ARG_INT( class, "width", 4, 
		_( "Width" ), 
		_( "Width of extract area" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsSmartcrop, width ),
		1, VIPS_MAX_COORD, 1 );

	VIPS_ARG_INT( class, "height", 5, 
		_( "Height" ), 
		_( "Height of extract area" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsSmartcrop, height ),
		1, VIPS_MAX_COORD, 1 );

	VIPS_ARG_ENUM( class, "interesting", 6, 
		_( "Interesting" ), 
		_( "How to measure interestingness" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsSmartcrop, interesting ),
		VIPS_TYPE_INTERESTING, VIPS_INTERESTING_ATTENTION );

}

static void
vips_smartcrop_init( VipsSmartcrop *smartcrop )
{
	smartcrop->interesting = VIPS_INTERESTING_ATTENTION;
}

/**
 * vips_smartcrop:
 * @in: input image
 * @out: output image
 * @width: width of area to extract
 * @height: height of area to extract
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @interesting: #VipsInteresting to use to find interesting areas (default: #VIPS_INTERESTING_ATTENTION)
 *
 * Crop an image down to a specified width and height by removing boring parts. 
 *
 * Use @interesting to pick the method vips uses to decide which bits of the
 * image should be kept. 
 *
 * You can test xoffset / yoffset on @out to find the location of the crop
 * within the input image. 
 *
 * See also: vips_extract_area().
 * 
 * Returns: 0 on success, -1 on error.
 */
int
vips_smartcrop( VipsImage *in, VipsImage **out, int width, int height, ... )
{
	va_list ap;
	int result;

	va_start( ap, height );
	result = vips_call_split( "smartcrop", ap, in, out, width, height );
	va_end( ap );

	return( result );
}
