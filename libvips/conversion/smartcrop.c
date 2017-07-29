/* crop an image down to a specified size by removing boring parts
 *
 * Adapted from sharp's smartcrop feature, with kind permission.
 *
 * 1/3/17
 * 	- first version, from sharp
 * 14/3/17
 * 	- revised attention smartcrop
 * 8/6/17
 * 	- revised again
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

/* Calculate sqrt(b1^2 + b2^2 ...)
 */
static int
pythagoras( VipsSmartcrop *smartcrop, VipsImage *in, VipsImage **out )
{
	VipsImage **t = (VipsImage **) 
		vips_object_local_array( VIPS_OBJECT( smartcrop ), 
			2 * in->Bands + 1 );

	int i;

	for( i = 0; i < in->Bands; i++ ) 
		if( vips_extract_band( in, &t[i], i, NULL ) )
			return( -1 );

	for( i = 0; i < in->Bands; i++ ) 
		if( vips_multiply( t[i], t[i], &t[i + in->Bands], NULL ) )
			return( -1 );

	if( vips_sum( &t[in->Bands], &t[2 * in->Bands], in->Bands, NULL ) ||
		vips_pow_const1( t[2 * in->Bands], out, 0.5, NULL ) )
		return( -1 );

	return( 0 );
}

static int
vips_smartcrop_attention( VipsSmartcrop *smartcrop, 
	VipsImage *in, int *left, int *top )
{
	/* From smartcrop.js.
	 */
	static double skin_vector[] = {-0.78, -0.57, -0.44};
	static double ones[] = {1.0, 1.0, 1.0};

	VipsImage **t = (VipsImage **) 
		vips_object_local_array( VIPS_OBJECT( smartcrop ), 24 );

	double hscale;
	double vscale;
	double sigma;
	double max;
	int x_pos;
	int y_pos;

	/* Simple edge detect.
	 */
	if( !(t[21] = vips_image_new_matrixv( 3, 3,
		 0.0, -1.0,  0.0, 
		-1.0,  4.0, -1.0, 
		 0.0, -1.0,  0.0 )) )
		return( -1 );

	/* Convert to XYZ and just use the first three bands.
	 */
	if( vips_colourspace( in, &t[0], VIPS_INTERPRETATION_XYZ, NULL ) ||
		vips_extract_band( t[0], &t[1], 0, "n", 3, NULL ) )
		return( -1 );

	/* Edge detect on Y. 
	 */
	if( vips_extract_band( t[1], &t[2], 1, NULL ) ||
		vips_conv( t[2], &t[3], t[21], 
			"precision", VIPS_PRECISION_INTEGER,
			NULL ) ||
		vips_linear1( t[3], &t[4], 5.0, 0.0, NULL ) ||
		vips_abs( t[4], &t[14], NULL ) )
		return( -1 );

	/* Look for skin colours. Taken from smartcrop.js.
	 */
	if( 
		/* Normalise to magnitude of colour in XYZ.
		 */
		pythagoras( smartcrop, t[1], &t[5] ) ||
		vips_divide( t[1], t[5], &t[6], NULL ) ||

		/* Distance from skin point.
		 */
		vips_linear( t[6], &t[7], ones, skin_vector, 3, NULL ) ||
		pythagoras( smartcrop, t[7], &t[8] ) ||

		/* Rescale to 100 - 0 score.
		 */
		vips_linear1( t[8], &t[9], -100.0, 100.0, NULL ) ||

		/* Ignore dark areas.
		 */
		vips_more_const1( t[2], &t[10], 5.0, NULL ) ||
		!(t[11] = vips_image_new_from_image1( t[10], 0.0 )) ||
		vips_ifthenelse( t[10], t[9], t[11], &t[15], NULL ) )
		return( -1 );

	/* Look for saturated areas.
	 */
	if( vips_colourspace( t[1], &t[12], 
		VIPS_INTERPRETATION_LCH, NULL ) ||
		vips_extract_band( t[12], &t[13], 1, NULL ) ||
		vips_ifthenelse( t[10], t[13], t[11], &t[16], NULL ) )
		return( -1 );

	/* Sum, shrink, blur and find maxpos. 
	 *
	 * The size we shrink to gives the precision with which we can place 
	 * the crop, the amount of blur is related to the size of the crop
	 * area: how large an area we want to consider for the scoring
	 * function.
	 */
	hscale = 32.0 / in->Xsize;
	vscale = 32.0 / in->Ysize;
	sigma = sqrt( pow( smartcrop->width * hscale, 2 ) + 
		pow( smartcrop->height * vscale, 2 ) ) / 10; 
	if( vips_sum( &t[14], &t[17], 3, NULL ) ||
		vips_resize( t[17], &t[18], hscale, 
			"vscale", vscale, 
			"kernel", VIPS_KERNEL_LINEAR, 
			NULL ) ||
		vips_gaussblur( t[18], &t[19], sigma, NULL ) ||
		vips_max( t[19], &max, "x", &x_pos, "y", &y_pos, NULL ) )
		return( -1 ); 

	/* Centre the crop over the max.
	 */
	*left = VIPS_CLIP( 0, 
		x_pos / hscale - smartcrop->width / 2, 
		in->Xsize - smartcrop->width );
	*top = VIPS_CLIP( 0, 
		y_pos / vscale - smartcrop->height / 2, 
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
		left = 0;
		top = 0;
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

		/* Stop a compiler warning.
		 */
		left = 0;
		top = 0;
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
