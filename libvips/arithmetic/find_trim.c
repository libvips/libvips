/* return the bounding box of the non-border part of the image
 *
 * 26/7/17
 * 	- from a ruby example
 * 18/9/17 kleisauke 
 * 	- missing bandor
 * 	- only flatten if there is an alpha
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
#include <glib/gi18n-lib.h>

#include <stdio.h>
#include <stdlib.h>
#include <math.h>

#include <vips/vips.h>

typedef struct _VipsFindTrim {
	VipsOperation parent_instance;

	VipsImage *in;
	double threshold;
	VipsArrayDouble *background;

	int left;
	int top;
	int width;
	int height;
} VipsFindTrim;

typedef VipsOperationClass VipsFindTrimClass;

G_DEFINE_TYPE( VipsFindTrim, vips_find_trim, VIPS_TYPE_OPERATION );

static int
vips_find_trim_build( VipsObject *object )
{
	VipsFindTrim *find_trim = (VipsFindTrim *) object;
	VipsImage **t = (VipsImage **) vips_object_local_array( object, 20 );

	VipsImage *in;
	double *background;
	int n;
	double *neg_bg;
	double *ones;
	int i;
	double left;
	double top;
	double right;
	double bottom;

	if( VIPS_OBJECT_CLASS( vips_find_trim_parent_class )->build( object ) )
		return( -1 );

	/* Is "background" unset? Default to the correct value 
	 * for this interpretation.
	 */
	if( !vips_object_argument_isset( object, "background" ) ) 
		if( find_trim->in->Type == VIPS_INTERPRETATION_GREY16 ||
			find_trim->in->Type == VIPS_INTERPRETATION_RGB16 ) {
			vips_area_unref( VIPS_AREA( find_trim->background ) );
			find_trim->background = 
				vips_array_double_newv( 1, 65535.0 );
		}

	/* Flatten out alpha, if any. 
	 */
	in = find_trim->in;
	if( vips_image_hasalpha( in ) ) {
		if( vips_flatten( in, &t[0], 
			"background", find_trim->background,
			NULL ) )
			return( -1 ); 
		in = t[0];
	}

	/* We want to subtract the bg.
	 */
	background = vips_array_double_get( find_trim->background, &n );
	if( !(neg_bg = VIPS_ARRAY( find_trim, n, double )) ||
		!(ones = VIPS_ARRAY( find_trim, n, double )) )
		return( -1 ); 
	for( i = 0; i < n; i++ ) {
		neg_bg[i] = -1 * background[i];
		ones[i] = 1.0;
	}

	/* Smooth, find difference from bg, abs, threshold.
	 */
	if( vips_median( in, &t[1], 3, NULL ) ||
		vips_linear( t[1], &t[2], ones, neg_bg, n, NULL ) ||
		vips_abs( t[2], &t[3], NULL ) ||
		vips_more_const1( t[3], &t[4], find_trim->threshold, NULL ) ||
		vips_bandor( t[4], &t[5], NULL ) )
		return( -1 ); 
	in = t[5];

	/* t[6] == column sums, t[7] == row sums. 
	 */
	if( vips_project( in, &t[6], &t[7], NULL ) )
		return( -1 );

	/* t[8] == search column sums in from left.
	 */
	if( vips_profile( t[6], &t[8], &t[9], NULL ) ||
		vips_avg( t[9], &left, NULL ) )
		return( -1 );
	if( vips_flip( t[6], &t[10], VIPS_DIRECTION_HORIZONTAL, NULL ) ||
		vips_profile( t[10], &t[11], &t[12], NULL ) ||
		vips_avg( t[12], &right, NULL ) )
		return( -1 );

	/* t[8] == search column sums in from left.
	 */
	if( vips_profile( t[7], &t[13], &t[14], NULL ) ||
		vips_avg( t[13], &top, NULL ) )
		return( -1 );
	if( vips_flip( t[7], &t[15], VIPS_DIRECTION_VERTICAL, NULL ) ||
		vips_profile( t[15], &t[16], &t[17], NULL ) ||
		vips_avg( t[16], &bottom, NULL ) )
		return( -1 );

	g_object_set( find_trim,
		"left", (int) left,
		"top", (int) top,
		"width", (int) VIPS_MAX( 0, (t[6]->Xsize - right) - left ),
		"height", (int) VIPS_MAX( 0, (t[7]->Ysize - bottom) - top ),
		NULL ); 

	return( 0 );
}

static void
vips_find_trim_class_init( VipsFindTrimClass *class )
{
	GObjectClass *gobject_class = (GObjectClass *) class;
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "find_trim";
	object_class->description = _( "search an image for non-edge areas" );
	object_class->build = vips_find_trim_build;

	//operation_class->flags = VIPS_OPERATION_SEQUENTIAL;

	VIPS_ARG_IMAGE( class, "in", 1,
		_( "Input" ), 
		_( "Image to find_trim" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsFindTrim, in ) );

	VIPS_ARG_DOUBLE( class, "threshold", 2, 
		_( "Threshold" ), 
		_( "Object threshold" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsFindTrim, threshold ),
		0, INFINITY, 10.0 );

	VIPS_ARG_BOXED( class, "background", 3, 
		_( "Background" ), 
		_( "Color for background pixels" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsFindTrim, background ),
		VIPS_TYPE_ARRAY_DOUBLE );

	VIPS_ARG_INT( class, "left", 5, 
		_( "Left" ), 
		_( "Left edge of image" ),
		VIPS_ARGUMENT_REQUIRED_OUTPUT,
		G_STRUCT_OFFSET( VipsFindTrim, left ),
		0, VIPS_MAX_COORD, 1 );

	VIPS_ARG_INT( class, "top", 11, 
		_( "Top" ), 
		_( "Top edge of extract area" ),
		VIPS_ARGUMENT_REQUIRED_OUTPUT,
		G_STRUCT_OFFSET( VipsFindTrim, top ),
		0, VIPS_MAX_COORD, 0 );

	VIPS_ARG_INT( class, "width", 12, 
		_( "Width" ), 
		_( "Width of extract area" ),
		VIPS_ARGUMENT_REQUIRED_OUTPUT,
		G_STRUCT_OFFSET( VipsFindTrim, width ),
		0, VIPS_MAX_COORD, 1 );

	VIPS_ARG_INT( class, "height", 13, 
		_( "Height" ), 
		_( "Height of extract area" ),
		VIPS_ARGUMENT_REQUIRED_OUTPUT,
		G_STRUCT_OFFSET( VipsFindTrim, height ),
		0, VIPS_MAX_COORD, 1 );

}

static void
vips_find_trim_init( VipsFindTrim *find_trim )
{
	find_trim->threshold = 10;
	find_trim->background = vips_array_double_newv( 1, 255.0 );
}

/**
 * vips_find_trim: (method)
 * @in: image to find_trim
 * @left: (out): output left edge
 * @top: (out): output top edge
 * @width: (out): output width
 * @height: (out): output height
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @threshold: %gdouble, background / object threshold
 * * @background: #VipsArrayDouble, background colour
 *
 * Search @in for the bounding box of the non-background area. 
 *
 * Any alpha is flattened out, then the image is median-filtered, all the row 
 * and column sums of the absolute
 * difference from @background are calculated in a
 * single pass, then the first row or column in each of the
 * four directions where the sum is greater than @threshold gives the bounding
 * box.
 *
 * If the image is entirely background, vips_find_trim() returns @width == 0
 * and @height == 0.
 *
 * @background defaults to 255, or 65535 for 16-bit images. Set another value, 
 * or use vips_getpoint() to pick a value from an edge. You'll need to flatten
 * before vips_getpoint() to get a correct background value.
 *
 * @threshold defaults to 10. 
 *
 * The image needs to be at least 3x3 pixels in size. 
 *
 * See also: vips_getpoint(), vips_extract_area(), vips_smartcrop().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_find_trim( VipsImage *in, 
	int *left, int *top, int *width, int *height, ... )
{
	va_list ap;
	int result;

	va_start( ap, height );
	result = vips_call_split( "find_trim", ap, in, 
		left, top, width, height );
	va_end( ap );

	return( result );
}
