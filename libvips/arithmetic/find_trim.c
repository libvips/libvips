/* return the bounding box of the non-border part of the image
 *
 * 26/7/17
 * 	- from a ruby example
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
#include <stdlib.h>
#include <math.h>

#include <vips/vips.h>

typedef struct _VipsFindTrim {
	VipsOperation parent_instance;

	VipsImage *in;
	double threshold;

	int left;
	int top;
	int width;
	int height;

	double *ones;
	double *background;
	int n;
} VipsFindTrim;

typedef VipsOperationClass VipsFindTrimClass;

G_DEFINE_TYPE( VipsFindTrim, vips_find_trim, VIPS_TYPE_OPERATION );

static void
vips_find_trim_finalize( GObject *gobject )
{
	VipsFindTrim *find_trim = (VipsFindTrim *) gobject;

#ifdef DEBUG
	printf( "vips_find_trim_finalize: " );
	vips_object_print_name( VIPS_OBJECT( gobject ) );
	printf( "\n" );
#endif /*DEBUG*/

	VIPS_FREE( find_trim->background ); 
	VIPS_FREE( find_trim->ones ); 

	G_OBJECT_CLASS( vips_find_trim_parent_class )->finalize( gobject );
}

static int
vips_find_trim_build( VipsObject *object )
{
	VipsFindTrim *find_trim = (VipsFindTrim *) object;
	VipsImage **t = (VipsImage **) vips_object_local_array( object, 2 );

	int i;
	double *ones;
	double d;

	if( VIPS_OBJECT_CLASS( vips_find_trim_parent_class )->build( object ) )
		return( -1 );

	if( vips_image_decode( find_trim->in, &t[0] ) )
		return( -1 ); 

	/* Fetch pixel (0, 0) as the background value.
	 */
	if( vips_getpoint( t[0], 
		&find_trim->background, &find_trim->n, 
		0, 0, NULL ) )
		return( -1 );

	/* We want to subtract the bg.
	 */
	if( !(ones = VIPS_ARRAY( find_trim, find_trim->n, double )) )
		return( -1 ); 
	for( i = 0; i < find_trim->n; i++ ) {
		ones[i] = 1.0;
		find_trim->background[i] *= -1;
	}

	/* Smooth, find difference from bg, abs, threshold.
	 */
	if( vips_median( t[0], &t[1], 3, NULL ) ||
		vips_linear( t[1], &t[2], 
			ones, find_trim->background, find_trim->n, NULL ) ||
		vips_abs( t[2], &t[3], NULL ) ||
		vips_more_const1( t[3], &t[4], find_trim->threshold, NULL ) )
		return( -1 ); 

	/* t[5] == column sums, t[6] == row sums. 
	 */
	if( vips_project( t[4], &t[5], &t[6], NULL ) )
		return( -1 );

	/* t[8] == search column sums in from left.
	 */
	if( vips_profile( t[5], &t[7], &t[8], NULL ) ||
		vips_avg( t[8], &d, NULL ) )
		return( -1 );
	find_trim->left = d;
	if( vips_flip( t[5], &t[9], VIPS_DIRECTION_HORIZONTAL, NULL ) ||
		vips_profile( t[9], &t[10], &t[11], NULL ) ||
		vips_avg( t[11], &d, NULL ) )
		return( -1 );
	find_trim->width = (t[5]->Xsize - d) - find_trim->left;

	/* t[8] == search column sums in from left.
	 */
	if( vips_profile( t[6], &t[12], &t[13], NULL ) ||
		vips_avg( t[12], &d, NULL ) )
		return( -1 );
	find_trim->top = d;
	if( vips_flip( t[6], &t[14], VIPS_DIRECTION_VERTICAL, NULL ) ||
		vips_profile( t[14], &t[15], &t[16], NULL ) ||
		vips_avg( t[15], &d, NULL ) )
		return( -1 );
	find_trim->height = (t[6]->Ysize - d) - find_trim->left;

	return( 0 );
}

static void
vips_find_trim_class_init( VipsFindTrimClass *class )
{
	GObjectClass *gobject_class = (GObjectClass *) class;
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsOperationClass *operation_class = VIPS_OPERATION_CLASS( class );

	gobject_class->finalize = vips_find_trim_finalize;
	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "find_trim";
	object_class->description = _( "search an image for non-edge areas" );
	object_class->build = vips_find_trim_build;

	operation_class->flags = VIPS_OPERATION_SEQUENTIAL;

	VIPS_ARG_IMAGE( class, "in", 1,
		_( "in" ), 
		_( "Image to find_trim" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsFindTrim, in ) );

	VIPS_ARG_DOUBLE( class, "threshold", 2, 
		_( "Threshold" ), 
		_( "Object threshold" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsFindTrim, threshold ),
		0, INFINITY, 10.0 );

	VIPS_ARG_INT( class, "left", 5, 
		_( "Left" ), 
		_( "Left edge of image" ),
		VIPS_ARGUMENT_REQUIRED_OUTPUT,
		G_STRUCT_OFFSET( VipsFindTrim, left ),
		1, VIPS_MAX_COORD, 1 );

	VIPS_ARG_INT( class, "top", 11, 
		_( "Top" ), 
		_( "Top edge of extract area" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsFindTrim, top ),
		0, VIPS_MAX_COORD, 0 );

	VIPS_ARG_INT( class, "width", 12, 
		_( "Width" ), 
		_( "Width of extract area" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsFindTrim, width ),
		1, VIPS_MAX_COORD, 1 );

	VIPS_ARG_INT( class, "height", 13, 
		_( "Height" ), 
		_( "Height of extract area" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsFindTrim, height ),
		1, VIPS_MAX_COORD, 1 );

}

static void
vips_find_trim_init( VipsFindTrim *find_trim )
{
	find_trim->threshold = 10;
}

/**
 * vips_find_trim:
 * @in: image to find_trim
 * @left: output left edge
 * @top: output top edge
 * @width: output width
 * @height: output height
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @threshold: background / object threshold
 *
 * See also: vips_extract_area(), vips_smartcrop().
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
