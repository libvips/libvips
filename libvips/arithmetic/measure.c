/* im_measure.c
 *
 * Modified: 
 * 19/8/94 JC
 *	- now uses doubles for addressing
 *	- could miss by up to h pixels previously!
 *	- ANSIfied
 *	- now issues warning if any deviations are greater than 20% of the
 *	  mean
 * 31/10/95 JC
 *	- more careful about warning for averages <0, or averages near zero
 *	- can get these cases with im_measure() of IM_TYPE_LAB images
 * 28/10/02 JC
 *	- number bands from zero in error messages
 * 7/7/04
 *	- works on labq
 * 18/8/08
 * 	- add gtkdoc comments
 * 	- remove deprecated im_extract()
 * 30/11/09
 * 	- changes for im_extract() broke averaging
 * 9/11/11
 * 	- redo as a class
 * 19/5/14
 * 	- add auto-unpack
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
#include <vips/internal.h>

#include "statistic.h"

typedef struct _VipsMeasure {
	VipsOperation parent_instance;

	VipsImage *in;
	VipsImage *out;
	int left;
	int top;
	int width;
	int height;
	int h;
	int v;
} VipsMeasure;

typedef VipsOperationClass VipsMeasureClass;

G_DEFINE_TYPE( VipsMeasure, vips_measure, VIPS_TYPE_OPERATION );

static int
vips_measure_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsMeasure *measure = (VipsMeasure *) object;

	VipsImage *ready;
	int bands;
	double pw;
	double ph;
	int j, i;
	int w, h;
	int b;

	if( VIPS_OBJECT_CLASS( vips_measure_parent_class )->build( object ) )
		return( -1 );

	/* We can't use vips_image_decode(), we want Lab, not LabS.
	 */
	if( measure->in->Coding == VIPS_CODING_LABQ ) {
		if( vips_LabQ2Lab( measure->in, &ready, NULL ) )
			return( -1 );
	} 
	else if( measure->in->Coding == VIPS_CODING_RAD ) {
		if( vips_rad2float( measure->in, &ready, NULL ) )
			return( -1 );
	}
	else {
		if( vips_copy( measure->in, &ready, NULL ) )
			return( -1 );
	}
	vips_object_local( measure, ready ); 

	bands = vips_image_get_bands( ready );

	g_object_set( object, 
		"out", vips_image_new_matrix( bands, measure->h * measure->v ),
		NULL );

	/* left/top/width/height default to the size of the image.
	 */
	if( !vips_object_argument_isset( object, "width" ) )
		g_object_set( object, 
			"width", vips_image_get_width( ready ),
			NULL );
	if( !vips_object_argument_isset( object, "height" ) )
		g_object_set( object, 
			"height", vips_image_get_height( ready ),
			NULL );

	/* How large are the patches we are to measure?
	 */
	pw = (double) measure->width / measure->h;
	ph = (double) measure->height / measure->v;

	/* The size of a patch.
	 */
	w = (pw + 1) / 2;
	h = (ph + 1) / 2;

	for( j = 0; j < measure->v; j++ ) {
		for( i = 0; i < measure->h; i++ ) {
			int x = measure->left + i * pw + (pw + 2) / 4;
			int y = measure->top + j * ph + (ph + 2) / 4;

			double avg, dev;

			for( b = 0; b < bands; b++ ) {
				VipsImage **t = (VipsImage **) 
					vips_object_local_array( object, 2 );

				/* Extract and measure.
				 */
				if( vips_extract_area( ready, &t[0], 
						x, y, w, h, NULL ) ||
					vips_extract_band( t[0], &t[1], 
						b, NULL ) ||
					vips_avg( t[1], &avg, NULL ) ||
					vips_deviate( t[1], &dev, NULL ) ) 
					return( -1 );

				/* Is the deviation large compared with the 
				 * average? This could be a clue that our 
				 * parameters have caused us to miss the 
				 * patch. Look out for averages <0, or 
				 * averages near zero (can get these if use
				 * measure on IM_TYPE_LAB images).
				 */
				if( dev * 5 > fabs( avg ) && fabs( avg ) > 3 )
					vips_warn( class->nickname,
						_( "patch %d x %d, band %d: " 
						   "avg = %g, sdev = %g" ), 
						i, j, b, avg, dev );

				*VIPS_MATRIX( measure->out, 
					b, i + j * measure->h ) = avg;
			}
		}
	}

	return( 0 );
}

/* xy range we sanity check on ... just to stop crazy numbers from 1/0 etc.
 * causing g_assert() failures later.
 */
#define RANGE (100000000)

static void
vips_measure_class_init( VipsMeasureClass *class )
{
	GObjectClass *gobject_class = (GObjectClass *) class;
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "measure";
	object_class->description = 
		_( "measure a set of patches on a color chart" );
	object_class->build = vips_measure_build;

	VIPS_ARG_IMAGE( class, "in", 1,
		_( "in" ), 
		_( "Image to measure" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsMeasure, in ) );

	VIPS_ARG_IMAGE( class, "out", 2, 
		_( "Output" ), 
		_( "Output array of statistics" ),
		VIPS_ARGUMENT_REQUIRED_OUTPUT, 
		G_STRUCT_OFFSET( VipsMeasure, out ) );

	VIPS_ARG_INT( class, "h", 5, 
		_( "Across" ), 
		_( "Number of patches across chart" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsMeasure, h ),
		1, RANGE, 1 );

	VIPS_ARG_INT( class, "v", 6, 
		_( "Down" ), 
		_( "Number of patches down chart" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsMeasure, v ),
		1, RANGE, 1 );

	VIPS_ARG_INT( class, "left", 10, 
		_( "Left" ), 
		_( "Left edge of extract area" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsMeasure, left ),
		0, RANGE, 0 );

	VIPS_ARG_INT( class, "top", 11, 
		_( "Top" ), 
		_( "Top edge of extract area" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsMeasure, top ),
		0, RANGE, 0 );

	VIPS_ARG_INT( class, "width", 12, 
		_( "Width" ), 
		_( "Width of extract area" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsMeasure, width ),
		1, RANGE, 1 );

	VIPS_ARG_INT( class, "height", 13, 
		_( "Height" ), 
		_( "Height of extract area" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsMeasure, height ),
		1, RANGE, 1 );

}

static void
vips_measure_init( VipsMeasure *measure )
{
}

/**
 * vips_measure:
 * @im: image to measure
 * @out: array of measurements
 * @h: patches across chart
 * @v: patches down chart
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * @left: area of image containing chart
 * @top: area of image containing chart
 * @width: area of image containing chart
 * @height: area of image containing chart
 *
 * Analyse a grid of colour patches, producing an array of patch averages.
 * The mask has a row for each measured patch and a column for each image
 * band. The operations issues a warning if any patch has a deviation more 
 * than 20% of
 * the mean. Only the central 50% of each patch is averaged. 
 *
 * If the chart does not fill the whole image, use the optional @left, @top, 
 * @width, @height arguments to indicate the
 * position of the chart.
 *
 * See also: vips_avg(), vips_deviate().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_measure( VipsImage *in, VipsImage **out, int h, int v, ... )
{
	va_list ap;
	int result;

	va_start( ap, v );
	result = vips_call_split( "measure", ap, in, out, h, v );
	va_end( ap );

	return( result );
}
