/* hough transform for lines
 *
 * 7/3/14
 * 	- from hist_find.c
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <string.h>

#include <vips/vips.h>

#include "statistic.h"
#include "hough.h"

typedef struct _VipsHoughLine {
	VipsHough parent_instance;

	/* Size of parameter space. 
	 */
	int width;
	int height;

	/* LUT for this transform.
	 */
	double *sin;

} VipsHoughLine;

typedef VipsHoughClass VipsHoughLineClass;

G_DEFINE_TYPE( VipsHoughLine, vips_hough_line, VIPS_TYPE_HOUGH );

static int
vips_hough_line_build( VipsObject *object )
{
	VipsHoughLine *hough_line = (VipsHoughLine *) object;
	int width = hough_line->width;

	int i;

	if( !(hough_line->sin = VIPS_ARRAY( object, width, double )) )
		return( -1 ); 

	for( i = 0; i < width; i++ )  
		hough_line->sin[i] = sin( 2 * VIPS_PI * i / width );  

	if( VIPS_OBJECT_CLASS( vips_hough_line_parent_class )->build( object ) )
		return( -1 );

	return( 0 );
}

static int
vips_hough_line_init_accumulator( VipsHough *hough, VipsImage *accumulator )
{
	VipsHoughLine *hough_line = (VipsHoughLine *) hough;

	vips_image_init_fields( accumulator,
		hough_line->width, hough_line->height, 1,
		VIPS_FORMAT_UINT, VIPS_CODING_NONE,
		VIPS_INTERPRETATION_MATRIX,
		1.0, 1.0 );

	return( 0 ); 
}

/* Cast votes for all lines passing through x, y.
 */
static void
vips_hough_line_vote( VipsHough *hough, VipsImage *accumulator, int x, int y )
{
	VipsHoughLine *hough_line = (VipsHoughLine *) hough; 
	VipsStatistic *statistic = (VipsStatistic *) hough;  
	double xd = (double) x / statistic->ready->Xsize;
	double yd = (double) y / statistic->ready->Ysize;
	int width = hough_line->width;
	int height = hough_line->height;

	int i;

	for( i = 0; i < width; i++ ) { 
		int i90 = (i + width / 4) % width;
		double r = xd * hough_line->sin[i90] + yd * hough_line->sin[i];
		int ri = height * r;

		if( ri >= 0 && 
			ri < height ) 
			*VIPS_IMAGE_ADDR( accumulator, i, ri ) += 1;
	}
}

static void
vips_hough_line_class_init( VipsHoughClass *class )
{
	GObjectClass *gobject_class = (GObjectClass *) class;
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsHoughClass *hclass = (VipsHoughClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "hough_line";
	object_class->description = _( "find hough line transform" );
	object_class->build = vips_hough_line_build;

	hclass->init_accumulator = vips_hough_line_init_accumulator;
	hclass->vote = vips_hough_line_vote;

	VIPS_ARG_INT( class, "width", 110, 
		_( "Width" ), 
		_( "horizontal size of parameter space" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT, 
		G_STRUCT_OFFSET( VipsHoughLine, width ),
		1, 100000, 256 );

	VIPS_ARG_INT( class, "height", 111, 
		_( "Height" ), 
		_( "Vertical size of parameter space" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT, 
		G_STRUCT_OFFSET( VipsHoughLine, height ),
		1, 100000, 256 );

}

static void
vips_hough_line_init( VipsHoughLine *hough_line )
{
	hough_line->width = 256;
	hough_line->height = 256;
}

/**
 * vips_hough_line:
 * @in: input image
 * @out: output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * @width: horizontal size of parameter space
 * @height: vertical size of parameter space
 *
 * Find the line Hough transform for @in. @in must have one band. @out has one
 * band, with pixels being the number of votes for that line. The X dimension
 * of @out is the line angle, the Y dimension is the distance of the line from
 * the origin. 
 *
 * Use @width @height to set the size of the parameter space image (@out),
 * that is, how accurate the line determination should be. 
 *
 * See also: vips_hough_circle().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_hough_line( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "hough_line", ap, in, out );
	va_end( ap );

	return( result );
}
