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

	/* LUT for this transform.
	 */
	double *sin;

} VipsHoughLine;

typedef VipsHoughClass VipsHoughLineClass;

G_DEFINE_TYPE( VipsHoughLine, vips_hough_line, VIPS_TYPE_HOUGH );

static int
vips_hough_line_build( VipsObject *object )
{
	VipsHough *hough = (VipsHough *) object;
	VipsHoughLine *hough_line = (VipsHoughLine *) object;

	int i;

	if( !(hough_line->sin = VIPS_ARRAY( object, hough->width, double )) )
		return( -1 ); 

	for( i = 0; i < hough->width; i++ )  
		hough_line->sin[i] = sin( 2 * VIPS_PI * i / hough->width );  

	if( VIPS_OBJECT_CLASS( vips_hough_line_parent_class )->build( object ) )
		return( -1 );

	return( 0 );
}

static int
vips_hough_line_init_accumulator( VipsHough *hough, VipsImage *accumulator )
{
	vips_image_init_fields( accumulator,
		hough->width, hough->height, 1,
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

	int i;

	for( i = 0; i < hough->width; i++ ) { 
		int i90 = (i + hough->width / 4) % hough->width;
		double r = xd * hough_line->sin[i90] + yd * hough_line->sin[i];
		int ri = hough->height * r;

		if( ri >= 0 && 
			ri < hough->height ) 
			*VIPS_IMAGE_ADDR( accumulator, i, ri ) += 1;
	}
}

static void
vips_hough_line_class_init( VipsHoughClass *class )
{
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsHoughClass *hclass = (VipsHoughClass *) class;

	object_class->nickname = "hough_line";
	object_class->description = _( "find hough line transform" );
	object_class->build = vips_hough_line_build;

	hclass->init_accumulator = vips_hough_line_init_accumulator;
	hclass->vote = vips_hough_line_vote;

}

static void
vips_hough_line_init( VipsHoughLine *hough_line )
{
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
 * See also: 
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
