/* hough transform
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

typedef VipsHoughLine VipsHough; 
typedef VipsHoughLineClass VipsHoughClass;

G_DEFINE_TYPE( VipsHough, vips_hough, VIPS_TYPE_HOUGH );

/* Build a new accumulator. 
 */
static VipsImage *
vips_houghline_new_accumulator( VipsHough *hough )
{
	VipsStatistic *statistic = (VipsSt
	VipsImage *accumulator;

	accumulator = vips_image_new_buffer(); 

	vips_image_pipelinev( accumulator,
		VIPS_DEMAND_STYLE_ANY, statistic->in, NULL );

	vips_image_init_fields( accumulator,
		hough->width, hough->height, 1,
		VIPS_FORMAT_UINT, VIPS_CODING_NONE,
		VIPS_INTERPRETATION_MATRIX,
		1.0, 1.0 );

	if( vips_image_write_prepare( accumulator ) ) {
		g_object_unref( accumulator );
		return( NULL );
	}

	/* vips does not guarantee image mem is zeroed.
	 */
	memset( VIPS_IMAGE_ADDR( accumulator, 0, 0 ), 0,
		VIPS_IMAGE_SIZEOF_IMAGE( accumulator ) ); 

	return( (void *) accumulator ); 
}

/* Add our finished accumulator to the main area.
 */
static int
vips_hough_stop( VipsStatistic *statistic, void *seq )
{
	VipsImage *accumulator = (VipsImage *) seq;
	VipsHough *hough = (VipsHough *) statistic;

	/* If this is the first stop, build the main accumulator array. We
	 * assume no more threads will start, see the assert above.
	 */
	if( !hough->threads )
		/* This will unref the accumulators automatically on dispose.
		 */
		hough->threads = (VipsImage **) 
			vips_object_local_array( VIPS_OBJECT( hough ), 
				hough->n_threads ); 

	g_assert( !hough->threads[hough->ith] );

	hough->threads[hough->ith] = accumulator;
	hough->ith += 1;

	return( 0 );
}

/* Cast votes for all lines passing through x, y.
 */
static void
hough_vote( VipsHough *hough, VipsImage *accumulator, int x, int y )
{
	VipsStatistic *statistic = (VipsStatistic *) hough;  
	double xd = (double) x / statistic->ready->Xsize;
	double yd = (double) y / statistic->ready->Ysize;

	int thetai;

	for( thetai = 0; thetai < hough->width; thetai++ ) { 
		double theta = 2 * M_PI * thetai / hough->width; 
		double r = xd * cos( theta ) + yd * sin( theta );
		int ri = hough->height * r;

		if( ri >= 0 && 
			ri < hough->height ) 
			*VIPS_IMAGE_ADDR( accumulator, thetai, ri ) += 1;
	}
}

/* See our superclass in statistic.c, but this is called for each section of
 * each scanline. @x, @y is the position of the left end, @in is the pixel
 * data, @n is the number of pixels in this scanline. VipsPel is uint8.
 */
static int
vips_hough_scan( VipsStatistic *statistic, 
	void *seq, int x, int y, void *in, int n )
{
	VipsHough *hough = (VipsHough *) statistic;
	VipsImage *accumulator = (VipsImage *) seq;
	VipsPel *p = (VipsPel *) in;

	int i;

	for( i = 0; i < n; i++ )
		if( p[i] )
			hough_vote( hough, accumulator, x + i, y );

	return( 0 );
}

#define UC VIPS_FORMAT_UCHAR

/* Input image is cast to this format.
 */
static const VipsBandFormat vips_hough_format_table[10] = {
/* UC   C  US   S  UI   I   F   X   D  DX */
   UC, UC, UC, UC, UC, UC, UC, UC, UC, UC
};

static void
vips_hough_class_init( VipsHoughClass *class )
{
	GObjectClass *gobject_class = (GObjectClass *) class;
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsStatisticClass *sclass = VIPS_STATISTIC_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "hough";
	object_class->description = _( "find hough transform" );
	object_class->build = vips_hough_build;

	sclass->start = vips_hough_start;
	sclass->scan = vips_hough_scan;
	sclass->stop = vips_hough_stop;
	sclass->format_table = vips_hough_format_table;

	VIPS_ARG_IMAGE( class, "out", 100, 
		_( "Output" ), 
		_( "Output image" ),
		VIPS_ARGUMENT_REQUIRED_OUTPUT, 
		G_STRUCT_OFFSET( VipsHough, out ) );

	VIPS_ARG_INT( class, "width", 110, 
		_( "Width" ), 
		_( "horizontal size of parameter space" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT, 
		G_STRUCT_OFFSET( VipsHough, width ),
		1, 100000, 256 );

	VIPS_ARG_INT( class, "height", 110, 
		_( "Height" ), 
		_( "Vertical size of parameter space" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT, 
		G_STRUCT_OFFSET( VipsHough, height ),
		1, 100000, 256 );

}

static void
vips_hough_init( VipsHough *hough )
{
	hough->width = 256;
	hough->height = 256;
}

/**
 * vips_hough:
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
vips_hough( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "hough", ap, in, out );
	va_end( ap );

	return( result );
}
