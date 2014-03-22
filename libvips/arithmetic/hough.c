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

typedef struct _VipsHough {
	VipsStatistic parent_instance;

	/* Size of parameter space.
	 */
	int width;
	int height;

	/* Each thread adds its accumulator image to this array on stop. 
	 * ith is the index the ith thread places its image at.
	 */
	VipsImage **threads;
	int n_threads;
	int ith;

	/* Sum the thread accumulators to here.
	 */
	VipsImage *out; 

} VipsHough;

typedef VipsStatisticClass VipsHoughClass;

G_DEFINE_TYPE( VipsHough, vips_hough, VIPS_TYPE_STATISTIC );

static int
vips_hough_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsStatistic *statistic = VIPS_STATISTIC( object ); 
	VipsHough *hough = (VipsHough *) object;

	VipsImage *out; 

	/* Mono only, we use the bands dimension of the output image for
	 * a parameter.
	 */
	if( statistic->in ) 
		if( vips_check_mono( class->nickname, statistic->in ) )
			return( -1 );

	if( VIPS_OBJECT_CLASS( vips_hough_parent_class )->build( object ) )
		return( -1 );

	/* hough->threads should be an array of completed accumulators, and we
	 * should have noted one for each thread we started.
	 */
	g_assert( hough->threads ); 
	g_assert( hough->n_threads > 0 ); 
	g_assert( hough->n_threads == hough->ith ); 

	if( vips_sum( hough->threads, &out, hough->n_threads, NULL ) )
		return( -1 ); 

	g_object_set( object, 
		"out", out,
		NULL );

	return( 0 );
}

/* Build a new accumulator. 
 */
static void *
vips_hough_start( VipsStatistic *statistic )
{
	VipsHough *hough = (VipsHough *) statistic;

	VipsImage *accumulator;

	/* Make a note of the number of threads we start.
	 */
	hough->n_threads += 1;

	/* We assume that we don't start any more threads after the first stop
	 * is called.
	 */
	g_assert( !hough->threads ); 

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
