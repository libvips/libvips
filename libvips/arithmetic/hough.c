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

G_DEFINE_ABSTRACT_TYPE( VipsHough, vips_hough, VIPS_TYPE_STATISTIC );

static VipsImage *
vips_hough_new_accumulator( VipsHough *hough )
{
	VipsHoughClass *class = VIPS_HOUGH_GET_CLASS( hough );
	VipsStatistic *statistic = VIPS_STATISTIC( hough ); 

	VipsImage *accumulator; 

	accumulator = vips_image_new_buffer(); 

	vips_image_pipelinev( accumulator,
		VIPS_DEMAND_STYLE_ANY, statistic->ready, NULL );

	if( class->init_accumulator( hough, accumulator ) ||
		vips_image_write_prepare( accumulator ) ) {
		g_object_unref( accumulator );
		return( NULL );
	}

	/* vips does not guarantee image mem is zeroed.
	 */
	memset( VIPS_IMAGE_ADDR( accumulator, 0, 0 ), 0,
		VIPS_IMAGE_SIZEOF_IMAGE( accumulator ) ); 

	return( accumulator );
}

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

	if( !(out = vips_hough_new_accumulator( hough )) )
		return( -1 );
	g_object_set( object, 
		"out", out,
		NULL );

	if( VIPS_OBJECT_CLASS( vips_hough_parent_class )->build( object ) )
		return( -1 );

	return( 0 );
}

/* Build a new accumulator. 
 */
static void *
vips_hough_start( VipsStatistic *statistic )
{
	VipsHough *hough = (VipsHough *) statistic;

	VipsImage *accumulator;

	if( !(accumulator = vips_hough_new_accumulator( hough )) )
		return( NULL ); 

	return( (void *) accumulator ); 
}

/* Add our finished accumulator to the main area.
 */
static int
vips_hough_stop( VipsStatistic *statistic, void *seq )
{
	VipsImage *accumulator = (VipsImage *) seq;
	VipsHough *hough = (VipsHough *) statistic;

	if( vips_draw_image( hough->out, accumulator, 0, 0,
		"mode", VIPS_COMBINE_MODE_ADD,
		NULL ) ) {
		g_object_unref( accumulator ); 
		return( -1 ); 
	}

	g_object_unref( accumulator ); 

	return( 0 );
}

static int
vips_hough_scan( VipsStatistic *statistic, 
	void *seq, int x, int y, void *in, int n )
{
	VipsHough *hough = (VipsHough *) statistic;
	VipsHoughClass *class = VIPS_HOUGH_GET_CLASS( hough );
	VipsImage *accumulator = (VipsImage *) seq;
	VipsPel *p = (VipsPel *) in;

	int i;

	for( i = 0; i < n; i++ )
		if( p[i] )
			class->vote( hough, accumulator, x + i, y );

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

}

static void
vips_hough_init( VipsHough *hough )
{
}
