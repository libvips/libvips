/* hough transform for circles
 *
 * 7/3/14
 * 	- from hough_line.c
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

typedef struct _VipsHoughCircle {
	VipsHough parent_instance;

	int min_radius;
	int max_radius;
	int bands;

} VipsHoughCircle;

typedef VipsHoughClass VipsHoughCircleClass;

G_DEFINE_TYPE( VipsHoughCircle, vips_hough_circle, VIPS_TYPE_HOUGH );

static int
vips_hough_circle_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsHough *hough = (VipsHough *) object;
	VipsHoughCircle *hough_circle = (VipsHoughCircle *) object;

	if( !vips_object_argument_isset( object, "bands" ) )
		hough_circle->bands = 1 + hough_circle->max_radius - 
			hough_circle->min_radius;

	if( hough_circle->min_radius > hough_circle->max_radius ) { 
		vips_error( class->nickname, 
			"%s", _( "parameters out of range" ) );
		return( NULL );
	}

	if( VIPS_OBJECT_CLASS( vips_hough_circle_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

static int
vips_hough_circle_init_accumulator( VipsHough *hough, VipsImage *accumulator )
{
	VipsHoughCircle *hough_circle = (VipsHoughCircle *) hough;

	vips_image_init_fields( accumulator,
		hough->width, hough->height, hough_circle->bands,
		VIPS_FORMAT_UINT, VIPS_CODING_NONE,
		VIPS_INTERPRETATION_MATRIX,
		1.0, 1.0 );

	return( 0 ); 
}

static inline void
vips_hough_circle_pel( VipsImage *accumulator, int band, int x, int y )
{
	VIPS_IMAGE_ADDR( accumulator, x, y )[band] += 1;
}

static inline void
vips_hough_circle_pel_clip( VipsImage *accumulator, int band, int x, int y )
{
	if( x >= 0 && 
		x < accumulator->Xsize &&
		y >= 0 && 
		y < accumulator->Ysize )
		VIPS_IMAGE_ADDR( accumulator, x, y )[band] += 1;
}

static void
vips_hough_circle_octants( VipsImage *accumulator, 
	gboolean noclip, int band,
	int cx, int cy, int x, int y )
{
	if( noclip ) {
		vips_hough_circle_pel( accumulator, band, cx + y, cy - x );
		vips_hough_circle_pel( accumulator, band, cx + y, cy + x );
		vips_hough_circle_pel( accumulator, band, cx - y, cy - x );
		vips_hough_circle_pel( accumulator, band, cx - y, cy + x );
		vips_hough_circle_pel( accumulator, band, cx + x, cy - y );
		vips_hough_circle_pel( accumulator, band, cx + x, cy + y );
		vips_hough_circle_pel( accumulator, band, cx - x, cy - y );
		vips_hough_circle_pel( accumulator, band, cx - x, cy + y );
	}
	else {
		vips_hough_circle_pel_clip( accumulator, band, cx + y, cy - x );
		vips_hough_circle_pel_clip( accumulator, band, cx + y, cy + x );
		vips_hough_circle_pel_clip( accumulator, band, cx - y, cy - x );
		vips_hough_circle_pel_clip( accumulator, band, cx - y, cy + x );
		vips_hough_circle_pel_clip( accumulator, band, cx + x, cy - y );
		vips_hough_circle_pel_clip( accumulator, band, cx + x, cy + y );
		vips_hough_circle_pel_clip( accumulator, band, cx - x, cy - y );
		vips_hough_circle_pel_clip( accumulator, band, cx - x, cy + y );
	}
}

static void
vips_hough_circle_draw( VipsHoughCircle *hough_circle,
	VipsImage *accumulator, int cx, int cy, int radius )
{
	int bands = hough_circle->bands;
	int band = bands * (radius - hough_circle->min_band) / bands; 

	gboolean noclip;
	int x, y, d;

	noclip = cx - radius >= 0 && 
		cx + radius < accumulator->Xsize &&
		cy - radius >= 0 && 
		cy + radius < accumulator->Ysize;

	y = radius;
	d = 3 - 2 * radius;

	for( x = 0; x < y; x++ ) {
		vips_draw_circle_octants( accumulator, noclip, band, x, y );

		if( d < 0 )
			d += 4 * x + 6;
		else {
			d += 4 * (x - y) + 10;
			y--;
		}
	}

	if( x == y ) 
		vips_draw_circle_octants( accumulator, noclip, band, x, y );
}

/* Cast votes for all possible circles passing through x, y.
 */
static void
vips_hough_circle_vote( VipsHough *hough, VipsImage *accumulator, int x, int y )
{
	VipsHoughCircle *hough_circle = (VipsHoughCircle *) hough; 
	VipsStatistic *statistic = (VipsStatistic *) hough;  
	double xd = (double) x / statistic->ready->Xsize;
	double yd = (double) y / statistic->ready->Ysize;

	int r;

	for( i = 0; i < hough->width; i++ ) { 
		int i90 = (i + hough->width / 4) % hough->width;
		double r = xd * hough_circle->sin[i90] + yd * hough_circle->sin[i];
		int ri = hough->height * r;

		if( ri >= 0 && 
			ri < hough->height ) 
			*VIPS_IMAGE_ADDR( accumulator, i, ri ) += 1;
	}
}

static void
vips_hough_circle_class_init( VipsHoughClass *class )
{
	GObjectClass *gobject_class = (GObjectClass *) class;
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsHoughClass *hclass = (VipsHoughClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "hough_circle";
	object_class->description = _( "find hough circle transform" );
	object_class->build = vips_hough_circle_build;

	hclass->init_accumulator = vips_hough_circle_init_accumulator;
	hclass->vote = vips_hough_circle_vote;

	VIPS_ARG_INT( class, "bands", 119, 
		_( "Bands" ), 
		_( "Number of bands in parameter space" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT, 
		G_STRUCT_OFFSET( VipsHoughCircle, bands ),
		1, 100000, 10 );

	VIPS_ARG_INT( class, "min_radius", 120, 
		_( "Min radius" ), 
		_( "Smallest radius to search for" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT, 
		G_STRUCT_OFFSET( VipsHoughCircle, min_radius ),
		1, 100000, 10 );

	VIPS_ARG_INT( class, "max_radius", 121, 
		_( "Max radius" ), 
		_( "Largest radius to search for" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT, 
		G_STRUCT_OFFSET( VipsHoughCircle, max_radius ),
		1, 100000, 20 );

}

static void
vips_hough_circle_init( VipsHoughCircle *hough_circle )
{
	hough_circle->min_radius = 10; 
	hough_circle->max_radius = 20; 
	hough_circle->bands = 10; 
}

/**
 * vips_hough_circle:
 * @in: input image
 * @out: output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * @width: horizontal size of parameter space
 * @height: vertical size of parameter space
 * @min_radius: smallest radius to search for
 * @max_radius: largest radius to search for
 *
 * See also: 
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_hough_circle( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "hough_circle", ap, in, out );
	va_end( ap );

	return( result );
}
