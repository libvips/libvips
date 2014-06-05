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

/* Derived in part from David Young's Matlab circle detector:
 *
 * http://www.mathworks.com/matlabcentral/fileexchange/26978-hough-transform-for-circles
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <string.h>

#include <vips/vips.h>
#include <vips/internal.h>

#include "statistic.h"
#include "hough.h"

typedef struct _VipsHoughCircle {
	VipsHough parent_instance;

	int scale;
	int min_radius;
	int max_radius;

	int width;
	int height;
	int bands;

} VipsHoughCircle;

typedef VipsHoughClass VipsHoughCircleClass;

G_DEFINE_TYPE( VipsHoughCircle, vips_hough_circle, VIPS_TYPE_HOUGH );

/* Smaller circles have fewer pixels and therefore fewer votes. Scale bands by
 * the ratio of circumference, so all radii get equal weight.
 */
static void
vips_hough_circle_normalise( VipsHoughCircle *hough_circle )
{
	VipsHough *hough = (VipsHough *) hough_circle;

	int max_radius = hough_circle->max_radius;
	int min_radius = hough_circle->min_radius;
	int scale = hough_circle->scale;
	int bands = hough_circle->bands;
	int width = hough_circle->width;
	int height = hough_circle->height;

	double max_circumference = 2 * VIPS_PI * max_radius;

	int b;

	for( b = 0; b < bands; b++ ) {
		int radius = b * scale + min_radius;
		double circumference = 2 * VIPS_PI * radius;
		double ratio = max_circumference / circumference;
		size_t n_pels = (size_t) width * height * bands; 

		size_t i;
		guint *q; 

		q = b + (guint *) VIPS_IMAGE_ADDR( hough->out, 0, 0 );
		for( i = 0; i < n_pels; i += bands )
			q[i] *= ratio;
	}
}

static int
vips_hough_circle_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsStatistic *statistic = (VipsStatistic *) object;  
	VipsHoughCircle *hough_circle = (VipsHoughCircle *) object;
	int range = hough_circle->max_radius - hough_circle->min_radius;

	if( range <= 0 ) {
		vips_error( class->nickname, 
			"%s", _( "parameters out of range" ) );
		return( -1 );
	}

	hough_circle->width = statistic->in->Xsize / hough_circle->scale;
	hough_circle->height = statistic->in->Ysize / hough_circle->scale;
	hough_circle->bands = 1 + range / hough_circle->scale;

	if( VIPS_OBJECT_CLASS( vips_hough_circle_parent_class )->
		build( object ) )
		return( -1 );

	vips_hough_circle_normalise( hough_circle );

	return( 0 );
}

static int
vips_hough_circle_init_accumulator( VipsHough *hough, VipsImage *accumulator )
{
	VipsHoughCircle *hough_circle = (VipsHoughCircle *) hough;

	vips_image_init_fields( accumulator,
		hough_circle->width, hough_circle->height, hough_circle->bands,
		VIPS_FORMAT_UINT, VIPS_CODING_NONE,
		VIPS_INTERPRETATION_MATRIX,
		1.0, 1.0 );

	return( 0 ); 
}

static inline void
vips_hough_circle_vote_point( VipsImage *image, int x, int y, void *client )
{
	guint *q = (guint *) VIPS_IMAGE_ADDR( image, x, y );
	int r = *((int *) client); 

	g_assert( image->BandFmt == VIPS_FORMAT_UINT ); 
	g_assert( x >= 0 ); 
	g_assert( y >= 0 ); 
	g_assert( x < image->Xsize ); 
	g_assert( y < image->Ysize ); 
	g_assert( r >= 0 ); 
	g_assert( r < image->Bands ); 

	q[r] += 1;
}

/* Vote endpoints, with clip.
 */
static void 
vips_hough_circle_vote_endpoints_clip( VipsImage *image,
	int y, int x1, int x2, void *client )
{
	if( y >= 0 &&
		y < image->Ysize ) {
		if( x1 >=0 &&
			x1 < image->Xsize )
			vips_hough_circle_vote_point( image, x1, y, client );
		if( x2 >=0 &&
			x2 < image->Xsize )
			vips_hough_circle_vote_point( image, x2, y, client );
	}
}

/* Vote endpoints, no clip.
 */
static void 
vips_hough_circle_vote_endpoints_noclip( VipsImage *image,
	int y, int x1, int x2, void *client )
{
	vips_hough_circle_vote_point( image, x1, y, client );
	vips_hough_circle_vote_point( image, x2, y, client );
}

/* Cast votes for all possible circles passing through x, y.
 */
static void
vips_hough_circle_vote( VipsHough *hough, VipsImage *accumulator, int x, int y )
{
	VipsHoughCircle *hough_circle = (VipsHoughCircle *) hough; 
	int min_radius = hough_circle->min_radius; 
	int max_radius = hough_circle->max_radius; 
	int range = max_radius - min_radius; 
	int cx = x / hough_circle->scale;
	int cy = y / hough_circle->scale;

	int rb;

	g_assert( range >= 0 ); 

	for( rb = 0; rb < hough_circle->bands; rb++ ) { 
		/* r needs to be in scaled down image space.
		 */
		int r = rb + min_radius / hough_circle->scale; 

		VipsDrawScanline draw_scanline;

		if( cx - r >= 0 && 
			cx + r < accumulator->Xsize &&
			cy - r >= 0 && 
			cy + r < accumulator->Ysize )
			draw_scanline = vips_hough_circle_vote_endpoints_noclip;
			else
			draw_scanline = vips_hough_circle_vote_endpoints_clip; 

		vips__draw_circle_direct( accumulator, 
			cx, cy, r, draw_scanline, &rb );
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

	VIPS_ARG_INT( class, "scale", 119, 
		_( "Scale" ), 
		_( "Scale down dimensions by this factor" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT, 
		G_STRUCT_OFFSET( VipsHoughCircle, scale ),
		1, 100000, 3 );

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
	hough_circle->scale = 3; 
	hough_circle->min_radius = 10; 
	hough_circle->max_radius = 20; 
}

/**
 * vips_hough_circle:
 * @in: input image
 * @out: output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * @scale: scale down dimensions by this much
 * @min_radius: smallest radius to search for
 * @max_radius: largest radius to search for
 *
 * Find the circular Hough transform of an image. @in must be one band, with
 * non-zero pixels for image edges. @out is three-band, with the third channel 
 * representing the detected circle radius. The operation scales the number of
 * votes by circle circumference so circles of differing size are given equal
 * weight. 
 *
 * Use @max_radius and @min_radius to set the range of radii to search for.
 *
 * Use @scale to set how @in coordinates are scaled to @out coordinates. A
 * @scale of 3, for example, will make @out 1/3rd of the width and height of
 * @in, and reduce the number of radii tested (and hence the number of bands
 * int @out) by a factor of three as well.
 *
 * See also: vips_hough_line().
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
