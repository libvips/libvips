/* nearest.c
 *
 * 31/10/17
 * 	- from labelregion 
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
#define DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <glib/gi18n-lib.h>

#include <stdio.h>

#include <vips/vips.h>
#include <vips/internal.h>

#include "pmorphology.h"

/* A seed pixel. We fill outwards from each of these.
 */
typedef struct _Seed {
	int x;
	int y;
	int r;

	/* Bits saying which octant can still grow. When they are all zero, the
	 * seed is dead.
	 */
	int octant_mask;
} Seed;

typedef struct _VipsFillNearest {
	VipsMorphology parent_instance;

	VipsImage *out;
	VipsImage *distance;

	/* Size of our image.
	 */
	int width;
	int height;

	/* All our seed pixels. There can be a lot of these.
	 */
	GArray *seeds;
} VipsFillNearest;

typedef VipsMorphologyClass VipsFillNearestClass;

G_DEFINE_TYPE( VipsFillNearest, vips_fill_nearest, VIPS_TYPE_MORPHOLOGY );

static void
vips_fill_nearest_finalize( GObject *gobject )
{
	VipsFillNearest *nearest = (VipsFillNearest *) gobject;

#ifdef DEBUG
	printf( "vips_fill_nearest_finalize: " );
	vips_object_print_name( VIPS_OBJECT( gobject ) );
	printf( "\n" );
#endif /*DEBUG*/

	VIPS_FREEF( g_array_unref, nearest->seeds ); 

	G_OBJECT_CLASS( vips_fill_nearest_parent_class )->finalize( gobject );
}

struct _Circle;
typedef void (*VipsFillNearestPixel)( struct _Circle *circle, 
	int x, int y, int octant );

typedef struct _Circle {
	VipsFillNearest *nearest;
	Seed *seed;
	int octant_mask;
	VipsFillNearestPixel nearest_pixel;
} Circle;

static void 
vips_fill_nearest_pixel( Circle *circle, int x, int y, int octant )
{
	float *p;
	float radius;
	int dx, dy;

	if( (circle->seed->octant_mask & (1 << octant)) == 0 )
		return;

	/* We need to do this as float, or we'll have dithering along edges.
	 */
	p = (float *) VIPS_IMAGE_ADDR( circle->nearest->distance, x, y );
	dx = x - circle->seed->x;
	dy = y - circle->seed->y;
	radius = sqrt( dx * dx + dy * dy );

	if( p[0] == 0 ||
		p[0] > radius ) {
		VipsMorphology *morphology = VIPS_MORPHOLOGY( circle->nearest );
		VipsImage *in = morphology->in;
		int ps = VIPS_IMAGE_SIZEOF_PEL( in );
		VipsPel *pi = VIPS_IMAGE_ADDR( in,
			circle->seed->x, circle->seed->y );
		VipsPel *qi = VIPS_IMAGE_ADDR( circle->nearest->out, 
			x, y ); 

		int i;

		p[0] = radius;
		circle->octant_mask |= 1 << octant;

		for( i = 0; i < ps; i++ )
			qi[i] = pi[i];
	}
}

static void 
vips_fill_nearest_pixel_clip( Circle *circle, int x, int y, int octant )
{
	if( (circle->seed->octant_mask & (1 << octant)) == 0 )
		return;

	if( x >= 0 &&
		x < circle->nearest->width &&
		y >= 0 &&
		y < circle->nearest->height )
		vips_fill_nearest_pixel( circle, x, y, octant );
}

static void
vips_fill_nearest_scanline( VipsImage *image, 
	int y, int x1, int x2, int quadrant, void *client )
{
	Circle *circle = (Circle *) client;

	circle->nearest_pixel( circle, x1, y, quadrant );
	circle->nearest_pixel( circle, x2, y, quadrant + 4 );

	/* We have to do one point back as well, or we'll leave gaps at 
	 * around 45 degrees.
	 */
	if( quadrant == 0 ) {
		circle->nearest_pixel( circle, x1, y - 1, quadrant );
		circle->nearest_pixel( circle, x2, y - 1, quadrant + 4 );
	}
	else if( quadrant == 1 ) {
		circle->nearest_pixel( circle, x1, y + 1, quadrant );
		circle->nearest_pixel( circle, x2, y + 1, quadrant + 4 );
	}
	else {
		circle->nearest_pixel( circle, x1 + 1, y, quadrant );
		circle->nearest_pixel( circle, x2 - 1, y, quadrant + 4 );
	}
}

static void
vips_fill_nearest_grow_seed( VipsFillNearest *nearest, Seed *seed )
{
	Circle circle;

	circle.nearest = nearest;
	circle.seed = seed;
	circle.octant_mask = 0;

	if( seed->x - seed->r >= 0 &&
		seed->x + seed->r < nearest->width &&
		seed->y - seed->r >= 0 &&
		seed->y + seed->r < nearest->height )
		circle.nearest_pixel = vips_fill_nearest_pixel;
	else
		circle.nearest_pixel = vips_fill_nearest_pixel_clip;

	vips__draw_circle_direct( nearest->distance, 
		seed->x, seed->y, seed->r, 
		vips_fill_nearest_scanline, &circle );

	/* Update the action_mask for this seed. Next time, we can skip any 
	 * octants where we failed to act this time. 
	 */
	seed->octant_mask = circle.octant_mask; 

	seed->r += 1;
}

static int
vips_fill_nearest_build( VipsObject *object )
{
	VipsMorphology *morphology = VIPS_MORPHOLOGY( object );
	VipsFillNearest *nearest = (VipsFillNearest *) object;
	VipsImage **t = (VipsImage **) vips_object_local_array( object, 2 );

	int ps;
	int x, y, i;

	if( VIPS_OBJECT_CLASS( vips_fill_nearest_parent_class )->
		build( object ) )
		return( -1 );

	if( vips_image_wio_input( morphology->in ) )
		return( -1 ); 
	nearest->width = morphology->in->Xsize;
	nearest->height = morphology->in->Ysize;

	ps = VIPS_IMAGE_SIZEOF_PEL( morphology->in );
	nearest->seeds = g_array_new( FALSE, FALSE, sizeof( Seed ) );
	for( y = 0; y < nearest->height; y++ )  {
		VipsPel *p;

		p = VIPS_IMAGE_ADDR( morphology->in, 0, y ); 
		for( x = 0; x < nearest->width; x++ ) {
			for( i = 0; i < ps; i++ )
				if( p[i] )
					break;

			if( i != ps ) { 
				Seed *seed;

				g_array_set_size( nearest->seeds, 
					nearest->seeds->len + 1 );
				seed = &g_array_index( nearest->seeds, 
					Seed, nearest->seeds->len - 1 );
				seed->x = x;
				seed->y = y;
				seed->r = 1;
				seed->octant_mask = 255;
			}

			p += ps;
		}
	}

	/* Create the output and distance images in memory.
	 */
	g_object_set( object, "distance", vips_image_new_memory(), NULL );
	if( vips_black( &t[1], nearest->width, nearest->height, NULL ) ||
		vips_cast( t[1], &t[2], VIPS_FORMAT_FLOAT, NULL ) || 
		vips_image_write( t[2], nearest->distance ) )
		return( -1 );

	g_object_set( object, "out", vips_image_new_memory(), NULL );
	if( vips_image_write( morphology->in, nearest->out ) )
		return( -1 );

	while( nearest->seeds->len > 0 ) {
#ifdef DEBUG
		printf( "looping for %d seeds ...\n", nearest->seeds->len );
#endif /*DEBUG*/

		/* Grow all seeds by one pixel.
		 */
		for( i = 0; i < nearest->seeds->len; i++ ) 
			vips_fill_nearest_grow_seed( nearest, 
				&g_array_index( nearest->seeds, Seed, i ) );

		/* Remove dead seeds.
		 */
		i = 0; 
		while( i < nearest->seeds->len )  {
			Seed *seed = &g_array_index( nearest->seeds, Seed, i );

			if( seed->octant_mask == 0 )
				g_array_remove_index_fast( nearest->seeds, i );
			else
				i += 1;
		}
	}

	return( 0 );
}

static void
vips_fill_nearest_class_init( VipsFillNearestClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	gobject_class->finalize = vips_fill_nearest_finalize;
	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "fill_nearest";
	vobject_class->description = 
		_( "fill image zeros with nearest non-zero pixel" ); 
	vobject_class->build = vips_fill_nearest_build;

	VIPS_ARG_IMAGE( class, "out", 2, 
		_( "Out" ), 
		_( "Value of nearest non-zero pixel" ),
		VIPS_ARGUMENT_REQUIRED_OUTPUT,
		G_STRUCT_OFFSET( VipsFillNearest, out ) ); 

	VIPS_ARG_IMAGE( class, "distance", 3, 
		_( "Distance" ), 
		_( "Distance to nearest non-zero pixel" ),
		VIPS_ARGUMENT_OPTIONAL_OUTPUT,
		G_STRUCT_OFFSET( VipsFillNearest, distance ) ); 

}

static void
vips_fill_nearest_init( VipsFillNearest *nearest )
{
}

/**
 * vips_fill_nearest: (method)
 * @in: image to test
 * @out: image with zero pixels filled with the nearest non-zero pixel
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @distance: output image of distance to nearest non-zero pixel
 *
 * Fill outwards from every non-zero pixel in @in, setting pixels in @distance
 * and @value. 
 *
 * At the position of zero pixels in @in, @distance contains the distance to
 * the nearest non-zero pixel in @in, and @value contains the value of that
 * pixel.
 *
 * @distance is a one-band float image. @value has the same number of bands and
 * format as @in.
 *
 * See also: vips_hist_find_indexed().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_fill_nearest( VipsImage *in, VipsImage **out, ... ) 
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "fill_nearest", ap, in, out );
	va_end( ap );

	return( result );
}
