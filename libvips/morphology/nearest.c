/* nearest.c
 *
 * 31/10/17
 * 	- from labelregion and draw_circle
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

#define DEBUG

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

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

typedef struct _VipsNearest {
	VipsMorphology parent_instance;

	VipsImage *out;
	VipsImage *distance;

	/* All our seed pixels. There can be a lot of these.
	 */
	GArray *seeds;
} VipsNearest;

typedef VipsMorphologyClass VipsNearestClass;

G_DEFINE_TYPE( VipsNearest, vips_nearest, VIPS_TYPE_MORPHOLOGY );

static void
vips_nearest_finalize( GObject *gobject )
{
	VipsNearest *nearest = (VipsNearest *) gobject;

#ifdef DEBUG
	printf( "vips_nearest_finalize: " );
	vips_object_print_name( VIPS_OBJECT( gobject ) );
	printf( "\n" );
#endif /*DEBUG*/

	VIPS_FREEF( g_array_unref, nearest->seeds ); 

	G_OBJECT_CLASS( vips_nearest_parent_class )->finalize( gobject );
}

struct _Circle;
typedef void (*VipsNearestPixel)( struct _Circle *circle, 
	int x, int y, int r, int octant );

typedef struct _Circle {
	VipsNearest *nearest;
	Seed *seed;
	int octant_mask;
	VipsNearestPixel nearest_pixel;
} Circle;

static void 
vips_nearest_pixel( Circle *circle, int x, int y, int r, int octant )
{
	guint *p;

	if( (circle->seed->octant_mask & (1 << octant)) == 0 )
		return;

	p = (guint *) VIPS_IMAGE_ADDR( circle->nearest->distance, x, y );

	if( p[0] == 0 ||
		p[0] > r ) {
		VipsMorphology *morphology = VIPS_MORPHOLOGY( circle->nearest );
		VipsImage *in = morphology->in;
		int ps = VIPS_IMAGE_SIZEOF_PEL( in );
		VipsPel *pi = VIPS_IMAGE_ADDR( in,
			circle->seed->x, circle->seed->y );
		VipsPel *qi = VIPS_IMAGE_ADDR( circle->nearest->out, 
			x, y ); 

		int i;

		p[0] = r;
		circle->octant_mask |= 1 << octant;

		for( i = 0; i < ps; i++ )
			qi[i] = pi[i];
	}
}

static void 
vips_nearest_pixel_clip( Circle *circle, int x, int y, int r, int octant )
{
	if( (circle->seed->octant_mask & (1 << octant)) == 0 )
		return;

	if( y >= 0 &&
		y < circle->nearest->distance->Ysize &&
		x >= 0 &&
		x < circle->nearest->distance->Xsize )
		vips_nearest_pixel( circle, x, y, r, octant );
}

static void
vips_nearest_scanline( VipsImage *image, 
	int y, int x1, int x2, int quadrant, void *client )
{
	Circle *circle = (Circle *) client;

	circle->nearest_pixel( circle, x1, y, circle->seed->r, quadrant );
	circle->nearest_pixel( circle, x2, y, circle->seed->r, quadrant + 4 );

	/* We have to do one point back as well, or we'll leave gaps at 
	 * around 45 degrees.
	 */
	if( quadrant == 0 ) {
		circle->nearest_pixel( circle, 
			x1, y - 1, circle->seed->r - 1, quadrant );
		circle->nearest_pixel( circle, 
			x2, y - 1, circle->seed->r - 1, quadrant + 4 );
	}
	else if( quadrant == 1 ) {
		circle->nearest_pixel( circle, 
			x1, y + 1, circle->seed->r - 1, quadrant );
		circle->nearest_pixel( circle, 
			x2, y + 1, circle->seed->r - 1, quadrant + 4 );
	}
	else {
		circle->nearest_pixel( circle, 
			x1 + 1, y, circle->seed->r - 1, quadrant );
		circle->nearest_pixel( circle, 
			x2 - 1, y, circle->seed->r - 1, quadrant + 4 );
	}
}

static void
vips_nearest_grow_seed( VipsNearest *nearest, Seed *seed )
{
	Circle circle;

	circle.nearest = nearest;
	circle.seed = seed;
	circle.octant_mask = 0;

	if( seed->x - seed->r >= 0 &&
		seed->x + seed->r < nearest->distance->Xsize &&
		seed->y - seed->r >= 0 &&
		seed->y + seed->r < nearest->distance->Ysize )
		circle.nearest_pixel = vips_nearest_pixel;
	else
		circle.nearest_pixel = vips_nearest_pixel_clip;

	vips__draw_circle_direct( nearest->distance, 
		seed->x, seed->y, seed->r, vips_nearest_scanline, &circle );

	/* Update the action_mask for this seed. Next time, we can skip any 
	 * octants where we failed to act this time. 
	 */
	seed->octant_mask = circle.octant_mask; 

	seed->r += 1;
}

static int
vips_nearest_build( VipsObject *object )
{
	VipsMorphology *morphology = VIPS_MORPHOLOGY( object );
	VipsNearest *nearest = (VipsNearest *) object;
	VipsImage **t = (VipsImage **) vips_object_local_array( object, 2 );
	VipsImage *in = morphology->in;

	int ps;
	int x, y, i;

	if( VIPS_OBJECT_CLASS( vips_nearest_parent_class )->build( object ) )
		return( -1 );

	if( vips_image_wio_input( in ) )
		return( -1 ); 

	ps = VIPS_IMAGE_SIZEOF_PEL( in );
	nearest->seeds = g_array_new( FALSE, FALSE, sizeof( Seed ) );
	for( y = 0; y < in->Ysize; y++ )  {
		VipsPel *p;

		p = VIPS_IMAGE_ADDR( in, 0, y ); 
		for( x = 0; x < in->Xsize; x++ ) {
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
	if( vips_black( &t[1], in->Xsize, in->Ysize, NULL ) ||
		vips_cast( t[1], &t[2], VIPS_FORMAT_UINT, NULL ) || 
		vips_image_write( t[2], nearest->distance ) )
		return( -1 );

	g_object_set( object, "out", vips_image_new_memory(), NULL );
	if( vips_image_write( in, nearest->out ) )
		return( -1 );

	while( nearest->seeds->len > 0 ) {
#ifdef DEBUG
		printf( "looping for %d seeds ...\n", nearest->seeds->len );
#endif /*DEBUG*/

		/* Grow all seeds by one pixel.
		 */
		for( i = 0; i < nearest->seeds->len; i++ ) 
			vips_nearest_grow_seed( nearest, 
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
vips_nearest_class_init( VipsNearestClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	gobject_class->finalize = vips_nearest_finalize;
	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "nearest";
	vobject_class->description = _( "find nearest pixel in an image" ); 
	vobject_class->build = vips_nearest_build;

	VIPS_ARG_IMAGE( class, "out", 2, 
		_( "Out" ), 
		_( "Value of nearest image point" ),
		VIPS_ARGUMENT_REQUIRED_OUTPUT,
		G_STRUCT_OFFSET( VipsNearest, out ) ); 

	VIPS_ARG_IMAGE( class, "distance", 3, 
		_( "Distance" ), 
		_( "Distance to nearest image point" ),
		VIPS_ARGUMENT_OPTIONAL_OUTPUT,
		G_STRUCT_OFFSET( VipsNearest, distance ) ); 

}

static void
vips_nearest_init( VipsNearest *nearest )
{
}

/**
 * vips_nearest: (method)
 * @in: image to test
 * @out: image with zero values filled with nearest pixel
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @distance: output image of distance to nearest image pixel
 *
 * Flood outwards from every non-zero pixel in @in, setting pixels in @distance
 * and @value. 
 *
 * At the position of zero pixels in @in, @distance contains the distance to
 * the nearest non-zero pixel in @in, and @value contains the value of that
 * pixel.
 *
 * @distance is a one-band uint image. @value has the same number of bands and
 * format as @in.
 *
 * See also: vips_hist_find_indexed().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_nearest( VipsImage *in, VipsImage **out, ... ) 
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "nearest", ap, in, out );
	va_end( ap );

	return( result );
}
