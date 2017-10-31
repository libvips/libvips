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
	int radius;

	/* Set when we know this seed cannot contribute any more values.
	 */
	gboolean dead;
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

static void
vips_nearest_seed( VipsNearest *nearest, Seed *seed )
{


	vips__draw_circle_direct( VipsImage *image, int cx, int cy, int r,
		VipsDrawScanline draw_scanline, void *client )

}

static int
vips_nearest_build( VipsObject *object )
{
	VipsMorphology *morphology = VIPS_MORPHOLOGY( object );
	VipsNearest *nearest = (VipsNearest *) object;
	VipsImage **t = (VipsImage **) vips_object_local_array( object, 2 );

	VipsImage *in;
	int ps;
	int x, y, i;

	if( VIPS_OBJECT_CLASS( vips_nearest_parent_class )->build( object ) )
		return( -1 );

	in = morphology->in;

	if( vips_image_decode( in, &t[0] ) ||
		vips_image_wio_input( t[0] ) )
		return( -1 ); 
	in = t[0];

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
				seed->radius = 0;
				seed->dead = FALSE;
			}

			p += ps;
		}
	}

#ifdef DEBUG
	printf( "found %d seeds\n", nearest->seeds->len );
#endif /*DEBUG*/

	/* Create the output and distance images in memory.
	 */
	g_object_set( object, "out", vips_image_new_memory(), NULL );
	g_object_set( object, "distance", vips_image_new_memory(), NULL );

	if( vips_black( &t[1], in->Xsize, in->Ysize, NULL ) ||
		vips_cast( t[1], &t[2], VIPS_FORMAT_UINT, NULL ) || 
		vips_image_write( t[2], nearest->distance ) )
		return( -1 );

	if( vips_image_write( in, nearest->out ) )
		return( -1 );

	while( nearest->seeds->len > 0 ) {
		for( i = 0; i < nearest->seeds->len; i++ ) 
			vips_nearest_seed( nearest, 
				&g_array_index( nearest->seeds, Seed, i ) );

		i = 0; 
		while( i < nearest->seeds->len )  {
			Seed *seed = &g_array_index( nearest->seeds, Seed, i );

			if( seed->dead )
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
 * * @distance: distance to nearest image pixel
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
