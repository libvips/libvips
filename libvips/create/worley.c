/* Worley noise generator.
 *
 * 19/7/16
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
#define VIPS_DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>

#include <vips/vips.h>

#include "pcreate.h"

typedef struct _VipsWorley {
	VipsCreate parent_instance;

	int width;
	int height;
	int cell_size;

	int cells_across;
	int cells_down;

	/* Use this to seed this call of our rng.
	 */
	guint32 seed;
} VipsWorley;

typedef struct _VipsWorleyClass {
	VipsCreateClass parent_class;

} VipsWorleyClass;

G_DEFINE_TYPE( VipsWorley, vips_worley, VIPS_TYPE_CREATE );

#define MAX_FEATURES (10)

/* Round N down to P boundary. 
 */
#define ROUND_DOWN( N, P ) ((N) - ((N) % P)) 

/* Round N up to P boundary. 
 */
#define ROUND_UP( N, P ) (ROUND_DOWN( (N) + (P) - 1, (P) ))

typedef struct _Cell {
	/* Cell position, in number of cells. Scale by cell_size to get
	 * absolute image cods.
	 */
	int cell_x;
	int cell_y;

	/* A cell contains 1 to n features.
	 */
	int n_features;

	/* Feature coordinates, in absolute image space.
	 */
	int feature_x[MAX_FEATURES];
	int feature_y[MAX_FEATURES];
} Cell;

typedef struct _Sequence {
	VipsWorley *worley;

	/* The position of the last cell we were in. Use this to avoid
	 * regenerating cells on every pixel lookup.
	 */
	int cell_x;
	int cell_y;

	/* The 3 x 3 grid of cells around the current point.
	 */
	Cell cells[9];

} Sequence;

/* A very simple random number generator. See:
 * http://isthe.com/chongo/tech/comp/fnv/#FNV-source
 */
static guint32
vips_worley_random( guint32 seed )
{
	return( 1103515245u * seed + 12345 );
}

static guint32 
vips_worley_seed_add( guint32 seed, int value )
{
	return( ((2166136261u ^ seed) * 16777619u) ^ value );
}

/* Generate a 3 x 3 grid of cells around a point. 
 */
static void
vips_worley_create_cells( VipsWorley *worley, 
	Cell cells[9], int cell_x, int cell_y )
{
	int x, y;

	for( y = 0; y < 3; y++ ) 
		for( x = 0; x < 3; x++ ) {
			Cell *cell = &cells[x + y * 3];

			guint32 seed;
			int value;
			int j;

			/* Can go <0 and >width for edges.
			 */
			cell->cell_x = cell_x + x - 1;
			cell->cell_y = cell_y + y - 1;

			seed = worley->seed;

			/* When we calculate the seed for this cell, we wrap
			 * around so that our output will tesselate.
			 */
			if( cell->cell_x >= worley->cells_across )
				value = 0;
			else if( cell->cell_x < 0 )
				value = worley->cells_across - 1;
			else 
				value = cell->cell_x;
			seed = vips_worley_seed_add( seed, value );

			if( cell->cell_y >= worley->cells_down )
				value = 0;
			else if( cell->cell_y < 0 )
				value = worley->cells_down - 1;
			else 
				value = cell->cell_y;
			seed = vips_worley_seed_add( seed, value );

			/* [1, MAX_FEATURES)
			 */
			seed = vips_worley_random( seed ); 
			cell->n_features = (seed % (MAX_FEATURES - 1)) + 1;

			for( j = 0; j < cell->n_features; j++ ) {
				seed = vips_worley_random( seed ); 
				cell->feature_x[j] = 
					cell->cell_x * worley->cell_size + 
					seed % worley->cell_size;

				seed = vips_worley_random( seed ); 
				cell->feature_y[j] = 
					cell->cell_y * worley->cell_size + 
					seed % worley->cell_size;
			}
		}
}

static int
vips_worley_stop( void *vseq, void *a, void *b )
{
	Sequence *seq = (Sequence *) vseq;

	VIPS_FREE( seq );

	return( 0 );
}

static void *
vips_worley_start( VipsImage *out, void *a, void *b )
{
	VipsWorley *worley = (VipsWorley *) b;

	Sequence *seq;

	if( !(seq = VIPS_NEW( NULL, Sequence )) )
		return( NULL );

	seq->worley = worley;
	seq->cell_x = -1;
	seq->cell_y = -1;

	return( seq );
}

static int
vips_hypot( int x, int y )
{
	/* Faster than hypot() for int args.
	 */
	return( sqrt( x * x + y * y ) );
}

static int
vips_worley_distance( VipsWorley *worley, Cell cells[9], int x, int y )
{
	int distance;

	int i, j;

	distance = worley->cell_size * 1.5;

	for( i = 0; i < 9; i++ ) {
		Cell *cell = &cells[i];

		for( j = 0; j < cell->n_features; j++ ) {
			int d = vips_hypot( 
				x - cell->feature_x[j], 
				y - cell->feature_y[j] );

			distance = VIPS_MIN( distance, d );
		}
	}

	return( distance );
}

static int
vips_worley_gen( VipsRegion *or, void *vseq, void *a, void *b,
	gboolean *stop )
{
	VipsWorley *worley = (VipsWorley *) a;
	VipsRect *r = &or->valid;
	Sequence *seq = (Sequence *) vseq;

	int x, y;

	for( y = 0; y < r->height; y++ ) {
		int *q = (int *) VIPS_REGION_ADDR( or, r->left, r->top + y );

		for( x = 0; x < r->width; x++ ) {
			int cell_x = (r->left + x) / worley->cell_size;
			int cell_y = (r->top + y) / worley->cell_size;

			if( cell_x != seq->cell_x ||
				cell_y != seq->cell_y ) {
				vips_worley_create_cells( worley, 
					seq->cells, cell_x, cell_y );
				seq->cell_x = cell_x;
				seq->cell_y = cell_y;
			}

			q[x] = vips_worley_distance( worley, seq->cells, 
				r->left + x, r->top + y );
		}
	}

	return( 0 );
}

static int
vips_worley_build( VipsObject *object )
{
	VipsCreate *create = VIPS_CREATE( object );
	VipsWorley *worley = (VipsWorley *) object;

	if( VIPS_OBJECT_CLASS( vips_worley_parent_class )->build( object ) )
		return( -1 );

	/* Be careful if width is a multiple of cell_size.
	 */
	worley->cells_across = ROUND_UP( worley->width, worley->cell_size ) / 
		worley->cell_size;
	worley->cells_down = ROUND_UP( worley->height, worley->cell_size ) / 
		worley->cell_size;

	worley->seed = g_random_double() * 0xffffffffu;

	vips_image_init_fields( create->out,
		worley->width, worley->height, 1,
		VIPS_FORMAT_INT, VIPS_CODING_NONE, VIPS_INTERPRETATION_B_W,
		1.0, 1.0 );
	vips_image_pipelinev( create->out,
		VIPS_DEMAND_STYLE_ANY, NULL );
	if( vips_image_generate( create->out,
		vips_worley_start, vips_worley_gen, vips_worley_stop, 
		worley, NULL ) )
		return( -1 );

	return( 0 );
}

static void
vips_worley_class_init( VipsWorleyClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "worley";
	vobject_class->description = _( "make a worley image" );
	vobject_class->build = vips_worley_build;

	VIPS_ARG_INT( class, "width", 2, 
		_( "Width" ), 
		_( "Image width in pixels" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsWorley, width ),
		1, VIPS_MAX_COORD, 1 );

	VIPS_ARG_INT( class, "height", 3, 
		_( "Height" ), 
		_( "Image height in pixels" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsWorley, height ),
		1, VIPS_MAX_COORD, 1 );

	VIPS_ARG_INT( class, "cell_size", 3, 
		_( "Cell size" ), 
		_( "Size of Worley cells" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsWorley, cell_size ),
		1, VIPS_MAX_COORD, 256 );

}

static void
vips_worley_init( VipsWorley *worley )
{
	worley->cell_size = 256;
}

/**
 * vips_worley:
 * @out: output image
 * @width: horizontal size
 * @height: vertical size
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @cell_size: %gint, size of Worley cells
 *
 * Create a one-band int image of Worley noise. See:
 *
 * https://en.wikipedia.org/wiki/Worley_noise
 *
 * Use @cell_size to set the size of the cells from which the image is
 * constructed. The default is 256 x 256.
 *
 * If @width and @height are multiples of @cell_size, the image will tessellate.
 *
 * See also: vips_gaussnoise().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_worley( VipsImage **out, int width, int height, ... )
{
	va_list ap;
	int result;

	va_start( ap, height );
	result = vips_call_split( "worley", ap, out, width, height );
	va_end( ap );

	return( result );
}

