/* Perlin noise generator.
 *
 * 24/7/16
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

typedef struct _VipsPerlin {
	VipsCreate parent_instance;

	int width;
	int height;
	int cell_size;
	gboolean uchar;

	int cells_across;
	int cells_down;

	/* Use this to seed this call of our rng.
	 */
	guint32 seed;
} VipsPerlin;

typedef struct _VipsPerlinClass {
	VipsCreateClass parent_class;

} VipsPerlinClass;

G_DEFINE_TYPE( VipsPerlin, vips_perlin, VIPS_TYPE_CREATE );

/* Round N down to P boundary. 
 */
#define ROUND_DOWN( N, P ) ((N) - ((N) % P)) 

/* Round N up to P boundary. 
 */
#define ROUND_UP( N, P ) (ROUND_DOWN( (N) + (P) - 1, (P) ))

/* cos and sin from an angle in 0 - 255.
 */
float vips_perlin_cos[256];
float vips_perlin_sin[256];

typedef struct _Sequence {
	VipsPerlin *perlin;

	/* The position of the last cell we were in. Use this to avoid
	 * regenerating vectors on every pixel lookup.
	 */
	int cell_x;
	int cell_y;

	/* The 2 x 2 grid of unit vectors, with cell_x/cell_y as the top left.
	 */
	float gx[4];
	float gy[4];

} Sequence;

/* A very simple random number generator. See:
 * http://isthe.com/chongo/tech/comp/fnv/#FNV-source
 */
static guint32
vips_perlin_random( guint32 seed )
{
	return( 1103515245u * seed + 12345 );
}

static guint32 
vips_perlin_seed_add( guint32 seed, int value )
{
	return( ((2166136261u ^ seed) * 16777619u) ^ value );
}

/* Generate a 3 x 3 grid of cells around a point. 
 */
static void
vips_perlin_create_cells( VipsPerlin *perlin, 
	float gx[4], float gy[4], int cell_x, int cell_y )
{
	int x, y;

	for( y = 0; y < 2; y++ ) 
		for( x = 0; x < 2; x++ ) {
			int ci = x + y * 2;

			guint32 seed;
			int cx;
			int cy;
			int angle;

			seed = perlin->seed;

			cx = cell_x + x;
			cy = cell_y + y;

			/* When we calculate the seed for this cell, we wrap
			 * around so that our output will tesselate.
			 */

			if( cy >= perlin->cells_down )
				cy = 0;
			seed = vips_perlin_seed_add( seed, cy );

			if( cx >= perlin->cells_across )
				cx = 0;
			seed = vips_perlin_seed_add( seed, cx );

			seed = vips_perlin_random( seed ); 
			angle = (seed ^ (seed >> 8) ^ (seed >> 16)) & 0xff;

			gx[ci] = vips_perlin_cos[angle];
			gy[ci] = vips_perlin_sin[angle];
		}
}

static int
vips_perlin_stop( void *vseq, void *a, void *b )
{
	Sequence *seq = (Sequence *) vseq;

	VIPS_FREE( seq );

	return( 0 );
}

static void *
vips_perlin_start( VipsImage *out, void *a, void *b )
{
	VipsPerlin *perlin = (VipsPerlin *) b;

	Sequence *seq;

	if( !(seq = VIPS_NEW( NULL, Sequence )) )
		return( NULL );

	seq->perlin = perlin;
	seq->cell_x = -1;
	seq->cell_y = -1;

	return( seq );
}

/* Smooth linear interpolation, 0 <= x <= 1.
 *
 * https://en.wikipedia.org/wiki/Smoothstep
 */
static float 
smootherstep( float x )
{
    return( x * x * x * (x * (x * 6 - 15) + 10) );
}

static int
vips_perlin_gen( VipsRegion *or, void *vseq, void *a, void *b,
	gboolean *stop )
{
	VipsPerlin *perlin = (VipsPerlin *) a;
	VipsRect *r = &or->valid;
	Sequence *seq = (Sequence *) vseq;

	int x, y;

	for( y = 0; y < r->height; y++ ) {
		float *fq = (float *) 
			VIPS_REGION_ADDR( or, r->left, r->top + y );
		VipsPel *q = (VipsPel *) fq;

		for( x = 0; x < r->width; x++ ) {
			int cs = perlin->cell_size;
			int cell_x = (r->left + x) / cs;
			int cell_y = (r->top + y) / cs;
			float dx = (x + r->left - cell_x * cs) / (float) cs;
			float dy = (y + r->top - cell_y * cs) / (float) cs;
			float sx = smootherstep( dx );
			float sy = smootherstep( dy );

			float n0, n1;
			float ix0, ix1;
			float p;

			if( cell_x != seq->cell_x ||
				cell_y != seq->cell_y ) {
				vips_perlin_create_cells( perlin, 
					seq->gx, seq->gy, cell_x, cell_y );
				seq->cell_x = cell_x;
				seq->cell_y = cell_y;
			}

			n0 = -dx * seq->gx[0] + -dy * seq->gy[0];
			n1 = (1 - dx) * seq->gx[1] + -dy * seq->gy[1];
			ix0 = n0 + sx * (n1 - n0);

			n0 = -dx * seq->gx[2] + (1 - dy) * seq->gy[2];
			n1 = (1 - dx) * seq->gx[3] + (1 - dy) * seq->gy[3];
			ix1 = n0 + sx * (n1 - n0);

			p = ix0 + sy * (ix1 - ix0);

			if( perlin->uchar )
				q[x] = 128 * p + 128;
			else
				fq[x] = p;
		}
	}

	return( 0 );
}

static int
vips_perlin_build( VipsObject *object )
{
	VipsCreate *create = VIPS_CREATE( object );
	VipsPerlin *perlin = (VipsPerlin *) object;

	if( VIPS_OBJECT_CLASS( vips_perlin_parent_class )->build( object ) )
		return( -1 );

	/* Be careful if width is a multiple of cell_size.
	 */
	perlin->cells_across = ROUND_UP( perlin->width, perlin->cell_size ) / 
		perlin->cell_size;
	perlin->cells_down = ROUND_UP( perlin->height, perlin->cell_size ) / 
		perlin->cell_size;

	perlin->seed = g_random_double() * 0xffffffffu;

	vips_image_init_fields( create->out,
		perlin->width, perlin->height, 1,
		perlin->uchar ? VIPS_FORMAT_UCHAR : VIPS_FORMAT_FLOAT, 
		VIPS_CODING_NONE, VIPS_INTERPRETATION_B_W,
		1.0, 1.0 );
	vips_image_pipelinev( create->out,
		VIPS_DEMAND_STYLE_ANY, NULL );
	if( vips_image_generate( create->out,
		vips_perlin_start, vips_perlin_gen, vips_perlin_stop, 
		perlin, NULL ) )
		return( -1 );

	return( 0 );
}

static void *
vips_perlin_make_tables( void *client )
{
	int i;

	for( i = 0; i < 256; i++ ) {
		double angle = 2 * M_PI * i / 256.0;

		vips_perlin_cos[i] = cos( angle );
		vips_perlin_sin[i] = sin( angle );
	}

	return( NULL );
}

static void
vips_perlin_class_init( VipsPerlinClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	static GOnce once = G_ONCE_INIT;

	(void) g_once( &once, vips_perlin_make_tables, NULL );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "perlin";
	vobject_class->description = _( "make a perlin noise image" );
	vobject_class->build = vips_perlin_build;

	VIPS_ARG_INT( class, "width", 2, 
		_( "Width" ), 
		_( "Image width in pixels" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsPerlin, width ),
		1, VIPS_MAX_COORD, 1 );

	VIPS_ARG_INT( class, "height", 3, 
		_( "Height" ), 
		_( "Image height in pixels" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsPerlin, height ),
		1, VIPS_MAX_COORD, 1 );

	VIPS_ARG_INT( class, "cell_size", 3, 
		_( "Cell size" ), 
		_( "Size of Perlin cells" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsPerlin, cell_size ),
		1, VIPS_MAX_COORD, 256 );

	VIPS_ARG_BOOL( class, "uchar", 4, 
		_( "Uchar" ), 
		_( "Output an unsigned char image" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsPerlin, uchar ),
		FALSE );

}

static void
vips_perlin_init( VipsPerlin *perlin )
{
	perlin->cell_size = 256;
}

/**
 * vips_perlin:
 * @out: output image
 * @width: horizontal size
 * @height: vertical size
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @cell_size: %gint, size of Perlin cells
 * * @uchar: output a uchar image
 *
 * Create a one-band float image of Perlin noise. See:
 *
 * https://en.wikipedia.org/wiki/Perlin_noise
 *
 * Use @cell_size to set the size of the cells from which the image is
 * constructed. The default is 256 x 256.
 *
 * If @width and @height are multiples of @cell_size, the image will tessellate.
 *
 * Normally, output pixels are #VIPS_FORMAT_FLOAT in the range [-1, +1]. Set 
 * @uchar to output a uchar image with pixels in [0, 255]. 
 *
 * See also: vips_worley(), vips_fractsurf(), vips_gaussnoise().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_perlin( VipsImage **out, int width, int height, ... )
{
	va_list ap;
	int result;

	va_start( ap, height );
	result = vips_call_split( "perlin", ap, out, width, height );
	va_end( ap );

	return( result );
}

