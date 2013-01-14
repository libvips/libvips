/* Tile tile cache from tiff2vips ... broken out so it can be shared with
 * openexr read.
 *
 * This isn't the same as im_cache(): we don't sub-divide, and we 
 * single-thread our callee.
 *
 * 23/8/06
 * 	- take ownership of reused tiles in case the cache is being shared
 * 13/2/07
 * 	- release ownership after fillng with pixels in case we read across
 * 	  threads
 * 4/2/10
 * 	- gtkdoc
 * 12/12/10
 * 	- use im_prepare_to() and avoid making a sequence for every cache tile
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
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

 */

/*

    These files are distributed with VIPS - http://www.vips.ecs.soton.ac.uk

 */

/* Turn on debugging output.
#define DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vips/vips.h>
#include <vips/thread.h>

/* A tile in our cache.
 */
typedef struct {
	struct _Read *read;

	REGION *region;			/* REGION with private mem for data */
	int time;			/* Time of last use for flush */
	int x;				/* xy pos in VIPS image cods */
	int y;
} Tile;

/* Stuff we track during a read.
 */
typedef struct _Read {
	/* Parameters.
	 */
	IMAGE *in;
	IMAGE *out;
	int tile_width;	
	int tile_height;
	int max_tiles;

	/* Cache.
	 */
	int time;			/* Update ticks for LRU here */
	int ntiles;			/* Current cache size */
	GMutex *lock;			/* Lock everything here */
	GSList *cache;			/* List of tiles */
} Read;

static void
tile_destroy( Tile *tile )
{
	Read *read = tile->read;

	read->cache = g_slist_remove( read->cache, tile );
	read->ntiles -= 1;
	g_assert( read->ntiles >= 0 );
	tile->read = NULL;

	IM_FREEF( im_region_free, tile->region );

	im_free( tile );
}

static void
read_destroy( Read *read )
{
	IM_FREEF( g_mutex_free, read->lock );

	while( read->cache ) {
		Tile *tile = (Tile *) read->cache->data;

		tile_destroy( tile );
	}

	im_free( read );
}

static Read *
read_new( IMAGE *in, IMAGE *out, 
	int tile_width, int tile_height, int max_tiles )
{
	Read *read;

	if( !(read = IM_NEW( NULL, Read )) )
		return( NULL );
	read->in = in;
	read->out = out;
	read->tile_width = tile_width;
	read->tile_height = tile_height;
	read->max_tiles = max_tiles;
	read->time = 0;
	read->ntiles = 0;
	read->lock = g_mutex_new();
	read->cache = NULL;

	if( im_add_close_callback( out, 
		(im_callback_fn) read_destroy, read, NULL ) ) {
		read_destroy( read );
		return( NULL );
	}

	return( read );
}

static Tile *
tile_new( Read *read )
{
	Tile *tile;

	if( !(tile = IM_NEW( NULL, Tile )) )
		return( NULL );

	tile->read = read;
	tile->region = NULL;
	tile->time = read->time;
	tile->x = -1;
	tile->y = -1;
	read->cache = g_slist_prepend( read->cache, tile );
	g_assert( read->ntiles >= 0 );
	read->ntiles += 1;

	if( !(tile->region = im_region_create( read->in )) ) {
		tile_destroy( tile );
		return( NULL );
	}
	im__region_no_ownership( tile->region );

	return( tile );
}

static int
tile_move( Tile *tile, int x, int y )
{
	Rect area;

	tile->x = x;
	tile->y = y;

	area.left = x;
	area.top = y;
	area.width = tile->read->tile_width;
	area.height = tile->read->tile_height;

	if( im_region_buffer( tile->region, &area ) )
		return( -1 );

	return( 0 );
}

/* Do we have a tile in the cache?
 */
static Tile *
tile_search( Read *read, int x, int y )
{
	GSList *p;

	for( p = read->cache; p; p = p->next ) {
		Tile *tile = (Tile *) p->data;

		if( tile->x == x && tile->y == y )
			return( tile );
	}

	return( NULL );
}

static void
tile_touch( Tile *tile )
{
	g_assert( tile->read->ntiles >= 0 );

	tile->time = tile->read->time++;
}

/* Fill a tile with pixels.
 */
static int
tile_fill( Tile *tile, REGION *in )
{
	Rect area;

#ifdef DEBUG
	printf( "im_tile_cache: filling tile %d x %d\n", tile->x, tile->y );
#endif /*DEBUG*/

	area.left = tile->x;
	area.top = tile->y;
	area.width = tile->read->tile_width;
	area.height = tile->read->tile_height;

	if( im_prepare_to( in, tile->region, &area, area.left, area.top ) ) 
		return( -1 );

	tile_touch( tile );

	return( 0 );
}

/* Find existing tile, make a new tile, or if we have a full set of tiles, 
 * reuse LRU.
 */
static Tile *
tile_find( Read *read, REGION *in, int x, int y )
{
	Tile *tile;
	int oldest;
	GSList *p;

	/* In cache already?
	 */
	if( (tile = tile_search( read, x, y )) ) {
		tile_touch( tile );

		return( tile );
	}

	/* Cache not full?
	 */
	if( read->max_tiles == -1 ||
		read->ntiles < read->max_tiles ) {
		if( !(tile = tile_new( read )) ||
			tile_move( tile, x, y ) ||
			tile_fill( tile, in ) )
			return( NULL );

		return( tile );
	}

	/* Reuse an old one.
	 */
	oldest = read->time;
	tile = NULL;
	for( p = read->cache; p; p = p->next ) {
		Tile *t = (Tile *) p->data;

		if( t->time < oldest ) {
			oldest = t->time;
			tile = t;
		}
	}

	g_assert( tile );

#ifdef DEBUG
	printf( "im_tile_cache: reusing tile %d x %d\n", tile->x, tile->y );
#endif /*DEBUG*/

	if( tile_move( tile, x, y ) ||
		tile_fill( tile, in ) )
		return( NULL );

	return( tile );
}

/* Copy rect from from to to.
 */
static void
copy_region( REGION *from, REGION *to, Rect *area )
{
	int y;

	/* Area should be inside both from and to.
	 */
	g_assert( im_rect_includesrect( &from->valid, area ) );
	g_assert( im_rect_includesrect( &to->valid, area ) );

	/* Loop down common area, copying.
	 */
	for( y = area->top; y < IM_RECT_BOTTOM( area ); y++ ) {
		PEL *p = (PEL *) IM_REGION_ADDR( from, area->left, y );
		PEL *q = (PEL *) IM_REGION_ADDR( to, area->left, y );

		memcpy( q, p, IM_IMAGE_SIZEOF_PEL( from->im ) * area->width );
	}
}

/* Loop over the output region, filling with data from cache.
 */
static int
tile_cache_fill( REGION *out, void *seq, void *a, void *b )
{
	REGION *in = (REGION *) seq;
	Read *read = (Read *) b;
	const int tw = read->tile_width;
	const int th = read->tile_height;
	Rect *r = &out->valid;

	/* Find top left of tiles we need.
	 */
	int xs = (r->left / tw) * tw;
	int ys = (r->top / th) * th;

	int x, y;

	g_mutex_lock( read->lock );

	for( y = ys; y < IM_RECT_BOTTOM( r ); y += th )
		for( x = xs; x < IM_RECT_RIGHT( r ); x += tw ) {
			Tile *tile;
			Rect tarea;
			Rect hit;

			if( !(tile = tile_find( read, in, x, y )) ) {
				g_mutex_unlock( read->lock );
				return( -1 );
			}

			/* The area of the tile.
			 */
			tarea.left = x;
			tarea.top = y;
			tarea.width = tw;
			tarea.height = th;

			/* The part of the tile that we need.
			 */
			im_rect_intersectrect( &tarea, r, &hit );

			copy_region( tile->region, out, &hit );
		}

	g_mutex_unlock( read->lock );

	return( 0 );
}

/** 
 * im_tile_cache:
 * @in: input image
 * @out: output image
 * @tile_width: tile width
 * @tile_height: tile height
 * @max_tiles: maximum number of tiles to cache
 *
 * This operation behaves rather like im_copy() between images
 * @in and @out, except that it keeps a cache of computed pixels. 
 * This cache is made of up to @max_tiles tiles (a value of -1 for
 * means any number of tiles), and each tile is of size @tile_width
 * by @tile_height pixels. Each cache tile is made with a single call to 
 * im_prepare().
 *
 * This is a lower-level operation than im_cache() since it does no 
 * subdivision. It is suitable for caching the output of operations like
 * im_exr2vips() on tiled images.
 *
 * See also: im_cache().
 *
 * Returns: 0 on success, -1 on error.
 */
int
im_tile_cache( IMAGE *in, IMAGE *out,
	int tile_width, int tile_height, int max_tiles )
{
	VipsImage *x;

	if( vips_tilecache( in, &x, 
		"tile_width", tile_width, 
		"tile_height", tile_height, 
		"max_tiles", max_tiles, 
		"strategy", VIPS_CACHE_SEQUENTIAL,
		"threaded", TRUE, 
		NULL ) )
		return( -1 );
	if( im_copy( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );

	/*
	Read *read;

	if( tile_width <= 0 || tile_height <= 0 || max_tiles < -1 ) {
		im_error( "im_tile_cache", "%s", _( "bad parameters" ) );
		return( -1 );
	}

	if( im_piocheck( in, out ) ||
		im_cp_desc( out, in ) ||
		im_demand_hint( out, IM_ANY, in, NULL ) ||
		!(read = read_new( in, out, 
			tile_width, tile_height, max_tiles )) ||
		im_generate( out, 
			im_start_one, tile_cache_fill, im_stop_one, in, read ) )
		return( -1 );

	return( 0 );
	 */

	return( im_copy( in, out ) ); 
}
