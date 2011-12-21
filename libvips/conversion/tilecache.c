/* Tile cache from tiff2vips ... broken out so it can be shared with
 * openexr read.
 *
 * This isn't the same as the sinkscreen cache: we don't sub-divide, and we 
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
 * 5/12/12
 * 	- rework as a class
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

    You should have received a cache of the GNU Lesser General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

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
#include <stdlib.h>
#include <string.h>

#include <vips/vips.h>
#include <vips/internal.h>
#include <vips/debug.h>

#include "conversion.h"

/* Lower and upper bounds for tile cache size. Choose an exact number based on
 * tile size.
 */
#define VIPS_MAX_TILE_CACHE (250)
#define VIPS_MIN_TILE_CACHE (5)

/* A tile in our cache.
 */
typedef struct {
	struct _VipsTileCache *cache;

	VipsRegion *region;		/* Region with private mem for data */
	int time;			/* Time of last use for flush */
	int x;				/* xy pos in VIPS image cods */
	int y;
} Tile;

typedef struct _VipsTileCache {
	VipsConversion parent_instance;

	VipsImage *in;
	int tile_width;	
	int tile_height;
	int max_tiles;

	/* VipsTileCache.
	 */
	int time;			/* Update ticks for LRU here */
	int ntiles;			/* Current cache size */
	GMutex *lock;			/* Lock everything here */
	GSList *tiles;			/* List of tiles */
} VipsTileCache;

typedef VipsConversionClass VipsTileCacheClass;

G_DEFINE_TYPE( VipsTileCache, vips_tile_cache, VIPS_TYPE_CONVERSION );

static void
tile_destroy( Tile *tile )
{
	VipsTileCache *cache = tile->cache;

	cache->tiles = g_slist_remove( cache->tiles, tile );
	cache->ntiles -= 1;
	g_assert( cache->ntiles >= 0 );
	tile->cache = NULL;

	VIPS_UNREF( tile->region );

	vips_free( tile );
}

static void
vips_tile_cache_dispose( GObject *gobject )
{
	VipsTileCache *cache = (VipsTileCache *) gobject;

	while( cache->tiles ) {
		Tile *tile = (Tile *) cache->tiles->data;

		tile_destroy( tile );
	}

	VIPS_FREEF( g_mutex_free, cache->lock );

	G_OBJECT_CLASS( vips_tile_cache_parent_class )->dispose( gobject );
}

static Tile *
tile_new( VipsTileCache *cache )
{
	Tile *tile;

	if( !(tile = VIPS_NEW( NULL, Tile )) )
		return( NULL );

	tile->cache = cache;
	tile->region = NULL;
	tile->time = cache->time;
	tile->x = -1;
	tile->y = -1;
	cache->tiles = g_slist_prepend( cache->tiles, tile );
	g_assert( cache->ntiles >= 0 );
	cache->ntiles += 1;

	if( !(tile->region = vips_region_new( cache->in )) ) {
		tile_destroy( tile );
		return( NULL );
	}
	vips__region_no_ownership( tile->region );

	return( tile );
}

static int
tile_move( Tile *tile, int x, int y )
{
	VipsRect area;

	tile->x = x;
	tile->y = y;

	area.left = x;
	area.top = y;
	area.width = tile->cache->tile_width;
	area.height = tile->cache->tile_height;

	if( vips_region_buffer( tile->region, &area ) )
		return( -1 );

	return( 0 );
}

/* Do we have a tile in the cache?
 */
static Tile *
tile_search( VipsTileCache *cache, int x, int y )
{
	GSList *p;

	for( p = cache->tiles; p; p = p->next ) {
		Tile *tile = (Tile *) p->data;

		if( tile->x == x && tile->y == y )
			return( tile );
	}

	return( NULL );
}

static void
tile_touch( Tile *tile )
{
	g_assert( tile->cache->ntiles >= 0 );

	tile->time = tile->cache->time++;
}

/* Fill a tile with pixels.
 */
static int
tile_fill( Tile *tile, VipsRegion *in )
{
	VipsRect area;

	VIPS_DEBUG_MSG( "tilecache: filling tile %d x %d\n", tile->x, tile->y );

	area.left = tile->x;
	area.top = tile->y;
	area.width = tile->cache->tile_width;
	area.height = tile->cache->tile_height;

	if( vips_region_prepare_to( in, tile->region, 
		&area, area.left, area.top ) ) 
		return( -1 );

	tile_touch( tile );

	return( 0 );
}

/* Find existing tile, make a new tile, or if we have a full set of tiles, 
 * reuse LRU.
 */
static Tile *
tile_find( VipsTileCache *cache, VipsRegion *in, int x, int y )
{
	Tile *tile;
	int oldest;
	GSList *p;

	/* In cache already?
	 */
	if( (tile = tile_search( cache, x, y )) ) {
		tile_touch( tile );

		return( tile );
	}

	/* VipsTileCache not full?
	 */
	if( cache->max_tiles == -1 ||
		cache->ntiles < cache->max_tiles ) {
		if( !(tile = tile_new( cache )) ||
			tile_move( tile, x, y ) ||
			tile_fill( tile, in ) )
			return( NULL );

		return( tile );
	}

	/* Reuse an old one.
	 */
	oldest = cache->time;
	tile = NULL;
	for( p = cache->tiles; p; p = p->next ) {
		Tile *t = (Tile *) p->data;

		if( t->time < oldest ) {
			oldest = t->time;
			tile = t;
		}
	}

	g_assert( tile );

	VIPS_DEBUG_MSG( "tilecache: reusing tile %d x %d\n", tile->x, tile->y );

	if( tile_move( tile, x, y ) ||
		tile_fill( tile, in ) )
		return( NULL );

	return( tile );
}

/* Copy rect from from to to.
 */
static void
copy_region( VipsRegion *from, VipsRegion *to, VipsRect *area )
{
	int y;

	/* Area should be inside both from and to.
	 */
	g_assert( vips_rect_includesrect( &from->valid, area ) );
	g_assert( vips_rect_includesrect( &to->valid, area ) );

	/* Loop down common area, copying.
	 */
	for( y = area->top; y < VIPS_RECT_BOTTOM( area ); y++ ) {
		PEL *p = (PEL *) VIPS_REGION_ADDR( from, area->left, y );
		PEL *q = (PEL *) VIPS_REGION_ADDR( to, area->left, y );

		memcpy( q, p, VIPS_IMAGE_SIZEOF_PEL( from->im ) * area->width );
	}
}

/* Generate func.
 */
static int
vips_tile_cache_gen( VipsRegion *or, 
	void *seq, void *a, void *b, gboolean *stop )
{
	VipsRegion *in = (VipsRegion *) seq;
	VipsTileCache *cache = (VipsTileCache *) b;
	const int tw = cache->tile_width;
	const int th = cache->tile_height;
	VipsRect *r = &or->valid;

	/* Find top left of tiles we need.
	 */
	int xs = (r->left / tw) * tw;
	int ys = (r->top / th) * th;

	int x, y;

	g_mutex_lock( cache->lock );

	for( y = ys; y < VIPS_RECT_BOTTOM( r ); y += th )
		for( x = xs; x < VIPS_RECT_RIGHT( r ); x += tw ) {
			Tile *tile;
			VipsRect tarea;
			VipsRect hit;

			if( !(tile = tile_find( cache, in, x, y )) ) {
				g_mutex_unlock( cache->lock );
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
			vips_rect_intersectrect( &tarea, r, &hit );

			copy_region( tile->region, or, &hit );
		}

	g_mutex_unlock( cache->lock );

	return( 0 );
}

static int
vips_tile_cache_build( VipsObject *object )
{
	VipsConversion *conversion = VIPS_CONVERSION( object );
	VipsTileCache *cache = (VipsTileCache *) object;

	VIPS_DEBUG_MSG( "vips_tile_cache_build\n" );

	if( VIPS_OBJECT_CLASS( vips_tile_cache_parent_class )->build( object ) )
		return( -1 );

	if( vips_image_pio_input( cache->in ) )
		return( -1 );

	if( vips_image_copy_fields( conversion->out, cache->in ) )
		return( -1 );
        vips_demand_hint( conversion->out, 
		VIPS_DEMAND_STYLE_SMALLTILE, cache->in, NULL );

	if( vips_image_generate( conversion->out,
		vips_start_one, vips_tile_cache_gen, vips_stop_one, 
		cache->in, cache ) )
		return( -1 );

	return( 0 );
}

static void
vips_tile_cache_class_init( VipsTileCacheClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	VIPS_DEBUG_MSG( "vips_tile_cache_class_init\n" );

	gobject_class->dispose = vips_tile_cache_dispose;
	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "tilecache";
	vobject_class->description = _( "cache an image" );
	vobject_class->build = vips_tile_cache_build;

	VIPS_ARG_IMAGE( class, "in", 1, 
		_( "Input" ), 
		_( "Input image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsTileCache, in ) );

	VIPS_ARG_INT( class, "tile_width", 3, 
		_( "Tile width" ), 
		_( "Tile width in pixels" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsTileCache, tile_width ),
		1, 1000000, 128 );

	VIPS_ARG_INT( class, "tile_height", 3, 
		_( "Tile height" ), 
		_( "Tile height in pixels" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsTileCache, tile_height ),
		1, 1000000, 128 );

	VIPS_ARG_INT( class, "max_tiles", 3, 
		_( "Max tiles" ), 
		_( "Maximum number of tiles to cache" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsTileCache, max_tiles ),
		-1, 1000000, 1000 );

}

static void
vips_tile_cache_init( VipsTileCache *cache )
{
	cache->tile_width = 128;
	cache->tile_height = 128;
	cache->max_tiles = 1000;
	cache->time = 0;
	cache->ntiles = 0;
	cache->lock = g_mutex_new();
	cache->tiles = NULL;
}

/**
 * vips_tilecache:
 * @in: input image
 * @out: output image
 * @tile_width: width of tiles in cache
 * @tile_height: height of tiles in cache
 * @max_tiles: maximum number of tiles to cache
 * @...: %NULL-terminated list of optional named arguments
 *
 * This operation behaves rather like vips_copy() between images
 * @in and @out, except that it keeps a cache of computed pixels. 
 * This cache is made of up to @max_tiles tiles (a value of -1 
 * means any number of tiles), and each tile is of size @tile_width
 * by @tile_height pixels. Each cache tile is made with a single call to 
 * vips_image_prepare().
 *
 * By default, @tile_width and @tile_height are 128 pixels, and the operation
 * will cache up to 1,000 tiles.
 *
 * This is a lower-level operation than vips_image_cache() since it does no 
 * subdivision and it single-threads its callee. It is suitable for caching 
 * the output of operations like exr2vips() on tiled images.
 *
 * See also: vips_image_cache().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_tilecache( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "tilecache", ap, in, out );
	va_end( ap );

	return( result );
}
