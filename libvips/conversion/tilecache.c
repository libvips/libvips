/* Simple tile or line cache.
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
 * 5/12/11
 * 	- rework as a class
 * 23/6/12
 * 	- listen for "minimise" signal
 * 23/8/12
 * 	- split to line and tile cache
 * 	- use a hash table instead of a list
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

/* A tile in our cache.
 */
typedef struct _VipsTile {
	struct _VipsBlockCache *cache;

	VipsRegion *region;		/* Region with private mem for data */

	/* Tile position. Just use left/top to calculate a hash. This is the
	 * key for the hash table. Don't use region->valid in case the region
	 * pointer is NULL.
	 */
	VipsRect pos; 

	int time;			/* Time of last use for flush */
} VipsTile;

typedef struct _VipsBlockCache {
	VipsConversion parent_instance;

	VipsImage *in;
	int tile_width;	
	int tile_height;
	int max_tiles;
	VipsCacheStrategy strategy;

	int time;			/* Update ticks for LRU here */
	int ntiles;			/* Current cache size */
	GMutex *lock;			/* Lock everything here */
	GHashTable *tiles;		/* Tiles, hashed by coordinates */
} VipsBlockCache;

typedef VipsConversionClass VipsBlockCacheClass;

G_DEFINE_TYPE( VipsBlockCache, vips_block_cache, VIPS_TYPE_CONVERSION );

#define VIPS_TYPE_BLOCK_CACHE (vips_block_cache_get_type())

static void
vips_block_cache_drop_all( VipsBlockCache *cache )
{
	g_hash_table_remove_all( cache->tiles ); 
}

static void
vips_block_cache_dispose( GObject *gobject )
{
	VipsBlockCache *cache = (VipsBlockCache *) gobject;

	vips_block_cache_drop_all( cache );
	VIPS_FREEF( g_mutex_free, cache->lock );

	G_OBJECT_CLASS( vips_block_cache_parent_class )->dispose( gobject );
}

static int
vips_tile_move( VipsTile *tile, int x, int y )
{
	/* We are changing x/y and therefore the hash value. We must unlink
	 * from the old hash position and relink at the new place.
	 */
	g_hash_table_steal( tile->cache->tiles, &tile->pos );

	tile->pos.left = x;
	tile->pos.top = y;
	tile->pos.width = tile->cache->tile_width;
	tile->pos.height = tile->cache->tile_height;

	g_hash_table_insert( tile->cache->tiles, &tile->pos, tile );

	if( vips_region_buffer( tile->region, &tile->pos ) )
		return( -1 );

	return( 0 );
}

static VipsTile *
vips_tile_new( VipsBlockCache *cache, int x, int y )
{
	VipsTile *tile;

	if( !(tile = VIPS_NEW( NULL, VipsTile )) )
		return( NULL );

	tile->cache = cache;
	tile->region = NULL;
	tile->time = cache->time;
	tile->pos.left = x;
	tile->pos.top = y;
	tile->pos.width = cache->tile_width;
	tile->pos.height = cache->tile_height;
	g_hash_table_insert( cache->tiles, &tile->pos, tile );
	g_assert( cache->ntiles >= 0 );
	cache->ntiles += 1;

	if( !(tile->region = vips_region_new( cache->in )) ) {
		g_hash_table_remove( cache->tiles, &tile->pos );
		return( NULL );
	}

	vips__region_no_ownership( tile->region );

	if( vips_tile_move( tile, x, y ) ) {
		g_hash_table_remove( cache->tiles, &tile->pos );
		return( NULL );
	}

	return( tile );
}

/* Do we have a tile in the cache?
 */
static VipsTile *
vips_tile_search( VipsBlockCache *cache, int x, int y )
{
	VipsRect pos;
	VipsTile *tile;

	pos.left = x;
	pos.top = y;
	pos.width = cache->tile_width;
	pos.height = cache->tile_height;
	tile = (VipsTile *) g_hash_table_lookup( cache->tiles, &pos );

	return( tile );
}

static void
vips_tile_touch( VipsTile *tile )
{
	g_assert( tile->cache->ntiles >= 0 );

	tile->time = tile->cache->time++;
}

/* Fill a tile with pixels.
 */
static int
vips_tile_fill( VipsTile *tile, VipsRegion *in )
{
	VIPS_DEBUG_MSG( "tilecache: filling tile %d x %d\n", 
		tile->pos.left, tile->pos.top );

	if( vips_region_prepare_to( in, tile->region, 
		&tile->pos, tile->pos.left, tile->pos.top ) ) 
		return( -1 );

	vips_tile_touch( tile );

	return( 0 );
}

typedef struct _VipsTileSearch {
	VipsTile *tile;

	int oldest;
	int topmost;
} VipsTileSearch;

void 
vips_tile_oldest( gpointer key, gpointer value, gpointer user_data )
{
	VipsTile *tile = (VipsTile *) value;
	VipsTileSearch *search = (VipsTileSearch *) user_data;

	if( tile->time < search->oldest ) {
		search->oldest = tile->time;
		search->tile = tile;
	}
}

void 
vips_tile_topmost( gpointer key, gpointer value, gpointer user_data )
{
	VipsTile *tile = (VipsTile *) value;
	VipsTileSearch *search = (VipsTileSearch *) user_data;

	if( tile->pos.top < search->topmost ) {
		search->topmost = tile->pos.top;
		search->tile = tile;
	}
}

/* Find existing tile, make a new tile, or if we have a full set of tiles, 
 * reuse LRU.
 */
static VipsTile *
vips_tile_find( VipsBlockCache *cache, VipsRegion *in, int x, int y )
{
	VipsTile *tile;
	VipsTileSearch search;

	/* In cache already?
	 */
	if( (tile = vips_tile_search( cache, x, y )) ) {
		vips_tile_touch( tile );

		return( tile );
	}

	/* VipsBlockCache not full?
	 */
	if( cache->max_tiles == -1 ||
		cache->ntiles < cache->max_tiles ) {
		if( !(tile = vips_tile_new( cache, x, y )) ||
			vips_tile_fill( tile, in ) )
			return( NULL );

		return( tile );
	}

	/* Reuse an old one.
	 */
	switch( cache->strategy ) {
	case VIPS_CACHE_RANDOM:
		search.oldest = cache->time;
		search.tile = NULL;
		g_hash_table_foreach( cache->tiles, 
			vips_tile_oldest, &search );
		tile = search.tile; 
		break;

	case VIPS_CACHE_SEQUENTIAL:
		search.topmost = cache->in->Ysize;
		search.tile = NULL;
		g_hash_table_foreach( cache->tiles, 
			vips_tile_topmost, &search );
		tile = search.tile; 
		break;

	default:
		g_assert( 0 );
	}

	g_assert( tile );

	VIPS_DEBUG_MSG( "tilecache: reusing tile %d x %d\n", 
		tile->pos.left, tile->pos.top );

	if( vips_tile_move( tile, x, y ) ||
		vips_tile_fill( tile, in ) )
		return( NULL );

	return( tile );
}

static void
vips_block_cache_minimise( VipsImage *image, VipsBlockCache *cache )
{
	vips_block_cache_drop_all( cache );
}

static int
vips_block_cache_build( VipsObject *object )
{
	VipsConversion *conversion = VIPS_CONVERSION( object );
	VipsBlockCache *cache = (VipsBlockCache *) object;

	VIPS_DEBUG_MSG( "vips_block_cache_build\n" );

	if( VIPS_OBJECT_CLASS( vips_block_cache_parent_class )->
		build( object ) )
		return( -1 );

	g_signal_connect( conversion->out, "minimise", 
		G_CALLBACK( vips_block_cache_minimise ), cache );

	return( 0 );
}

static void
vips_block_cache_class_init( VipsBlockCacheClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	VIPS_DEBUG_MSG( "vips_block_cache_class_init\n" );

	gobject_class->dispose = vips_block_cache_dispose;
	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "blockcache";
	vobject_class->description = _( "cache an image" );
	vobject_class->build = vips_block_cache_build;

	VIPS_ARG_IMAGE( class, "in", 1, 
		_( "Input" ), 
		_( "Input image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsBlockCache, in ) );

	VIPS_ARG_INT( class, "tile_height", 3, 
		_( "Tile height" ), 
		_( "Tile height in pixels" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsBlockCache, tile_height ),
		1, 1000000, 128 );

	VIPS_ARG_ENUM( class, "strategy", 3, 
		_( "Strategy" ), 
		_( "Expected access pattern" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsBlockCache, strategy ),
		VIPS_TYPE_CACHE_STRATEGY, VIPS_CACHE_RANDOM );
}

static unsigned int
vips_rect_hash( VipsRect *pos )
{
	guint hash;

	/* We could shift down by the tile size?
	 */
	hash = pos->left ^ (pos->top << 16);

	return( hash );
}

static gboolean 
vips_rect_equal( VipsRect *a, VipsRect *b )
{
	return( a->left == b->left && a->top == b->top );
}

static void
vips_tile_destroy( VipsTile *tile )
{
	VipsBlockCache *cache = tile->cache;

	cache->ntiles -= 1;
	g_assert( cache->ntiles >= 0 );
	tile->cache = NULL;

	VIPS_UNREF( tile->region );

	vips_free( tile );
}

static void
vips_block_cache_init( VipsBlockCache *cache )
{
	cache->tile_width = 128;
	cache->tile_height = 128;
	cache->max_tiles = 1000;
	cache->strategy = VIPS_CACHE_RANDOM;

	cache->time = 0;
	cache->ntiles = 0;
	cache->lock = g_mutex_new();
	cache->tiles = g_hash_table_new_full( 
		(GHashFunc) vips_rect_hash, 
		(GEqualFunc) vips_rect_equal,
		NULL,
		(GDestroyNotify) vips_tile_destroy );
}

typedef struct _VipsTileCache {
	VipsBlockCache parent_instance;

} VipsTileCache;

typedef VipsBlockCacheClass VipsTileCacheClass;

G_DEFINE_TYPE( VipsTileCache, vips_tile_cache, VIPS_TYPE_BLOCK_CACHE );

/* Also called from vips_line_cache_gen(), beware.
 */
static int
vips_tile_cache_gen( VipsRegion *or, 
	void *seq, void *a, void *b, gboolean *stop )
{
	VipsRegion *in = (VipsRegion *) seq;
	VipsBlockCache *block_cache = (VipsBlockCache *) b;
	const int tw = block_cache->tile_width;
	const int th = block_cache->tile_height;
	VipsRect *r = &or->valid;

	/* Find top left of tiles we need.
	 */
	int xs = (r->left / tw) * tw;
	int ys = (r->top / th) * th;

	int x, y;

	g_mutex_lock( block_cache->lock );

	/* If the output region fits within a tile, we could save a copy by 
	 * routing the output region directly to the tile.
	 *
	 * However this would mean that tile drop on minimise could then leave
	 * dangling pointers, if minimise were called on an active pipeline.
	 */

	VIPS_DEBUG_MSG( "vips_tile_cache_gen: "
		"left = %d, top = %d, width = %d, height = %d\n",
		r->left, r->top, r->width, r->height );

	for( y = ys; y < VIPS_RECT_BOTTOM( r ); y += th )
		for( x = xs; x < VIPS_RECT_RIGHT( r ); x += tw ) {
			VipsTile *tile;
			VipsRect tarea;
			VipsRect hit;

			if( !(tile = vips_tile_find( block_cache, 
				in, x, y )) ) {
				g_mutex_unlock( block_cache->lock );
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
			vips_region_copy( tile->region, or, &hit, 
				hit.left, hit.top ); 
		}

	g_mutex_unlock( block_cache->lock );

	return( 0 );
}

static int
vips_tile_cache_build( VipsObject *object )
{
	VipsConversion *conversion = VIPS_CONVERSION( object );
	VipsBlockCache *block_cache = (VipsBlockCache *) object;
	VipsTileCache *cache = (VipsTileCache *) object;

	VIPS_DEBUG_MSG( "vips_tile_cache_build\n" );

	if( VIPS_OBJECT_CLASS( vips_tile_cache_parent_class )->
		build( object ) )
		return( -1 );

	if( vips_image_pio_input( block_cache->in ) )
		return( -1 );

	if( vips_image_copy_fields( conversion->out, block_cache->in ) )
		return( -1 );
        vips_demand_hint( conversion->out, 
		VIPS_DEMAND_STYLE_SMALLTILE, block_cache->in, NULL );

	if( vips_image_generate( conversion->out,
		vips_start_one, vips_tile_cache_gen, vips_stop_one, 
		block_cache->in, cache ) )
		return( -1 );

	return( 0 );
}

static void
vips_tile_cache_class_init( VipsTileCacheClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	VIPS_DEBUG_MSG( "vips_tile_cache_class_init\n" );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "tilecache";
	vobject_class->description = _( "cache an image as a set of tiles" );
	vobject_class->build = vips_tile_cache_build;

	VIPS_ARG_INT( class, "tile_width", 3, 
		_( "Tile width" ), 
		_( "Tile width in pixels" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsBlockCache, tile_width ),
		1, 1000000, 128 );

	VIPS_ARG_INT( class, "max_tiles", 3, 
		_( "Max tiles" ), 
		_( "Maximum number of tiles to cache" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsBlockCache, max_tiles ),
		-1, 1000000, 1000 );

}

static void
vips_tile_cache_init( VipsTileCache *cache )
{
}

/**
 * vips_tilecache:
 * @in: input image
 * @out: output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * @tile_width: width of tiles in cache
 * @tile_height: height of tiles in cache
 * @max_tiles: maximum number of tiles to cache
 * @strategy: hint expected access pattern #VipsCacheStrategy
 *
 * This operation behaves rather like vips_copy() between images
 * @in and @out, except that it keeps a cache of computed pixels. 
 * This cache is made of up to @max_tiles tiles (a value of -1 
 * means any number of tiles), and each tile is of size @tile_width
 * by @tile_height pixels. 
 *
 * Each cache tile is made with a single call to 
 * vips_image_prepare(). 
 *
 * When the cache fills, a tile is chosen for reuse. If @strategy is
 * #VIPS_CACHE_RANDOM, then the least-recently-used tile is reused. If 
 * @strategy is #VIPS_CACHE_SEQUENTIAL, the top-most tile is reused.
 *
 * By default, @tile_width and @tile_height are 128 pixels, and the operation
 * will cache up to 1,000 tiles. @strategy defaults to #VIPS_CACHE_RANDOM.
 *
 * This is a lower-level operation than vips_image_cache() since it does no 
 * subdivision and it single-threads its callee. It is suitable for caching 
 * the output of operations like exr2vips() on tiled images.
 *
 * See also: vips_cache(), vips_linecache().
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

typedef struct _VipsLineCache {
	VipsBlockCache parent_instance;

} VipsLineCache;

typedef VipsBlockCacheClass VipsLineCacheClass;

G_DEFINE_TYPE( VipsLineCache, vips_line_cache, VIPS_TYPE_BLOCK_CACHE );

static int
vips_line_cache_gen( VipsRegion *or, 
	void *seq, void *a, void *b, gboolean *stop )
{
	VipsBlockCache *block_cache = (VipsBlockCache *) b;

	g_mutex_lock( block_cache->lock );

	/* We size up the cache to the largest request.
	 */
	if( or->valid.height > block_cache->max_tiles )
		block_cache->max_tiles = or->valid.height;

	g_mutex_unlock( block_cache->lock );

	return( vips_tile_cache_gen( or, seq, a, b, stop ) ); 
}

static int
vips_line_cache_build( VipsObject *object )
{
	VipsConversion *conversion = VIPS_CONVERSION( object );
	VipsBlockCache *block_cache = (VipsBlockCache *) object;
	VipsLineCache *cache = (VipsLineCache *) object;

	int tile_width;
	int tile_height;
	int nlines;

	VIPS_DEBUG_MSG( "vips_line_cache_build\n" );

	if( VIPS_OBJECT_CLASS( vips_line_cache_parent_class )->
		build( object ) )
		return( -1 );

	/* tile_height is set by a param, or defaulted below.
	 */
	block_cache->tile_width = block_cache->in->Xsize;

	/* Enough lines for two complete buffers.
	 *
	 * This can go up with request size, see vips_line_cache_gen().
	 */
	vips_get_tile_size( block_cache->in, 
		&tile_width, &tile_height, &nlines );
	block_cache->max_tiles = 2 * (1 + nlines / block_cache->tile_height);

	VIPS_DEBUG_MSG( "vips_line_cache_build: max_tiles = %d\n",
		block_cache->max_tiles );

	if( vips_image_pio_input( block_cache->in ) )
		return( -1 );

	if( vips_image_copy_fields( conversion->out, block_cache->in ) )
		return( -1 );
        vips_demand_hint( conversion->out, 
		VIPS_DEMAND_STYLE_THINSTRIP, block_cache->in, NULL );

	if( vips_image_generate( conversion->out,
		vips_start_one, vips_line_cache_gen, vips_stop_one, 
		block_cache->in, cache ) )
		return( -1 );

	return( 0 );
}

static void
vips_line_cache_class_init( VipsLineCacheClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	VIPS_DEBUG_MSG( "vips_line_cache_class_init\n" );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "linecache";
	vobject_class->description = _( "cache an image as a set of lines" );
	vobject_class->build = vips_line_cache_build;

}

static void
vips_line_cache_init( VipsLineCache *cache )
{
}

/**
 * vips_linecache:
 * @in: input image
 * @out: output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * @strategy: hint expected access pattern #VipsCacheStrategy
 * @tile_height: height of tiles in cache
 *
 * This operation behaves rather like vips_copy() between images
 * @in and @out, except that it keeps a cache of computed pixels. 
 * This cache is made of a set of scanlines. The number of lines cached is
 * equal to the maximum prepare request.
 *
 * Each cache tile is made with a single call to 
 * vips_image_prepare(). 
 *
 * When the cache fills, a tile is chosen for reuse. If @strategy is
 * #VIPS_CACHE_RANDOM, then the least-recently-used tile is reused. If 
 * @strategy is #VIPS_CACHE_SEQUENTIAL, the top-most tile is reused.
 * @strategy defaults to #VIPS_CACHE_RANDOM.
 *
 * @tile_height can be used to set the size of the strips that
 * vips_linecache() uses. The default is 1 (a single scanline).
 *
 * This is a lower-level operation than vips_image_cache() since it does no 
 * subdivision and it single-threads its callee. It is suitable for caching 
 * the output of operations like png load. 
 *
 * See also: vips_cache(), vips_tilecache(). 
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_linecache( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "linecache", ap, in, out );
	va_end( ap );

	return( result );
}
