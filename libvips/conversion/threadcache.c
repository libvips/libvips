/* Threaded tile cache
 *
 * A tile cache with threaded access. Manty readers coordinate tile
 * calculation. 
 *
 * 8/10/12
 * 	- from tilecache
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

/* A tile in cache can be in one of three states:
 *
 * DATA		- the tile holds valid pixels 
 * CALC		- some thread somewhere is calculating it
 * PEND		- some thread somewhere wants it
 */
typedef enum VipsTileState {
	VIPS_TILE_STATE_DATA,
	VIPS_TILE_STATE_CALC,
	VIPS_TILE_STATE_PEND
} VipsTileState;

/* A tile in our cache.
 */
typedef struct _VipsTile {
	struct _VipsThreadCache *cache;

	VipsTileState state;

	/* We count how many threads are relying on this tile. This tile can't
	 * be flushed if ref_count > 0.
	 */
	int ref_count; 

	VipsRegion *region;		/* Region with private mem for data */

	/* Tile position. Just use left/top to calculate a hash. This is the
	 * key for the hash table. Don't use region->valid in case the region
	 * pointer is NULL.
	 */
	VipsRect pos; 

	int time;			/* Time of last use for LRU */
} VipsTile;

typedef struct _VipsThreadCache {
	VipsConversion parent_instance;

	VipsImage *in;
	int tile_width;	
	int tile_height;
	int max_tiles;
	VipsCacheStrategy strategy;

	int time;			/* Update ticks for LRU here */
	int ntiles;			/* Current cache size */
	GMutex *lock;			/* Lock everything here */
	GCond *new_tile;		/* A new tile is ready */
	GHashTable *tiles;		/* Tiles, hashed by coordinates */
} VipsThreadCache;

typedef VipsConversionClass VipsThreadCacheClass;

G_DEFINE_TYPE( VipsThreadCache, vips_thread_cache, VIPS_TYPE_CONVERSION );

#define VIPS_TYPE_THREAD_CACHE (vips_thread_cache_get_type())

static void
vips_thread_cache_drop_all( VipsThreadCache *cache )
{
	g_hash_table_remove_all( cache->tiles ); 
}

static void
vips_thread_cache_dispose( GObject *gobject )
{
	VipsThreadCache *cache = (VipsThreadCache *) gobject;

	vips_thread_cache_drop_all( cache );
	VIPS_FREEF( g_mutex_free, cache->lock );
	VIPS_FREEF( g_cond_free, cache->new_tile );

	G_OBJECT_CLASS( vips_thread_cache_parent_class )->dispose( gobject );
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

	/* No data yet, but someone must want it.
	 */
	tile->state = VIPS_TILE_STATE_PEND;

	return( 0 );
}

static VipsTile *
vips_tile_new( VipsThreadCache *cache, int x, int y )
{
	VipsTile *tile;

	if( !(tile = VIPS_NEW( NULL, VipsTile )) )
		return( NULL );

	tile->cache = cache;
	tile->state = VIPS_TILE_STATE_PEND;
	tile->ref_count = 0;
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
vips_tile_search( VipsThreadCache *cache, int x, int y )
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
	tile->state = VIPS_TILE_STATE_DATA;

	vips_tile_touch( tile );

	return( 0 );
}

typedef struct _VipsTileSearch {
	VipsTile *tile;

	int oldest;
	int topmost;
} VipsTileSearch;

static void 
vips_tile_oldest( gpointer key, gpointer value, gpointer user_data )
{
	VipsTile *tile = (VipsTile *) value;
	VipsTileSearch *search = (VipsTileSearch *) user_data;

	/* Only consider unreffed tiles for recycling.
	 */
	if( !tile->ref_count &&
		tile->time < search->oldest ) {
		search->oldest = tile->time;
		search->tile = tile;
	}
}

static void 
vips_tile_topmost( gpointer key, gpointer value, gpointer user_data )
{
	VipsTile *tile = (VipsTile *) value;
	VipsTileSearch *search = (VipsTileSearch *) user_data;

	/* Only consider unreffed tiles for recycling.
	 */
	if( !tile->ref_count &&
		tile->pos.top < search->topmost ) {
		search->topmost = tile->pos.top;
		search->tile = tile;
	}
}

/* Find existing tile, make a new tile, or if we have a full set of tiles, 
 * reuse a tile.
 */
static VipsTile *
vips_tile_find( VipsThreadCache *cache, int x, int y )
{
	VipsTile *tile;
	VipsTileSearch search;

	/* In cache already?
	 */
	if( (tile = vips_tile_search( cache, x, y )) ) {
		vips_tile_touch( tile );

		return( tile );
	}

	/* VipsThreadCache not full? Make a new tile.
	 */
	if( cache->max_tiles == -1 ||
		cache->ntiles < cache->max_tiles ) {
		if( !(tile = vips_tile_new( cache, x, y )) )
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

	if( !tile ) {
		/* There are no tiles we can reuse -- we have to make another
		 * for now. They will get culled down again next time around.
		 */
		if( !(tile = vips_tile_new( cache, x, y )) ) 
			return( NULL );

		return( tile );
	}

	VIPS_DEBUG_MSG( "tilecache: reusing tile %d x %d\n", 
		tile->pos.left, tile->pos.top );

	if( vips_tile_move( tile, x, y ) )
		return( NULL );

	return( tile );
}

static gboolean            
vips_tile_unlocked( gpointer key, gpointer value, gpointer user_data )
{
	VipsTile *tile = (VipsTile *) value;

	return( !tile->ref_count );
}

static void
vips_thread_cache_minimise( VipsImage *image, VipsThreadCache *cache )
{
	/* We can't drop tiles that are in use.
	 */
	g_mutex_lock( cache->lock );

	g_hash_table_foreach_remove( cache->tiles, 
		vips_tile_unlocked, NULL );

	g_mutex_unlock( cache->lock );
}

static void
vips_thread_cache_unref( GSList *work )
{
	GSList *p;

	for( p = work; p; p = p->next ) { 
		VipsTile *tile = (VipsTile *) p->data;

		tile->ref_count -= 1;
	}

	g_slist_free( work );
}

/* Make a set of work tiles.
 */
static GSList *
vips_thread_cache_ref( VipsThreadCache *cache, VipsRect *r )
{
	const int tw = cache->tile_width;
	const int th = cache->tile_height;

	/* Find top left of tiles we need.
	 */
	const int xs = (r->left / tw) * tw;
	const int ys = (r->top / th) * th;

	GSList *work;
	VipsTile *tile;
	int x, y;

	/* Ref all the tiles we will need.
	 */
	work = NULL;
	for( y = ys; y < VIPS_RECT_BOTTOM( r ); y += th )
		for( x = xs; x < VIPS_RECT_RIGHT( r ); x += tw ) {
			if( !(tile = vips_tile_find( cache, x, y )) ) {
				vips_thread_cache_unref( work );
				return( NULL );
			}

			tile->ref_count += 1;
			work = g_slist_prepend( work, tile );

			VIPS_DEBUG_MSG( "vips_thread_cache_gen: "
				"tile %d, %d (%p)\n", x, y, tile ); 
		}

	return( work );
}

static void
vips_tile_paste( VipsTile *tile, VipsRegion *or )
{
	VipsRect hit;

	/* The part of the tile that we need.
	 */
	vips_rect_intersectrect( &or->valid, &tile->pos, &hit );
	if( !vips_rect_isempty( &hit ) )
		vips_region_copy( tile->region, or, &hit, hit.left, hit.top ); 
}

static int
vips_thread_cache_gen( VipsRegion *or, 
	void *seq, void *a, void *b, gboolean *stop )
{
	VipsRegion *in = (VipsRegion *) seq;
	VipsThreadCache *cache = (VipsThreadCache *) b;
	VipsRect *r = &or->valid;

	VipsTile *tile;
	GSList *work;
	GSList *p;

	g_mutex_lock( cache->lock );

	VIPS_DEBUG_MSG( "vips_thread_cache_gen: "
		"left = %d, top = %d, width = %d, height = %d\n",
		r->left, r->top, r->width, r->height );

	/* Ref all the tiles we will need.
	 */
	work = vips_thread_cache_ref( cache, r );

	while( work ) {
		/* Search for data tiles: easy, we can just paste those in.
		 */
		for(;;) { 
			for( p = work; p; p = p->next ) { 
				tile = (VipsTile *) p->data;

				if( tile->state == VIPS_TILE_STATE_DATA ) 
					break;
			}

			if( !p )
				break;
			
			VIPS_DEBUG_MSG( "vips_thread_cache_gen: "
					"pasting %p\n", tile ); 

			vips_tile_paste( tile, or );

			/* We're done with this tile.
			 */
			work = g_slist_remove( work, tile );
			tile->ref_count -= 1;
		}

		/* Now search for PEND tiles, we can calculate them. 
		 */
		for( p = work; p; p = p->next ) { 
			tile = (VipsTile *) p->data;

			if( tile->state == VIPS_TILE_STATE_PEND ) {
				/* Calculate this tile. Other threads can use 
				 * the cache while we calculate pixels.
				 */
				tile->state = VIPS_TILE_STATE_CALC;

				VIPS_DEBUG_MSG( "vips_thread_cache_gen: "
					"calc of %p\n", tile ); 

				g_mutex_unlock( cache->lock );

				if( vips_tile_fill( tile, in ) ) {
					vips_thread_cache_unref( work );
					return( -1 );
				}

				g_mutex_lock( cache->lock );

				/* Let everyone know there's a new DATA tile. 
				 * They need to all check their work lists.
				 */
				g_cond_broadcast( cache->new_tile );

				break;
			}
		}

		if( !p && 
			work ) {
			VIPS_DEBUG_MSG( "vips_thread_cache_gen: waiting\n" ); 

			/* All the tiles we need are being calculated. We 
			 * must block on the new-tile cond, then try again.
			 */
			g_cond_wait( cache->new_tile, cache->lock );

			VIPS_DEBUG_MSG( "vips_thread_cache_gen: awake!\n" ); 
		}
	}

	g_mutex_unlock( cache->lock );

	return( 0 );
}

static int
vips_thread_cache_build( VipsObject *object )
{
	VipsConversion *conversion = VIPS_CONVERSION( object );
	VipsThreadCache *cache = (VipsThreadCache *) object;

	VIPS_DEBUG_MSG( "vips_thread_cache_build\n" );

	if( VIPS_OBJECT_CLASS( vips_thread_cache_parent_class )->
		build( object ) )
		return( -1 );

	g_signal_connect( conversion->out, "minimise", 
		G_CALLBACK( vips_thread_cache_minimise ), cache );

	if( vips_image_pio_input( cache->in ) )
		return( -1 );

	if( vips_image_copy_fields( conversion->out, cache->in ) )
		return( -1 );
        vips_demand_hint( conversion->out, 
		VIPS_DEMAND_STYLE_SMALLTILE, cache->in, NULL );

	if( vips_image_generate( conversion->out,
		vips_start_one, vips_thread_cache_gen, vips_stop_one, 
		cache->in, cache ) )
		return( -1 );

	return( 0 );
}

static void
vips_thread_cache_class_init( VipsThreadCacheClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	VIPS_DEBUG_MSG( "vips_thread_cache_class_init\n" );

	gobject_class->dispose = vips_thread_cache_dispose;
	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "threadcache";
	vobject_class->description = _( "cache an image" );
	vobject_class->build = vips_thread_cache_build;

	VIPS_ARG_IMAGE( class, "in", 1, 
		_( "Input" ), 
		_( "Input image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsThreadCache, in ) );

	VIPS_ARG_INT( class, "tile_width", 2, 
		_( "Tile width" ), 
		_( "Tile width in pixels" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsThreadCache, tile_width ),
		1, 1000000, 128 );

	VIPS_ARG_INT( class, "tile_height", 3, 
		_( "Tile height" ), 
		_( "Tile height in pixels" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsThreadCache, tile_height ),
		1, 1000000, 128 );

	VIPS_ARG_ENUM( class, "strategy", 4, 
		_( "Strategy" ), 
		_( "Expected access pattern" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsThreadCache, strategy ),
		VIPS_TYPE_CACHE_STRATEGY, VIPS_CACHE_RANDOM );

	VIPS_ARG_INT( class, "max_tiles", 5, 
		_( "Max tiles" ), 
		_( "Maximum number of tiles to cache" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsThreadCache, max_tiles ),
		-1, 1000000, 1000 );
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
	VipsThreadCache *cache = tile->cache;

	cache->ntiles -= 1;
	g_assert( cache->ntiles >= 0 );
	tile->cache = NULL;

	VIPS_UNREF( tile->region );

	vips_free( tile );
}

static void
vips_thread_cache_init( VipsThreadCache *cache )
{
	cache->tile_width = 128;
	cache->tile_height = 128;
	cache->max_tiles = 1000;
	cache->strategy = VIPS_CACHE_RANDOM;

	cache->time = 0;
	cache->ntiles = 0;
	cache->lock = g_mutex_new();
	cache->new_tile = g_cond_new();
	cache->tiles = g_hash_table_new_full( 
		(GHashFunc) vips_rect_hash, 
		(GEqualFunc) vips_rect_equal,
		NULL,
		(GDestroyNotify) vips_tile_destroy );
}

/**
 * vips_threadcache:
 * @in: input image
 * @out: output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * @tile_width: width of tiles in cache
 * @tile_height: height of tiles in cache
 * @strategy: hint expected access pattern #VipsCacheStrategy
 * @max_tiles: maximum number of tiles to cache
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
 * Unlike vips_tilecache(), this operation does not single-thread it's callee.
 * Many tile requests can happen in parallel, and vips_threadcache()
 * coordinates them to prevent recomputation.
 *
 * See also: vips_cache(), vips_linecache().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_threadcache( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "threadcache", ap, in, out );
	va_end( ap );

	return( result );
}
