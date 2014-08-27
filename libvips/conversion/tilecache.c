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
 * 13/9/12
 * 	- oops, linecache was oversized
 * 12/11/12
 * 	- make linecache 50% larger to give some slop room
 * 8/10/12
 * 	- make it optionally threaded
 * 21/2/13
 * 	- could deadlock if downstream raised an error (thanks Todd)
 * 25/4/13
 * 	- cache minimisation is optional, see "persistent" flag
 * 26/8/14 Lovell
 * 	- free the hash table in _dispose()
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
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
    02110-1301  USA

 */

/*

    These files are distributed with VIPS - http://www.vips.ecs.soton.ac.uk

 */

/*
#define VIPS_DEBUG_RED
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

#include "pconversion.h"

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
	struct _VipsBlockCache *cache;

	VipsTileState state;

	VipsRegion *region;		/* Region with private mem for data */

	/* We count how many threads are relying on this tile. This tile can't
	 * be flushed if ref_count > 0.
	 */
	int ref_count; 

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
	VipsAccess access;
	gboolean threaded;
	gboolean persistent;

	int time;			/* Update ticks for LRU here */
	int ntiles;			/* Current cache size */
	GMutex *lock;			/* Lock everything here */
	GCond *new_tile;		/* A new tile is ready */
	GHashTable *tiles;		/* Tiles, hashed by coordinates */
} VipsBlockCache;

typedef VipsConversionClass VipsBlockCacheClass;

G_DEFINE_TYPE( VipsBlockCache, vips_block_cache, VIPS_TYPE_CONVERSION );

#define VIPS_TYPE_BLOCK_CACHE (vips_block_cache_get_type())

static void
vips_block_cache_drop_all( VipsBlockCache *cache )
{
	/* FIXME this is a disaster if active threads are working on tiles. We
	 * should have something to block new requests, and only dispose once
	 * all tiles are unreffed.
	 */
	g_hash_table_remove_all( cache->tiles ); 
}

static void
vips_block_cache_dispose( GObject *gobject )
{
	VipsBlockCache *cache = (VipsBlockCache *) gobject;

	vips_block_cache_drop_all( cache );
	VIPS_FREEF( vips_g_mutex_free, cache->lock );
	VIPS_FREEF( vips_g_cond_free, cache->new_tile );

	if( cache->tiles )
		g_assert( g_hash_table_size( cache->tiles ) == 0 );
	VIPS_FREEF( g_hash_table_destroy, cache->tiles );

	G_OBJECT_CLASS( vips_block_cache_parent_class )->dispose( gobject );
}

static void
vips_tile_touch( VipsTile *tile )
{
	g_assert( tile->cache->ntiles >= 0 );

	tile->time = tile->cache->time++;
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
vips_tile_new( VipsBlockCache *cache, int x, int y )
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

typedef struct _VipsTileSearch {
	VipsTile *tile;

	int oldest;
	int topmost;
} VipsTileSearch;

static void 
vips_tile_search_recycle( gpointer key, gpointer value, gpointer user_data )
{
	VipsTile *tile = (VipsTile *) value;
	VipsBlockCache *cache = tile->cache;
	VipsTileSearch *search = (VipsTileSearch *) user_data;

	/* Only consider unreffed tiles for recycling.
	 */
	if( !tile->ref_count ) {
		switch( cache->access ) {
		case VIPS_ACCESS_RANDOM:
			if( tile->time < search->oldest ) {
				search->oldest = tile->time;
				search->tile = tile;
			}
			break;

		case VIPS_ACCESS_SEQUENTIAL:
		case VIPS_ACCESS_SEQUENTIAL_UNBUFFERED:
			if( tile->pos.top < search->topmost ) {
				search->topmost = tile->pos.top;
				search->tile = tile;
			}
			break;

		default:
			g_assert( 0 );
		}
	}
}

/* Find existing tile, make a new tile, or if we have a full set of tiles, 
 * reuse one.
 */
static VipsTile *
vips_tile_find( VipsBlockCache *cache, int x, int y )
{
	VipsTile *tile;
	VipsTileSearch search;

	/* In cache already?
	 */
	if( (tile = vips_tile_search( cache, x, y )) ) {
		VIPS_DEBUG_MSG_RED( "vips_tile_find: "
			"tile %d x %d in cache\n", x, y ); 
		return( tile );
	}

	/* VipsBlockCache not full?
	 */
	if( cache->max_tiles == -1 ||
		cache->ntiles < cache->max_tiles ) {
		VIPS_DEBUG_MSG_RED( "vips_tile_find: "
			"making new tile at %d x %d\n", x, y ); 
		if( !(tile = vips_tile_new( cache, x, y )) )
			return( NULL );

		return( tile );
	}

	/* Reuse an old one.
	 */
	search.oldest = cache->time;
	search.topmost = cache->in->Ysize;
	search.tile = NULL;
	g_hash_table_foreach( cache->tiles, vips_tile_search_recycle, &search );
	tile = search.tile; 

	if( !tile ) {
		/* There are no tiles we can reuse -- we have to make another
		 * for now. They will get culled down again next time around.
		 */
		if( !(tile = vips_tile_new( cache, x, y )) ) 
			return( NULL );

		return( tile );
	}

	VIPS_DEBUG_MSG_RED( "vips_tile_find: reusing tile %d x %d\n", 
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
vips_block_cache_minimise( VipsImage *image, VipsBlockCache *cache )
{
	/* We can't drop tiles that are in use.
	 */
	g_mutex_lock( cache->lock );

	g_hash_table_foreach_remove( cache->tiles, 
		vips_tile_unlocked, NULL );

	g_mutex_unlock( cache->lock );
}

static int
vips_block_cache_build( VipsObject *object )
{
	VipsConversion *conversion = VIPS_CONVERSION( object );
	VipsBlockCache *cache = (VipsBlockCache *) object;

	VIPS_DEBUG_MSG( "vips_block_cache_build:\n" );

	if( VIPS_OBJECT_CLASS( vips_block_cache_parent_class )->
		build( object ) )
		return( -1 );

	VIPS_DEBUG_MSG( "vips_block_cache_build: max size = %g MB\n",
		(cache->max_tiles * cache->tile_width * cache->tile_height *
		 	VIPS_IMAGE_SIZEOF_PEL( cache->in )) / (1024 * 1024.0) );

	if( !cache->persistent )
		g_signal_connect( conversion->out, "minimise", 
			G_CALLBACK( vips_block_cache_minimise ), cache );

	return( 0 );
}

static void
vips_block_cache_class_init( VipsBlockCacheClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );
	VipsOperationClass *operation_class = VIPS_OPERATION_CLASS( class );

	VIPS_DEBUG_MSG( "vips_block_cache_class_init\n" );

	gobject_class->dispose = vips_block_cache_dispose;
	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "blockcache";
	vobject_class->description = _( "cache an image" );
	vobject_class->build = vips_block_cache_build;

	operation_class->flags = VIPS_OPERATION_SEQUENTIAL;

	VIPS_ARG_IMAGE( class, "in", 1, 
		_( "Input" ), 
		_( "Input image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsBlockCache, in ) );

	VIPS_ARG_INT( class, "tile_height", 4, 
		_( "Tile height" ), 
		_( "Tile height in pixels" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsBlockCache, tile_height ),
		1, 1000000, 128 );

	VIPS_ARG_ENUM( class, "access", 6, 
		_( "Access" ), 
		_( "Expected access pattern" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsBlockCache, access ),
		VIPS_TYPE_ACCESS, VIPS_ACCESS_RANDOM );

	VIPS_ARG_BOOL( class, "threaded", 7, 
		_( "Threaded" ), 
		_( "Allow threaded access" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsBlockCache, threaded ),
		FALSE );

	VIPS_ARG_BOOL( class, "persistent", 8, 
		_( "Persistent" ), 
		_( "Keep cache between evaluations" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsBlockCache, persistent ),
		FALSE );
}

static unsigned int
vips_rect_hash( VipsRect *pos )
{
	guint hash;

	/* We could shift down by the tile size?
	 *
	 * X discrimination is more important than Y, since
	 * most tiles will have a similar Y. 
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

	VIPS_DEBUG_MSG_RED( "vips_tile_destroy: tile %d, %d (%p)\n", 
		tile->pos.left, tile->pos.top, tile ); 

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
	cache->access = VIPS_ACCESS_RANDOM;
	cache->threaded = FALSE;
	cache->persistent = FALSE;

	cache->time = 0;
	cache->ntiles = 0;
	cache->lock = vips_g_mutex_new();
	cache->new_tile = vips_g_cond_new();
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

static void
vips_tile_unref( VipsTile *tile )
{
	g_assert( tile->ref_count > 0 );

	tile->ref_count -= 1;
}

static void
vips_tile_ref( VipsTile *tile )
{
	tile->ref_count += 1;

	g_assert( tile->ref_count > 0 );
}

static void
vips_tile_cache_unref( GSList *work )
{
	GSList *p;

	for( p = work; p; p = p->next ) 
		vips_tile_unref( (VipsTile *) p->data ); 

	g_slist_free( work );
}

/* Make a set of work tiles.
 */
static GSList *
vips_tile_cache_ref( VipsBlockCache *cache, VipsRect *r )
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
				vips_tile_cache_unref( work );
				return( NULL );
			}

			vips_tile_touch( tile );

			vips_tile_ref( tile ); 

			/* We must append, since we want to keep tile ordering
			 * for sequential sources.
			 */
			work = g_slist_append( work, tile );

			VIPS_DEBUG_MSG_RED( "vips_tile_cache_ref: "
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

/* Also called from vips_line_cache_gen(), beware.
 */
static int
vips_tile_cache_gen( VipsRegion *or, 
	void *seq, void *a, void *b, gboolean *stop )
{
	VipsRegion *in = (VipsRegion *) seq;
	VipsBlockCache *cache = (VipsBlockCache *) b;
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( cache );
	VipsRect *r = &or->valid;

	VipsTile *tile;
	GSList *work;
	GSList *p;

	VIPS_GATE_START( "vips_tile_cache_gen: wait1" );

	g_mutex_lock( cache->lock );

	VIPS_GATE_STOP( "vips_tile_cache_gen: wait1" );

	VIPS_DEBUG_MSG_RED( "vips_tile_cache_gen: "
		"left = %d, top = %d, width = %d, height = %d\n",
		r->left, r->top, r->width, r->height );

	/* Ref all the tiles we will need.
	 */
	work = vips_tile_cache_ref( cache, r );

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

			VIPS_DEBUG_MSG_RED( "vips_tile_cache_gen: "
				"pasting %p\n", tile ); 

			vips_tile_paste( tile, or );

			/* We're done with this tile.
			 */
			work = g_slist_remove( work, tile );
			vips_tile_unref( tile ); 
		}

		/* Calculate the first PEND tile we find on the work list. We
		 * don't calculate all PEND tiles since after the first, more
		 * DATA tiles might heve been made available by other threads
		 * and we want to get them out of the way as soon as we can.
		 */
		for( p = work; p; p = p->next ) { 
			tile = (VipsTile *) p->data;

			if( tile->state == VIPS_TILE_STATE_PEND ) {
				int result;

				tile->state = VIPS_TILE_STATE_CALC;

				VIPS_DEBUG_MSG_RED( "vips_tile_cache_gen: "
					"calc of %p\n", tile ); 

				/* In threaded mode, we let other threads run
				 * while we calc this tile. In non-threaded
				 * mode, we keep the lock and make 'em wait.
				 */
				if( cache->threaded ) 
					g_mutex_unlock( cache->lock );

				result = vips_region_prepare_to( in, 
					tile->region, 
					&tile->pos, 
					tile->pos.left, tile->pos.top );

				if( cache->threaded ) {
					VIPS_GATE_START( "vips_tile_cache_gen: "
						"wait2" );

					g_mutex_lock( cache->lock );

					VIPS_GATE_STOP( "vips_tile_cache_gen: "
						"wait2" );
				}

				/* If there was an error calculating this
				 * tile, just warn and carry on.
				 *
				 * This can happen with things like reading
				 * .scn files via openslide. We don't want the
				 * read to fail because of one broken tile.
				 */
				if( result ) {
					VIPS_DEBUG_MSG_RED( 
						"vips_tile_cache_gen: "
						"error on tile %p\n", tile ); 

					vips_warn( class->nickname,
						_( "error reading tile %dx%d: "
							"%s" ),
						tile->pos.left, tile->pos.top,
						vips_error_buffer() ); 
					vips_error_clear();

					vips_region_black( tile->region );
				}

				tile->state = VIPS_TILE_STATE_DATA;

				vips_tile_touch( tile );

				/* Let everyone know there's a new DATA tile. 
				 * They need to all check their work lists.
				 */
				g_cond_broadcast( cache->new_tile );

				break;
			}
		}

		/* There are no PEND or DATA tiles, we must need a tile some
		 * other thread is currently calculating.
		 *
		 * We must block until the CALC tiles we need are done.
		 */
		if( !p && 
			work ) {
			for( p = work; p; p = p->next ) { 
				tile = (VipsTile *) p->data;

				g_assert( tile->state == VIPS_TILE_STATE_CALC );
			}

			VIPS_DEBUG_MSG_RED( "vips_tile_cache_gen: waiting\n" ); 

			VIPS_GATE_START( "vips_tile_cache_gen: wait3" );

			g_cond_wait( cache->new_tile, cache->lock );

			VIPS_GATE_STOP( "vips_tile_cache_gen: wait3" );

			VIPS_DEBUG_MSG( "vips_tile_cache_gen: awake!\n" ); 
		}
	}

	g_mutex_unlock( cache->lock );

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

	if( vips_image_pipelinev( conversion->out, 
		VIPS_DEMAND_STYLE_SMALLTILE, block_cache->in, NULL ) )
		return( -1 );

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

	VIPS_ARG_INT( class, "max_tiles", 5, 
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
 * @access: hint expected access pattern #VipsAccess
 * @threaded: allow many threads
 * @persistent: don't drop cache at end of computation
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
 * When the cache fills, a tile is chosen for reuse. If @access is
 * #VIPS_ACCESS_RANDOM, then the least-recently-used tile is reused. If 
 * @access is #VIPS_ACCESS_SEQUENTIAL or #VIPS_ACCESS_SEQUENTIAL_UNBUFFERED, 
 * the top-most tile is reused.
 *
 * By default, @tile_width and @tile_height are 128 pixels, and the operation
 * will cache up to 1,000 tiles. @access defaults to #VIPS_ACCESS_RANDOM.
 *
 * Normally, only a single thread at once is allowed to calculate tiles. If
 * you set @threaded to %TRUE, vips_tilecache() will allow many threads to
 * calculate tiles at once, and share the cache between them.
 *
 * Normally the cache is dropped when computation finishes. Set @persistent to
 * %TRUE to keep the cache between computations.
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

	VipsAccess access;

} VipsLineCache;

typedef VipsBlockCacheClass VipsLineCacheClass;

G_DEFINE_TYPE( VipsLineCache, vips_line_cache, VIPS_TYPE_BLOCK_CACHE );

static int
vips_line_cache_gen( VipsRegion *or, 
	void *seq, void *a, void *b, gboolean *stop )
{
	VipsBlockCache *block_cache = (VipsBlockCache *) b;

	VIPS_GATE_START( "vips_line_cache_gen: wait" );

	g_mutex_lock( block_cache->lock );

	VIPS_GATE_STOP( "vips_line_cache_gen: wait" );

	/* We size up the cache to the largest request.
	 */
	if( or->valid.height > 
		block_cache->max_tiles * block_cache->tile_height ) {
		block_cache->max_tiles = 
			1 + (or->valid.height / block_cache->tile_height);
		VIPS_DEBUG_MSG( "vips_line_cache_gen: bumped max_tiles to %d\n",
			block_cache->max_tiles ); 
	}

	g_mutex_unlock( block_cache->lock );

	return( vips_tile_cache_gen( or, seq, a, b, stop ) ); 
}

static int
vips_line_cache_build( VipsObject *object )
{
	VipsConversion *conversion = VIPS_CONVERSION( object );
	VipsBlockCache *block_cache = (VipsBlockCache *) object;
	VipsLineCache *cache = (VipsLineCache *) object;

	VIPS_DEBUG_MSG( "vips_line_cache_build\n" );

	if( VIPS_OBJECT_CLASS( vips_line_cache_parent_class )->
		build( object ) )
		return( -1 );

	/* tile_height is set by a param, or defaulted below.
	 */
	block_cache->tile_width = block_cache->in->Xsize;

	block_cache->access = cache->access; 

	if( cache->access == VIPS_ACCESS_SEQUENTIAL_UNBUFFERED )
		/* A tile per thread. 
		 *
		 * Imagine scanline tiles and four threads. And add a bit for
		 * slop. 
		 */
		block_cache->max_tiles = 2 * vips_concurrency_get();
	else { 
		/* Enough lines for two complete buffers would be exactly 
		 * right. Make it 3 to give us some slop room. 
		 *
		 * This can go up with request size, see vips_line_cache_gen().
		 */
		int tile_width;
		int tile_height;
		int nlines;

		vips_get_tile_size( block_cache->in, 
			&tile_width, &tile_height, &nlines );
		block_cache->max_tiles = 4 * 
			(1 + nlines / block_cache->tile_height);

		VIPS_DEBUG_MSG( "vips_line_cache_build: nlines = %d\n", 
			nlines );
	}

	VIPS_DEBUG_MSG( "vips_line_cache_build: "
		"max_tiles = %d, tile_height = %d\n", 
		block_cache->max_tiles, block_cache->tile_height ); 

	VIPS_DEBUG_MSG( "vips_line_cache_build: max size = %g MB\n",
		(block_cache->max_tiles * 
		 block_cache->tile_width * 
		 block_cache->tile_height * 
		 VIPS_IMAGE_SIZEOF_PEL( block_cache->in )) / (1024 * 1024.0) );

	if( vips_image_pio_input( block_cache->in ) )
		return( -1 );

	if( vips_image_pipelinev( conversion->out, 
		VIPS_DEMAND_STYLE_THINSTRIP, block_cache->in, NULL ) )
		return( -1 );

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

	VIPS_ARG_ENUM( class, "access", 6, 
		_( "Access" ), 
		_( "Expected access pattern" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsLineCache, access ),
		VIPS_TYPE_ACCESS, VIPS_ACCESS_SEQUENTIAL );

}

static void
vips_line_cache_init( VipsLineCache *cache )
{
	cache->access = VIPS_ACCESS_SEQUENTIAL;
}

/**
 * vips_linecache:
 * @in: input image
 * @out: output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * @access: hint expected access pattern #VipsAccess
 * @tile_height: height of tiles in cache
 * @threaded: allow many threads
 *
 * This operation behaves rather like vips_copy() between images
 * @in and @out, except that it keeps a cache of computed scanlines. 
 *
 * The number of lines cached is enough for a small amount of non-local
 * access. If you know you will not be making any non-local access, you can
 * save some memory and set @access to #VIPS_ACCESS_SEQUENTIAL_UNBUFFERED. 
 *
 * Each cache tile is made with a single call to 
 * vips_image_prepare(). 
 *
 * When the cache fills, a tile is chosen for reuse. If @access is
 * #VIPS_ACCESS_RANDOM, then the least-recently-used tile is reused. If 
 * @access is #VIPS_ACCESS_SEQUENTIAL or #VIPS_ACCESS_SEQUENTIAL_UNBUFFERED, 
 * the top-most tile is reused. @access defaults to #VIPS_ACCESS_RANDOM.
 *
 * @tile_height can be used to set the size of the strips that
 * vips_linecache() uses. The default is 1 (a single scanline).
 *
 * Normally, only a single thread at once is allowed to calculate tiles. If
 * you set @threaded to %TRUE, vips_linecache() will allow many threads to
 * calculate tiles at once and share the cache between them.
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
