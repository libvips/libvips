/* render an image in the background as a set of tiles
 *
 * don't read from mask after closing out
 *
 * JC, 30 sep 03 
 *
 * 22/10/03 JC
 *	- now uses threadgroup kill system, avoiding race condition
 * 2/2/04 JC
 *	- cache failed for large images
 * 8/4/04
 *	- touch reused tiles so they don't get reused again too soon ... helps
 *	  stop thrashing when we've many pending paints and lots of threads
 * 15/4/04
 *	- added im_cache() convenience function
 * 26/1/05
 *	- added im_render_fade() ... fade tiles display for nip2
 *	- mask can now be NULL for no mask output
 * 11/2/05
 *	- tidies
 * 27/2/05
 *	- limit the number of simultaneous renders
 *	- kill threadgroups when no dirties left
 *	- max == -1 means unlimited cache size
 *	- 'priority' marks non-suspendable renders
 * 1/4/05
 *	- rewritten for a few global threads instead, and a job queue ...
 *	  should be simpler & more reliable
 * 23/4/07
 * 	- oop, race condition fixed
 * 14/3/08
 * 	- oop, still making fade threads even when not fading
 * 	- more instrumenting
 * 23/4/08
 * 	- oop, broken for mask == NULL
 * 5/3/09
 * 	- remove all the fading stuff, a bit useless and it adds 
 * 	  complexity
 * 12/10/09
 * 	- gtkdoc comment
 * 	- im_render(), im_render_fade() moved to deprecated
 * 22/1/10
 * 	- drop painted tiles on invalidate
 * 10/3/10
 * 	- better lifetime management for im_invalidate() callbacks
 * 12/3/10
 * 	- drawing the mask image no longer sets those parts of the image
 * 	  rendering, it just queries the cache
 * 	- better mask painting
 * 17/3/10
 * 	- don't use invalidate callbacks after all, just test region->invalid,
 * 	  much simpler!
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
#define DEBUG_TG
#define DEBUG_MAKE
#define DEBUG_REUSE
#define DEBUG_PAINT
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif /*HAVE_UNISTD_H*/

#include <vips/vips.h>
#include <vips/thread.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

#ifdef HAVE_THREADS
static const int have_threads = 1;
#else /*!HAVE_THREADS*/
static const int have_threads = 0;
#endif /*HAVE_THREADS*/

#ifdef DEBUG_TG
static int threadgroup_count = 0;
static int threadgroup_active = 0;
#endif /*DEBUG_TG*/

/* A manager thread. We have a fixed number of these taking jobs off the list
 * of current renders with dirty tiles, doing a tile, and putting the render 
 * back.
 */
typedef struct _RenderThread {
	GThread *gthread;
	struct _Render *render;	/* The last render we worked on */
} RenderThread;

/* Notify caller through this.
 */
typedef void (*notify_fn)( IMAGE *, Rect *, void * );

/* The states a tile can be in.
 */
typedef enum {
	TILE_DIRTY,		/* On the dirty list .. contains no pixels */
	TILE_WORKING,		/* Currently being worked on */
	TILE_PAINTED		/* Painted, ready for reuse */
} TileState;

/* A tile in our cache. 
 */
typedef struct {
	struct _Render *render;

	Rect area;		/* Place here (unclipped) */
	REGION *region;		/* REGION with the pixels */

	int access_ticks;	/* Time of last use for LRU flush */
	int time;		/* Time when we finished painting */

	TileState state;
} Tile;

/*

	FIXME ... should have an LRU queue rather than this thing with times

	FIXME ... could also hash from tile xy to tile pointer

 */

/* Per-call state.
 */
typedef struct _Render {
	/* Reference count this, since we use these things from several
	 * threads. Can't easily use the gobject ref count system since we
	 * need a lock around operations.
	 */
	int ref_count;
	GMutex *ref_count_lock;	

	/* Parameters.
	 */
	IMAGE *in;		/* Image we render */
	IMAGE *out;		/* Write tiles here on demand */
	IMAGE *mask;		/* Set valid pixels here */
	int width, height;	/* Tile size */
	int max;		/* Maximum number of tiles */
	int priority;		/* Larger numbers done sooner */
	notify_fn notify;	/* Tell caller about paints here */
	void *client;

	/* Make readers single thread with this. No point allowing
	 * multi-thread read.
	 */
	GMutex *read_lock;	

	/* Tile cache.
	 */
	GSList *cache;		/* List of all our tiles */
	int ntiles;		/* Number of cache tiles */
	int access_ticks;	/* Inc. on each access ... used for LRU */

	/* List of tiles which are to be painted.
	 */
	GMutex *dirty_lock;	/* Lock before we read/write the dirty list */
	GSList *dirty;		/* Tiles which need painting */

	/* Render thread stuff.
	 */
	im_threadgroup_t *tg;	/* Render with this threadgroup */
	int render_kill;	/* This render is dying */
} Render;

/* Number of RenderThread we create.
 */
static const int render_thread_max = 1;

static GSList *render_thread_all = NULL;

/* Number of renders with dirty tiles. RenderThreads queue up on this.
 */
static im_semaphore_t render_dirty_sem;

/* All the renders with dirty tiles.
 */
static GMutex *render_dirty_lock = NULL;
static GSList *render_dirty_all = NULL;

static void
render_dirty_remove( Render *render )
{
	g_mutex_lock( render_dirty_lock );

	if( g_slist_find( render_dirty_all, render ) ) {
		render_dirty_all = g_slist_remove( render_dirty_all, render );

		im_semaphore_upn( &render_dirty_sem, -1 );
	}

	g_mutex_unlock( render_dirty_lock );
}

static void *
tile_free( Tile *tile )
{
#ifdef DEBUG_MAKE
	printf( "tile_free\n" );
#endif /*DEBUG_MAKE*/

	IM_FREEF( im_region_free, tile->region );
	im_free( tile );

	return( NULL );
}

static int
render_free( Render *render )
{
#ifdef DEBUG_MAKE
	printf( "render_free: %p\n", render );
#endif /*DEBUG_MAKE*/

	g_assert( render->ref_count == 0 );

	render_dirty_remove( render );

	IM_FREEF( im_threadgroup_free, render->tg );

	/* Free cache.
	 */
	im_slist_map2( render->cache,
		(VSListMap2Fn) tile_free, NULL, NULL );
	IM_FREEF( g_slist_free, render->cache );
	render->ntiles = 0;
	IM_FREEF( g_slist_free, render->dirty );

	g_mutex_free( render->ref_count_lock );
	g_mutex_free( render->dirty_lock );
	g_mutex_free( render->read_lock );

	im_free( render );

	return( 0 );
}

/* Ref and unref a Render ... free on last unref.
 */
static int
render_ref( Render *render )
{
	g_mutex_lock( render->ref_count_lock );
	g_assert( render->ref_count != 0 );
	render->ref_count += 1;
	g_mutex_unlock( render->ref_count_lock );

	return( 0 );
}

static int
render_unref( Render *render )
{
	int kill;

	g_mutex_lock( render->ref_count_lock );
	g_assert( render->ref_count > 0 );
	render->ref_count -= 1;
	kill = render->ref_count == 0;
	g_mutex_unlock( render->ref_count_lock );

	if( kill )
		render_free( render );

	return( 0 );
}

/* Wait for a render with dirty tiles.
 */
static Render *
render_dirty_get( void )
{
	Render *render;

	/* Wait for a render with dirty tiles.
	 */
	im_semaphore_down( &render_dirty_sem );

	g_mutex_lock( render_dirty_lock );

	/* Just take the head of the jobs list ... we sort when we add. If
	 * render_dirty_remove() is called between our semaphore letting us in
	 * and the _lock(), render_dirty_all can be NULL.
	 */
	render = NULL;
	if( render_dirty_all ) {
		render = (Render *) render_dirty_all->data;

		g_assert( render->ref_count == 1 );

		/* Ref the render to make sure it can't die while we're
		 * working on it.
		 */
		render_ref( render );

		render_dirty_all = g_slist_remove( render_dirty_all, render );
	}

	g_mutex_unlock( render_dirty_lock );

	return( render );
}

/* Do a single tile. Take a dirty tile from the dirty list and fill with 
 * pixels.
 */
static void
render_dirty_process( Render *render )
{
	Tile *tile;

	/* Take a tile off the dirty list.
	 */
	g_mutex_lock( render->dirty_lock );
	if( render->dirty ) { 
		tile = (Tile *) render->dirty->data;
		g_assert( tile->state == TILE_DIRTY );
		render->dirty = g_slist_remove( render->dirty, tile );
		tile->state = TILE_WORKING;
	}
	else
		tile = NULL;
	g_mutex_unlock( render->dirty_lock );

	if( tile ) {
		int result;

		result = -1;
		if( !render->tg ) {
			render->tg = im_threadgroup_create( render->in );

#ifdef DEBUG_TG
			printf( "render_paint_tile: "
				"%p starting threadgroup\n",
				render );
			threadgroup_count += 1;
			printf( "render_paint_tile: %d\n", threadgroup_count );
			threadgroup_active += 1;
			printf( "render_dirty_put: %d active\n", 
				threadgroup_active );
#endif /*DEBUG_TG*/
		}

		if( render->tg ) {
#ifdef DEBUG_PAINT
			printf( "render_fill_tile: "
				"%p paint of tile %dx%d\n",
				render,
				tile->area.left, tile->area.top );
#endif /*DEBUG_PAINT*/

			/* We're writing to the tile region, but we didn't 
			 * make it.
			 */
			im__region_take_ownership( tile->region );

			result = im_prepare_thread( render->tg, 
				tile->region, &tile->area );
		}

		/*

			FIXME ... nice if we did something with the error return

		 */
#ifdef DEBUG_PAINT
		if( result )
			printf( "render_fill_tile: "
				"im_prepare_thread() failed!\n\t%s\n", 
				im_error_buffer() );
#endif /*DEBUG_PAINT*/

		/* All done.
		 */
		tile->state = TILE_PAINTED;
		im__region_no_ownership( tile->region );

		/* Now clients can update.
		 */
		if( render->notify ) 
			render->notify( render->out, 
				&tile->area, render->client );
	}
}

static int       
render_dirty_sort( Render *a, Render *b )
{
	return( b->priority - a->priority );
}

/* Add to the jobs list, if it has work to be done.
 */
static void
render_dirty_put( Render *render )
{
	g_mutex_lock( render_dirty_lock );

	if( render->dirty && !render->render_kill ) {
		if( !g_slist_find( render_dirty_all, render ) ) {
			render_dirty_all = g_slist_prepend( render_dirty_all, 
				render );
			render_dirty_all = g_slist_sort( render_dirty_all,
				(GCompareFunc) render_dirty_sort );
			im_semaphore_up( &render_dirty_sem );
		}
	}
	else {
		/* Coming off the jobs list ... shut down the render pipeline.
		 */
#ifdef DEBUG_TG
		printf( "render_dirty_put: %p stopping threadgroup\n", render );
		threadgroup_active -= 1;
		printf( "render_dirty_put: %d active\n", threadgroup_active );
#endif /*DEBUG_TG*/
		IM_FREEF( im_threadgroup_free, render->tg );
	}

	g_mutex_unlock( render_dirty_lock );
}

/* Main loop for RenderThreads.
 */
static void *
render_thread_main( void *client )
{
	/* Could use this if we want per-thread state in the future.
	RenderThread *thread = (RenderThread *) client;
	 */

	for(;;) {
		Render *render;

		if( (render = render_dirty_get()) ) {
			/* Loop here if this is the only dirty render, rather
			 * than bouncing back to _put()/_get(). We don't
			 * lock before testing since this is just a trivial
			 * optimisation and does not affect integrity.
			 */
			do {
				render_dirty_process( render );
			} while( !render_dirty_all && render->dirty );

			render_dirty_put( render );

			g_assert( render->ref_count == 1 ||
				render->ref_count == 2 );

			/* _get() does a ref to make sure we keep the render
			 * alive during processing ... unref before we loop.
			 * This can kill off the render.
			 */
			render_unref( render );
		}
	}

	return( NULL );
}

/* Create our set of RenderThread. Assume we're single-threaded here.
 */
static int
render_thread_create( void )
{
	int len = g_slist_length( render_thread_all );
	int i;

	if( !have_threads )
		return( 0 );

	/* 1st time through only.
	 */
	if( !render_dirty_lock ) {
		render_dirty_lock = g_mutex_new();
		im_semaphore_init( &render_dirty_sem, 0, "render_dirty_sem" );
	}

	for( i = len; i < render_thread_max; i++ ) {
		RenderThread *thread = IM_NEW( NULL, RenderThread );

		thread->gthread = NULL;
		thread->render = NULL;

		if( !(thread->gthread = g_thread_create_full( 
			render_thread_main, thread, 
			IM__DEFAULT_STACK_SIZE, TRUE, FALSE, 
			G_THREAD_PRIORITY_NORMAL, NULL )) ) {
			im_free( thread );
			im_error( "im_render", 
				"%s", _( "unable to create thread" ) );
			return( -1 );
		}

		render_thread_all = g_slist_prepend( render_thread_all, 
			thread );
	}

	return( 0 );
}

static void *
tile_test_clean_ticks( Tile *this, Tile **best )
{
	if( this->state == TILE_PAINTED )
		if( !*best || this->access_ticks < (*best)->access_ticks )
			*best = this;

	return( NULL );
}

/* Pick a painted tile to reuse. Search for LRU (slow!).
 */
static Tile *
render_tile_get_painted( Render *render )
{
	Tile *tile;

	tile = NULL;
	im_slist_map2( render->cache,
		(VSListMap2Fn) tile_test_clean_ticks, &tile, NULL );

	if( tile ) {
		g_assert( tile->state == TILE_PAINTED );

#ifdef DEBUG_REUSE
		printf( "render_tile_get_painted: reusing painted %p\n", tile );

		g_mutex_lock( render->dirty_lock );
		g_assert( !g_slist_find( render->dirty, tile ) );
		g_mutex_unlock( render->dirty_lock );
#endif /*DEBUG_REUSE*/

		tile->state = TILE_WORKING;
	}

	return( tile );
}

static Render *
render_new( IMAGE *in, IMAGE *out, IMAGE *mask, 
	int width, int height, int max, 
	int priority,
	notify_fn notify, void *client )
{
	Render *render;

	/* Don't use auto-free for render, we do our own lifetime management
	 * with _ref() and _unref().
	 */
	if( !(render = IM_NEW( NULL, Render )) )
		return( NULL );

	render->ref_count = 1;
	render->ref_count_lock = g_mutex_new();

	render->in = in;
	render->out = out;
	render->mask = mask;
	render->width = width;
	render->height = height;
	render->max = max;
	render->priority = priority;
	render->notify = notify;
	render->client = client;

	render->read_lock = g_mutex_new();

	render->cache = NULL;
	render->ntiles = 0;
	render->access_ticks = 0;

	render->dirty_lock = g_mutex_new();
	render->dirty = NULL;

	render->tg = NULL;
	render->render_kill = FALSE;

	if( im_add_close_callback( out, 
                (im_callback_fn) render_unref, render, NULL ) ) {
                (void) render_unref( render );
                return( NULL );
        }

	return( render );
}

/* Make a Tile.
 */
static Tile *
tile_new( Render *render )
{
	Tile *tile;

#ifdef DEBUG_MAKE
	printf( "tile_new\n" );
#endif /*DEBUG_MAKE*/

	/* Don't use auto-free: we need to make sure we free the tile after
	 * Render.
	 */
	if( !(tile = IM_NEW( NULL, Tile )) )
		return( NULL );

	tile->render = render;
	tile->region = NULL;
	tile->area.left = 0;
	tile->area.top = 0;
	tile->area.width = 0;
	tile->area.height = 0;
	tile->access_ticks = render->access_ticks;
	tile->time = 0;
	tile->state = TILE_WORKING;

	if( !(tile->region = im_region_create( render->in )) ) {
		(void) tile_free( tile );
		return( NULL );
	}

	render->cache = g_slist_prepend( render->cache, tile );
	render->ntiles += 1;

	return( tile );
}

static void *
tile_test_area( Tile *tile, Rect *area )
{
	if( im_rect_equalsrect( &tile->area, area ) )
		return( tile );

	return( NULL );
}

/* Search the cache for a tile, NULL if not there. Could be *much* faster.
 *
 * This is always called from the downstream thread, and upstream never adds
 * or positions tiles, so no need to lock.
 */
static Tile *
render_tile_lookup( Render *render, Rect *area )
{
	Tile *tile;

	tile = (Tile *) im_slist_map2( render->cache,
		(VSListMap2Fn) tile_test_area, area, NULL );

	return( tile );
}

/* We've looked at a tile ... bump to end of LRU and front of dirty.
 */
static void
render_tile_touch( Tile *tile )
{
	Render *render = tile->render;

	tile->access_ticks = render->access_ticks;
	render->access_ticks += 1;

	g_mutex_lock( render->dirty_lock );
	if( tile->state == TILE_DIRTY ) {
#ifdef DEBUG
		printf( "tile_bump_dirty: bumping tile %dx%d\n",
			tile->area.left, tile->area.top );
#endif /*DEBUG*/

		render->dirty = g_slist_remove( render->dirty, tile );
		render->dirty = g_slist_prepend( render->dirty, tile );
	}
	g_mutex_unlock( render->dirty_lock );
}

/* Add a tile to the dirty list.
 */
static void
tile_set_dirty( Tile *tile, Rect *area )
{
	Render *render = tile->render;

#ifdef DEBUG_PAINT
	printf( "tile_set_dirty: adding tile %dx%d to dirty\n",
		area->left, area->top );
#endif /*DEBUG_PAINT*/

	g_assert( tile->state == TILE_WORKING );

	/* Touch the ticks ... we want to make sure this tile will not be
	 * reused too soon, so it gets a chance to get painted.
	 */
	tile->access_ticks = render->access_ticks;
	render->access_ticks += 1;

	g_mutex_lock( render->dirty_lock );

	tile->state = TILE_DIRTY;
	tile->area = *area;
	render->dirty = g_slist_prepend( render->dirty, tile );

	/* Someone else will write to it now.
	 */
	im__region_no_ownership( tile->region );

	/* Can't unlock render->dirty_lock here, we need to render_dirty_put()
	 * before the tile is processed.
	 */

	if( render->notify && have_threads ) 
		/* Add to the list of renders with dirty tiles. One of our bg 
		 * threads will pick it up and paint it.
		 */
		render_dirty_put( render );
	else {
		/* No threads, or no notify ... paint the tile ourselves, 
		 * sychronously. No need to notify the client since they'll 
		 * never see black tiles.
		 */
#ifdef DEBUG_PAINT
		printf( "tile_set_dirty: painting tile %dx%d synchronously\n",
			area->left, area->top );
#endif /*DEBUG_PAINT*/

		if( !render->tg )
			render->tg = im_threadgroup_create( render->in );

		/* We're writing to the tile region, but we didn't make it.
		 */
		im__region_take_ownership( tile->region );

		if( render->tg )
			im_prepare_thread( render->tg, 
				tile->region, &tile->area );

		tile->state = TILE_PAINTED;
		render->dirty = g_slist_remove( render->dirty, tile );
	}

	g_mutex_unlock( render->dirty_lock );
}

/* Take a tile off the end of the dirty list.
 */
static Tile *
render_tile_get_dirty( Render *render )
{
	Tile *tile;

	g_mutex_lock( render->dirty_lock );
	if( !render->dirty )
		tile = NULL;
	else {
		tile = (Tile *) g_slist_last( render->dirty )->data;
		render->dirty = g_slist_remove( render->dirty, tile );
		tile->state = TILE_WORKING;
	}
	g_mutex_unlock( render->dirty_lock );

#ifdef DEBUG_REUSE
	if( tile )
		printf( "render_tile_get_dirty: reusing dirty %p\n", tile );
#endif /*DEBUG_REUSE*/

	return( tile );
}

static Tile *
render_tile_get( Render *render, Rect *area )
{
	Tile *tile;

	/* Got this tile already?
	 */
	if( (tile = render_tile_lookup( render, area )) ) {
#ifdef DEBUG_PAINT
		printf( "render_tile_get: found %dx%d in cache\n",
			area->left, area->top );
#endif /*DEBUG_PAINT*/

		/* If the tile is painted but invalid, send it for
		 * calculation.
		 *
		 * Otherwise just touch it to keep it in cache a little
		 * longer.
		 */
		if( tile->state == TILE_PAINTED && 
			tile->region->invalid ) {
			tile->state = TILE_WORKING;
			tile_set_dirty( tile, area );
		}
		else
			render_tile_touch( tile );

		return( tile );
	}

	/* Have we fewer tiles than teh max? Can just make a new tile.
	 */
	if( render->ntiles < render->max || render->max == -1 ) {
		if( !(tile = tile_new( render )) ) 
			return( NULL );
	}
	else {
		/* Need to reuse a tile. Try for an old painted tile first, 
		 * then if that fails, reuse a dirty tile. 
		 */
		if( !(tile = render_tile_get_painted( render )) &&
			!(tile = render_tile_get_dirty( render )) ) 
			return( NULL );

#ifdef DEBUG_REUSE
		printf( "(render_tile_get: was at %dx%d, moving to %dx%d)\n",
			tile->area.left, tile->area.top,
			area->left, area->top );
#endif /*DEBUG_REUSE*/
	}

#ifdef DEBUG_PAINT
	printf( "render_tile_get: sending %dx%d for calc\n",
		area->left, area->top );
#endif /*DEBUG_PAINT*/

	tile_set_dirty( tile, area );

	return( tile );
}

/* Copy what we can from the tile into the region.
 */
static void
tile_copy( Tile *tile, REGION *to )
{
	Rect ovlap;
	int y;

	/* Find common pixels.
	 */
	im_rect_intersectrect( &tile->area, &to->valid, &ovlap );
	g_assert( !im_rect_isempty( &ovlap ) );

	/* If the tile is painted, copy over the pixels. Otherwise, fill with
	 * zero. 
	 */
	if( tile->state == TILE_PAINTED &&
		!tile->region->invalid ) {
		int len = IM_IMAGE_SIZEOF_PEL( to->im ) * ovlap.width;

#ifdef DEBUG_PAINT
		printf( "tile_copy: copying calculated pixels for %dx%d\n",
			tile->area.left, tile->area.top ); 
#endif /*DEBUG_PAINT*/

		for( y = ovlap.top; y < IM_RECT_BOTTOM( &ovlap ); y++ ) {
			PEL *p = (PEL *) IM_REGION_ADDR( tile->region, 
				ovlap.left, y );
			PEL *q = (PEL *) IM_REGION_ADDR( to, ovlap.left, y );

			memcpy( q, p, len );
		}
	}
	else {
#ifdef DEBUG_PAINT
		printf( "tile_copy: zero filling for %dx%d\n",
			tile->area.left, tile->area.top ); 
#endif /*DEBUG_PAINT*/
		im_region_paint( to, &ovlap, 0 );
	}
}

/* Loop over the output region, filling with data from cache.
 */
static int
region_fill( REGION *out, void *seq, void *a, void *b )
{
	Render *render = (Render *) a;
	Rect *r = &out->valid;
	int x, y;

	/* Find top left of tiles we need.
	 */
	int xs = (r->left / render->width) * render->width;
	int ys = (r->top / render->height) * render->height;

#ifdef DEBUG_PAINT
	printf( "region_fill: left = %d, top = %d, width = %d, height = %d\n",
                r->left, r->top, r->width, r->height );
#endif /*DEBUG_PAINT*/

	/* Only allow one reader. No point threading this, calculation is
	 * decoupled anyway.
	 */
	g_mutex_lock( render->read_lock );

	/* 

		FIXME ... if r fits inside a single tile, could skip the copy.

	 */

	for( y = ys; y < IM_RECT_BOTTOM( r ); y += render->height )
		for( x = xs; x < IM_RECT_RIGHT( r ); x += render->width ) {
			Rect area;
			Tile *tile;

			area.left = x;
			area.top = y;
			area.width = render->width;
			area.height = render->height;

			if( (tile = render_tile_get( render, &area )) )
				tile_copy( tile, out );
		}

	g_mutex_unlock( render->read_lock );

	return( 0 );
}

/* The mask image is 255 / 0 for the state of painted for each tile.
 */
static int
mask_fill( REGION *out, void *seq, void *a, void *b )
{
	Render *render = (Render *) a;
	Rect *r = &out->valid;
	int x, y;

	/* Find top left of tiles we need.
	 */
	int xs = (r->left / render->width) * render->width;
	int ys = (r->top / render->height) * render->height;

#ifdef DEBUG_PAINT
	printf( "mask_fill: left = %d, top = %d, width = %d, height = %d\n",
                r->left, r->top, r->width, r->height );
#endif /*DEBUG_PAINT*/

	g_mutex_lock( render->read_lock );

	for( y = ys; y < IM_RECT_BOTTOM( r ); y += render->height )
		for( x = xs; x < IM_RECT_RIGHT( r ); x += render->width ) {
			Rect area;
			Tile *tile;

			area.left = x;
			area.top = y;
			area.width = render->width;
			area.height = render->height;

			tile = render_tile_lookup( render, &area );

			/* Only mark painted tiles containing valid pixels.
			 */
			im_region_paint( out, &area, 
				(tile && 
				tile->state == TILE_PAINTED &&
				!tile->region->invalid) ? 255 : 0 );
		}

	g_mutex_unlock( render->read_lock );

	return( 0 );
}

/**
 * im_render_priority:
 * @in: input image
 * @out: output image
 * @mask: mask image indicating valid pixels
 * @width: tile width
 * @height: tile height
 * @max: maximum tiles to cache
 * @priority: rendering priority
 * @notify: pixels are ready notification callback
 * @client: client data for callback
 *
 * This operation renders @in in the background, making pixels available on
 * @out as they are calculated. The @notify callback is run every time a new
 * set of pixels are available. Calculated pixels are kept in a cache with
 * tiles sized @width by @height pixels and at most @max tiles.
 * If @max is -1, the cache is of unlimited size (up to the maximum image
 * size).
 * The @mask image s a one-band uchar image and has 255 for pixels which are 
 * currently in cache and 0 for uncalculated pixels.
 *
 * The pixel rendering system has a single global #im_threadgroup_t which is 
 * used for all currently active instances of im_render_priority(). As
 * renderers are added and removed from the system, the threadgroup switches
 * between renderers based on their priority setting. Zero means normal
 * priority, negative numbers are low priority, positive numbers high
 * priority.
 *
 * Calls to im_prepare() on @out return immediately and hold whatever is
 * currently in cache for that #Rect (check @mask to see which parts of the
 * #Rect are valid). Any pixels in the #Rect which are not in cache are added
 * to a queue, and the @notify callback will trigger when those pixels are
 * ready.
 *
 * The @notify callback is run from the background thread. In the callback,
 * you need to somehow send a message to the main thread that the pixels are
 * ready. In a glib-based application, this is easily done with g_idle_add().
 *
 * If @notify is %NULL, then im_render_priority() runs synchronously.
 * im_prepare() on @out will always block until the pixels have been
 * calculated by the background #im_threadgroup_t.
 *
 * See also: im_cache(), im_prepare().
 *
 * Returns: 0 on sucess, -1 on error.
 */
int
im_render_priority( IMAGE *in, IMAGE *out, IMAGE *mask, 
	int width, int height, int max, 
	int priority,
	notify_fn notify, void *client )
{
	Render *render;

	/* Make sure the bg work threads are ready.
	 */
	if( render_thread_create() )
		return( -1 );

	if( width <= 0 || 
		height <= 0 || 
		max < -1 ) {
		im_error( "im_render", "%s", _( "bad parameters" ) );
		return( -1 );
	}
	if( im_piocheck( in, out ) )
		return( -1 );
	if( mask ) {
		if( im_poutcheck( mask ) ||
			im_cp_desc( mask, in ) )
			return( -1 );

		mask->Bands = 1;
		mask->BandFmt = IM_BANDFMT_UCHAR;
		mask->Type = IM_TYPE_B_W;
		mask->Coding = IM_CODING_NONE;
	}
	if( im_cp_desc( out, in ) )
		return( -1 );
	if( im_demand_hint( out, IM_SMALLTILE, in, NULL ) )
		return( -1 );
	if( mask && 
		im_demand_hint( mask, IM_SMALLTILE, in, NULL ) )
		return( -1 );

	if( !(render = render_new( in, out, mask, 
		width, height, max, priority, notify, client )) )
		return( -1 );

#ifdef DEBUG_MAKE
	printf( "im_render: max = %d, %p\n", max, render );
#endif /*DEBUG_MAKE*/

	if( im_generate( out, NULL, region_fill, NULL, 
		render, NULL ) )
		return( -1 );
	if( mask && 
		im_generate( mask, NULL, mask_fill, NULL, 
		render, NULL ) )
		return( -1 );

	return( 0 );
}

/**
 * im_cache:
 * @in: input image
 * @out: output image
 * @width: tile width
 * @height: tile height
 * @max: maximum tiles to cache
 *
 * im_cache() works exactly as im_copy(), except that calculated pixels are
 * kept in a cache. If @in is the result of a large computation and you are
 * expecting to reuse the result in a number of places, im_cache() can save a
 * lot of time.
 *
 * im_cache() is a convenience function over im_render_priority().
 *
 * See also: im_render_priority(), im_copy(), im_prepare_thread(). 
 */
int 
im_cache( IMAGE *in, IMAGE *out, int width, int height, int max )
{
	return( im_render_priority( in, out, NULL, 
		width, height, max, 
		0,
		NULL, NULL ) );
}
