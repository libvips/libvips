/* Manage sets of pixel buffers on an image.
 * 
 * 30/10/06
 *	- from window.c
 * 2/2/07
 * 	- speed up the search, use our own lock (thanks Christian)
 * 5/2/07
 * 	- split to many buffer lists per image
 * 11/2/07
 * 	- split to a buffer hash per thread
 * 	- reuse buffer mallocs when we can 
 * 20/2/07
 * 	- add VipsBufferCacheList and we can avoid some hash ops on
 * 	  done/undone
 * 5/3/10
 * 	- move invalid stuff to region
 * 	- move link maintenance to im_demand_hint
 * 21/9/11
 * 	- switch to vips_tracked_malloc()
 * 18/12/13
 * 	- keep a few buffers in reserve per image, stops malloc/free 
 * 	  cycling when sharing is repeatedly discovered
 * 6/6/16
 * 	- free buffers on image close as well as thread exit, so main thread
 * 	  buffers don't clog up the system
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
#define DEBUG_VERBOSE
#define DEBUG_CREATE
#define DEBUG
#define DEBUG_GLOBAL
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <stdlib.h>

#include <vips/vips.h>
#include <vips/internal.h>
#include <vips/thread.h>

#ifdef DEBUG
/* Track all buffers here for debugging.
 */
static GSList *vips__buffer_all = NULL;
#endif /*DEBUG*/

#ifdef DEBUG_CREATE
static GSList *vips__buffer_cache_all = NULL; 
#endif /*DEBUG_CREATE*/

/* The maximum numbers of buffers we hold in reserve per image. 
 */
static const int buffer_cache_max_reserve = 2; 

/* Workers have a buffer_thread in a GPrivate they have exclusive access to.
 */
static GPrivate *buffer_thread_key = NULL;

/* All non-worker threads share a single global set of buffers protected by a
 * mutex.
 */
static VipsBufferThread *vips_buffer_thread_global = NULL;

#ifdef DEBUG_GLOBAL
/* Count main thread buffers in and out.
 */
static int vips_buffer_thread_global_n = 0;
static int vips_buffer_thread_global_highwater = 0;
#endif /*DEBUG_GLOBAL*/

#ifdef DEBUG
static void *
vips_buffer_dump( VipsBuffer *buffer, size_t *reserve, size_t *alive )
{
	vips_buffer_print( buffer ); 

	if( buffer->im &&
		buffer->buf &&
		buffer->cache ) {  
		printf( "buffer %p, %.3g MB\n", 
			buffer, buffer->bsize / (1024 * 1024.0) ); 
		*alive += buffer->bsize;
	}
	else 
	if( buffer->im &&
		buffer->buf &&
		!buffer->cache )   	
		*reserve += buffer->bsize;
	else
		printf( "buffer craziness!\n" ); 

	return( NULL );
}
#endif /*DEBUG*/

#ifdef DEBUG_CREATE
static void *
vips_buffer_cache_dump( VipsBufferCache *cache )
{
	printf( "VipsBufferCache: %p\n", cache );
	printf( "\t%d buffers\n", g_slist_length( cache->buffers ) );
	printf( "\tthread %p\n", cache->thread );
	printf( "\timage %p\n", cache->im );
	printf( "\tbuffer_thread %p\n", cache->buffer_thread );
	printf( "\t%d in reserve\n", g_slist_length( cache->reserve ) );

	return( NULL ); 
}
#endif /*DEBUG_CREATE*/

void
vips_buffer_dump_all( void )
{
#ifdef DEBUG
	if( vips__buffer_all ) { 
		size_t reserve;
		size_t alive;

		printf( "buffers:\n" ); 

		reserve = 0;
		alive = 0;
		vips_slist_map2( vips__buffer_all, 
			(VipsSListMap2Fn) vips_buffer_dump, &reserve, &alive );
		printf( "%.3g MB alive\n", alive / (1024 * 1024.0) ); 
		printf( "%.3g MB in reserve\n", reserve / (1024 * 1024.0) ); 
	}

#ifdef DEBUG_CREATE
	if( vips__buffer_cache_all ) {
		printf( "buffers: %d buffer cache still alive\n", 
			g_slist_length( vips__buffer_cache_all ) ); 
		vips_slist_map2( vips__buffer_cache_all, 
			(VipsSListMap2Fn) vips_buffer_cache_dump, NULL, NULL );
		printf( "g_thread_self() == %p\n", g_thread_self() ); 
	}
#endif /*DEBUG_CREATE*/
#endif /*DEBUG*/

#ifdef DEBUG_GLOBAL
	printf( "buffers: %d global buffers\n", vips_buffer_thread_global_n );
	printf( "buffers: %d high water global buffers\n", 
		vips_buffer_thread_global_highwater ); 
#endif /*DEBUG_GLOBAL*/
}

static void
vips_buffer_free( VipsBuffer *buffer )
{
	VIPS_FREEF( vips_tracked_free, buffer->buf );
	buffer->bsize = 0;
	g_free( buffer );

#ifdef DEBUG
	g_mutex_lock( vips__global_lock );

	g_assert( g_slist_find( vips__buffer_all, buffer ) );
	vips__buffer_all = g_slist_remove( vips__buffer_all, buffer );

	g_mutex_unlock( vips__global_lock );
#endif /*DEBUG*/
}

static void
buffer_thread_free( VipsBufferThread *buffer_thread )
{
	/* We only come here from workers, so no need to lock.
	 */
	VIPS_FREEF( g_hash_table_destroy, buffer_thread->hash );
	VIPS_FREE( buffer_thread );
}

/* This can be called via two routes: 
 *
 * - on thread shutdown, the enclosing hash is destroyed, and that will 
 *   trigger this via GDestroyNotify.
 * - if the BufferCache has been allocated by the main thread,  this will be
 *   triggered from postclose on the image
 *
 * These can happen in either order. 
 */
static void
buffer_cache_free( VipsBufferCache *cache )
{
	GSList *p;

#ifdef DEBUG_CREATE
	g_mutex_lock( vips__global_lock );
	vips__buffer_cache_all = 
		g_slist_remove( vips__buffer_cache_all, cache );
	g_mutex_unlock( vips__global_lock );

	printf( "buffer_cache_free: freeing cache %p on thread %p\n",
		cache, g_thread_self() );
	printf( "\t(%d caches left)\n", 
		g_slist_length( vips__buffer_cache_all ) );
#endif /*DEBUG_CREATE*/

	/* Need to mark undone so we don't try and take them off this cache on
	 * unref.
	 */
	for( p = cache->buffers; p; p = p->next ) {
		VipsBuffer *buffer = (VipsBuffer *) p->data;

		buffer->done = FALSE;
	}
	VIPS_FREEF( g_slist_free, cache->buffers );

	for( p = cache->reserve; p; p = p->next ) {
		VipsBuffer *buffer = (VipsBuffer *) p->data;

		vips_buffer_free( buffer ); 
	}
	VIPS_FREEF( g_slist_free, cache->reserve );

	g_free( cache );
}

static void
buffer_cache_image_postclose( VipsImage *im, VipsBufferCache *cache )
{
	VipsBufferThread *buffer_thread = cache->buffer_thread;

	/* Runs to clean up main thread buffers on image close.
	 */
	g_assert( cache->im == im );
	g_assert( !vips_thread_isworker() );

	/* All non-worker threads come through here, so we need to lock around
	 * changes to the global buffer_thread.
	 */
	g_mutex_lock( vips__global_lock );

	g_hash_table_remove( buffer_thread->hash, im );

#ifdef DEBUG_GLOBAL
	vips_buffer_thread_global_n -= 1;
	printf( "buffer_cache_image_postclose: %d global buffers\n",
		vips_buffer_thread_global_n ); 
#endif /*DEBUG_GLOBAL*/

	g_mutex_unlock( vips__global_lock );
}

static VipsBufferCache *
buffer_cache_new( VipsBufferThread *buffer_thread, VipsImage *im )
{
	VipsBufferCache *cache;

	cache = g_new( VipsBufferCache, 1 );
	cache->buffers = NULL;
	cache->thread = g_thread_self();
	cache->im = im;
	cache->buffer_thread = buffer_thread;
	cache->reserve = NULL;
	cache->n_reserve = 0;

	/* VipsBufferCache allocated from worker threads will be freed when
	 * workers shut down. This won't happen for VipsBufferCache allocated 
	 * from the main thread, since (obviously) thread shutdown will never 
	 * happen. In this case, we need to free resources on image close.
	 */
	if( !vips_thread_isworker() ) {
		g_signal_connect( im, "postclose", 
			G_CALLBACK( buffer_cache_image_postclose ), cache );

#ifdef DEBUG_GLOBAL
		/* No need to lock. Main thread buffer_cache_new() calls are
		 * always inside a lock already.
		 */
		vips_buffer_thread_global_n += 1;
		vips_buffer_thread_global_highwater = VIPS_MAX( 
			vips_buffer_thread_global_highwater, 
			vips_buffer_thread_global_n ); 

		printf( "buffer_cache_new: %d global buffers\n",
			vips_buffer_thread_global_n ); 
#endif /*DEBUG_GLOBAL*/
	}

#ifdef DEBUG_CREATE
	g_mutex_lock( vips__global_lock );
	vips__buffer_cache_all = 
		g_slist_prepend( vips__buffer_cache_all, cache );
	g_mutex_unlock( vips__global_lock );

	printf( "buffer_cache_new: new cache %p for thread %p\n",
		cache, g_thread_self() );
	printf( "\t(%d caches now)\n", 
		g_slist_length( vips__buffer_cache_all ) );
#endif /*DEBUG_CREATE*/

	return( cache );
}

static VipsBufferThread *
buffer_thread_new( void )
{
	VipsBufferThread *buffer_thread;

	buffer_thread = g_new( VipsBufferThread, 1 );
	buffer_thread->hash = g_hash_table_new_full( 
		g_direct_hash, g_direct_equal, 
		NULL, (GDestroyNotify) buffer_cache_free );
	buffer_thread->thread = g_thread_self();

	return( buffer_thread );
}

static VipsBufferThread *
buffer_thread_get( void )
{
	VipsBufferThread *buffer_thread;

	if( vips_thread_isworker() ) {
		/* Workers get a private set of buffers.
		 */
		if( !(buffer_thread = g_private_get( buffer_thread_key )) ) {
			buffer_thread = buffer_thread_new();
			g_private_set( buffer_thread_key, buffer_thread );
		}

		g_assert( buffer_thread->thread == g_thread_self() ); 
	}
	else {
		/* All main threads share a single set of buffers. 
		 */
		g_mutex_lock( vips__global_lock );

		if( !vips_buffer_thread_global ) {
			vips_buffer_thread_global = buffer_thread_new(); 

			/* Shared by many threads, so no checking.
			 */
			vips_buffer_thread_global->thread = NULL;
		}
		buffer_thread = vips_buffer_thread_global;

		g_mutex_unlock( vips__global_lock );
	}

	return( buffer_thread );
}

static VipsBufferCache *
buffer_cache_get( VipsImage *im )
{
	VipsBufferThread *buffer_thread = buffer_thread_get();

	VipsBufferCache *cache;

	if( !vips_thread_isworker() ) 
		g_mutex_lock( vips__global_lock );

	if( !(cache = (VipsBufferCache *) 
		g_hash_table_lookup( buffer_thread->hash, im )) ) {
		cache = buffer_cache_new( buffer_thread, im );
		g_hash_table_insert( buffer_thread->hash, im, cache );
	}

	if( !vips_thread_isworker() ) 
		g_mutex_unlock( vips__global_lock );

	g_assert( !cache->thread ||
		cache->thread == g_thread_self() ); 

	return( cache ); 
}

/* Pixels have been calculated: publish for other parts of this thread to see.
 */
void 
vips_buffer_done( VipsBuffer *buffer )
{
	if( !buffer->done ) {
		VipsImage *im = buffer->im;
		VipsBufferCache *cache = buffer_cache_get( im ); 

#ifdef DEBUG_VERBOSE
		printf( "vips_buffer_done: thread %p adding to cache %p\n",
			g_thread_self(), cache );
		vips_buffer_print( buffer ); 
#endif /*DEBUG_VERBOSE*/

		g_assert( !g_slist_find( cache->buffers, buffer ) );
		g_assert( !buffer->cache ); 

		buffer->done = TRUE;
		buffer->cache = cache;

		cache->buffers = g_slist_prepend( cache->buffers, buffer );
	}
}

/* Take off the public 'done' list. Make sure it has no calculated pixels in. 
 */
void
vips_buffer_undone( VipsBuffer *buffer )
{
	if( buffer->done ) {
		VipsBufferCache *cache = buffer->cache;

#ifdef DEBUG_VERBOSE
		printf( "vips_buffer_undone: thread %p removing "
			"buffer %p from cache %p\n",
			g_thread_self(), buffer, cache );
#endif /*DEBUG_VERBOSE*/

		g_assert( !cache->thread ||
			cache->thread == g_thread_self() );
		g_assert( !cache->thread ||
			cache->buffer_thread->thread == cache->thread );
		g_assert( g_slist_find( cache->buffers, buffer ) );
		g_assert( cache->buffer_thread == buffer_thread_get() );

		cache->buffers = g_slist_remove( cache->buffers, buffer );

		buffer->done = FALSE;

#ifdef DEBUG_VERBOSE
		printf( "vips_buffer_undone: %d buffers left\n",
			g_slist_length( cache_list->buffers ) );
#endif /*DEBUG_VERBOSE*/
	}

	buffer->cache = NULL;
	buffer->area.width = 0;
	buffer->area.height = 0;
}

void
vips_buffer_unref( VipsBuffer *buffer )
{
#ifdef DEBUG_VERBOSE
	printf( "** vips_buffer_unref: left = %d, top = %d, "
		"width = %d, height = %d (%p)\n",
		buffer->area.left, buffer->area.top, 
		buffer->area.width, buffer->area.height, 
		buffer );
#endif /*DEBUG_VERBOSE*/

	g_assert( buffer->ref_count > 0 );

	buffer->ref_count -= 1;

	if( buffer->ref_count == 0 ) {
		/* We are not always the creating thread, for example if we 
		 * come here during vips_region_dispose(). cache may have been
		 * NULLed out during thread exit. 
		 */
		VipsBufferCache *cache = buffer->cache;

#ifdef DEBUG_VERBOSE
		if( !buffer->done )
			printf( "vips_buffer_unref: buffer was not done\n" );
#endif /*DEBUG_VERBOSE*/

		vips_buffer_undone( buffer );

		/* Place on this thread's reserve list for reuse.
		 */
		if( cache &&
			cache->n_reserve < buffer_cache_max_reserve ) { 
			g_assert( !buffer->cache ); 

			cache->reserve = 
				g_slist_prepend( cache->reserve, buffer );
			cache->n_reserve += 1; 

			buffer->area.width = 0;
			buffer->area.height = 0;
		}
		else 
			vips_buffer_free( buffer ); 
	}
}

static int
buffer_move( VipsBuffer *buffer, VipsRect *area )
{
	VipsImage *im = buffer->im;
	size_t new_bsize;

	g_assert( buffer->ref_count == 1 );

	vips_buffer_undone( buffer );
	g_assert( !buffer->done );

	buffer->area = *area;

	new_bsize = (size_t) VIPS_IMAGE_SIZEOF_PEL( im ) * 
		area->width * area->height;
	if( buffer->bsize < new_bsize ||
		!buffer->buf ) {
		buffer->bsize = new_bsize;
		VIPS_FREEF( vips_tracked_free, buffer->buf );
		if( !(buffer->buf = vips_tracked_malloc( buffer->bsize )) ) 
			return( -1 );
	}

	return( 0 );
}

/* Make a new buffer.
 */
VipsBuffer *
vips_buffer_new( VipsImage *im, VipsRect *area )
{
	VipsBufferCache *cache = buffer_cache_get( im );

	VipsBuffer *buffer;

	if( cache->reserve ) { 
		buffer = (VipsBuffer *) cache->reserve->data;
		cache->reserve = g_slist_remove( cache->reserve, buffer ); 
		cache->n_reserve -= 1; 

		g_assert( buffer->im == im );
		g_assert( buffer->done == FALSE );
		g_assert( !buffer->cache );

		buffer->ref_count = 1;
	}
	else {
		buffer = g_new0( VipsBuffer, 1 );
		buffer->ref_count = 1;
		buffer->im = im;
		buffer->done = FALSE;
		buffer->cache = NULL;
		buffer->buf = NULL;
		buffer->bsize = 0;

#ifdef DEBUG
		g_mutex_lock( vips__global_lock );
		vips__buffer_all = 
			g_slist_prepend( vips__buffer_all, buffer );
		g_mutex_unlock( vips__global_lock );
#endif /*DEBUG*/
	}

	if( buffer_move( buffer, area ) ) {
		vips_buffer_free( buffer ); 
		return( NULL ); 
	}

	return( buffer );
}

/* Find an existing buffer that encloses area and return a ref.
 */
static VipsBuffer *
buffer_find( VipsImage *im, VipsRect *r )
{
	VipsBufferCache *cache = buffer_cache_get( im );

	VipsBuffer *buffer;
	GSList *p;
	VipsRect *area;

	/* This needs to be quick :-( don't use
	 * vips_slist_map2()/vips_rect_includesrect(), do the search inline.
	 *
	 * FIXME we return the first enclosing buffer, perhaps we should
	 * search for the largest? 
	 */
	for( p = cache->buffers; p; p = p->next ) {
		buffer = (VipsBuffer *) p->data;
		area = &buffer->area;

		if( area->left <= r->left &&
			area->top <= r->top &&
			area->left + area->width >= r->left + r->width &&
			area->top + area->height >= r->top + r->height ) {
			buffer->ref_count += 1;

#ifdef DEBUG_VERBOSE
			printf( "vips_buffer_find: left = %d, top = %d, "
				"width = %d, height = %d, count = %d (%p)\n",
				buffer->area.left, buffer->area.top, 
				buffer->area.width, buffer->area.height, 
				buffer->ref_count,
				buffer );
#endif /*DEBUG_VERBOSE*/

			return( buffer );
		}
	}

	return( NULL );
}

/* Return a ref to a buffer that encloses area. The buffer we return might be
 * done. 
 */
VipsBuffer *
vips_buffer_ref( VipsImage *im, VipsRect *area )
{
	VipsBuffer *buffer;

	if( !(buffer = buffer_find( im, area )) ) 
		/* No existing buffer ... make a new one.
		 */
		if( !(buffer = vips_buffer_new( im, area )) ) 
			return( NULL );

	return( buffer );
}

/* Unref old, ref new, in a single operation. Reuse stuff if we can. The
 * buffer we return might or might not be done.
 */
VipsBuffer *
vips_buffer_unref_ref( VipsBuffer *old_buffer, VipsImage *im, VipsRect *area )
{
	VipsBuffer *buffer;

	g_assert( !old_buffer || 
		old_buffer->im == im );

	/* Is the current buffer OK?
	 */
	if( old_buffer && 
		vips_rect_includesrect( &old_buffer->area, area ) ) 
		return( old_buffer );

	/* Does the new area already have a buffer?
	 */
	if( (buffer = buffer_find( im, area )) ) {
		VIPS_FREEF( vips_buffer_unref, old_buffer );
		return( buffer );
	}

	/* Is the current buffer unshared? We can just move it.
	 */
	if( old_buffer && 
		old_buffer->ref_count == 1 ) {
		if( buffer_move( old_buffer, area ) ) {
			vips_buffer_unref( old_buffer );
			return( NULL );
		}

		return( old_buffer );
	}

	/* Fallback ... unref the old one, make a new one.
	 */
	VIPS_FREEF( vips_buffer_unref, old_buffer );
	if( !(buffer = vips_buffer_new( im, area )) ) 
		return( NULL );

	return( buffer );
}

void
vips_buffer_print( VipsBuffer *buffer )
{
	printf( "VipsBuffer: %p ref_count = %d, ", buffer, buffer->ref_count );
	printf( "im = %p, ", buffer->im );
	printf( "area.left = %d, ", buffer->area.left );
	printf( "area.top = %d, ", buffer->area.top );
	printf( "area.width = %d, ", buffer->area.width );
	printf( "area.height = %d, ", buffer->area.height );
	printf( "done = %d, ", buffer->done );
	printf( "buf = %p, ", buffer->buf );
	printf( "bsize = %zd\n", buffer->bsize );
}

static void
buffer_thread_destroy_notify( VipsBufferThread *buffer_thread )
{
	/* We only come here if vips_thread_shutdown() was not called for this
	 * thread. Do our best to clean up.
	 *
	 * GPrivate has stopped working by this point in destruction, be 
	 * careful not to touch that. 
	 */
	buffer_thread_free( buffer_thread );
}

/* Init the buffer cache system.
 */
void
vips__buffer_init( void )
{
#ifdef HAVE_PRIVATE_INIT
	static GPrivate private = 
		G_PRIVATE_INIT( (GDestroyNotify) buffer_thread_destroy_notify );

	buffer_thread_key = &private;
#else
	if( !buffer_thread_key ) 
		buffer_thread_key = g_private_new( 
			(GDestroyNotify) buffer_thread_destroy_notify );
#endif

	if( buffer_cache_max_reserve < 1 )
		printf( "vips__buffer_init: buffer reserve disabled\n" );

#ifdef DEBUG
	printf( "vips__buffer_init: DEBUG enabled\n" ); 
#endif /*DEBUG*/

#ifdef DEBUG_CREATE
	printf( "vips__buffer_init: DEBUG_CREATE enabled\n" ); 
#endif /*DEBUG_CREATE*/
}

void
vips__buffer_shutdown( void )
{
	VipsBufferThread *buffer_thread;

	if( (buffer_thread = g_private_get( buffer_thread_key )) ) {
		buffer_thread_free( buffer_thread );
		g_private_set( buffer_thread_key, NULL );
	}
}
