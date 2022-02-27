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
 * 13/10/16
 * 	- better solution: don't keep a buffercache for non-workers
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
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <glib/gi18n-lib.h>

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

/* Workers have a BufferThread (and BufferCache) in a GPrivate they have 
 * exclusive access to.
 */
static GPrivate *buffer_thread_key = NULL;

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
	printf( "cache = %p, ", buffer->cache );
	printf( "buf = %p, ", buffer->buf );
	printf( "bsize = %zd\n", buffer->bsize );
}

#ifdef DEBUG
static void *
vips_buffer_dump( VipsBuffer *buffer, size_t *reserve, size_t *alive )
{
	vips_buffer_print( buffer ); 

	g_assert( buffer->im );
	g_assert( buffer->buf );

	if( !buffer->cache &&
		!buffer->done ) {  
		/* Global buffer, not linked to any cache.
		 */
		printf( "global buffer %p, %.3g MB\n", 
			buffer, buffer->bsize / (1024 * 1024.0) ); 
		*alive += buffer->bsize;
	}

	else if( buffer->cache &&
		buffer->done &&
		!vips_rect_isempty( &buffer->area ) &&
		g_slist_find( buffer->cache->buffers, buffer ) ) {
		/* Published on a thread. 
		 */
		printf( "thread buffer %p, %.3g MB\n", 
			buffer, buffer->bsize / (1024 * 1024.0) ); 
		*alive += buffer->bsize;
	}

	else if( buffer->ref_count == 0 &&
		buffer->cache &&
		!buffer->done &&
		vips_rect_isempty( &buffer->area ) &&
		g_slist_find( buffer->cache->reserve, buffer ) )
		/* Held in reserve.
		 */
		*reserve += buffer->bsize;

	else
		printf( "buffer craziness!\n" ); 

	return( NULL );
}
#endif /*DEBUG*/

#ifdef DEBUG_CREATE
static void *
vips_buffer_cache_dump( VipsBufferCache *cache, void *a, void *b )
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

#ifdef DEBUG_VERBOSE
	printf( "vips_buffer_free: freeing buffer %p\n", buffer );
#endif /*DEBUG_VERBOSE*/
}

static void
buffer_thread_free( VipsBufferThread *buffer_thread )
{
	VIPS_FREEF( g_hash_table_destroy, buffer_thread->hash );
	VIPS_FREE( buffer_thread );
}

/* Run for GDestroyNotify on the VipsBufferThread hash. 
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

		g_assert( buffer->done ); 
		g_assert( buffer->cache == cache ); 

		buffer->done = FALSE;
		buffer->cache = NULL;
	}
	VIPS_FREEF( g_slist_free, cache->buffers );

	for( p = cache->reserve; p; p = p->next ) {
		VipsBuffer *buffer = (VipsBuffer *) p->data;

		vips_buffer_free( buffer ); 
	}
	VIPS_FREEF( g_slist_free, cache->reserve );

	g_free( cache );
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

#ifdef DEBUG_CREATE
	g_mutex_lock( vips__global_lock );
	vips__buffer_cache_all = 
		g_slist_prepend( vips__buffer_cache_all, cache );
	g_mutex_unlock( vips__global_lock );

	printf( "buffer_cache_new: new cache %p for thread %p on image %p\n",
		cache, g_thread_self(), im );
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

/* Get our private VipsBufferThread. NULL for non-worker threads.
 */
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
	else 
		/* Non-workers don't have one. 
		 */
		buffer_thread = NULL; 

	return( buffer_thread );
}

/* Get the VipsBufferCache for this image, or NULL for a non-worker.
 */
static VipsBufferCache *
buffer_cache_get( VipsImage *im )
{
	VipsBufferThread *buffer_thread;
	VipsBufferCache *cache;

	if( (buffer_thread = buffer_thread_get()) ) { 
		if( !(cache = (VipsBufferCache *) 
			g_hash_table_lookup( buffer_thread->hash, im )) ) {
			cache = buffer_cache_new( buffer_thread, im );
			g_hash_table_insert( buffer_thread->hash, im, cache );
		}

		g_assert( cache->thread == g_thread_self() ); 
	}
	else
		cache = NULL;

	return( cache ); 
}

/* Pixels have been calculated: publish for other parts of this thread to see.
 */
void 
vips_buffer_done( VipsBuffer *buffer )
{
	VipsImage *im = buffer->im;
	VipsBufferCache *cache;

	if( !buffer->done &&
		(cache = buffer_cache_get( im )) ) { 
		g_assert( !g_slist_find( cache->buffers, buffer ) );
		g_assert( !buffer->cache ); 

		buffer->done = TRUE;
		buffer->cache = cache;

		cache->buffers = g_slist_prepend( cache->buffers, buffer );

#ifdef DEBUG_VERBOSE
		printf( "vips_buffer_done: "
			"thread %p adding buffer %p to cache %p\n",
			g_thread_self(), buffer, cache );
		vips_buffer_print( buffer ); 
#endif /*DEBUG_VERBOSE*/
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

		g_assert( cache->thread == g_thread_self() );
		g_assert( cache->buffer_thread->thread == cache->thread );
		g_assert( g_slist_find( cache->buffers, buffer ) );
		g_assert( buffer_thread_get() );
		g_assert( cache->buffer_thread == buffer_thread_get() );

		cache->buffers = g_slist_remove( cache->buffers, buffer );
		buffer->done = FALSE;

#ifdef DEBUG_VERBOSE
		printf( "vips_buffer_undone: %d buffers left\n",
			g_slist_length( cache->buffers ) );
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
		VipsBufferCache *cache;

#ifdef DEBUG_VERBOSE
		if( !buffer->done )
			printf( "vips_buffer_unref: buffer was not done\n" );
#endif /*DEBUG_VERBOSE*/

		vips_buffer_undone( buffer );

		/* Place on this thread's reserve list for reuse.
		 */
		if( (cache = buffer_cache_get( buffer->im )) && 
			cache->n_reserve < buffer_cache_max_reserve ) { 
			g_assert( !buffer->cache ); 

			cache->reserve = 
				g_slist_prepend( cache->reserve, buffer );
			cache->n_reserve += 1; 

			buffer->cache = cache;
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
	VipsBufferCache *cache;
	VipsBuffer *buffer;

	if( (cache = buffer_cache_get( im )) && 
		cache->reserve ) { 
		buffer = (VipsBuffer *) cache->reserve->data;
		cache->reserve = g_slist_remove( cache->reserve, buffer ); 
		cache->n_reserve -= 1; 

		g_assert( buffer->im == im );
		g_assert( buffer->done == FALSE );
		g_assert( buffer->cache );

		buffer->ref_count = 1;
		buffer->done = FALSE;
		buffer->cache = NULL;
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

/* Find an existing buffer that encloses area and return a ref. Or NULL for no
 * existing buffer. 
 */
static VipsBuffer *
buffer_find( VipsImage *im, VipsRect *r )
{
	VipsBufferCache *cache;
	VipsBuffer *buffer;
	GSList *p;
	VipsRect *area;

	if( !(cache = buffer_cache_get( im )) ) 
		return( NULL ); 

	/* This needs to be quick :-( don't use
	 * vips_slist_map2()/vips_rect_includesrect(), do the search 
	 * inline.
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
			printf( "buffer_find: left = %d, top = %d, "
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

	if( (buffer = buffer_find( im, area )) ) 
		return( buffer ); 
	else
		return( vips_buffer_new( im, area ) );
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

/* Init the buffer cache system. This is called during vips_init.
 */
void
vips__buffer_init( void )
{
	static GPrivate private = 
		G_PRIVATE_INIT( (GDestroyNotify) buffer_thread_destroy_notify );

	buffer_thread_key = &private;

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
