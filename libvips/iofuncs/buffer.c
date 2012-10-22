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

/*
#define DEBUG_CREATE
#define DEBUG
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
/* Track all regions here for debugging.
 */
static GSList *vips__buffers_all = NULL;
#endif /*DEBUG*/

#ifdef DEBUG_CREATE
static int buffer_cache_n = 0; 
#endif /*DEBUG_CREATE*/

static GPrivate *thread_buffer_cache_key = NULL;

static void
buffer_cache_free( VipsBufferCache *cache )
{
#ifdef DEBUG_CREATE
	buffer_cache_n -= 1;

	printf( "buffer_cache_free: freeing cache %p on thread %p\n",
		cache, g_thread_self() );
	printf( "\t(%d cachees left)\n", buffer_cache_n );
#endif /*DEBUG_CREATE*/

	VIPS_FREEF( g_hash_table_destroy, cache->hash );
	VIPS_FREE( cache );
}

static void
buffer_cache_list_free( VipsBufferCacheList *cache_list )
{
	GSList *p;

	/* Need to mark undone so we don't try and take them off this hash on
	 * unref.
	 */
	for( p = cache_list->buffers; p; p = p->next ) {
		VipsBuffer *buffer = (VipsBuffer *) p->data;

		buffer->done = FALSE;
	}

	g_slist_free( cache_list->buffers );
	g_free( cache_list );
}

static VipsBufferCacheList *
buffer_cache_list_new( VipsBufferCache *cache, VipsImage *im )
{
	VipsBufferCacheList *cache_list;

	cache_list = g_new( VipsBufferCacheList, 1 );
	cache_list->buffers = NULL;
	cache_list->thread = g_thread_self();
	cache_list->cache = cache;
	cache_list->im = im;

#ifdef DEBUG_CREATE
	printf( "buffer_cache_list_new: new cache %p for thread %p\n",
		cache, g_thread_self() );
	printf( "\t(%d cachees now)\n", buffer_cache_n );
#endif /*DEBUG_CREATE*/

	return( cache_list );
}

static VipsBufferCache *
buffer_cache_new( void )
{
	VipsBufferCache *cache;

	cache = g_new( VipsBufferCache, 1 );
	cache->hash = g_hash_table_new_full( g_direct_hash, g_direct_equal, 
		NULL, (GDestroyNotify) buffer_cache_list_free );
	cache->thread = g_thread_self();

#ifdef DEBUG_CREATE
	buffer_cache_n += 1;

	printf( "buffer_cache_new: new cache %p for thread %p\n",
		cache, g_thread_self() );
	printf( "\t(%d cachees now)\n", buffer_cache_n );
#endif /*DEBUG_CREATE*/

	return( cache );
}

/* Get the buffer cache. 
 */
static VipsBufferCache *
buffer_cache_get( void )
{
	VipsBufferCache *cache;

	if( !(cache = g_private_get( thread_buffer_cache_key )) ) {
		cache = buffer_cache_new();
		g_private_set( thread_buffer_cache_key, cache );
	}

	return( cache );
}

/* Pixels have been calculated: publish for other parts of this thread to see.
 */
void 
vips_buffer_done( VipsBuffer *buffer )
{
	if( !buffer->done ) {
		VipsImage *im = buffer->im;
		VipsBufferCache *cache = buffer_cache_get();
		VipsBufferCacheList *cache_list;

#ifdef DEBUG
		printf( "vips_buffer_done: thread %p adding to cache %p\n",
			g_thread_self(), cache );
		vips_buffer_print( buffer ); 
#endif /*DEBUG*/

		/* Look up and update the buffer list. 
		 */
		if( !(cache_list = g_hash_table_lookup( cache->hash, im )) ) {
			cache_list = buffer_cache_list_new( cache, im );
			g_hash_table_insert( cache->hash, im, cache_list );
		}

		g_assert( !g_slist_find( cache_list->buffers, buffer ) );
		g_assert( cache_list->thread == cache->thread );

		cache_list->buffers = 
			g_slist_prepend( cache_list->buffers, buffer );
		buffer->done = TRUE;
		buffer->cache = cache;
	}
}

/* Take off the public 'done' list. 
 */
void
vips_buffer_undone( VipsBuffer *buffer )
{
	if( buffer->done ) {
		VipsImage *im = buffer->im;
		VipsBufferCache *cache = buffer->cache;
		VipsBufferCacheList *cache_list;

#ifdef DEBUG
		printf( "vips_buffer_undone: thread %p removing "
			"buffer %p from cache %p\n",
			g_thread_self(), buffer, cache );
#endif /*DEBUG*/

		g_assert( cache->thread == g_thread_self() );

		cache_list = g_hash_table_lookup( cache->hash, im );

		g_assert( cache_list );
		g_assert( cache_list->thread == cache->thread );
		g_assert( g_slist_find( cache_list->buffers, buffer ) );

		cache_list->buffers = 
			g_slist_remove( cache_list->buffers, buffer );
		buffer->done = FALSE;
		buffer->cache = NULL;

#ifdef DEBUG
		printf( "vips_buffer_undone: %d buffers left\n",
			g_slist_length( cache_list->buffers ) );
#endif /*DEBUG*/
	}
}

void
vips_buffer_unref( VipsBuffer *buffer )
{
#ifdef DEBUG
	printf( "** vips_buffer_unref: left = %d, top = %d, "
		"width = %d, height = %d (%p)\n",
		buffer->area.left, buffer->area.top, 
		buffer->area.width, buffer->area.height, 
		buffer );
#endif /*DEBUG*/

	g_assert( buffer->ref_count > 0 );

	buffer->ref_count -= 1;

	if( buffer->ref_count == 0 ) {
#ifdef DEBUG
		if( !buffer->done )
			printf( "vips_buffer_unref: buffer was not done\n" );
#endif /*DEBUG*/

		vips_buffer_undone( buffer );

		buffer->im = NULL;
		vips_tracked_free( buffer->buf );
		buffer->bsize = 0;
		g_free( buffer );

#ifdef DEBUG
		g_mutex_lock( vips__global_lock );
		g_assert( g_slist_find( vips__buffers_all, buffer ) );
		vips__buffers_all = g_slist_remove( vips__buffers_all, buffer );
		printf( "%d buffers in vips\n", 
			g_slist_length( vips__buffers_all ) );
		g_mutex_unlock( vips__global_lock );
#endif /*DEBUG*/
	}
}

/* Make a new buffer.
 */
VipsBuffer *
vips_buffer_new( VipsImage *im, VipsRect *area )
{
	VipsBuffer *buffer;

	buffer = g_new( VipsBuffer, 1 );
	buffer->ref_count = 1;
	buffer->im = im;
	buffer->area = *area;
	buffer->done = FALSE;
	buffer->cache = NULL;
	buffer->bsize = (size_t) VIPS_IMAGE_SIZEOF_PEL( im ) * 
		area->width * area->height;
	if( !(buffer->buf = vips_tracked_malloc( buffer->bsize )) ) {
		vips_buffer_unref( buffer );
		return( NULL );
	}

#ifdef DEBUG
	printf( "** vips_buffer_new: left = %d, top = %d, "
		"width = %d, height = %d (%p)\n",
		buffer->area.left, buffer->area.top, 
		buffer->area.width, buffer->area.height, 
		buffer );
#endif /*DEBUG*/

#ifdef DEBUG
	g_mutex_lock( vips__global_lock );
	vips__buffers_all = g_slist_prepend( vips__buffers_all, buffer );
	printf( "%d buffers in vips\n", g_slist_length( vips__buffers_all ) );
	g_mutex_unlock( vips__global_lock );
#endif /*DEBUG*/

	return( buffer );
}

static int
buffer_move( VipsBuffer *buffer, VipsRect *area )
{
	VipsImage *im = buffer->im;
	size_t new_bsize;

	g_assert( buffer->ref_count == 1 );

	buffer->area = *area;
	vips_buffer_undone( buffer );
	g_assert( !buffer->done );

	new_bsize = (size_t) VIPS_IMAGE_SIZEOF_PEL( im ) * 
		area->width * area->height;
	if( buffer->bsize < new_bsize ) {
		buffer->bsize = new_bsize;
		vips_tracked_free( buffer->buf );
		if( !(buffer->buf = vips_tracked_malloc( buffer->bsize )) ) 
			return( -1 );
	}

	return( 0 );
}

/* Find an existing buffer that encloses area and return a ref.
 */
static VipsBuffer *
buffer_find( VipsImage *im, VipsRect *r )
{
	VipsBufferCache *cache = buffer_cache_get();
	VipsBufferCacheList *cache_list;
	VipsBuffer *buffer;
	GSList *p;
	VipsRect *area;

	cache_list = g_hash_table_lookup( cache->hash, im );
	p = cache_list ? cache_list->buffers : NULL;

	/* This needs to be quick :-( don't use
	 * vips_slist_map2()/vips_rect_includesrect(), do the search inline.
	 *
	 * FIXME we return the first enclosing buffer, perhaps we should
	 * search for the largest? 
	 */
	for( ; p; p = p->next ) {
		buffer = (VipsBuffer *) p->data;
		area = &buffer->area;

		if( area->left <= r->left &&
			area->top <= r->top &&
			area->left + area->width >= r->left + r->width &&
			area->top + area->height >= r->top + r->height ) {
			buffer->ref_count += 1;

#ifdef DEBUG
			printf( "vips_buffer_find: left = %d, top = %d, "
				"width = %d, height = %d, count = %d (%p)\n",
				buffer->area.left, buffer->area.top, 
				buffer->area.width, buffer->area.height, 
				buffer->ref_count,
				buffer );
#endif /*DEBUG*/

			break;
		}
	}

	if( p )
		return( buffer );
	else
		return( NULL );
}

/* Return a ref to a buffer that encloses area.
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

	g_assert( !old_buffer || old_buffer->im == im );

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
	if( old_buffer && old_buffer->ref_count == 1 ) {
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

/* Init the buffer cache system.
 */
void
vips__buffer_init( void )
{
	if( !thread_buffer_cache_key ) 
		thread_buffer_cache_key = g_private_new( 
			(GDestroyNotify) buffer_cache_free );
}
