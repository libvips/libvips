/* Support for thread pools ... like threadgroups, but lighter.
 * 
 * 18/3/10
 * 	- from threadgroup.c
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
#define TIME_THREAD
#define DEBUG_CREATE
#define DEBUG_HIGHWATER
#define DEBUG_IO
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif /*HAVE_UNISTD_H*/
#include <errno.h>

#include <vips/vips.h>
#include <vips/internal.h>
#include <vips/thread.h>
#include <vips/threadpool.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/**
 * SECTION: threadpool
 * @short_description: pools of worker threads ... a lighter version of
 * threadgroups
 * @stability: Stable
 * @see_also: <link linkend="libvips-generate">generate</link>
 * @include: vips/vips.h
 *
 * This is like threadgroup, but the work allocation is distributed. This
 * reduces the synchronisation overhead and improves scalability.
 *
 * Most of this is internal to VIPS and does not need to be documented. You
 * should only need vips_threadpool_new() and vips_threadpool_free().
 */

#ifdef TIME_THREAD
/* Size of time buffers.
 */
#define IM_TBUF_SIZE (20000)
#endif /*TIME_THREAD*/

#ifdef TIME_THREAD
/* Save time buffers.
 */
static int
save_time_buffers( REGION *reg )
{
	int i;
	static int rn = 1;
	FILE *fp;
	char name[ 256 ];

	im_snprintf( name, 256, "time%d", rn++ );
	if( !(fp = fopen( name, "w" )) )
		error_exit( "unable to write to \"%s\"", name );
	for( i = 0; i < reg->tpos; i++ )
		fprintf( fp, "%lld\n%lld\n", reg->btime[i], reg->etime[i] );
	fclose( fp );

	return( 0 );
}
#endif /*TIME_THREAD*/

/* Junk a thread.
 */
static void
thread_free( VipsThread *thr )
{
        /* Is there a thread running this region? Kill it!
         */
        if( thr->thread ) {
                thr->kill = 1;
		im_semaphore_up( &thr->go );

		/* Return value is always NULL (see thread_main_loop).
		 */
		(void) g_thread_join( thr->thread );
#ifdef DEBUG_CREATE
		printf( "thread_free: g_thread_join()\n" );
#endif /*DEBUG_CREATE*/

		thr->thread = NULL;
        }
	im_semaphore_destroy( &thr->go );

	IM_FREEF( im_region_free, thr->reg );
	thr->oreg = NULL;
	thr->tg = NULL;

#ifdef TIME_THREAD
	if( thr->btime )
		(void) save_time_buffers( thr );
#endif /*TIME_THREAD*/
}

/* The work we do in one loop. This can run from the main thread in a loop if
 * we're unthreaded, or in parallel if we are threaded.
 */
static void
work_fn( VipsThread *thr )
{
	/* Doublecheck only one thread per region.
	 */
	g_assert( thr->thread == g_thread_self() );

	g_assert( thr->pool->work );

	/* Call our work function.
	 */
	if( !thr->error && 
		thr->pool->work( thr, thr->reg, thr->a, thr->b, thr->c ) )
		thr->error = 1;
}

#ifdef HAVE_THREADS
/* What runs as a thread ... loop, waiting to be told to do stuff.
 */
static void *
thread_main_loop( void *a )
{
        VipsThread *thr = (VipsThread *) a;
	VipsThreadpool *pool = thr->pool;

	g_assert( pool == thr->pool );

	/* We now control the region (it was created by pool when we 
	 * were built).
	 */
	im__region_take_ownership( thr->reg );

	for(;;) {
		/* Block until work is ready for us.
		 */
		im_semaphore_down( &thr->go );

		/* Asked to exit?
		 */
		if( thr->kill )
			break;

		/* Starting to work on something.
		 */
		for(;;) {
			gboolean alldone;

			/* Ask for a work unit.
			 */
			g_mutex_lock( &pool->allocate_lock );
			alldone = pool->allocate( thr );
			if( alldone && !pool->stop ) {
				/* The allocate function has returned TRUE
				 * (all done) for the first time. Set
				 * everything to make all threads return to
				 * their 'go' semaphores and restart the main
				 * thread.
				 */
				pool->stop = TRUE;
				im_semaphore_up( &pool->main );
			}
			g_mutex_unlock( &pool->allocate_lock );

			/* Asked to stop work?
			 */
			if( thr->stop || thr->kill ||
				pool->stop || pool->kill )
				break;

#ifdef TIME_THREAD
			/* Note start time.
			 */
			if( thr->btime )
				thr->btime[thr->tpos] = gethrtime();
#endif /*TIME_THREAD*/

			/* Loop once.
			 */
			work_fn( thr ); 

#ifdef TIME_THREAD
			/* Note stop time.
			 */
			if( thr->etime ) {
				thr->etime[thr->tpos] = gethrtime();
				thr->tpos++;
			}
#endif /*TIME_THREAD*/
		}
	}

        return( NULL );
}
#endif /*HAVE_THREADS*/

/* Attach another thread to a threadgroup.
 */
static VipsThread *
vips_thread_new( VipsThreadpool *pool )
{
	VipsThread *thr;

	if( !(thr = IM_NEW( pool->im, VipsThread )) )
		return( NULL );
	thr->pool = pool;
	thr->reg = NULL;
	thr->thread = NULL;
	thr->kill = 0;
	thr->stop = 0;
	thr->error = 0;
	thr->oreg = NULL;
	thr->a = thr->b = thr->c = NULL;
#ifdef TIME_THREAD
	thr->btime = NULL;
	thr->etime = NULL;
	thr->tpos = 0;
#endif /*TIME_THREAD*/

	/* Attach stuff. 
	 */
	if( !(thr->reg = im_region_create( pool->im )) ) {
		thread_free( thr );
		return( NULL );
	}

	/* Get ready to hand the region over to the thread.
	 */
	im__region_no_ownership( thr->reg );

#ifdef TIME_THREAD
	thr->btime = IM_ARRAY( pool->im, IM_TBUF_SIZE, hrtime_t );
	thr->etime = IM_ARRAY( pool->im, IM_TBUF_SIZE, hrtime_t );
	if( !thr->btime || !thr->etime ) {
		thread_free( thr );
		return( NULL );
	}
#endif /*TIME_THREAD*/

#ifdef HAVE_THREADS
	/* Make a worker thread. We have to use g_thread_create_full() because
	 * we need to insist on a non-tiny stack. Some platforms default to
	 * very small values (eg. various BSDs).
	 */
	if( !(thr->thread = g_thread_create_full( thread_main_loop, thr, 
		IM__DEFAULT_STACK_SIZE, TRUE, FALSE, 
		G_THREAD_PRIORITY_NORMAL, NULL )) ) {
		im_error( "threadgroup_thread_new", 
			"%s", _( "unable to create thread" ) );
		thread_free( thr );
		return( NULL );
	}

#ifdef DEBUG_CREATE
	printf( "threadgroup_thread_new: g_thread_create_full()\n" );
#endif /*DEBUG_CREATE*/
#endif /*HAVE_THREADS*/

	return( thr );
}

/* Kill all threads in a threadgroup, if there are any.
 */
static void
threadpool_kill_threads( VipsThreadpool *pool )
{
	if( pool->thr ) {
		int i;

		for( i = 0; i < pool->nthr; i++ ) 
			thread_free( pool->thr[i] );
		pool->thr = NULL;

#ifdef DEBUG_IO
		printf( "threadpool_kill_threads: killed %d threads\n", 
			pool->nthr );
#endif /*DEBUG_IO*/
	}
}

/**
 * vips_threadpool_free:
 * @pool: pool to free
 *
 * Frees a VipsThreadpool. This function can be called multiple times, though
 * only the first call will have any effect.
 *
 * All worker threads are terminated and all resources freed.
 *
 * See also: vips_threadpool_new().
 *
 * Returns: 0.
 */
int
vips_threadpool_free( VipsThreadpool *pool )
{
#ifdef DEBUG_IO
	printf( "vips_threadpool_free: \"%s\" (%p)\n", 
		pool->im->filename, pool );
#endif /*DEBUG_IO*/

	if( !pool || pool->zombie )
		return( 0 );

	threadpool_kill_threads( pool );
	IM_FREEF( g_mutex_free, pool->allocate_lock );
	pool->zombie = 1;

#ifdef DEBUG_HIGHWATER
	printf( "vips_threadpool_free %p: max busy workers = %d\n", 
		pool, pool->nthr - pool->min_idle );
#endif /*DEBUG_HIGHWATER*/

	return( 0 );
}

/**
 * vips_threadpool_new:
 * @im: image to create the threadgroup on
 *
 * Makes a threadpool attached to the image. The threadgroup will be freed
 * for you if the image is closed, but you can free it yourself with
 * vips_threadpool_free() if you wish.
 *
 * See also: vips_threadpool_free().
 *
 * Returns: an #VipsThreadpool on success, %NULL on error.
 */
VipsThreadpool *
vips_threadpool_new( VipsImage *im )
{
	VipsThreadpool *pool;
	int i;

	/* Allocate and init new thread block.
	 */
	if( !(pool = IM_NEW( im, VipsThreadpool )) )
		return( NULL );
	pool->im = im;
	pool->allocate = NULL;
	pool->work = NULL;
	pool->allocate_lock = g_mutex_new();
	if( (pool->nthr = im_concurrency_get()) < 0 )
		return( NULL );
	pool->thr = NULL;
	im_semaphore_init( &pool->finish, 0, "finish" );
	pool->kill = FALSE;
	pool->stop = FALSE;
	pool->progress = FALSE;
	pool->zombie = FALSE;

	/* Pick a render geometry.
	 */
	switch( pool->im->dhint ) {
	case IM_SMALLTILE:
		pool->pw = im__tile_width;
		pool->ph = im__tile_height;

		/* Enough lines of tiles that we can expect to be able to keep
		 * nthr busy.
		 */
		pool->nlines = pool->ph * (1 + pool->nthr / 
			IM_MAX( 1, pool->im->Xsize / pool->pw ));
		break;

	case IM_FATSTRIP:
		pool->pw = pool->im->Xsize;
		pool->ph = im__fatstrip_height;
		pool->nlines = pool->ph * pool->nthr * 2;
		break;

	case IM_ANY:
	case IM_THINSTRIP:
		pool->pw = pool->im->Xsize;
		pool->ph = im__thinstrip_height;
		pool->nlines = pool->ph * pool->nthr * 2;
		break;

	default:
		g_assert( 0 );
	}

	/* Attach tidy-up callback.
	 */
	if( im_add_close_callback( im, 
		(im_callback_fn) vips_threadpool_free, pool, NULL ) ) {
		(void) vips_threadpool_free( pool );
		return( NULL );
	}

#ifdef DEBUG_IO
	printf( "vips_threadpool_new: %d by %d patches, "
		"groups of %d scanlines\n", pool->pw, pool->ph, pool->nlines );
#endif /*DEBUG_IO*/

#ifdef DEBUG_HIGHWATER
	pool->nidle = 0;
	pool->min_idle = pool->nthr;
#endif /*DEBUG_HIGHWATER*/

#ifdef DEBUG_IO
	printf( "vips_threadpool_new: \"%s\" (%p), with %d threads\n", 
		im->filename, pool, pool->nthr );
#endif /*DEBUG_IO*/

	return( pool );
}

/* Attach a set of threads.
 */
static int
threadpool_create_threads( VipsThreadpool *pool )
{
	int i;

	g_assert( !pool->thr );

	/* Make thread array.
	 */
	if( !(pool->thr = IM_ARRAY( im, pool->nthr, VipsThread * )) )
		return( -1 );
	for( i = 0; i < pool->nthr; i++ )
		pool->thr[i] = NULL;

	/* Attach threads and start them working.
	 */
	for( i = 0; i < pool->nthr; i++ )
		if( !(pool->thr[i] = vips_thread_new( pool )) ) {
			threadpool_kill_threads( pool );
			return( -1 );
		}

	return( 0 );
}

/* Run a threadpool. The allocate and work fns need to have been set.
 *
 * If we don't have threading enabled, do the work in the main thread.
 */
int
vips_threadpool_run( VipsThreadpool *pool, 
	VipsThreadpoolAllocate allocate, VipsThreadpoolWork work )
{
	int result;

	pool->allocate = allocate;
	pool->work = work;
	pool->kill = 0;
	pool->stop = 0;

	/* Attach workers and set them going.
	 */
	if( threadpool_create_threads( pool ) )
		return( -1 );

#ifdef HAVE_THREADS
	/* Wait for them all to hit finish.
	 */
	im_semaphore_downn( &pool->finish, pool->nthr );
#else
	/* No threads, do the work ourselves in the main thread.
	 */
	for(;;) {
		gboolean alldone;

		alldone = pool->allocate( pool->thr[0] );
		if( alldone && !pool->stop )
			pool->stop = TRUE;
		if( pool->thr[0]->error )
			break;
		if( pool->thr[0]->stop || pool->thr[0]->kill || 
			pool->stop || pool->kill )
			break;

		work_fn( pool->thr[0] );
	}
#endif /*HAVE_THREADS*/

	/* Test for error.
	 */
	result = 0;
	if( pool->kill || 
		pool->im->kill ) 
		result = -1;
	else {
		for( i = 0; i < pool->nthr; i++ ) 
			if( pool->thr[i]->error )
				result = -1;
	}
	if( result ) {
		threadpool_kill_threads( pool );
		return( -1 );
	}

	pool->kill = 0;
	pool->stop = 0;

	return( 0 );
}
