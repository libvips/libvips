/* Support for thread pools ... like threadgroups, but lighter.
 * 
 * 18/3/10
 * 	- from threadgroup.c
 * 	- distributed work allocation idea from Christian Blenia, thank you
 * 	  very much
 * 21/3/10
 * 	- progress feedback
 * 	- only expose VipsThreadState
 * 11/5/10
 * 	- argh, stopping many threads could sometimes leave allocated work
 * 	  undone
 * 17/7/10
 * 	- set pool->error whenever we set thr->error, lets us catch allocate
 * 	  errors (thanks Tim)
 * 25/7/14
 * 	- limit nthr on tiny images
 * 6/3/17
 * 	- remove single-thread-first-request thing, new seq system makes it
 * 	  unnecessary
 * 23/4/17
 * 	- add ->stall
 * 	- don't depend on image width when setting n_lines
 * 27/2/19 jtorresfabra
 * 	- free threadpool earlier 
 * 02/02/20 kleisauke
 *	- reuse threads by using GLib's threadpool
 * 	- remove mutex lock for VipsThreadStartFn
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
#define VIPS_DEBUG
#define VIPS_DEBUG_RED
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <glib/gi18n-lib.h>

#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif /*HAVE_UNISTD_H*/
#include <errno.h>

#include <vips/vips.h>
#include <vips/internal.h>
#include <vips/thread.h>
#include <vips/debug.h>

#ifdef G_OS_WIN32
#include <windows.h>
#endif /*G_OS_WIN32*/

/**
 * SECTION: threadpool
 * @short_description: pools of worker threads 
 * @stability: Stable
 * @see_also: <link linkend="libvips-generate">generate</link>
 * @include: vips/vips.h
 * @title: VipsThreadpool
 *
 * A threadpool which allows reusing already started threads. Implementing
 * this can be tedious and error-prone. Therefore we use the GLib
 * provided threadpool for our convenience. An added advantage is, that
 * the threads can be shared between the different subsystems, when they
 * are using GLib.
 *
 * The threadpool is created during vips_init() and is destroyed by
 * vips_shutdown().
 *
 * vips_threadpool_run() loops a set of threads over an image. Threads take it
 * in turns to allocate units of work (a unit might be a tile in an image),
 * then run in parallel to process those units. An optional progress function
 * can be used to give feedback.
 */

/* Set to stall threads for debugging.
 */
static gboolean vips__stall = FALSE;

/* The threadset we'll use.
 */
static VipsThreadset *vips__threadset = NULL;

/* Create the vips threadpool. This is called during vips_init.
 */
void
vips__threadpool_init( void )
{
	if( g_getenv( "VIPS_STALL" ) )
		vips__stall = TRUE;

	vips__threadset = vips_threadset_new();
}

/**
 * vips__thread_execute:
 * @name: a name for the thread
 * @func: a function to execute in the thread pool
 * @data: an argument to supply to @func
 *
 * A newly created or reused thread will execute @func with with the 
 * argument @data.
 *
 * See also: vips_concurrency_set().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips__thread_execute( const char *domain, GFunc func, gpointer data )
{
        return( vips_threadset_run( vips__threadset, domain, func, data ) );
}

/* Called from vips_shutdown().
 */
void
vips__threadpool_shutdown( void )
{
        VIPS_FREEF( vips_threadset_free, vips__threadset );
}

/* The VipsThreadStartFn arg to vips_threadpool_run() is called once for each
 * thread to make one of these things to hold the thread state.
 */

G_DEFINE_TYPE( VipsThreadState, vips_thread_state, VIPS_TYPE_OBJECT );

static void
vips_thread_state_dispose( GObject *gobject )
{
	VipsThreadState *state = (VipsThreadState *) gobject;

	VIPS_DEBUG_MSG( "vips_thread_state_dispose:\n" );

	VIPS_UNREF( state->reg );

	G_OBJECT_CLASS( vips_thread_state_parent_class )->dispose( gobject );
}

static int
vips_thread_state_build( VipsObject *object )
{
	VipsThreadState *state = (VipsThreadState *) object;

	if( !(state->reg = vips_region_new( state->im )) )
		return( -1 );

	return( VIPS_OBJECT_CLASS( 
		vips_thread_state_parent_class )->build( object ) );
}

static void
vips_thread_state_class_init( VipsThreadStateClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = VIPS_OBJECT_CLASS( class );

	gobject_class->dispose = vips_thread_state_dispose;

	object_class->build = vips_thread_state_build;
	object_class->nickname = "threadstate";
	object_class->description = _( "per-thread state for vipsthreadpool" );
}

static void
vips_thread_state_init( VipsThreadState *state )
{
	VIPS_DEBUG_MSG( "vips_thread_state_init:\n" );

	state->reg = NULL;
	state->stop = FALSE;
	state->stall = FALSE;
}

void *
vips_thread_state_set( VipsObject *object, void *a, void *b )
{
	VipsThreadState *state = (VipsThreadState *) object;
	VipsImage *im = (VipsImage *) a;

	VIPS_DEBUG_MSG( "vips_thread_state_set: image %p\n", im );

	state->im = im;
	state->a = b;

	return( NULL );
}

VipsThreadState *
vips_thread_state_new( VipsImage *im, void *a )
{
	VIPS_DEBUG_MSG( "vips_thread_state_new: image %p\n", im );

	return( VIPS_THREAD_STATE( vips_object_new( 
		VIPS_TYPE_THREAD_STATE, vips_thread_state_set, im, a ) ) );
}

/* A VipsTask is the state of one call to vips_threadpool_run().
 */
typedef struct _VipsTask {
	/* All private.
	 */
	/*< private >*/
	VipsImage *im;		/* Image we are calculating */

	/* Start or reuse a thread, do a unit of work (runs in parallel) 
	 * and allocate a unit of work (serial). Plus the mutex we use to 
	 * serialize work allocation.
	 */
	VipsThreadStartFn start; 
	VipsThreadpoolAllocateFn allocate;
	VipsThreadpoolWorkFn work;
	GMutex *allocate_lock;
        void *a; 		/* User argument to start / allocate / etc. */

	/* The caller blocks here until all tasks finish.
	 */
	VipsSemaphore finish;	

	/* Workers up this for every loop to make the main thread tick.
	 */
	VipsSemaphore tick;	

	/* Set this to abort evaluation early with an error.
	 */
	gboolean error;		

	/* Set by Allocate (via an arg) to indicate normal end of computation.
	 */
	gboolean stop;
} VipsTask;

/* Allocate some work (single-threaded), then do it (many-threaded).
 *
 * The very first workunit is also executed single-threaded. This gives
 * loaders a change to seek to the correct spot, see vips_sequential().
 */
static void
vips_task_work_unit( VipsTask *task, VipsThreadState *state )
{
	if( task->error )
		return;

	VIPS_GATE_START( "vips_task_work_unit: wait" ); 

	g_mutex_lock( task->allocate_lock );

	VIPS_GATE_STOP( "vips_task_work_unit: wait" ); 

	/* Has another worker signaled stop while we've been waiting?
	 */
	if( task->stop ) {
		g_mutex_unlock( task->allocate_lock );
		return;
	}

	if( task->allocate( state, task->a, &task->stop ) ) {
		task->error = TRUE;
		g_mutex_unlock( task->allocate_lock );
		return;
	}

	/* Have we just signalled stop?
	 */
	if( task->stop ) {
		g_mutex_unlock( task->allocate_lock );
		return;
	}

	g_mutex_unlock( task->allocate_lock );

	if( state->stall &&
		vips__stall ) { 
		/* Sleep for 0.5s. Handy for stressing the seq system. Stall
		 * is set by allocate funcs in various places. 
		 */
		g_usleep( 500000 ); 
		state->stall = FALSE;
		printf( "vips_task_work_unit: "
			"stall done, releasing y = %d ...\n", state->y );
	}

	/* Process a work unit.
	 */
	if( task->work( state, task->a ) )
		task->error = TRUE;
}

/* What runs as a pipeline thread ... loop, waiting to be told to do stuff.
 */
static void
vips_task_run( gpointer data, gpointer user_data )
{
	VipsTask *task = (VipsTask *) data;
	VipsThreadState *state;

	VIPS_GATE_START( "vips_task_run: thread" );

	if( !(state = task->start( task->im, task->a )) )
		task->error = TRUE;

	/* Process work units! Always tick, even if we are stopping, so the
	 * main thread will wake up for exit. 
	 */
	for(;;) {
		VIPS_GATE_START( "vips_task_work_unit: u" );
		vips_task_work_unit( task, state );
		VIPS_GATE_STOP( "vips_task_work_unit: u" );
		vips_semaphore_up( &task->tick );

		if( task->stop ||
			task->error )
			break;
	} 

	VIPS_FREEF( g_object_unref, state );

	/* We are exiting: tell the main thread. 
	 */
	vips_semaphore_up( &task->finish );

	VIPS_GATE_STOP( "vips_task_run: thread" );
}

static VipsTask *
vips_task_new( VipsImage *im, int *n_tasks )
{
	VipsTask *task;
	int tile_width;
	int tile_height;
	gint64 n_tiles;
	int n_lines;

	if( !(task = VIPS_NEW( NULL, VipsTask )) )
		return( NULL );
	task->im = im;
	task->allocate = NULL;
	task->work = NULL;
	task->allocate_lock = vips_g_mutex_new();
	vips_semaphore_init( &task->finish, 0, "finish" );
	vips_semaphore_init( &task->tick, 0, "tick" );
	task->error = FALSE;
	task->stop = FALSE;

	*n_tasks = vips_concurrency_get();

	/* If this is a tiny image, we won't need all n_tasks. Guess how
	 * many tiles we might need to cover the image and use that to limit
	 * the number of tasks we create.
	 */
	vips_get_tile_size( im, &tile_width, &tile_height, &n_lines );
	n_tiles = (1 + (gint64) im->Xsize / tile_width) * 
		(1 + (gint64) im->Ysize / tile_height);
	n_tiles = VIPS_MAX( 1, n_tiles );
	*n_tasks = VIPS_MIN( *n_tasks, n_tiles );

	VIPS_DEBUG_MSG( "vips_task_new: \"%s\" (%p), with %d tasks\n",
		im->filename, task, *n_tasks );

	return( task );
}

static void
vips_task_free( VipsTask *task )
{
	VIPS_DEBUG_MSG( "vips_task_free: \"%s\" (%p)\n",
		task->im->filename, task );

	VIPS_FREEF( vips_g_mutex_free, task->allocate_lock );
	vips_semaphore_destroy( &task->finish );
	vips_semaphore_destroy( &task->tick );
	VIPS_FREE( task );
}

/**
 * VipsThreadpoolStartFn:
 * @a: client data
 * @b: client data
 * @c: client data
 *
 * This function is called once by each worker just before the first time work
 * is allocated to it to build the per-thread state. Per-thread state is used
 * by #VipsThreadpoolAllocate and #VipsThreadpoolWork to communicate.
 *
 * #VipsThreadState is a subclass of #VipsObject. Start functions can be
 * executed concurrently.
 *
 * See also: vips_threadpool_run().
 *
 * Returns: a new #VipsThreadState object, or NULL on error
 */

/**
 * VipsThreadpoolAllocateFn:
 * @state: per-thread state
 * @a: client data
 * @b: client data
 * @c: client data
 * @stop: set this to signal end of computation
 *
 * This function is called to allocate a new work unit for the thread. It is
 * always single-threaded, so it can modify per-pool state (such as a
 * counter). 
 *
 * @a, @b, @c are the values supplied to the call to 
 * vips_threadpool_run().
 *
 * It should set @stop to %TRUE to indicate that no work could be allocated
 * because the job is done.
 *
 * See also: vips_threadpool_run().
 *
 * Returns: 0 on success, or -1 on error
 */

/**
 * VipsThreadpoolWorkFn:
 * @state: per-thread state
 * @a: client data
 * @b: client data
 * @c: client data
 *
 * This function is called to process a work unit. Many copies of this can run
 * at once, so it should not write to the per-pool state. It can write to
 * per-thread state.
 *
 * @a, @b, @c are the values supplied to the call to 
 * vips_threadpool_run().
 *
 * See also: vips_threadpool_run().
 *
 * Returns: 0 on success, or -1 on error
 */

/**
 * VipsThreadpoolProgressFn:
 * @a: client data
 * @b: client data
 * @c: client data
 *
 * This function is called by the main thread once for every work unit
 * processed. It can be used to give the user progress feedback.
 *
 * See also: vips_threadpool_run().
 *
 * Returns: 0 on success, or -1 on error
 */

/**
 * vips_threadpool_run:
 * @im: image to loop over
 * @start: allocate per-thread state
 * @allocate: allocate a work unit
 * @work: process a work unit
 * @progress: give progress feedback about a work unit, or %NULL
 * @a: client data
 *
 * This function runs a set of threads over an image. It will use a newly
 * created or reused thread within the #VipsThreadPool. Each thread first calls
 * @start to create new per-thread state, then runs
 * @allocate to set up a new work unit (perhaps the next tile in an image, for
 * example), then @work to process that work unit. After each unit is
 * processed, @progress is called, so that the operation can give
 * progress feedback. @progress may be %NULL.
 *
 * The object returned by @start must be an instance of a subclass of
 * #VipsThreadState. Use this to communicate between @allocate and @work. 
 *
 * @allocate is always single-threaded (so it can write to the 
 * per-pool state), whereas @start and @work can be executed concurrently.
 * @progress is always called by 
 * the main thread (ie. the thread which called vips_threadpool_run()).
 *
 * See also: vips_concurrency_set().
 *
 * Returns: 0 on success, or -1 on error.
 */
int
vips_threadpool_run( VipsImage *im, 
	VipsThreadStartFn start, 
	VipsThreadpoolAllocateFn allocate, 
	VipsThreadpoolWorkFn work,
	VipsThreadpoolProgressFn progress, 
	void *a )
{
	VipsTask *task;
	int n_tasks;
	int i;
	int result;

	if( !(task = vips_task_new( im, &n_tasks )) )
		return( -1 );

	task->start = start;
	task->allocate = allocate;
	task->work = work;
	task->a = a;

	/* Create a set of workers for this pipeline.
	 */
	for( i = 0; i < n_tasks; i++ )
		if( vips__thread_execute( "worker", vips_task_run, task ) )
			return( -1 );

	for(;;) {
		/* Wait for a tick from a worker.
		 */
		vips_semaphore_down( &task->tick );

		if( task->stop ||
			task->error )
			break;

		if( progress &&
			progress( task->a ) )
			task->error = TRUE;

		if( task->stop ||
			task->error )
			break;
	}

	/* Wait for them all to hit finish.
	 */
	vips_semaphore_downn( &task->finish, n_tasks );

	/* Return 0 for success.
	 */
	result = task->error ? -1 : 0;

	vips_task_free( task );

	return( result );
}

