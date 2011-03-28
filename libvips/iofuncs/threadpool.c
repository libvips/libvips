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
#define VIPS_DEBUG_RED
#define VIPS_DEBUG
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
#include <vips/debug.h>

#ifdef OS_WIN32
#include <windows.h>
#endif /*OS_WIN32*/

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/**
 * SECTION: threadpool
 * @short_description: pools of worker threads 
 * @stability: Stable
 * @see_also: <link linkend="libvips-generate">generate</link>
 * @include: vips/vips.h
 *
 * vips_threadpool_run() loops a set of threads over an image. Threads take it
 * in turns to allocate units of work (a unit might be a tile in an image),
 * then run in parallel to process those units. An optional progress function
 * can be used to give feedback.
 */

/* Maximum number of concurrent threads we allow. No reason for the limit,
 * it's just there to stop mad values for IM_CONCURRENCY killing the system.
 */
#define MAX_THREADS (1024)

/* Name of environment variable we get concurrency level from.
 */
#define IM_CONCURRENCY "IM_CONCURRENCY"

/* Default tile geometry ... can be set by init_world.
 */
int im__tile_width = IM__TILE_WIDTH;
int im__tile_height = IM__TILE_HEIGHT;
int im__fatstrip_height = IM__FATSTRIP_HEIGHT;
int im__thinstrip_height = IM__THINSTRIP_HEIGHT;

/* Default n threads ... 0 means get from environment.
 */
int im__concurrency = 0;

#ifndef HAVE_THREADS
/* If we're building without gthread, we need stubs for the g_thread_*() and
 * g_mutex_*() functions. <vips/thread.h> has #defines which point the g_
 * names here.
 */

void im__g_thread_init( GThreadFunctions *vtable ) {}
gpointer im__g_thread_join( GThread *dummy ) { return( NULL ); }
gpointer im__g_thread_self( void ) { return( NULL ); }
GThread *im__g_thread_create_full( GThreadFunc d1, 
	gpointer d2, gulong d3, gboolean d4, gboolean d5, GThreadPriority d6,
	GError **d7 )
	{ return( NULL ); }

GMutex *im__g_mutex_new( void ) { return( NULL ); }
void im__g_mutex_free( GMutex *d ) {}
void im__g_mutex_lock( GMutex *d ) {}
void im__g_mutex_unlock( GMutex *d ) {}
#endif /*!HAVE_THREADS*/

void
im_concurrency_set( int concurrency )
{
	im__concurrency = concurrency;
}

static int
get_num_processors( void )
{
	int nproc;

	nproc = 1;

#ifdef G_OS_UNIX

#if defined(HAVE_UNISTD_H) && defined(_SC_NPROCESSORS_ONLN)
{
	/* POSIX style.
	 */
	int x;

	x = sysconf( _SC_NPROCESSORS_ONLN );
	if( x > 0 )
		nproc = x;
}
#elif defined HW_NCPU
{
	/* BSD style.
	 */
	int x;
	size_t len = sizeof(x);

	sysctl( (int[2]) {CTL_HW, HW_NCPU}, 2, &x, &len, NULL, 0 );
	if( x > 0 )
		nproc = x;
}
#endif

	/* libgomp has some very complex code on Linux to count the number of
	 * processors available to the current process taking pthread affinity
	 * into account, but we don't attempt that here. Perhaps we should?
	 */

#endif /*G_OS_UNIX*/

#ifdef OS_WIN32
{
	/* Count the CPUs currently available to this process.  
	 */
	DWORD_PTR process_cpus;
	DWORD_PTR system_cpus;

	if( GetProcessAffinityMask( GetCurrentProcess(), 
		&process_cpus, &system_cpus ) ) {
		unsigned int count;

		for( count = 0; process_cpus != 0; process_cpus >>= 1 )
			if( process_cpus & 1 )
				count++;

		if( count > 0 )
			nproc = count;
	}
}
#endif /*OS_WIN32*/

	return( nproc );
}

/* Set (p)thr_concurrency() from IM_CONCURRENCY environment variable. Return 
 * the number of regions we should pass over the image.
 */
int
im_concurrency_get( void )
{
	const char *str;
	int nthr;
	int x;

	/* Tell the threads system how much concurrency we expect.
	 */
	if( im__concurrency > 0 )
		nthr = im__concurrency;
	else if( (str = g_getenv( IM_CONCURRENCY )) && 
		(x = atoi( str )) > 0 )
		nthr = x;
	else 
		nthr = get_num_processors();

	if( nthr < 1 || nthr > MAX_THREADS ) {
		nthr = VIPS_CLIP( 1, nthr, MAX_THREADS );

		vips_warn( "im_concurrency_get", 
			_( "threads clipped to %d" ), nthr );
	}

	/* Save for next time around.
	 */
	im_concurrency_set( nthr );

	return( nthr );
}

/**
 * VipsThreadState:
 * @im: the #VipsImage being operated upon
 * @reg: a #REGION
 * @pos: a #Rect
 * @x: an int
 * @y: an int
 * @a: client data
 *
 * These per-thread values are carried around for your use by
 * vips_threadpool_run(). They are private to each thread, so they are a
 * useful place
 * for #VipsThreadpoolAllocate and #VipsThreadpoolWork to communicate.
 *
 * @reg is created for you at the start of processing and freed at the end,
 * but you can do what you like with it.
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
}

void *
vips_thread_state_set( VipsObject *object, void *a, void *b )
{
	VipsThreadState *state = (VipsThreadState *) object;
	VipsImage *im = (VipsImage *) a;

	VIPS_DEBUG_MSG( "vips_thread_state_set:\n" );

	state->im = im;
	state->a = b;

	return( NULL );
}

VipsThreadState *
vips_thread_state_new( VipsImage *im, void *a )
{
	VIPS_DEBUG_MSG( "vips_thread_state_new:\n" );

	return( VIPS_THREAD_STATE( vips_object_new( 
		VIPS_TYPE_THREAD_STATE, vips_thread_state_set, im, a ) ) );
}

/* What we track for each thread in the pool.
 */
typedef struct {
	/* All private.
	 */
	/*< private >*/
	struct _VipsThreadpool *pool; /* Pool we are part of */

	VipsThreadState *state;

	/* Thread we are running.
	 */
        GThread *thread;  	

	/* Set this to ask the thread to exit.
	 */
	gboolean exit;	

	/* Set by the thread if work or allocate return an error.
	 */
	gboolean error;	

#ifdef TIME_THREAD
	double *btime, *etime;
	int tpos;
#endif /*TIME_THREAD*/
} VipsThread;

/* What we track for a group of threads working together.
 */
typedef struct _VipsThreadpool {
	/* All private.
	 */
	/*< private >*/
	VipsImage *im;		/* Image we are calculating */

	/* Start a thread, do a unit of work (runs in parallel) and allocate 
	 * a unit of work (serial). Plus the mutex we use to serialize work 
	 * allocation.
	 */
	VipsThreadStart start; 
	VipsThreadpoolAllocate allocate;
	VipsThreadpoolWork work;
	GMutex *allocate_lock;
        void *a; 		/* User argument to start / allocate / etc. */

	int nthr;		/* Number of threads in pool */
	VipsThread **thr;	/* Threads */

	/* The caller blocks here until all threads finish.
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
} VipsThreadpool;

#ifdef TIME_THREAD
/* Size of time buffers.
 */
#define TBUF_SIZE (20000)
static GTimer *thread_timer = NULL;
#endif /*TIME_THREAD*/

#ifdef TIME_THREAD
/* Save time buffers.
 */
static int
vips_thread_save_time_buffers( VipsThread *thr )
{
	int i;
	static int rn = 1;
	FILE *fp;
	char name[256];

	im_snprintf( name, 256, "time%d", rn++ );
	printf( "vips_thread_save_time_buffers: "
		"saving buffer to \"%s\"\n", name );
	if( !(fp = im__file_open_write( name, TRUE )) ) 
		return( -1 );
	for( i = 0; i < thr->tpos; i++ )
		fprintf( fp, "%g, %g\n", thr->btime[i], thr->etime[i] );
	fclose( fp );

	return( 0 );
}
#endif /*TIME_THREAD*/

/* Junk a thread.
 */
static void
vips_thread_free( VipsThread *thr )
{
        /* Is there a thread running this region? Kill it!
         */
        if( thr->thread ) {
                thr->exit = 1;

		/* Return value is always NULL (see thread_main_loop).
		 */
		(void) g_thread_join( thr->thread );
		VIPS_DEBUG_MSG_RED( "thread_free: g_thread_join()\n" );
		thr->thread = NULL;
        }

	VIPS_FREEF( g_object_unref, thr->state );
	thr->pool = NULL;

#ifdef TIME_THREAD
	if( thr->btime )
		(void) vips_thread_save_time_buffers( thr );
#endif /*TIME_THREAD*/
}

static int
vips_thread_allocate( VipsThread *thr )
{
	VipsThreadpool *pool = thr->pool;

	g_assert( !pool->stop );

	if( !thr->state ) {
		if( !(thr->state = pool->start( pool->im, pool->a )) ) 
			return( -1 );
	}

	if( pool->allocate( thr->state, pool->a, &pool->stop ) ) 
		return( -1 );

	return( 0 );
}

static int
vips_thread_work( VipsThread *thr )
{
	VipsThreadpool *pool = thr->pool;
	int result;

	result = 0;

#ifdef TIME_THREAD
	/* Note start time.
	 */
	if( thr->btime && thr->tpos < TBUF_SIZE )
		thr->btime[thr->tpos] = 
			g_timer_elapsed( thread_timer, NULL );
#endif /*TIME_THREAD*/

	if( pool->work( thr->state, pool->a ) ) 
		result = -1;

#ifdef TIME_THREAD
	/* Note stop time.
	 */
	if( thr->etime && thr->tpos < TBUF_SIZE ) {
		thr->etime[thr->tpos] = 
			g_timer_elapsed( thread_timer, NULL );
		thr->tpos += 1;
	}
#endif /*TIME_THREAD*/

	return( result );
}

/* The main loop: get some work, do it! Can run from many worker threads, or 
 * from the main thread if threading is off. 
 */
static void
vips_thread_work_unit( VipsThread *thr )
{
	VipsThreadpool *pool = thr->pool;

	if( thr->error )
		return;

	g_mutex_lock( pool->allocate_lock );

	/* Has another worker signaled stop while we've been working?
	 */
	if( pool->stop ) {
		g_mutex_unlock( pool->allocate_lock );
		return;
	}

	if( vips_thread_allocate( thr ) ) {
		thr->error = TRUE;
		pool->error = TRUE;
		g_mutex_unlock( pool->allocate_lock );
		return;
	}

	/* Have we just signalled stop?
	 */
	if( pool->stop ) {
		g_mutex_unlock( pool->allocate_lock );
		return;
	}

	g_mutex_unlock( pool->allocate_lock );

	/* Process a work unit.
	 */
	if( vips_thread_work( thr ) ) {
		thr->error = TRUE;
		pool->error = TRUE;
	}
}

#ifdef HAVE_THREADS
/* What runs as a thread ... loop, waiting to be told to do stuff.
 */
static void *
vips_thread_main_loop( void *a )
{
        VipsThread *thr = (VipsThread *) a;
	VipsThreadpool *pool = thr->pool;

	g_assert( pool == thr->pool );

	/* Process work units! Always tick, even if we are stopping, so the
	 * main thread will wake up for exit. 
	 */
	for(;;) {
		vips_thread_work_unit( thr );
		vips_semaphore_up( &pool->tick );

		if( pool->stop || pool->error )
			break;
	} 

	/* We are exiting: tell the main thread. 
	 */
	vips_semaphore_up( &pool->finish );

        return( NULL );
}
#endif /*HAVE_THREADS*/

/* Attach another thread to a threadpool.
 */
static VipsThread *
vips_thread_new( VipsThreadpool *pool )
{
	VipsThread *thr;

	if( !(thr = VIPS_NEW( pool->im, VipsThread )) )
		return( NULL );
	thr->pool = pool;
	thr->state = NULL;
	thr->thread = NULL;
	thr->exit = 0;
	thr->error = 0;
#ifdef TIME_THREAD
	thr->btime = NULL;
	thr->etime = NULL;
	thr->tpos = 0;
#endif /*TIME_THREAD*/

	/* We can't build the state here, it has to be done by the worker
	 * itself the first time that allocate runs so that any regions are 
	 * owned by the correct thread.
	 */

#ifdef TIME_THREAD
	thr->btime = VIPS_ARRAY( pool->im, TBUF_SIZE, double );
	thr->etime = VIPS_ARRAY( pool->im, TBUF_SIZE, double );
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
	if( !(thr->thread = g_thread_create_full( vips_thread_main_loop, thr, 
		IM__DEFAULT_STACK_SIZE, TRUE, FALSE, 
		G_THREAD_PRIORITY_NORMAL, NULL )) ) {
		vips_error( "vips_thread_new", 
			"%s", _( "unable to create thread" ) );
		vips_thread_free( thr );
		return( NULL );
	}

	VIPS_DEBUG_MSG_RED( "vips_thread_new: g_thread_create_full()\n" );
#endif /*HAVE_THREADS*/

	return( thr );
}

/* Kill all threads in a threadpool, if there are any.
 */
static void
vips_threadpool_kill_threads( VipsThreadpool *pool )
{
	if( pool->thr ) {
		int i;

		for( i = 0; i < pool->nthr; i++ ) 
			vips_thread_free( pool->thr[i] );
		pool->thr = NULL;

		VIPS_DEBUG_MSG( "vips_threadpool_kill_threads: "
			"killed %d threads\n", pool->nthr );
	}
}

/* This can be called multiple times, careful.
 */
static int
vips_threadpool_free( VipsThreadpool *pool )
{
	VIPS_DEBUG_MSG( "vips_threadpool_free: \"%s\" (%p)\n", 
		pool->im->filename, pool );

	vips_threadpool_kill_threads( pool );
	VIPS_FREEF( g_mutex_free, pool->allocate_lock );
	vips_semaphore_destroy( &pool->finish );
	vips_semaphore_destroy( &pool->tick );

	return( 0 );
}

static void
vips_threadpool_new_cb( VipsImage *im, VipsThreadpool *pool )
{
	vips_threadpool_free( pool );
}

static VipsThreadpool *
vips_threadpool_new( VipsImage *im )
{
	VipsThreadpool *pool;

	/* Allocate and init new thread block.
	 */
	if( !(pool = VIPS_NEW( im, VipsThreadpool )) )
		return( NULL );
	pool->im = im;
	pool->allocate = NULL;
	pool->work = NULL;
	pool->allocate_lock = g_mutex_new();
	pool->nthr = im_concurrency_get();
	pool->thr = NULL;
	vips_semaphore_init( &pool->finish, 0, "finish" );
	vips_semaphore_init( &pool->tick, 0, "tick" );
	pool->stop = FALSE;
	pool->error = FALSE;

	/* Attach tidy-up callback.
	 */
	g_signal_connect( im, "close", 
		G_CALLBACK( vips_threadpool_new_cb ), pool ); 

	VIPS_DEBUG_MSG( "vips_threadpool_new: \"%s\" (%p), with %d threads\n", 
		im->filename, pool, pool->nthr );

	return( pool );
}

/* Attach a set of threads.
 */
static int
vips_threadpool_create_threads( VipsThreadpool *pool )
{
	int i;

	g_assert( !pool->thr );

	/* Make thread array.
	 */
	if( !(pool->thr = VIPS_ARRAY( pool->im, pool->nthr, VipsThread * )) )
		return( -1 );
	for( i = 0; i < pool->nthr; i++ )
		pool->thr[i] = NULL;

	/* Attach threads and start them working.
	 */
	for( i = 0; i < pool->nthr; i++ )
		if( !(pool->thr[i] = vips_thread_new( pool )) ) {
			vips_threadpool_kill_threads( pool );
			return( -1 );
		}

	return( 0 );
}

/**
 * VipsThreadpoolStart:
 * @a: client data
 * @b: client data
 * @c: client data
 *
 * This function is called once by each worker just before the first time work
 * is allocated to it to build the per-thread state. Per-thread state is used
 * by #VipsThreadpoolAllocate and #VipsThreadpoolWork to communicate.
 *
 * #VipsThreadState is a subclass of #VipsObject. Start functions are called
 * from allocate, that is, they are single-threaded.
 *
 * See also: vips_threadpool_run().
 *
 * Returns: a new #VipsThreadState object, or NULL on error
 */

/**
 * _VipsThreadpoolAllocate:
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
 * _VipsThreadpoolWork:
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
 * _VipsThreadpoolProgress:
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
 * This function runs a set of threads over an image. Each thread first calls
 * @start to create new per-thread state, then runs
 * @allocate to set up a new work unit (perhaps the next tile in an image, for
 * example), then @work to process that work unit. After each unit is
 * processed, @progress is called, so that the operation can give
 * progress feedback. @progress may be %NULL.
 *
 * Each thread has private state that the @allocate and @work functions can 
 * use to communicate. This state is created by each worker as it starts using
 * @start. Use the state destructor to clean up.
 *
 * @allocate and @start are always single-threaded (so they can write to the 
 * per-pool state), whereas @work can be executed concurrently. @progress is 
 * always called by 
 * the main thread (ie. the thread which called vips_threadpool_run()).
 *
 * See also: im_wbuffer2(), im_concurrency_set().
 *
 * Returns: 0 on success, or -1 on error.
 */
int
vips_threadpool_run( VipsImage *im, 
	VipsThreadStart start, 
	VipsThreadpoolAllocate allocate, 
	VipsThreadpoolWork work,
	VipsThreadpoolProgress progress, 
	void *a )
{
	VipsThreadpool *pool; 
	int result;

#ifdef TIME_THREAD
	if( !thread_timer )
		thread_timer = g_timer_new();
#endif /*TIME_THREAD*/

	if( !(pool = vips_threadpool_new( im )) )
		return( -1 );

	pool->start = start;
	pool->allocate = allocate;
	pool->work = work;
	pool->a = a;

	/* Attach workers and set them going.
	 */
	if( vips_threadpool_create_threads( pool ) ) {
		vips_threadpool_free( pool );
		return( -1 );
	}

	for(;;) {
#ifdef HAVE_THREADS
		/* Wait for a tick from a worker.
		 */
		vips_semaphore_down( &pool->tick );
#else
		/* No threads, do the work ourselves in the main thread.
		 */
		vips_thread_work_unit( pool->thr[0] );
#endif /*HAVE_THREADS*/

		VIPS_DEBUG_MSG( "vips_threadpool_run: tick\n" );

		if( pool->stop || pool->error )
			break;

		if( progress &&
			progress( pool->a ) ) 
			pool->error = TRUE;

		if( pool->stop || pool->error )
			break;
	}

	/* Wait for them all to hit finish.
	 */
	vips_semaphore_downn( &pool->finish, pool->nthr );

	/* Return 0 for success.
	 */
	result = pool->error ? -1 : 0;

	vips_threadpool_free( pool );

	return( result );
}

/**
 * vips_get_tile_size:
 * @im: image to guess for
 * @tile_width: return selected tile width 
 * @tile_height: return selected tile height 
 * @nlines: return buffer height in scanlines
 *
 * Pick a tile size and a buffer height for this image and the current
 * value of im_concurrency_get(). The buffer height 
 * will always be a multiple of tile_height.
 */
void
vips_get_tile_size( VipsImage *im, 
	int *tile_width, int *tile_height, int *nlines )
{
	const int nthr = im_concurrency_get();

	/* Pick a render geometry.
	 */
	switch( im->dhint ) {
	case VIPS_DEMAND_STYLE_SMALLTILE:
		*tile_width = im__tile_width;
		*tile_height = im__tile_height;

		/* Enough lines of tiles that we can expect to be able to keep
		 * nthr busy. Then double it.
		 */
		*nlines = *tile_height * 
			(1 + nthr / VIPS_MAX( 1, im->Xsize / *tile_width )) * 2;
		break;

	case VIPS_DEMAND_STYLE_ANY:
	case VIPS_DEMAND_STYLE_FATSTRIP:
		*tile_width = im->Xsize;
		*tile_height = im__fatstrip_height;
		*nlines = *tile_height * nthr * 2;
		break;

	case VIPS_DEMAND_STYLE_THINSTRIP:
		*tile_width = im->Xsize;
		*tile_height = im__thinstrip_height;
		*nlines = *tile_height * nthr * 2;
		break;

	default:
		g_assert( 0 );
	}

	/* We make this assumption in several places.
	 */
	g_assert( *nlines % *tile_height == 0 );

	VIPS_DEBUG_MSG( "vips_get_tile_size: %d by %d patches, "
		"groups of %d scanlines\n", 
		*tile_width, *tile_height, *nlines );
}

