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
 * it's just there to stop mad values for VIPS_CONCURRENCY killing the system.
 */
#define MAX_THREADS (1024)

/* Default tile geometry ... can be set by vips_init().
 */
int vips__tile_width = VIPS__TILE_WIDTH;
int vips__tile_height = VIPS__TILE_HEIGHT;
int vips__fatstrip_height = VIPS__FATSTRIP_HEIGHT;
int vips__thinstrip_height = VIPS__THINSTRIP_HEIGHT;

/* Default n threads ... 0 means get from environment.
 */
int vips__concurrency = 0;

/* Glib 2.32 revised the thread API. We need some compat functions.
 */

GMutex *
vips_g_mutex_new( void )
{
	GMutex *mutex;

#ifdef HAVE_MUTEX_INIT
	mutex = g_new( GMutex, 1 );
	g_mutex_init( mutex );
#else
	mutex = g_mutex_new();
#endif

	return( mutex );
}

void
vips_g_mutex_free( GMutex *mutex )
{
#ifdef HAVE_MUTEX_INIT
	g_mutex_clear( mutex );
	g_free( mutex );
#else
	g_mutex_free( mutex );
#endif
}

GCond *
vips_g_cond_new( void )
{
	GCond *cond;

#ifdef HAVE_COND_INIT
	cond = g_new( GCond, 1 );
	g_cond_init( cond );
#else
	cond = g_cond_new();
#endif

	return( cond );
}

void
vips_g_cond_free( GCond *cond )
{
#ifdef HAVE_COND_INIT
	g_cond_clear( cond );
	g_free( cond );
#else
	g_cond_free( cond );
#endif
}

typedef struct {
	const char *domain; 
	GThreadFunc func; 
	gpointer data;
} VipsThreadInfo; 

static void *
vips_thread_run( gpointer data )
{
	VipsThreadInfo *info = (VipsThreadInfo *) data;

	void *result;

	if( vips__thread_profile ) 
		vips__thread_profile_attach( info->domain );

	result = info->func( info->data );

	g_free( info ); 

	vips_thread_shutdown();

	return( result ); 
}

GThread *
vips_g_thread_new( const char *domain, GThreadFunc func, gpointer data )
{
	GThread *thread;
	VipsThreadInfo *info; 
	GError *error = NULL;

	info = g_new( VipsThreadInfo, 1 ); 
	info->domain = domain;
	info->func = func;
	info->data = data;

#ifdef HAVE_THREAD_NEW
	thread = g_thread_try_new( domain, vips_thread_run, info, &error );
#else
	thread = g_thread_create( vips_thread_run, info, TRUE, &error );
#endif

	if( !thread ) {
		if( error ) 
			vips_g_error( &error ); 
		else
			vips_error( domain, 
				"%s", _( "unable to create thread" ) );
	}

	return( thread );
}

/**
 * vips_concurrency_set:
 * @concurrency: number of threads to run
 *
 * Sets the number of worker threads that vips should use when running a
 * #VipsThreadPool. 
 *
 * The special value 0 means "default". In this case, the number of threads is
 * set by the environment variable VIPS_CONCURRENCY, or if that is not set, the
 * number of threads availble on the host machine. 
 *
 * See also: vips_concurrency_get().
 */
void
vips_concurrency_set( int concurrency )
{
	vips__concurrency = concurrency;
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

/**
 * vips_concurrency_get:
 *
 * Returns the number of worker threads that vips should use when running a
 * #VipsThreadPool. 
 *
 * vips gets this values from these sources in turn:
 *
 * If vips_concurrency_set() has been called, this value is used. The special
 * value 0 means "default". You can also use the command-line argument
 * "--vips-concurrency" to set this value.
 *
 * If vips_concurrency_set() has not been called and no command-line argument
 * was used, vips uses the value of the environment variable VIPS_CONCURRENCY,
 *
 * If VIPS_CONCURRENCY has not been set, vips find the number of hardware
 * threads that the host machine can run in parallel and uses that value. 
 *
 * The final value is clipped to the range 1 - 1024.
 *
 * See also: vips_concurrency_get().
 *
 * Returns: number of worker threads to use.
 */
int
vips_concurrency_get( void )
{
	const char *str;
	int nthr;
	int x;

	/* Tell the threads system how much concurrency we expect.
	 */
	if( vips__concurrency > 0 )
		nthr = vips__concurrency;
	else if( ((str = g_getenv( "VIPS_CONCURRENCY" )) ||
		(str = g_getenv( "IM_CONCURRENCY" ))) && 
		(x = atoi( str )) > 0 )
		nthr = x;
	else 
		nthr = get_num_processors();

	if( nthr < 1 || nthr > MAX_THREADS ) {
		nthr = VIPS_CLIP( 1, nthr, MAX_THREADS );

		vips_warn( "vips_concurrency_get", 
			_( "threads clipped to %d" ), nthr );
	}

	/* Save for next time around.
	 */
	vips_concurrency_set( nthr );

	return( nthr );
}

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
	VipsThreadStartFn start; 
	VipsThreadpoolAllocateFn allocate;
	VipsThreadpoolWorkFn work;
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

	/* Set by the first thread to hit allocate. The first work unit runs
	 * single-threaded to give loaders a change to get to the right spot
	 * in the input.
	 */
	gboolean done_first;
} VipsThreadpool;

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

/* Run this once per main loop. Get some work (single-threaded), then do it
 * (many-threaded).
 *
 * The very first workunit is also executed single-threaded. This gives
 * loaders a change to seek to the correct spot, see vips_sequential().
 */
static void
vips_thread_work_unit( VipsThread *thr )
{
	VipsThreadpool *pool = thr->pool;

	if( thr->error )
		return;

	VIPS_GATE_START( "vips_thread_work_unit: wait" ); 

	g_mutex_lock( pool->allocate_lock );

	VIPS_GATE_STOP( "vips_thread_work_unit: wait" ); 

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

	if( pool->done_first )
		g_mutex_unlock( pool->allocate_lock );

	/* Process a work unit.
	 */
	if( pool->work( thr->state, pool->a ) ) { 
		thr->error = TRUE;
		pool->error = TRUE;
	}

	if( !pool->done_first ) {
		pool->done_first = TRUE;
		g_mutex_unlock( pool->allocate_lock );
	}
}

/* What runs as a thread ... loop, waiting to be told to do stuff.
 */
static void *
vips_thread_main_loop( void *a )
{
        VipsThread *thr = (VipsThread *) a;
	VipsThreadpool *pool = thr->pool;

	g_assert( pool == thr->pool );

	VIPS_GATE_START( "vips_thread_main_loop: thread" ); 

	/* Process work units! Always tick, even if we are stopping, so the
	 * main thread will wake up for exit. 
	 */
	for(;;) {
		VIPS_GATE_START( "vips_thread_work_unit: u" ); 
		vips_thread_work_unit( thr );
		VIPS_GATE_STOP( "vips_thread_work_unit: u" ); 
		vips_semaphore_up( &pool->tick );

		if( pool->stop || 
			pool->error )
			break;
	} 

	/* We are exiting: tell the main thread. 
	 */
	vips_semaphore_up( &pool->finish );

	VIPS_GATE_STOP( "vips_thread_main_loop: thread" ); 

        return( NULL );
}

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

	/* We can't build the state here, it has to be done by the worker
	 * itself the first time that allocate runs so that any regions are 
	 * owned by the correct thread.
	 */

	if( !(thr->thread = vips_g_thread_new( "worker", 
		vips_thread_main_loop, thr )) ) {  
		vips_thread_free( thr );
		return( NULL );
	}

	VIPS_DEBUG_MSG_RED( "vips_thread_new: vips_g_thread_new()\n" );

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
	VIPS_FREEF( vips_g_mutex_free, pool->allocate_lock );
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
	int tile_width;
	int tile_height;
	int n_tiles;
	int n_lines;

	/* Allocate and init new thread block.
	 */
	if( !(pool = VIPS_NEW( im, VipsThreadpool )) )
		return( NULL );
	pool->im = im;
	pool->allocate = NULL;
	pool->work = NULL;
	pool->allocate_lock = vips_g_mutex_new();
	pool->nthr = vips_concurrency_get();
	pool->thr = NULL;
	vips_semaphore_init( &pool->finish, 0, "finish" );
	vips_semaphore_init( &pool->tick, 0, "tick" );
	pool->error = FALSE;
	pool->stop = FALSE;
	pool->done_first = FALSE;

	/* If this is a tiny image, we won't need all nthr threads. Guess how
	 * many tiles we might need to cover the image and use that to limit
	 * the number of threads we create.
	 */
	vips_get_tile_size( im, &tile_width, &tile_height, &n_lines );
	n_tiles = (1 + im->Xsize / tile_width) * (1 + im->Ysize / tile_height);
	pool->nthr = VIPS_MIN( pool->nthr, n_tiles ); 

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
 * VipsThreadpoolStartFn:
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
 * This function runs a set of threads over an image. Each thread first calls
 * @start to create new per-thread state, then runs
 * @allocate to set up a new work unit (perhaps the next tile in an image, for
 * example), then @work to process that work unit. After each unit is
 * processed, @progress is called, so that the operation can give
 * progress feedback. @progress may be %NULL.
 *
 * The object returned by @start must be an instance of a subclass of
 * #VipsThreadState. Use this to communicate between @allocate and @work. 
 *
 * @allocate and @start are always single-threaded (so they can write to the 
 * per-pool state), whereas @work can be executed concurrently. @progress is 
 * always called by 
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
	VipsThreadpool *pool; 
	int result;

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
		/* Wait for a tick from a worker.
		 */
		vips_semaphore_down( &pool->tick );

		VIPS_DEBUG_MSG( "vips_threadpool_run: tick\n" );

		if( pool->stop || 
			pool->error )
			break;

		if( progress &&
			progress( pool->a ) ) 
			pool->error = TRUE;

		if( pool->stop || 
			pool->error )
			break;
	}

	/* Wait for them all to hit finish.
	 */
	vips_semaphore_downn( &pool->finish, pool->nthr );

	/* Return 0 for success.
	 */
	result = pool->error ? -1 : 0;

	vips_threadpool_free( pool );

	vips_image_minimise_all( im );

	return( result );
}

/* Round N down to P boundary. 
 */
#define ROUND_DOWN(N,P) ((N) - ((N) % P)) 

/* Round N up to P boundary. 
 */
#define ROUND_UP(N,P) (ROUND_DOWN( (N) + (P) - 1, (P) ))

/**
 * vips_get_tile_size:
 * @im: image to guess for
 * @tile_width: return selected tile width 
 * @tile_height: return selected tile height 
 * @n_lines: return buffer height in scanlines
 *
 * Pick a tile size and a buffer height for this image and the current
 * value of vips_concurrency_get(). The buffer height 
 * will always be a multiple of tile_height.
 */
void
vips_get_tile_size( VipsImage *im, 
	int *tile_width, int *tile_height, int *n_lines )
{
	const int nthr = vips_concurrency_get();

	/* Pick a render geometry.
	 */
	switch( im->dhint ) {
	case VIPS_DEMAND_STYLE_SMALLTILE:
		*tile_width = vips__tile_width;
		*tile_height = vips__tile_height;
		break;

	case VIPS_DEMAND_STYLE_ANY:
	case VIPS_DEMAND_STYLE_FATSTRIP:
		*tile_width = im->Xsize;
		*tile_height = vips__fatstrip_height;
		break;

	case VIPS_DEMAND_STYLE_THINSTRIP:
		*tile_width = im->Xsize;
		*tile_height = vips__thinstrip_height;
		break;

	default:
		g_assert_not_reached();
	}

	/* We can't set n_lines for the current demand style: a later bit of
	 * the pipeline might see a different hint and we need to synchronise
	 * buffer sizes everywhere.
	 *
	 * Pick the maximum buffer size we might possibly need, then round up
	 * to a multiple of tileheight.
	 */
	*n_lines = vips__tile_height * 
		(1 + nthr / VIPS_MAX( 1, im->Xsize / vips__tile_width )) * 2;
	*n_lines = VIPS_MAX( *n_lines, vips__fatstrip_height * nthr * 2 );
	*n_lines = VIPS_MAX( *n_lines, vips__thinstrip_height * nthr * 2 );
	*n_lines = ROUND_UP( *n_lines, *tile_height );

	/* We make this assumption in several places.
	 */
	g_assert( *n_lines % *tile_height == 0 );

	VIPS_DEBUG_MSG( "vips_get_tile_size: %d by %d patches, "
		"groups of %d scanlines\n", 
		*tile_width, *tile_height, *n_lines );
}

