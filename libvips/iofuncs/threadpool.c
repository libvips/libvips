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

/* Maximum number of concurrent threads we allow. It prevents huge values of 
 * VIPS_CONCURRENCY killing the system.
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

/* Set this GPrivate to indicate that this thread is a worker inside
 * the vips threadpool.
 */
static GPrivate *is_worker_key = NULL;

/* Set to stall threads for debugging.
 */
static gboolean vips__stall = FALSE;

/* The thread pool we'll use.
 */
static GThreadPool *vips__pool = NULL;

/* Glib 2.32 revised the thread API. We need some compat functions.
 */

GMutex *
vips_g_mutex_new( void )
{
	GMutex *mutex;

	mutex = g_new( GMutex, 1 );
	g_mutex_init( mutex );

	return( mutex );
}

void
vips_g_mutex_free( GMutex *mutex )
{
	g_mutex_clear( mutex );
	g_free( mutex );
}

GCond *
vips_g_cond_new( void )
{
	GCond *cond;

	cond = g_new( GCond, 1 );
	g_cond_init( cond );

	return( cond );
}

void
vips_g_cond_free( GCond *cond )
{
	g_cond_clear( cond );
	g_free( cond );
}

/* TRUE if we are a vips worker thread. We sometimes manage resource allocation
 * differently for vips workers since we can cheaply free stuff on thread
 * termination.
 */
gboolean
vips_thread_isworker( void )
{
	return( g_private_get( is_worker_key ) != NULL );
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

	/* Set this to something (anything) to tag this thread as a vips 
	 * worker.
	 */
	g_private_set( is_worker_key, data );

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

	thread = g_thread_try_new( domain, vips_thread_run, info, &error );

	VIPS_DEBUG_MSG_RED( "vips_g_thread_new: g_thread_create( %s ) = %p\n",
		domain, thread );

	if( !thread ) {
		if( error ) 
			vips_g_error( &error ); 
		else
			vips_error( domain, 
				"%s", _( "unable to create thread" ) );
	}

	return( thread );
}

void *
vips_g_thread_join( GThread *thread )
{
	void *result;

	result = g_thread_join( thread );

	VIPS_DEBUG_MSG_RED( "vips_g_thread_join: g_thread_join( %p )\n", 
		thread );

	return( result ); 
}

typedef struct {
	/* An name for this thread.
	 */
	const char *name;

	/* The function to execute within the #VipsThreadPool.
	 */
	GFunc func;

	/* User data that is handed over to func when it is called.
	 */
	gpointer data;
} VipsThreadExec;

static void
vips_thread_main_loop( gpointer thread_data, gpointer pool_data )
{
	VipsThreadExec *exec = (VipsThreadExec *) thread_data;

	/* Set this to something (anything) to tag this thread as a vips 
	 * worker. No need to call g_private_replace as there is no
	 * GDestroyNotify handler associated with a worker.
	 */
	g_private_set( is_worker_key, thread_data );

	if( vips__thread_profile ) 
		vips__thread_profile_attach( exec->name );

	exec->func( exec->data, pool_data );

	g_free( exec ); 

	/* Free all thread-private caches, since they probably won't be valid 
	 * for the next task this thread is given.
	 */
	vips_thread_shutdown();
}

static int
get_num_processors( void )
{
#if GLIB_CHECK_VERSION( 2, 48, 1 )
	/* We could use g_get_num_processors when GLib >= 2.48.1, see:
	 * https://gitlab.gnome.org/GNOME/glib/commit/999711abc82ea3a698d05977f9f91c0b73957f7f
	 * https://gitlab.gnome.org/GNOME/glib/commit/2149b29468bb99af3c29d5de61f75aad735082dc
	 */
	return( g_get_num_processors() );
#else
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

#ifdef G_OS_WIN32
{
	/* Count the CPUs currently available to this process.  
	 */
	SYSTEM_INFO sysinfo;
	DWORD_PTR process_cpus;
	DWORD_PTR system_cpus;

	/* This *never* fails, use it as fallback 
	 */
	GetNativeSystemInfo( &sysinfo );
	nproc = (int) sysinfo.dwNumberOfProcessors;

	if( GetProcessAffinityMask( GetCurrentProcess(), 
		&process_cpus, &system_cpus ) ) {
		unsigned int af_count;

		for( af_count = 0; process_cpus != 0; process_cpus >>= 1 )
			if( process_cpus & 1 )
				af_count++;

		/* Prefer affinity-based result, if available 
		 */
		if( af_count > 0 )
			nproc = af_count;
	}
}
#endif /*G_OS_WIN32*/

	return( nproc );
#endif /*!GLIB_CHECK_VERSION( 2, 48, 1 )*/
}

/* The default concurrency, set by the environment variable VIPS_CONCURRENCY,
 * or if that is not set, the number of threads available on the host machine.
 */
static int
vips__concurrency_get_default( void )
{
	const char *str;
	int nthr;
	int x;

	/* Tell the threads system how much concurrency we expect.
	 */
	if( vips__concurrency > 0 )
		nthr = vips__concurrency;
	else if( ((str = g_getenv( "VIPS_CONCURRENCY" ))
#if ENABLE_DEPRECATED
		|| (str = g_getenv( "IM_CONCURRENCY" ))
#endif
	) && (x = atoi( str )) > 0 )
		nthr = x;
	else 
		nthr = get_num_processors();

	if( nthr < 1 || 
		nthr > MAX_THREADS ) {
		nthr = VIPS_CLIP( 1, nthr, MAX_THREADS );

		g_warning( _( "threads clipped to %d" ), nthr );
	}

	return( nthr );
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
 * number of threads available on the host machine.
 *
 * See also: vips_concurrency_get().
 */
void
vips_concurrency_set( int concurrency )
{
	/* Tell the threads system how much concurrency we expect.
	 */
	if( concurrency < 1 )
		concurrency = vips__concurrency_get_default();
	else if( concurrency > MAX_THREADS ) {
		concurrency = MAX_THREADS;

		g_warning( _( "threads clipped to %d" ), MAX_THREADS );
	}

	vips__concurrency = concurrency;
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
 * If VIPS_CONCURRENCY has not been set, vips finds the number of hardware
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
	return( vips__concurrency );
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

/* Called from vips_shutdown().
 */
void
vips__threadpool_shutdown( void )
{
	/* We may come here without having inited.
	 */
	if( vips__pool ) {
		VIPS_DEBUG_MSG( "vips__threadpool_shutdown: (%p)\n", 
			vips__pool );

		g_thread_pool_free( vips__pool, TRUE, TRUE );
		vips__pool = NULL;
	}
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

static void *
vips__thread_once_init( void *data )
{
	/* We can have many more than vips__concurrency threads -- each active
	 * pipeline will make vips__concurrency more, see
	 * vips_threadpool_run().
	 */
	vips__pool = g_thread_pool_new( vips_thread_main_loop, NULL,
		-1, FALSE, NULL );

	return( NULL );
}

/**
 * vips__thread_execute:
 * @name: a name for the thread
 * @func: a function to execute in the thread pool
 * @data: an argument to supply to @func
 *
 * A newly created or reused thread will execute @func with with the 
 * argument data.
 *
 * See also: vips_concurrency_set().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips__thread_execute( const char *name, GFunc func, gpointer data )
{
	static GOnce once = G_ONCE_INIT;

	VipsThreadExec *exec;
	GError *error = NULL;
	gboolean result;

	VIPS_ONCE( &once, vips__thread_once_init, NULL );

	exec = g_new( VipsThreadExec, 1 );
	exec->name = name;
	exec->func = func;
	exec->data = data;

	result = g_thread_pool_push( vips__pool, exec, &error );
	if( error ) {
		vips_g_error( &error );
		return( -1 );
	}

	VIPS_DEBUG_MSG( "vips__thread_execute: %u threads in pool\n",
		g_thread_pool_get_num_threads( vips__pool ) );

	return( result ? 0 : -1 );
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

		VIPS_DEBUG_MSG( "vips_threadpool_run: tick\n" );

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

/* Create the vips threadpool. This is called during vips_init.
 */
void
vips__threadpool_init( void )
{
	static GPrivate private = { 0 }; 

	is_worker_key = &private;

	if( g_getenv( "VIPS_STALL" ) )
		vips__stall = TRUE;

	if( vips__concurrency == 0 )
		vips__concurrency = vips__concurrency_get_default();

	/* The threadpool is built in the first vips__thread_execute()
	 * call, since we want thread creation to happen as late as possible.
	 *
	 * Many web platforms start up in a base environment, then fork() for
	 * each request. We must not make the threadpool before the fork.
	 */

	VIPS_DEBUG_MSG( "vips__threadpool_init: (%p)\n", vips__pool );
}

/**
 * vips_get_tile_size: (method)
 * @im: image to guess for
 * @tile_width: (out): return selected tile width 
 * @tile_height: (out): return selected tile height 
 * @n_lines: (out): return buffer height in scanlines
 *
 * Pick a tile size and a buffer height for this image and the current
 * value of vips_concurrency_get(). The buffer height 
 * will always be a multiple of tile_height.
 *
 * The buffer height is the height of each buffer we fill in sink disc. Since
 * we have two buffers, the largest range of input locality is twice the output
 * buffer size, plus whatever margin we add for things like convolution. 
 */
void
vips_get_tile_size( VipsImage *im, 
	int *tile_width, int *tile_height, int *n_lines )
{
	const int nthr = vips_concurrency_get();
	const int typical_image_width = 1000;

	/* Compiler warnings.
	 */
	*tile_width = 1;
	*tile_height = 1;

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
	 * We also can't depend on the current image size, since that might
	 * change down the pipeline too. Pick a typical image width.
	 *
	 * Pick the maximum buffer size we might possibly need, then round up
	 * to a multiple of tileheight.
	 */
	*n_lines = vips__tile_height * 
		VIPS_ROUND_UP( vips__tile_width * nthr, typical_image_width ) / 
			typical_image_width;
	*n_lines = VIPS_MAX( *n_lines, vips__fatstrip_height * nthr );
	*n_lines = VIPS_MAX( *n_lines, vips__thinstrip_height * nthr );
	*n_lines = VIPS_ROUND_UP( *n_lines, *tile_height );

	/* We make this assumption in several places.
	 */
	g_assert( *n_lines % *tile_height == 0 );

	VIPS_DEBUG_MSG( "vips_get_tile_size: %d by %d patches, "
		"groups of %d scanlines\n", 
		*tile_width, *tile_height, *n_lines );
}
