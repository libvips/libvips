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
#include <vips/debug.h>

#ifdef G_OS_WIN32
#include <windows.h>
#endif /*G_OS_WIN32*/

/**
 * VipsThreadState:
 *
 * A [class@VipsThreadState] represents a per-thread state.
 *
 * [callback@ThreadpoolAllocateFn] functions can use these members to
 * communicate with [callback@ThreadpoolWorkFn] functions.
 *
 * ::: seealso
 *     [func@threadpool_run].
 */

/* Set to stall threads for debugging.
 */
static gboolean vips__stall = FALSE;

/* The global threadset we run workers in.
 */
static VipsThreadset *vips__threadset = NULL;

/* Set this GPrivate to link a thread back to its VipsWorker struct.
 */
static GPrivate worker_key;

/* Maximum value we allow for VIPS_CONCURRENCY. We need to stop huge values
 * killing the system.
 */
#define MAX_THREADS (1024)

/* Start up threadpools. This is called during vips_init.
 */
void
vips__threadpool_init(void)
{
	/* 3 is the useful minimum, and huge values can crash the machine.
	 */
	const char *max_threads_env = g_getenv("VIPS_MAX_THREADS");
	int max_threads = max_threads_env
		? VIPS_CLIP(3, atoi(max_threads_env), MAX_THREADS)
		: 0;

	if (g_getenv("VIPS_STALL"))
		vips__stall = TRUE;

	/* max_threads > 0 will create a set of threads on startup. This is
	 * necessary for wasm, but may break on systems that try to fork()
	 * after init.
	 */
	vips__threadset = vips_threadset_new(max_threads);
}

void
vips__threadpool_shutdown(void)
{
	VIPS_FREEF(vips_threadset_free, vips__threadset);
}

/**
 * vips_thread_execute:
 * @domain: a name for the thread (useful for debugging)
 * @func: (scope async) (closure data): a function to execute in the libvips threadset
 * @data: (nullable): an argument to supply to @func
 *
 * A newly created or reused thread will execute @func with the
 * argument @data.
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_thread_execute(const char *domain, GFunc func, gpointer data)
{
	return vips_threadset_run(vips__threadset, domain, func, data);
}

G_DEFINE_TYPE(VipsThreadState, vips_thread_state, VIPS_TYPE_OBJECT);

static void
vips_thread_state_dispose(GObject *gobject)
{
	VipsThreadState *state = (VipsThreadState *) gobject;

	VIPS_DEBUG_MSG("vips_thread_state_dispose:\n");

	VIPS_UNREF(state->reg);

	G_OBJECT_CLASS(vips_thread_state_parent_class)->dispose(gobject);
}

static int
vips_thread_state_build(VipsObject *object)
{
	VipsThreadState *state = (VipsThreadState *) object;

	if (!(state->reg = vips_region_new(state->im)))
		return -1;

	return VIPS_OBJECT_CLASS(vips_thread_state_parent_class)
		->build(object);
}

static void
vips_thread_state_class_init(VipsThreadStateClass *class)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS(class);
	VipsObjectClass *object_class = VIPS_OBJECT_CLASS(class);

	gobject_class->dispose = vips_thread_state_dispose;

	object_class->build = vips_thread_state_build;
	object_class->nickname = "threadstate";
	object_class->description = _("per-thread state for vipsthreadpool");
}

static void
vips_thread_state_init(VipsThreadState *state)
{
	VIPS_DEBUG_MSG("vips_thread_state_init:\n");

	state->reg = NULL;
	state->stop = FALSE;
	state->stall = FALSE;
}

void *
vips_thread_state_set(VipsObject *object, void *a, void *b)
{
	VipsThreadState *state = (VipsThreadState *) object;
	VipsImage *im = (VipsImage *) a;

	VIPS_DEBUG_MSG("vips_thread_state_set: image %p\n", im);

	state->im = im;
	state->a = b;

	return NULL;
}

VipsThreadState *
vips_thread_state_new(VipsImage *im, void *a)
{
	VIPS_DEBUG_MSG("vips_thread_state_new: image %p\n", im);

	return VIPS_THREAD_STATE(vips_object_new(
		VIPS_TYPE_THREAD_STATE, vips_thread_state_set, im, a));
}

/* What we track for each thread in the pool.
 */
typedef struct _VipsWorker {
	struct _VipsThreadpool *pool; /* Pool we are part of */

	VipsThreadState *state;

	gboolean stop;

} VipsWorker;

/* What we track for a group of threads working together.
 */
typedef struct _VipsThreadpool {
	VipsImage *im; /* Image we are calculating */

	/* Start a thread, do a unit of work (runs in parallel) and allocate
	 * a unit of work (serial). Plus the mutex we use to serialize work
	 * allocation.
	 */
	VipsThreadStartFn start;
	VipsThreadpoolAllocateFn allocate;
	VipsThreadpoolWorkFn work;
	GMutex allocate_lock;
	void *a; /* User argument to start / allocate / etc. */

	int max_workers; /* Max number of workers in pool */

	/* The number of workers in the pool (as a negative number, so
	 * -4 means 4 workers are running).
	 */
	VipsSemaphore n_workers;

	/* Workers up this for every loop to make the main thread tick.
	 */
	VipsSemaphore tick;

	/* The number of workers queueing up on allocate_lock. Use this to
	 * grow and shrink the threadpool.
	 */
	int n_waiting; // (atomic)

	/* Increment this and the next worker will decrement and exit if needed
	 * (used to downsize the threadpool).
	 */
	int exit; // (atomic)

	/* Set this to abort evaluation early with an error.
	 */
	gboolean error;

	/* Ask threads to exit, either set by allocate, or on free.
	 */
	gboolean stop;
} VipsThreadpool;

static int
vips_worker_allocate(VipsWorker *worker)
{
	VipsThreadpool *pool = worker->pool;

	g_assert(!pool->stop);

	if (!worker->state &&
		!(worker->state = pool->start(pool->im, pool->a)))
		return -1;

	if (pool->allocate(worker->state, pool->a, &pool->stop))
		return -1;

	return 0;
}

/* Run this once per main loop. Get some work (single-threaded), then do it
 * (many-threaded).
 */
static void
vips_worker_work_unit(VipsWorker *worker)
{
	VipsThreadpool *pool = worker->pool;

	VIPS_GATE_START("vips_worker_work_unit: wait");

	vips__worker_lock(&pool->allocate_lock);

	VIPS_GATE_STOP("vips_worker_work_unit: wait");

	/* Has another worker signaled stop while we've been waiting?
	 */
	if (pool->stop) {
		worker->stop = TRUE;
		g_mutex_unlock(&pool->allocate_lock);
		return;
	}

	/* Has a thread been asked to exit? Volunteer if yes.
	 */
	if (g_atomic_int_add(&pool->exit, -1) > 0) {
		/* A thread had been asked to exit, and we've grabbed the
		 * flag.
		 */
		worker->stop = TRUE;
		g_mutex_unlock(&pool->allocate_lock);
		return;
	}
	else {
		/* No one had been asked to exit and we've mistakenly taken
		 * the exit count below zero. Put it back up again.
		 */
		g_atomic_int_inc(&pool->exit);
	}

	if (vips_worker_allocate(worker)) {
		pool->error = TRUE;
		worker->stop = TRUE;
		g_mutex_unlock(&pool->allocate_lock);
		return;
	}

	/* Have we just signalled stop?
	 */
	if (pool->stop) {
		worker->stop = TRUE;
		g_mutex_unlock(&pool->allocate_lock);
		return;
	}

	g_mutex_unlock(&pool->allocate_lock);

	if (worker->state->stall &&
		vips__stall) {
		/* Sleep for 0.5s. Handy for stressing the seq system. Stall
		 * is set by allocate funcs in various places.
		 */
		g_usleep(500000);
		worker->state->stall = FALSE;
		printf("vips_worker_work_unit: stall done, releasing y = %d ...\n",
			worker->state->y);
	}

	/* Process a work unit.
	 */
	if (pool->work(worker->state, pool->a)) {
		worker->stop = TRUE;
		pool->error = TRUE;
	}
}

/* What runs as a thread ... loop, waiting to be told to do stuff.
 */
static void
vips_thread_main_loop(void *a, void *b)
{
	VipsWorker *worker = (VipsWorker *) a;
	VipsThreadpool *pool = worker->pool;

	g_assert(pool == worker->pool);

	VIPS_GATE_START("vips_thread_main_loop: thread");

	g_private_set(&worker_key, worker);

	/* Process work units! Always tick, even if we are stopping, so the
	 * main thread will wake up for exit.
	 */
	while (!pool->stop &&
		!worker->stop &&
		!pool->error) {
		VIPS_GATE_START("vips_worker_work_unit: u");
		vips_worker_work_unit(worker);
		VIPS_GATE_STOP("vips_worker_work_unit: u");
		vips_semaphore_up(&pool->tick);
	}

	VIPS_GATE_STOP("vips_thread_main_loop: thread");

	/* unreffing the worker state will trigger stop in the threadstate, so
	 * we need to single-thread.
	 */
	g_mutex_lock(&pool->allocate_lock);

	VIPS_FREEF(g_object_unref, worker->state);

	g_mutex_unlock(&pool->allocate_lock);

	VIPS_FREE(worker);
	g_private_set(&worker_key, NULL);

	/* We are done: tell the main thread.
	 */
	vips_semaphore_upn(&pool->n_workers, 1);
}

/* Attach another thread to a threadpool.
 */
static int
vips_worker_new(VipsThreadpool *pool)
{
	VipsWorker *worker;

	if (!(worker = VIPS_NEW(NULL, VipsWorker)))
		return -1;
	worker->pool = pool;
	worker->state = NULL;

	/* We can't build the state here, it has to be done by the worker
	 * itself the first time that allocate runs so that any regions are
	 * owned by the correct thread.
	 */

	if (vips_thread_execute("worker", vips_thread_main_loop, worker)) {
		g_free(worker);
		return -1;
	}

	/* One more worker in the pool.
	 */
	vips_semaphore_upn(&pool->n_workers, -1);

	return 0;
}

void
vips__worker_lock(GMutex *mutex)
{
	VipsWorker *worker = (VipsWorker *) g_private_get(&worker_key);

	if (worker)
		g_atomic_int_inc(&worker->pool->n_waiting);
	g_mutex_lock(mutex);
	if (worker)
		g_atomic_int_dec_and_test(&worker->pool->n_waiting);
}

void
vips__worker_cond_wait(GCond *cond, GMutex *mutex)
{
	VipsWorker *worker = (VipsWorker *) g_private_get(&worker_key);

	if (worker)
		g_atomic_int_inc(&worker->pool->n_waiting);
	g_cond_wait(cond, mutex);
	if (worker)
		g_atomic_int_dec_and_test(&worker->pool->n_waiting);
}

static void
vips_threadpool_wait(VipsThreadpool *pool)
{
	/* Wait for them all to exit.
	 */
	pool->stop = TRUE;
	vips_semaphore_downn(&pool->n_workers, 0);
}

static void
vips_threadpool_free(VipsThreadpool *pool)
{
	VIPS_DEBUG_MSG("vips_threadpool_free: \"%s\" (%p)\n",
		pool->im->filename, pool);

	vips_threadpool_wait(pool);

	g_mutex_clear(&pool->allocate_lock);
	vips_semaphore_destroy(&pool->n_workers);
	vips_semaphore_destroy(&pool->tick);
	VIPS_FREE(pool);
}

static VipsThreadpool *
vips_threadpool_new(VipsImage *im)
{
	VipsThreadpool *pool;
	int tile_width;
	int tile_height;
	gint64 n_tiles;
	int n_lines;

	/* Allocate and init new thread block.
	 */
	if (!(pool = VIPS_NEW(NULL, VipsThreadpool)))
		return NULL;
	pool->im = im;
	pool->allocate = NULL;
	pool->work = NULL;
	g_mutex_init(&pool->allocate_lock);
	pool->max_workers = vips_concurrency_get();
	vips_semaphore_init(&pool->n_workers, 0, "n_workers");
	vips_semaphore_init(&pool->tick, 0, "tick");
	pool->error = FALSE;
	pool->stop = FALSE;
	pool->exit = 0;

	/* If this is a tiny image, we won't need all max_workers threads.
	 * Guess how
	 * many tiles we might need to cover the image and use that to limit
	 * the number of threads we create.
	 */
	vips_get_tile_size(im, &tile_width, &tile_height, &n_lines);
	n_tiles = (1 + (gint64) im->Xsize / tile_width) *
		(1 + (gint64) im->Ysize / tile_height);
	n_tiles = VIPS_CLIP(1, n_tiles, 1024);
	pool->max_workers = VIPS_MIN(pool->max_workers, n_tiles);

	/* VIPS_META_CONCURRENCY on the image can optionally override
	 * concurrency.
	 */
	pool->max_workers = vips_image_get_concurrency(im, pool->max_workers);

	VIPS_DEBUG_MSG("vips_threadpool_new: \"%s\" (%p), with %d threads\n",
		im->filename, pool, pool->max_workers);

	return pool;
}

/**
 * VipsThreadpoolStartFn:
 * @a: client data
 * @b: client data
 * @c: client data
 *
 * This function is called once by each worker just before the first time work
 * is allocated to it to build the per-thread state. Per-thread state is used
 * by [callback@ThreadpoolAllocateFn] and [callback@ThreadpoolWorkFn] to
 * communicate.
 *
 * [class@ThreadState] is a subclass of [class@Object]. Start functions are
 * called from allocate, that is, they are single-threaded.
 *
 * ::: seealso
 *     [func@threadpool_run].
 *
 * Returns: a new [class@ThreadState] object, or NULL on error
 */

/**
 * VipsThreadpoolAllocateFn:
 * @state: per-thread state
 * @a: client data
 * @stop: set this to signal end of computation
 *
 * This function is called to allocate a new work unit for the thread. It is
 * always single-threaded, so it can modify per-pool state (such as a
 * counter).
 *
 * It should set @stop to `TRUE` to indicate that no work could be allocated
 * because the job is done.
 *
 * ::: seealso
 *     [func@threadpool_run].
 *
 * Returns: 0 on success, or -1 on error
 */

/**
 * VipsThreadpoolWorkFn:
 * @state: per-thread state
 * @a: client data
 *
 * This function is called to process a work unit. Many copies of this can run
 * at once, so it should not write to the per-pool state. It can write to
 * per-thread state.
 *
 * ::: seealso
 *     [func@threadpool_run].
 *
 * Returns: 0 on success, or -1 on error
 */

/**
 * VipsThreadpoolProgressFn:
 * @a: client data
 *
 * This function is called by the main thread once for every work unit
 * processed. It can be used to give the user progress feedback.
 *
 * ::: seealso
 *     [func@threadpool_run].
 *
 * Returns: 0 on success, or -1 on error
 */

/**
 * vips_threadpool_run:
 * @im: image to loop over
 * @start: (scope async): allocate per-thread state
 * @allocate: (scope async): allocate a work unit
 * @work: (scope async): process a work unit
 * @progress: (scope async): give progress feedback about a work unit, or `NULL`
 * @a: client data
 *
 * This function runs a set of threads over an image. Each thread first calls
 * @start to create new per-thread state, then runs
 * @allocate to set up a new work unit (perhaps the next tile in an image, for
 * example), then @work to process that work unit. After each unit is
 * processed, @progress is called, so that the operation can give
 * progress feedback. @progress may be `NULL`.
 *
 * The object returned by @start must be an instance of a subclass of
 * [class@ThreadState]. Use this to communicate between @allocate and @work.
 *
 * @allocate and @start are always single-threaded (so they can write to the
 * per-pool state), whereas @work can be executed concurrently. @progress is
 * always called by
 * the main thread (ie. the thread which called [func@threadpool_run]).
 *
 * ::: seealso
 *     [func@concurrency_set].
 *
 * Returns: 0 on success, or -1 on error.
 */
int
vips_threadpool_run(VipsImage *im,
	VipsThreadStartFn start,
	VipsThreadpoolAllocateFn allocate,
	VipsThreadpoolWorkFn work,
	VipsThreadpoolProgressFn progress,
	void *a)
{
	VipsThreadpool *pool;
	int result;
	int n_waiting;
	int n_working;

	if (!(pool = vips_threadpool_new(im)))
		return -1;

	pool->start = start;
	pool->allocate = allocate;
	pool->work = work;
	pool->a = a;

	/* Start with half of the max number of threads, then let it drift up
	 * and down with load.
	 */
	for (n_working = 0; n_working < 1 + pool->max_workers / 2; n_working++)
		if (vips_worker_new(pool)) {
			vips_threadpool_free(pool);
			return -1;
		}

	for (;;) {
		/* Wait for a tick from a worker.
		 */
		vips_semaphore_down(&pool->tick);

		VIPS_DEBUG_MSG("vips_threadpool_run: tick\n");

		if (pool->stop ||
			pool->error)
			break;

		if (progress &&
			progress(pool->a))
			pool->error = TRUE;

		if (pool->stop ||
			pool->error)
			break;

		n_waiting = g_atomic_int_get(&pool->n_waiting);
		VIPS_DEBUG_MSG("n_waiting = %d\n", n_waiting);
		VIPS_DEBUG_MSG("n_working = %d\n", n_working);
		VIPS_DEBUG_MSG("exit = %d\n", pool->exit);

		if (n_waiting > 3 &&
			n_working > 1) {
			VIPS_DEBUG_MSG("shrinking thread pool\n");
			g_atomic_int_inc(&pool->exit);
			n_working -= 1;
		}
		else if (n_waiting < 2 &&
			n_working < pool->max_workers) {
			VIPS_DEBUG_MSG("expanding thread pool\n");
			if (vips_worker_new(pool)) {
				vips_threadpool_free(pool);
				return -1;
			}
			n_working += 1;
		}
	}

	/* This will block until the last worker completes.
	 */
	vips_threadpool_wait(pool);

	/* Return 0 for success.
	 */
	result = pool->error ? -1 : 0;

	vips_threadpool_free(pool);

	if (!vips_image_get_concurrency(im, 0))
		g_info("threadpool completed with %d workers", n_working);

	/* "minimise" is only emitted for top-level threadpools.
	 */
	if (!vips_image_get_typeof(im, "vips-no-minimise"))
		vips_image_minimise_all(im);

	return result;
}
