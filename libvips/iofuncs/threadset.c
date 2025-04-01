/* A set of threads.
 *
 * Creating and destroying threads can be expensive on some platforms, so we
 * try to only create once, then reuse.
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

/*
#define VIPS_DEBUG
 */

#include <vips/vips.h>
#include <vips/internal.h>
#include <vips/debug.h>

typedef struct _VipsThreadExec {
	/* The source of this function.
	 */
	const char *domain;

	/* The function to execute within the thread.
	 */
	GFunc func;

	/* User data that is handed over to func when it is called.
	 */
	gpointer data;
} VipsThreadExec;

struct _VipsThreadset {
	/* An asynchronous queue of tasks.
	 */
	GAsyncQueue *queue;

	/* Idle threads wait on this semaphore.
	 */
	VipsSemaphore idle;

	/* The number of threads that haven't reached their entry point.
	 */
	int queue_guard;

	/* The current number of (idle-)threads, the highwater mark,
	 * and the max we allow before blocking thread creation.
	 */
	int n_threads;
	int n_threads_highwater;
	int n_idle_threads;
	int max_threads;

	/* Set by our controller to request exit.
	 */
	gboolean exit;
};

/* The maximum relative time (in microseconds) that a thread waits
 * for work before being stopped.
 */
static const gint64 max_idle_time = 15 * G_TIME_SPAN_SECOND;

/* The maximum number of idle threads.
 */
static const int max_idle_threads = 2;

static gboolean
vips_threadset_reuse_wait(VipsThreadset *set)
{
	int result;

	/* A superfluous thread? Leave this thread.
	 */
	if (++set->n_idle_threads > max_idle_threads)
		return FALSE;

	g_async_queue_unlock(set->queue);

	/* Wait for at least 15 seconds before leaving this thread.
	 */
	result = vips_semaphore_down_timeout(&set->idle, max_idle_time);

	g_async_queue_lock(set->queue);

	return result != -1;
}

static void
vips_threadset_free_internal(VipsThreadset *set)
{
	VIPS_FREEF(g_async_queue_unref, set->queue);
	vips_semaphore_destroy(&set->idle);
	VIPS_FREE(set);
}

/* The thread work function.
 */
static void *
vips_threadset_work(void *pointer)
{
	VipsThreadset *set = (VipsThreadset *) pointer;
	gboolean cleanup = FALSE;

	VIPS_DEBUG_MSG("vips_threadset_work: starting %p\n", g_thread_self());

	g_async_queue_lock(set->queue);

	set->queue_guard--;

	for (;;) {
		/* Pop a task from the queue. If the number of threads is limited,
		 * this will block until a task becomes available. Otherwise, it
		 * waits for at least 1/2 second before being marked as idle.
		 */
		VipsThreadExec *task = set->max_threads > 0
			? g_async_queue_pop_unlocked(set->queue)
			: g_async_queue_timeout_pop_unlocked(set->queue,
				  G_USEC_PER_SEC / 2);

		/* Request to exit? Leave this thread.
		 */
		if (set->exit) {
			/* The last thread should cleanup the set.
			 */
			cleanup = set->n_threads == 1;
			break;
		}

		/* No task available? Wait for being reused.
		 */
		if (task == NULL) {
			if (!vips_threadset_reuse_wait(set)) {
				set->n_idle_threads--;
				break;
			}

			continue;
		}

		/* A task was received and there was no request to exit.
		 */
		g_async_queue_unlock(set->queue);

		/* If we're profiling, attach a prof struct to this thread.
		 */
		if (vips__thread_profile)
			vips__thread_profile_attach(task->domain);

		/* Execute the task.
		 */
		task->func(task->data, NULL);

		/* Free any thread-private resources -- they will not be
		 * useful for the next task to use this thread.
		 */
		vips_thread_shutdown();
		VIPS_FREE(task);

		g_async_queue_lock(set->queue);
	}

	/* Timed-out or exit has been requested, decrement number of threads.
	 */
	set->n_threads--;
	VIPS_DEBUG_MSG(
		"vips_threadset_work: stopping %p (%d remaining, %d idle)\n",
		g_thread_self(), set->n_threads, set->n_idle_threads);

	g_async_queue_unlock(set->queue);

	if (cleanup)
		vips_threadset_free_internal(set);

	return NULL;
}

/* Add a new thread to the set.
 */
static gboolean
vips_threadset_add_thread(VipsThreadset *set)
{
	gboolean reused = FALSE;

	/* There are already sufficient threads running.
	 */
	if (set->max_threads > 0 &&
		set->n_threads >= set->max_threads)
		return TRUE;

	if (set->n_idle_threads > 0) {
		vips_semaphore_up(&set->idle);

		set->n_idle_threads--;
		reused = TRUE;
	}

	if (!reused) {
		/* No idle thread was found, we have to start a new one.
		 */
		GThread *thread;

		if (!(thread = vips_g_thread_new("libvips worker",
				  vips_threadset_work, set)))
			return FALSE;

		/* Ensure threads are freed on exit.
		 */
		g_thread_unref(thread);

		set->n_threads++;
		set->queue_guard++;
		set->n_threads_highwater =
			VIPS_MAX(set->n_threads_highwater, set->n_threads);
	}

	return TRUE;
}

/**
 * vips_threadset_new: (free-func vips_threadset_free) (skip)
 * @max_threads: maximum number of system threads
 *
 * Create a new threadset.
 *
 * If @max_threads is 0, new threads will be created when necessary by
 * [func@threadset_run], with no limit on the number of threads.
 *
 * If @max_threads is > 0, then that many threads will be created by
 * [ctor@Threadset.new] during startup and [func@threadset_run] will
 * not spawn any additional threads.
 *
 * Returns: the new threadset.
 */
VipsThreadset *
vips_threadset_new(int max_threads)
{
	VipsThreadset *set;

	set = g_new0(VipsThreadset, 1);
	set->queue = g_async_queue_new();
	vips_semaphore_init(&set->idle, 0, "idle");
	set->max_threads = max_threads;

	if (set->max_threads > 0)
		for (int i = 0; i < set->max_threads; i++) {
			if (!vips_threadset_add_thread(set)) {
				vips_threadset_free(set);
				return NULL;
			}
		}

	return set;
}

/**
 * vips_threadset_run:
 * @set: the threadset to run the task in
 * @domain: the name of the task (useful for debugging)
 * @func: (scope async) (closure data): the task to execute
 * @data: (nullable): the task's data
 *
 * Execute a task in a thread. If there are no idle threads and the maximum
 * thread limit specified by @max_threads has not been reached, a new thread
 * will be spawned.
 *
 * ::: seealso
 *     [ctor@Threadset.new].
 *
 * Returns: 0 on success, or -1 on error.
 */
int
vips_threadset_run(VipsThreadset *set,
	const char *domain, GFunc func, gpointer data)
{
	VipsThreadExec *task;

	g_async_queue_lock(set->queue);

	/* Create or reuse an idle thread if there are at least as many tasks
	 * in the queue as waiting threads. The guard comparison prevents
	 * oversubscription by threads that haven't started yet.
	 */
	if (g_async_queue_length_unlocked(set->queue) >= set->queue_guard)
		if (!vips_threadset_add_thread(set)) {
			g_async_queue_unlock(set->queue);

			/* Thread create has failed.
			 */
			return -1;
		}

	/* Allocate the task and push it into the queue.
	 */
	task = g_new0(VipsThreadExec, 1);
	task->domain = domain;
	task->func = func;
	task->data = data;

	g_async_queue_push_unlocked(set->queue, task);
	g_async_queue_unlock(set->queue);

	return 0;
}

/**
 * vips_threadset_free:
 * @set: the threadset to free
 *
 * Free a threadset. This call returns immediately.
 */
void
vips_threadset_free(VipsThreadset *set)
{
	VIPS_DEBUG_MSG("vips_threadset_free: %p\n", set);

	g_async_queue_lock(set->queue);

	if (vips__leak)
		printf("vips_threadset_free: peak of %d threads\n",
			set->n_threads_highwater);

	set->exit = TRUE;

	/* No threads left, we cleanup.
	 */
	if (set->n_threads == 0) {
		g_async_queue_unlock(set->queue);
		vips_threadset_free_internal(set);
		return;
	}

	/* Wake up idle threads, if any.
	 */
	if (set->n_idle_threads > 0)
		vips_semaphore_upn(&set->idle, set->n_idle_threads);

	/* Send dummy data to the queue, causing threads to wake up and check
	 * the above set->exit condition.
	 */
	for (int i = 0; i < set->n_threads; i++)
		g_async_queue_push_unlocked(set->queue, GUINT_TO_POINTER(1));

	g_async_queue_unlock(set->queue);
}
