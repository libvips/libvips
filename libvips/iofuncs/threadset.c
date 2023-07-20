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
#include <vips/thread.h>
#include <vips/debug.h>

typedef struct _VipsThreadsetMember {
	/* The set we are part of.
	 */
	VipsThreadset *set;

	/* The underlying glib thread object.
	 */
	GThread *thread;

	/* The task the thread should run next.
	 */
	const char *domain;
	GFunc func;
	void *data;
	void *user_data;

	/* The thread waits on this when it's free.
	 */
	VipsSemaphore idle;

	/* Set by our controller to request exit.
	 */
	gboolean kill;
} VipsThreadsetMember;

struct _VipsThreadset {
	GMutex *lock;

	/* All the VipsThreadsetMember we have created.
	 */
	GSList *members;

	/* The set of currently idle threads.
	 */
	GSList *free;

	/* The current number of threads, the highwater mark, and
	 * the max we allow before blocking thread creation.
	 */
	int n_threads;
	int n_threads_highwater;
	int max_threads;
};

/* The maximum relative time (in microseconds) that a thread waits
 * for work before being stopped.
 */
static const gint64 max_idle_time = 15 * G_TIME_SPAN_SECOND;

/* The thread work function.
 */
static void *
vips_threadset_work(void *pointer)
{
	VipsThreadsetMember *member = (VipsThreadsetMember *) pointer;
	VipsThreadset *set = member->set;

	VIPS_DEBUG_MSG("vips_threadset_work: starting %p\n", member);

	for (;;) {
		/* Wait for at least 15 seconds to be given work.
		 */
		if (vips_semaphore_down_timeout(&member->idle,
				max_idle_time) == -1)
			break;

		/* Killed or no task available? Leave this thread.
		 */
		if (member->kill ||
			!member->func)
			break;

		/* If we're profiling, attach a prof struct to this thread.
		 */
		if (vips__thread_profile)
			vips__thread_profile_attach(member->domain);

		/* Execute the task.
		 */
		member->func(member->data, member->user_data);

		/* Free any thread-private resources -- they will not be
		 * useful for the next task to use this thread.
		 */
		vips_thread_shutdown();

		member->domain = NULL;
		member->func = NULL;
		member->data = NULL;
		member->user_data = NULL;

		/* We are free ... back on the free list!
		 */
		g_mutex_lock(set->lock);
		set->free = g_slist_prepend(set->free, member);
		g_mutex_unlock(set->lock);
	}

	/* Timed-out or kill has been requested ... remove from both free
	 * and member list.
	 */
	g_mutex_lock(set->lock);
	set->free = g_slist_remove(set->free, member);
	set->members = g_slist_remove(set->members, member);
	set->n_threads -= 1;
	VIPS_DEBUG_MSG("vips_threadset_work: stopping %p (%d remaining)\n",
		member, set->n_threads);
	g_mutex_unlock(set->lock);

	vips_semaphore_destroy(&member->idle);

	VIPS_FREE(member);

	return NULL;
}

/* Create a new idle member for the set.
 */
static VipsThreadsetMember *
vips_threadset_add(VipsThreadset *set)
{
	VipsThreadsetMember *member;

	if (set->max_threads &&
		set->n_threads >= set->max_threads) {
		vips_error("VipsThreadset",
			"%s", _("threadset is exhausted"));
		return NULL;
	}

	member = g_new0(VipsThreadsetMember, 1);
	member->set = set;

	vips_semaphore_init(&member->idle, 0, "idle");

	if (!(member->thread = vips_g_thread_new("libvips worker",
			  vips_threadset_work, member))) {
		vips_semaphore_destroy(&member->idle);
		VIPS_FREE(member);

		return NULL;
	}

	/* Ensure idle threads are freed on exit, this
	 * ref is increased before the thread is joined.
	 */
	g_thread_unref(member->thread);

	g_mutex_lock(set->lock);
	set->members = g_slist_prepend(set->members, member);
	set->n_threads += 1;
	set->n_threads_highwater =
		VIPS_MAX(set->n_threads_highwater, set->n_threads);
	g_mutex_unlock(set->lock);

	return member;
}

/**
 * vips_threadset_new:
 * @max_threads: maximum number of system threads
 *
 * Create a new threadset.
 *
 * If @max_threads is 0, new threads will be created when necessary by
 * vips_threadset_run(), with no limit on the number of threads.
 *
 * If @max_threads is > 0, then that many threads will be created by
 * vips_threadset_new() during startup and vips_threadset_run() will fail if
 * no free threads are available.
 *
 * Returns: the new threadset.
 */
VipsThreadset *
vips_threadset_new(int max_threads)
{
	VipsThreadset *set;

	set = g_new0(VipsThreadset, 1);
	set->lock = vips_g_mutex_new();
	set->max_threads = max_threads;

	if (set->max_threads > 0)
		for (int i = 0; i < set->max_threads; i++) {
			VipsThreadsetMember *member;

			if (!(member = vips_threadset_add(set))) {
				vips_threadset_free(set);
				return NULL;
			}

			set->free = g_slist_prepend(set->free, member);
		}

	return set;
}

/**
 * vips_threadset_run:
 * @set: the threadset to run the task in
 * @domain: the name of the task (useful for debugging)
 * @func: the task to execute
 * @data: the task's data
 *
 * Execute a task in a thread. If there are no idle threads, create a new one,
 * provided we are under @max_threads.
 *
 * See also: vips_threadset_new().
 *
 * Returns: 0 on success, or -1 on error.
 */
int
vips_threadset_run(VipsThreadset *set,
	const char *domain, GFunc func, gpointer data)
{
	VipsThreadsetMember *member;

	member = NULL;

	/* Try to get an idle thread.
	 */
	g_mutex_lock(set->lock);
	if (set->free) {
		member = (VipsThreadsetMember *) set->free->data;
		set->free = g_slist_remove(set->free, member);
	}
	g_mutex_unlock(set->lock);

	/* None? Make a new idle but not free member.
	 */
	if (!member)
		member = vips_threadset_add(set);

	/* Still nothing? Thread create has failed.
	 */
	if (!member)
		return -1;

	/* Allocate the task and set it going.
	 */
	member->domain = domain;
	member->func = func;
	member->data = data;
	member->user_data = NULL;
	vips_semaphore_up(&member->idle);

	return 0;
}

/* Kill a member.
 */
static void
vips_threadset_kill_member(VipsThreadsetMember *member)
{
	GThread *thread;

	thread = g_thread_ref(member->thread);
	member->kill = TRUE;

	vips_semaphore_up(&member->idle);

	(void) g_thread_join(thread);

	/* member is freed on thread exit.
	 */
}

/**
 * vips_threadset_free:
 * @set: the threadset to free
 *
 * Free a threadset. This call will block until all pending tasks are
 * finished.
 */
void
vips_threadset_free(VipsThreadset *set)
{
	VIPS_DEBUG_MSG("vips_threadset_free: %p\n", set);

	/* Try to get and finish a thread.
	 */
	for (;;) {
		VipsThreadsetMember *member;

		member = NULL;
		g_mutex_lock(set->lock);
		if (set->members)
			member = (VipsThreadsetMember *) set->members->data;
		g_mutex_unlock(set->lock);

		if (!member)
			break;

		vips_threadset_kill_member(member);
	}

	if (vips__leak)
		printf("vips_threadset_free: peak of %d threads\n",
			set->n_threads_highwater);

	VIPS_FREEF(vips_g_mutex_free, set->lock);
	VIPS_FREE(set);
}
