/* Support for thread stuff.
 *
 * JC & KM 9/5/94
 * Modified:
 * 28/11/94 JC
 *	- return(0) missing from tidy_thread_info()
 * 4/8/99 RP JC
 *	- reorganised for POSIX
 * 28/3/11
 * 	- moved to vips_ namespace
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
#define DEBUG_IO
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <glib/gi18n-lib.h>

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include <vips/vips.h>
#include <vips/internal.h>

void
vips_semaphore_init(VipsSemaphore *s, int v, char *name)
{
	s->v = v;
	s->name = name;
	g_mutex_init(&s->mutex);
	s->cond = g_new(GCond, 1);
	g_cond_init(s->cond);
}

void
vips_semaphore_destroy(VipsSemaphore *s)
{
	g_mutex_clear(&s->mutex);
	g_cond_clear(s->cond);
	g_free(s->cond);
}

/* Add n to the semaphore and signal any threads that are blocked waiting
 * a change.
 */
int
vips_semaphore_upn(VipsSemaphore *s, int n)
{
	int value_after_op;

	g_mutex_lock(&s->mutex);
	s->v += n;
	value_after_op = s->v;

	/* If we are only incrementing by one, we only need to wake a single
	 * thread. If we are incrementing by a lot, we must wake all threads.
	 */
	if (n == 1)
		g_cond_signal(s->cond);
	else
		g_cond_broadcast(s->cond);
	g_mutex_unlock(&s->mutex);

#ifdef DEBUG_IO
	printf("vips_semaphore_upn(\"%s\",%d) = %d\n",
		s->name, n, value_after_op);
	if (value_after_op > 1)
		vips_error("vips_semaphore_upn", "up over 1!");
#endif /*DEBUG_IO*/

	return value_after_op;
}

/* Increment the semaphore.
 */
int
vips_semaphore_up(VipsSemaphore *s)
{
	return vips_semaphore_upn(s, 1);
}

/* Wait for sem > n, then subtract n.
 * Returns -1 when the monotonic time in @end_time was passed.
 */
static int
vips__semaphore_downn_until(VipsSemaphore *s, int n, gint64 end_time)
{
	int value_after_op;

	VIPS_GATE_START("vips__semaphore_downn_until: wait");

	g_mutex_lock(&s->mutex);

	while (s->v < n) {
		if (end_time == -1)
			vips__worker_cond_wait(s->cond, &s->mutex);
		else if (!g_cond_wait_until(s->cond, &s->mutex, end_time)) {
			/* timeout has passed.
			 */
			g_mutex_unlock(&s->mutex);

			VIPS_GATE_STOP("vips__semaphore_downn_until: wait");
			return -1;
		}
	}

	s->v -= n;
	value_after_op = s->v;

	g_mutex_unlock(&s->mutex);

#ifdef DEBUG_IO
	printf("vips__semaphore_downn_until(\"%s\",%d): %d\n",
		s->name, n, value_after_op);
#endif /*DEBUG_IO*/

	VIPS_GATE_STOP("vips__semaphore_downn_until: wait");

	return value_after_op;
}

/* Wait for sem>n, then subtract n. n must be >= 0. Returns the new semaphore
 * value.
 */
int
vips_semaphore_downn(VipsSemaphore *s, int n)
{
	g_assert(n >= 0);

	return vips__semaphore_downn_until(s, n, -1);
}

/* Wait for sem > 0, then decrement. Returns the new semaphore value.
 */
int
vips_semaphore_down(VipsSemaphore *s)
{
	return vips__semaphore_downn_until(s, 1, -1);
}

/* Wait for sem > 0, then decrement.
 * Returns -1 when @timeout (in microseconds) has passed, or the new
 * semaphore value.
 */
int
vips_semaphore_down_timeout(VipsSemaphore *s, gint64 timeout)
{
	gint64 end_time = g_get_monotonic_time() + timeout;

	return vips__semaphore_downn_until(s, 1, end_time);
}
