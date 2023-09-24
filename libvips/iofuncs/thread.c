/* Basic functions to support threading.
 *
 * 29/9/22
 * 	- from threadpool.c
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

/* Maximum value we allow for VIPS_CONCURRENCY. We need to stop huge values
 * killing the system.
 */
#define MAX_THREADS (1024)

/* Default n threads ... 0 means get from environment.
 */
int vips__concurrency = 0;

/* Default tile geometry ... can be set by vips_init().
 */
int vips__tile_width = VIPS__TILE_WIDTH;
int vips__tile_height = VIPS__TILE_HEIGHT;
int vips__fatstrip_height = VIPS__FATSTRIP_HEIGHT;
int vips__thinstrip_height = VIPS__THINSTRIP_HEIGHT;

/* Set this GPrivate to indicate that is a libvips thread.
 */
static GPrivate *is_vips_thread_key = NULL;

/* TRUE if we are a vips thread. We sometimes manage resource allocation
 * differently for vips threads since we can cheaply free stuff on thread
 * termination.
 */
gboolean
vips_thread_isvips(void)
{
	return g_private_get(is_vips_thread_key) != NULL;
}

/* Glib 2.32 revised the thread API. We need some compat functions.
 */

GMutex *
vips_g_mutex_new(void)
{
	GMutex *mutex;

	mutex = g_new(GMutex, 1);
	g_mutex_init(mutex);

	return mutex;
}

void
vips_g_mutex_free(GMutex *mutex)
{
	g_mutex_clear(mutex);
	g_free(mutex);
}

GCond *
vips_g_cond_new(void)
{
	GCond *cond;

	cond = g_new(GCond, 1);
	g_cond_init(cond);

	return cond;
}

void
vips_g_cond_free(GCond *cond)
{
	g_cond_clear(cond);
	g_free(cond);
}

typedef struct {
	const char *domain;
	GThreadFunc func;
	gpointer data;
} VipsThreadInfo;

static void *
vips_thread_run(gpointer data)
{
	VipsThreadInfo *info = (VipsThreadInfo *) data;

	void *result;

	/* Set this to something (anything) to tag this thread as a vips
	 * worker. No need to call g_private_replace as there is no
	 * GDestroyNotify handler associated with a worker.
	 */
	g_private_set(is_vips_thread_key, info);

	result = info->func(info->data);

	g_free(info);

	vips_thread_shutdown();

	return result;
}

GThread *
vips_g_thread_new(const char *domain, GThreadFunc func, gpointer data)
{
	GThread *thread;
	VipsThreadInfo *info;
	GError *error = NULL;

	info = g_new(VipsThreadInfo, 1);
	info->domain = domain;
	info->func = func;
	info->data = data;

	thread = g_thread_try_new(domain, vips_thread_run, info, &error);

	VIPS_DEBUG_MSG_RED("vips_g_thread_new: g_thread_create(%s) = %p\n",
		domain, thread);

	if (!thread) {
		if (error)
			vips_g_error(&error);
		else
			vips_error(domain,
				"%s", _("unable to create thread"));
	}

	return thread;
}

/* The default concurrency, set by the environment variable VIPS_CONCURRENCY,
 * or if that is not set, the number of threads available on the host machine.
 */
static int
vips__concurrency_get_default(void)
{
	const char *str;
	int nthr;
	int x;

	/* Tell the threads system how much concurrency we expect.
	 */
	if (vips__concurrency > 0)
		nthr = vips__concurrency;
	else if (
		((str = g_getenv("VIPS_CONCURRENCY"))
#if ENABLE_DEPRECATED
			|| (str = g_getenv("IM_CONCURRENCY"))
#endif
				) &&
		(x = atoi(str)) > 0)
		nthr = x;
	else
		nthr = g_get_num_processors();

	if (nthr < 1 ||
		nthr > MAX_THREADS) {
		nthr = VIPS_CLIP(1, nthr, MAX_THREADS);

		g_warning(_("threads clipped to %d"), nthr);
	}

	return nthr;
}

/**
 * vips_concurrency_set:
 * @concurrency: number of threads to run
 *
 * Sets the number of worker threads that vips should use when running a
 * #VipsThreadPool.
 *
 * The special value 0 means "default". In this case, the number of threads
 * is set by the environment variable VIPS_CONCURRENCY, or if that is not
 * set, the number of threads available on the host machine.
 *
 * See also: vips_concurrency_get().
 */
void
vips_concurrency_set(int concurrency)
{
	/* Tell the threads system how much concurrency we expect.
	 */
	if (concurrency < 1)
		concurrency = vips__concurrency_get_default();
	else if (concurrency > MAX_THREADS) {
		concurrency = MAX_THREADS;

		g_warning(_("threads clipped to %d"), MAX_THREADS);
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
vips_concurrency_get(void)
{
	return vips__concurrency;
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
vips_get_tile_size(VipsImage *im,
	int *tile_width, int *tile_height, int *n_lines)
{
	const int nthr = vips_concurrency_get();
	const int typical_image_width = 1000;

	/* Compiler warnings.
	 */
	*tile_width = 1;
	*tile_height = 1;

	/* Pick a render geometry.
	 */
	switch (im->dhint) {
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
		/* Only enable thinstrip height for very wide images -- the
		 * overheads are too high to be worthwhile otherwise.
		 */
		*tile_height = im->Xsize > 10000
			? vips__thinstrip_height
			: vips__fatstrip_height;
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
		VIPS_ROUND_UP(vips__tile_width * nthr,
			typical_image_width) /
		typical_image_width;
	*n_lines = VIPS_MAX(*n_lines, vips__fatstrip_height * nthr);
	*n_lines = VIPS_MAX(*n_lines, vips__thinstrip_height * nthr);
	*n_lines = VIPS_ROUND_UP(*n_lines, *tile_height);

	/* We make this assumption in several places.
	 */
	g_assert(*n_lines % *tile_height == 0);

	VIPS_DEBUG_MSG("vips_get_tile_size: %d by %d patches, "
				   "groups of %d scanlines\n",
		*tile_width, *tile_height, *n_lines);
}

void
vips__thread_init(void)
{
	static GPrivate private = G_PRIVATE_INIT(NULL);

	is_vips_thread_key = &private;

	if (vips__concurrency == 0)
		vips__concurrency = vips__concurrency_get_default();
}
