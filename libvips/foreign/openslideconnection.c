/* Share and reuse openslide_t between many openslideload operations.
 *
 * 1/4/25
 *	- first version!
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
#define VIPS_DEBUG
#define DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <glib/gi18n-lib.h>

#ifdef HAVE_OPENSLIDE

#include <vips/vips.h>
#include <vips/internal.h>

#include "pforeign.h"

#include <openslide.h>

// we keep this many connections around after they are closed, ready for reuse
#define OPENSLIDECONNECTION (3)

// a tile cache shared between all active openslide connections ... 32mb
#define OPENSLIDECONNECTION_CACHE_SIZE (64 * 1024 * 1024)

typedef struct _VipsOpenslideConnection {
	char *filename;

	// protected by vips_openslideconnection_lock
	int ref_count;

	// first access protected by separate lock, since initialization
	// is slow
	openslide_t *osr;
	GMutex osr_lock;

} VipsOpenslideConnection;

static GHashTable *vips_openslideconnection_cache = NULL;
static GQueue *vips_openslideconnection_unused = NULL;
static GMutex vips_openslideconnection_lock;

/* Added in 4.0 ... this is a tile cache that's shared between all active
 * openslide connections.
 */
#ifdef HAVE_OPENSLIDE_CACHE_CREATE
openslide_cache_t *vips_openslideconnection_openslide_cache;
#endif /*HAVE_OPENSLIDE_CACHE_CREATE*/

static void
vips_openslideconnection_free(VipsOpenslideConnection *connection)
{
#ifdef DEBUG
	printf("vips_openslideconnection_free: %s\n", connection->filename);
#endif /*DEBUG*/

	VipsOpenslideConnection *cached G_GNUC_UNUSED =
		g_hash_table_lookup(vips_openslideconnection_cache,
			connection->filename);
	g_assert(cached);
	g_assert(cached == connection);
	g_hash_table_remove(vips_openslideconnection_cache, connection->filename);
	g_queue_remove(vips_openslideconnection_unused, connection);

	g_mutex_lock(&connection->osr_lock);
	VIPS_FREEF(openslide_close, connection->osr);
	g_mutex_unlock(&connection->osr_lock);
	g_mutex_clear(&connection->osr_lock);
	VIPS_FREE(connection->filename);
	g_free(connection);
}

static void
vips_openslideconnection_trim(void)
{
	while (vips_openslideconnection_unused->length > OPENSLIDECONNECTION) {
		VipsOpenslideConnection *oldest =
			g_queue_pop_head(vips_openslideconnection_unused);
		vips_openslideconnection_free(oldest);
	}
}

static void
vips_openslideconnection_unref(VipsOpenslideConnection *connection)
{
#ifdef DEBUG
	printf("vips_openslideconnection_unref: %s\n", connection->filename);
#endif /*DEBUG*/

	g_assert(connection->ref_count > 0);

	connection->ref_count -= 1;

	if (connection->ref_count == 0) {
		/* If the openslide_t is in an error state, or we've no connection,
		 * don't leave it in the cache.
		 */
		if (!connection->osr ||
			openslide_get_error(connection->osr))
			vips_openslideconnection_free(connection);
		else {
			g_queue_push_tail(vips_openslideconnection_unused, connection);
			vips_openslideconnection_trim();
		}
	}
}

static void
vips_openslideconnection_ref(VipsOpenslideConnection *connection)
{
#ifdef DEBUG
	printf("vips_openslideconnection_ref: %s\n", connection->filename);
#endif /*DEBUG*/

	g_assert(connection->ref_count >= 0);

	if (connection->ref_count == 0)
		g_queue_remove(vips_openslideconnection_unused, connection);

	connection->ref_count += 1;
}

static VipsOpenslideConnection *
vips_openslideconnection_new(const char *filename)
{
#ifdef DEBUG
	printf("vips_openslideconnection_new: %s\n", filename);
#endif /*DEBUG*/

	VipsOpenslideConnection *connection;

	connection = g_new0(VipsOpenslideConnection, 1);
	connection->filename = g_strdup(filename);
	g_mutex_init(&connection->osr_lock);

	g_assert(!g_hash_table_lookup(vips_openslideconnection_cache, filename));

	g_hash_table_insert(vips_openslideconnection_cache,
		connection->filename, connection);

	return connection;
}

openslide_t *
vips__openslideconnection_open(const char *filename, gboolean revalidate)
{
#ifdef DEBUG
	printf("vips_openslideconnection_open: %s, revalidate = %d\n",
		filename, revalidate);
#endif /*DEBUG*/

	g_mutex_lock(&vips_openslideconnection_lock);

	if (!vips_openslideconnection_cache) {
		vips_openslideconnection_cache =
			g_hash_table_new(g_str_hash, g_str_equal);
		vips_openslideconnection_unused = g_queue_new();

#ifdef HAVE_OPENSLIDE_CACHE_CREATE
		vips_openslideconnection_openslide_cache =
			openslide_cache_create(OPENSLIDECONNECTION_CACHE_SIZE);
#endif /*HAVE_OPENSLIDE_CACHE_CREATE*/
	}

	VipsOpenslideConnection *connection;

	connection = g_hash_table_lookup(vips_openslideconnection_cache, filename);

	// discard any cached connection on revalidate
	if (connection &&
		connection->ref_count == 0 &&
		revalidate)
		VIPS_FREEF(vips_openslideconnection_free, connection);

	if (!connection)
		connection = vips_openslideconnection_new(filename);

	vips_openslideconnection_ref(connection);

	g_mutex_unlock(&vips_openslideconnection_lock);

	g_mutex_lock(&connection->osr_lock);

	gboolean unref;

	/* We do the open outside the main lock (just in the connection lock)
	 * since it can take many seconds for some slides.
	 */
	unref = FALSE;
	if (!connection->osr) {
		connection->osr = openslide_open(connection->filename);

		/* If open fails, we must unref the connection, since we'll return
		 * NULL.
		 */
		if (!connection->osr)
			unref = TRUE;

#ifdef HAVE_OPENSLIDE_CACHE_CREATE
		if (connection->osr)
			openslide_set_cache(connection->osr,
				vips_openslideconnection_openslide_cache);
#endif /*HAVE_OPENSLIDE_CACHE_CREATE*/
	}

	openslide_t *osr = connection->osr;

	g_mutex_unlock(&connection->osr_lock);

	if (unref) {
		g_mutex_lock(&vips_openslideconnection_lock);
		vips_openslideconnection_unref(connection);
		g_mutex_unlock(&vips_openslideconnection_lock);
	}

	return osr;
}

void
vips__openslideconnection_close(const char *filename)
{
#ifdef DEBUG
	printf("vips_openslideconnection_close: %s\n", filename);
#endif /*DEBUG*/

	g_mutex_lock(&vips_openslideconnection_lock);

	VipsOpenslideConnection *connection;
	connection = g_hash_table_lookup(vips_openslideconnection_cache, filename);
	if (connection)
		vips_openslideconnection_unref(connection);

	g_mutex_unlock(&vips_openslideconnection_lock);
}

int
vips__openslideconnection_leak(void)
{
	int n_leaks;

	n_leaks = 0;

	g_mutex_lock(&vips_openslideconnection_lock);

	if (vips_openslideconnection_cache)
		n_leaks += g_hash_table_size(vips_openslideconnection_cache) -
			vips_openslideconnection_unused->length;

	g_mutex_unlock(&vips_openslideconnection_lock);

	if (n_leaks > 0)
		printf("vips__openslideconnection_leak: %d leaked connections\n",
			n_leaks);

	return n_leaks;
}

#endif /*HAVE_OPENSLIDE*/
