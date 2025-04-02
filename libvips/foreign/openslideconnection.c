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

typedef struct _VipsOpenslideConnection {
	// lock access to these vars here
	GMutex lock;

	int ref_count;
	int time;
	char *filename;
	openslide_t *osr;
} VipsOpenslideConnection;

static GHashTable *vips_openslideconnection_cache = NULL;
static GMutex vips_openslideconnection_lock;

static void
vips_openslideconnection_free(VipsOpenslideConnection *connection)
{
	VipsOpenslideConnection *cached =
		g_hash_table_lookup(vips_openslideconnection_cache,
			connection->filename);
	g_assert(cached);
	g_assert(cached == connection);
	g_hash_table_remove(vips_openslideconnection_cache, connection->filename);

	g_mutex_clear(&connection->lock);
	VIPS_FREE(connection->filename);
	VIPS_FREEF(openslide_close, connection->osr);
	g_free(connection);
}

static void
vips_openslideconnection_unused_cb(gpointer key, gpointer value, gpointer data)
{
	VipsOpenslideConnection *connection = (VipsOpenslideConnection *) value;
	int *count = (int *) data;

	g_mutex_lock(&connection->lock);

	if (connection->ref_count == 0)
		*count += 1;

	g_mutex_unlock(&connection->lock);
}

static int
vips_openslideconnection_unused(void)
{
	int unused;

	unused = 0;
	g_hash_table_foreach(vips_openslideconnection_cache,
		vips_openslideconnection_unused_cb, &unused);

	return unused;
}

static void
vips_openslideconnection_oldest_cb(gpointer key, gpointer value, gpointer data)
{
	VipsOpenslideConnection *connection = (VipsOpenslideConnection *) value;
	VipsOpenslideConnection **oldest = (VipsOpenslideConnection **) data;

	g_mutex_lock(&connection->lock);

	if (!*oldest ||
		connection->time < (*oldest)->time)
		*oldest = connection;

	g_mutex_unlock(&connection->lock);
}

static VipsOpenslideConnection *
vips_openslideconnection_oldest(void)
{
	VipsOpenslideConnection *oldest;

	oldest = NULL;
	g_hash_table_foreach(vips_openslideconnection_cache,
		vips_openslideconnection_oldest_cb, &oldest);

	return oldest;
}

static void
vips_openslideconnection_trim(void)
{
	VipsOpenslideConnection *oldest;

	while (vips_openslideconnection_unused() > OPENSLIDECONNECTION &&
		(oldest = vips_openslideconnection_oldest()))
		vips_openslideconnection_free(oldest);
}

static void
vips_openslideconnection_unref(VipsOpenslideConnection *connection)
{
	gboolean trim;

	g_mutex_lock(&connection->lock);

	g_assert(connection->ref_count > 0);

	connection->ref_count -= 1;
	trim = connection->ref_count == 0;

	g_mutex_unlock(&connection->lock);

	if (trim)
		vips_openslideconnection_trim();
}

static void
vips_openslideconnection_ref(VipsOpenslideConnection *connection)
{
	g_mutex_lock(&connection->lock);

	g_assert(connection->ref_count >= 0);

	connection->ref_count += 1;

	g_mutex_unlock(&connection->lock);
}

static VipsOpenslideConnection *
vips_openslideconnection_new(const char *filename)
{
	VipsOpenslideConnection *connection;

	connection = g_new0(VipsOpenslideConnection, 1);
	connection->filename = g_strdup(filename);

	g_assert(!g_hash_table_lookup(vips_openslideconnection_cache, filename));

	g_hash_table_insert(vips_openslideconnection_cache,
		connection->filename, connection);

	return connection;
}

static void
vips_openslideconnection_touch(VipsOpenslideConnection *connection)
{
	static int time = 0;

	g_mutex_lock(&connection->lock);

	connection->time = time++;

	g_mutex_unlock(&connection->lock);
}

openslide_t *
vips__openslideconnection_open(const char *filename)
{
	g_mutex_lock(&vips_openslideconnection_lock);

	if (!vips_openslideconnection_cache)
		vips_openslideconnection_cache =
			g_hash_table_new(g_str_hash, g_str_equal);

	VipsOpenslideConnection *connection;

	connection = g_hash_table_lookup(vips_openslideconnection_cache, filename);

	if (!connection)
		connection = vips_openslideconnection_new(filename);

	vips_openslideconnection_ref(connection);
	vips_openslideconnection_touch(connection);

	g_mutex_unlock(&vips_openslideconnection_lock);

	g_mutex_lock(&connection->lock);

	/* We do the open outside the main lock (just in the connection lock)
	 * since it can take many seconds for some slides.
	 */
	if (!connection->osr)
		connection->osr = openslide_open(connection->filename);

	openslide_t *osr = connection->osr;

	g_mutex_unlock(&connection->lock);

	return osr;
}

void
vips__openslideconnection_close(const char *filename)
{
	g_mutex_lock(&vips_openslideconnection_lock);

	VipsOpenslideConnection *connection;
	connection = g_hash_table_lookup(vips_openslideconnection_cache, filename);

	/* We unref in the main lock since openslide_close() is always relatively
	 * quick.
	 */
	if (connection)
		vips_openslideconnection_unref(connection);

	g_mutex_unlock(&vips_openslideconnection_lock);
}

#endif /*HAVE_OPENSLIDE*/
