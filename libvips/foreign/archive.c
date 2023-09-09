/* wrapper around libarchive
 *
 * 8/9/23
 *	- extracted from dzsave
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
#define DEBUG_VERBOSE
#define VIPS_DEBUG
#define DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <glib/gi18n-lib.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <vips/vips.h>
#include <vips/internal.h>

#include "pforeign.h"

#ifdef HAVE_LIBARCHIVE
#include <archive.h>
#include <archive_entry.h>

static GMutex *vips_libarchive_mutex = NULL;

struct _VipsArchive {
	// set for filesystem output
	char *dirname;

	// write a zip to a target
	struct archive *archive;
	VipsTarget *target;
};

static int
vips__archive_mkdir_zip(VipsArchive *archive, const char *dirname)
{
	struct archive_entry *entry;

	vips__worker_lock(vips_libarchive_mutex);

	if (!(entry = archive_entry_new())) {
		g_mutex_unlock(vips_libarchive_mutex);
		return -1;
	}

	archive_entry_set_pathname(entry, dirname);
	archive_entry_set_mode(entry, S_IFDIR | 0755);

	if (archive_write_header(archive->archive, entry) != ARCHIVE_OK) {
		char *utf8name = g_filename_display_name(dirname);
		vips_error("dzsave", _("unable to add directory \"%s\", %s"),
			utf8name, archive_error_string(archive->archive));
		g_free(utf8name);
		archive_entry_free(entry);
		g_mutex_unlock(vips_libarchive_mutex);
		return -1;
	}

	archive_entry_free(entry);
	g_mutex_unlock(vips_libarchive_mutex);

	return 0;
}

static int
vips__archive_mkdir_file(VipsArchive *archive, const char *dirname)
{
	if (g_mkdir_with_parents(dirname, 0777) &&
		errno != EEXIST) {
		int save_errno = errno;
		char *utf8name = g_filename_display_name(dirname);
		vips_error("dzsave", _("unable to create directory \"%s\", %s"),
			utf8name, g_strerror(save_errno));
		g_free(utf8name);
		return -1;
	}

	return 0;
}

int
vips__archive_mkdir(VipsArchive *archive, const char *dirname)
{
	return ((archive->archive) ?
			vips__archive_mkdir_zip :
			vips__archive_mkdir_file)
		(archive, dirname);
}

static int
vips__archive_mkfile_zip(VipsArchive *archive,
	const char *filename, void *buf, size_t len)
{
	struct archive_entry *entry;

	vips__worker_lock(vips_libarchive_mutex);

	if (!(entry = archive_entry_new())) {
		g_mutex_unlock(vips_libarchive_mutex);
		return -1;
	}

	archive_entry_set_pathname(entry, filename);
	archive_entry_set_mode(entry, S_IFREG | 0664);
	archive_entry_set_size(entry, len);

	if (archive_write_header(archive->archive, entry) != ARCHIVE_OK) {
		archive_entry_free(entry);
		g_mutex_unlock(vips_libarchive_mutex);
		return -1;
	}

	archive_entry_free(entry);

	if (archive_write_data(archive->archive, buf, len) != len) {
		g_mutex_unlock(vips_libarchive_mutex);
		return -1;
	}

	g_mutex_unlock(vips_libarchive_mutex);

	return 0;
}

static int
vips__archive_mkfile_file(VipsArchive *archive,
	const char *filename, void *buf, size_t len)
{
	FILE *f;

	if (!(f = vips__file_open_write(filename, TRUE))) {
		return -1;
	}

	if (fwrite(buf, sizeof(char), len, f) != len) {
		fclose(f);
		return -1;
	}

	fclose(f);

	return 0;
}

int
vips__archive_mkfile(VipsArchive *archive,
	const char *filename, void *buf, size_t len)
{
	return ((archive->archive) ?
			vips__archive_mkfile_zip :
			vips__archive_mkfile_file)
		(archive, filename, buf, len);
}

void
vips__archive_free(VipsArchive *archive)
{
	// flush any pending writes to zip output
	if (archive->archive)
		archive_write_close(archive->archive);

	VIPS_FREE(archive->dirname);
	VIPS_FREEF(archive_write_free, archive->archive);
	VIPS_FREE(archive);
}

static ssize_t
zip_write_target_cb(struct archive *a, void *client_data,
	const void *data, size_t length)
{
	VipsArchive *archive = (VipsArchive *) client_data;

	if (vips_target_write(archive->target, data, length))
		return -1;

	return length;
}

static int
zip_close_target_cb(struct archive *a, void *client_data)
{
	VipsArchive *archive = (VipsArchive *) client_data;

	if (vips_target_end(archive->target))
		return ARCHIVE_FATAL;

	return ARCHIVE_OK;
}

static void *
vips__archive_once_init(void *client)
{
	vips_libarchive_mutex = vips_g_mutex_new();

	return NULL;
}

static void
vips__archive_init(void)
{
	static GOnce once = G_ONCE_INIT;

	VIPS_ONCE(&once, vips__archive_once_init, NULL);
}

// write to a filesystem directory
VipsArchive *
vips__archive_new_to_dir(const char *dirname)
{
	VipsArchive *archive;

	vips__archive_init();

	archive = VIPS_NEW(NULL, VipsArchive);

	archive->dirname = g_strdup(dirname);

	return archive;
}

// write a zip to a target
VipsArchive *
vips__archive_new_to_target(VipsTarget *target, int compression)
{
	VipsArchive *archive;

	vips__archive_init();

	archive = VIPS_NEW(NULL, VipsArchive);

	archive->target = target;

	if (!(archive->archive = archive_write_new())) {
		vips__archive_free(archive);
		return NULL;
	}

	/* Set format to zip.
	 */
	if (archive_write_set_format(archive->archive, ARCHIVE_FORMAT_ZIP) !=
		ARCHIVE_OK) {
		vips__archive_free(archive);
		return NULL;
	}

	/* Remap compression=-1 to compression=6.
	 */
	if (compression == -1)
		compression = 6; /* Z_DEFAULT_COMPRESSION */

	/* Deflate compression requires libarchive >= v3.2.0.
	 * https://github.com/libarchive/libarchive/pull/84
	 */
#if ARCHIVE_VERSION_NUMBER >= 3002000
	char compression_string[2] = { '0' + compression, 0 };
	if (archive_write_set_format_option(archive->archive, "zip",
			"compression-level", compression_string) != ARCHIVE_OK) {
		vips__archive_free(archive);
		return NULL;
	}
#else
	if (compression > 0)
		g_warning("libarchive >= v3.2.0 required for Deflate compression");
#endif

	/* Do not pad last block.
	 */
	if (archive_write_set_bytes_in_last_block(archive->archive, 1)) {
		vips__archive_free(archive);
		return NULL;
	}

	/* Register target callback functions.
	 */
	if (archive_write_open(archive->archive, archive, NULL,
			zip_write_target_cb, zip_close_target_cb) != ARCHIVE_OK) {
		vips__archive_free(archive);
		return NULL;
	}

	return archive;
}

#endif /*HAVE_LIBARCHIVE*/
