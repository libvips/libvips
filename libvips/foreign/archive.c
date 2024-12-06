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

static GMutex vips_libarchive_mutex;

struct _VipsArchive {
	// prepend filenames with this for filesystem output
	char *base_dirname;

	// write a zip to a target
	struct archive *archive;
	VipsTarget *target;
};

void
vips__archive_free(VipsArchive *archive)
{
	// flush any pending writes to zip output
	if (archive->archive)
		archive_write_close(archive->archive);

	VIPS_FREE(archive->base_dirname);
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

// write to a filesystem directory
VipsArchive *
vips__archive_new_to_dir(const char *base_dirname)
{
	VipsArchive *archive;

	if (!(archive = VIPS_NEW(NULL, VipsArchive)))
		return NULL;

	archive->base_dirname = g_strdup(base_dirname);

	return archive;
}

// write a zip to a target
VipsArchive *
vips__archive_new_to_target(VipsTarget *target,
	const char *base_dirname, int compression)
{
	VipsArchive *archive;

#ifdef DEBUG
	printf("vips__archive_new_to_target: base_dirname = %s, compression = %d\n",
		base_dirname, compression);
#endif /*DEBUG*/

	if (!(archive = VIPS_NEW(NULL, VipsArchive)))
		return NULL;

	archive->target = target;
	archive->base_dirname = g_strdup(base_dirname);

	if (!(archive->archive = archive_write_new())) {
		vips_error("archive", "%s", _("unable to create archive"));
		vips__archive_free(archive);
		return NULL;
	}

	/* Set format to zip.
	 */
	if (archive_write_set_format(archive->archive, ARCHIVE_FORMAT_ZIP)) {
		vips_error("archive", "%s", _("unable to set zip format"));
		vips__archive_free(archive);
		return NULL;
	}

	/* Remap compression=-1 to compression=6.
	 */
	if (compression == -1)
		compression = 6; /* Z_DEFAULT_COMPRESSION */

#if ARCHIVE_VERSION_NUMBER >= 3002000
	/* Deflate compression requires libarchive >= v3.2.0.
	 * https://github.com/libarchive/libarchive/pull/84
	 */
	char compression_string[2] = { '0' + compression, 0 };
	if (archive_write_set_format_option(archive->archive, "zip",
			"compression-level", compression_string)) {
		vips_error("archive", "%s", _("unable to set compression"));
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
		vips_error("archive", "%s", _("unable to set padding"));
		vips__archive_free(archive);
		return NULL;
	}

	/* Register target callback functions.
	 */
	if (archive_write_open(archive->archive, archive, NULL,
			zip_write_target_cb, zip_close_target_cb)) {
		vips_error("archive", "%s", _("unable to open for write"));
		vips__archive_free(archive);
		return NULL;
	}

	return archive;
}

static int
vips__archive_mkdir_file(VipsArchive *archive, const char *dirname)
{
	char *path;

	path = g_build_filename(archive->base_dirname, dirname, NULL);

	if (g_mkdir_with_parents(path, 0777) &&
		errno != EEXIST) {
		int save_errno = errno;
		char *utf8name;

		utf8name = g_filename_display_name(path);
		vips_error("archive", _("unable to create directory \"%s\", %s"),
			utf8name, g_strerror(save_errno));

		g_free(utf8name);
		g_free(path);

		return -1;
	}

	g_free(path);

	return 0;
}

int
vips__archive_mkdir(VipsArchive *archive, const char *dirname)
{
	/* The ZIP format maintains a hierarchical structure, avoiding
	 * the need to create individual entries for each (sub-)directory.
	 */
	if (archive->archive)
		return 0;

	return vips__archive_mkdir_file(archive, dirname);
}

static int
vips__archive_mkfile_zip(VipsArchive *archive,
	const char *filename, void *buf, size_t len)
{
	struct archive_entry *entry;

	vips__worker_lock(&vips_libarchive_mutex);

	if (!(entry = archive_entry_new())) {
		vips_error("archive", "%s", _("unable to create entry"));
		g_mutex_unlock(&vips_libarchive_mutex);
		return -1;
	}

	char *path;

	path = g_build_filename(archive->base_dirname, filename, NULL);

	archive_entry_set_pathname(entry, path);
	archive_entry_set_mode(entry, S_IFREG | 0664);
	archive_entry_set_size(entry, len);

	g_free(path);

	if (archive_write_header(archive->archive, entry)) {
		vips_error("archive", "%s", _("unable to write header"));
		archive_entry_free(entry);
		g_mutex_unlock(&vips_libarchive_mutex);
		return -1;
	}

	archive_entry_free(entry);

	if (archive_write_data(archive->archive, buf, len) != len) {
		vips_error("archive", "%s", _("unable to write data"));
		g_mutex_unlock(&vips_libarchive_mutex);
		return -1;
	}

	g_mutex_unlock(&vips_libarchive_mutex);

	return 0;
}

static int
vips__archive_mkfile_file(VipsArchive *archive,
	const char *filename, void *buf, size_t len)
{
	char *path;
	FILE *f;

	path = g_build_filename(archive->base_dirname, filename, NULL);

	if (!(f = vips__file_open_write(path, FALSE))) {
		g_free(path);
		return -1;
	}

	if (vips__file_write(buf, sizeof(char), len, f)) {
		g_free(path);
		fclose(f);
		return -1;
	}

	fclose(f);
	g_free(path);

	return 0;
}

int
vips__archive_mkfile(VipsArchive *archive,
	const char *filename, void *buf, size_t len)
{
	return ((archive->archive)
			? vips__archive_mkfile_zip
			: vips__archive_mkfile_file)(archive, filename, buf, len);
}

#endif /*HAVE_LIBARCHIVE*/
