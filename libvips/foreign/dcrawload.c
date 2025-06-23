/* load RAW camera files with libraw
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
#define DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <glib/gi18n-lib.h>

#include <stdio.h>
#include <stdlib.h>

#include <vips/vips.h>

#ifdef HAVE_LIBRAW

#include <libraw/libraw.h>

#define VIPS_TYPE_FOREIGN_LOAD_DCRAW (vips_foreign_load_dcraw_get_type())
#define VIPS_FOREIGN_LOAD_DCRAW(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST((obj), \
		VIPS_TYPE_FOREIGN_LOAD_DCRAW, VipsForeignLoadDcRaw))

static const char *vips_foreign_dcraw_suffs[] = {
	".arw", ".cr2", ".cr3", ".crw", ".dng", ".nef", ".nrw",
	".orf", ".pef", ".raf", ".raw", ".rw2", ".srw", ".x3f",
	".erf", ".kdc", ".mdc", ".mos", ".pxn", ".srf",
	".3fr", ".ari", ".cap", ".cin", ".dcr", ".fff", ".iiq", ".k25",
	".mrw", ".ori", ".rwl", ".sr2", NULL
};

typedef struct _VipsForeignLoadDcRaw {
	VipsForeignLoad parent_object;

	/* LibRaw processor.
	 */
	libraw_data_t *raw_processor;

	/* Internal Libraw processed image
	 */
	libraw_processed_image_t *processed;

	/* Load from this source (set by subclasses).
	 */
	VipsSource *source;

} VipsForeignLoadDcRaw;

typedef VipsForeignLoadClass VipsForeignLoadDcRawClass;

G_DEFINE_ABSTRACT_TYPE(VipsForeignLoadDcRaw, vips_foreign_load_dcraw,
	VIPS_TYPE_FOREIGN_LOAD);

static void
vips_foreign_load_dcraw_dispose(GObject *gobject)
{
	VipsForeignLoadDcRaw *raw = (VipsForeignLoadDcRaw *) gobject;

	VIPS_FREEF(libraw_dcraw_clear_mem, raw->processed);
	VIPS_FREEF(libraw_close, raw->raw_processor);
	VIPS_UNREF(raw->source);

	G_OBJECT_CLASS(vips_foreign_load_dcraw_parent_class)->dispose(gobject);
}

static int
vips_foreign_load_dcraw_build(VipsObject *object)
{
	VipsForeignLoadDcRaw *raw = VIPS_FOREIGN_LOAD_DCRAW(object);
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS(raw);

	raw->raw_processor = libraw_init(0);
	if (!raw->raw_processor) {
		vips_error(class->nickname, _("unable to initialize libraw"));
		return -1;
	}

	return VIPS_OBJECT_CLASS(vips_foreign_load_dcraw_parent_class)
		->build(object);
}

static VipsForeignFlags
vips_foreign_load_dcraw_get_flags(VipsForeignLoad *load)
{
	return 0;
}

static void
vips_foreign_load_dcraw_error(VipsForeignLoadDcRaw *raw,
	const char *message, int code)
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS(raw);

	vips_error(class->nickname, "%s: %s", message, libraw_strerror(code));
}

static int
vips_foreign_load_dcraw_header(VipsForeignLoad *load)
{
	VipsForeignLoadDcRaw *raw = (VipsForeignLoadDcRaw *) load;

	/* Enforce VIPS_FORMAT_USHORT output.
	 */
	raw->raw_processor->params.output_bps = 16;

	/* Apply camera white balance.
	 */
	raw->raw_processor->params.use_camera_wb = 1;

	/* We can use the libraw file interface for filename sources. This
	 * interface can often read more metadata, since it can open secondary
	 * files.
	 */
	int result;
	if (vips_source_is_file(raw->source)) {
		const char *filename =
			vips_connection_filename(VIPS_CONNECTION(raw->source));

		result = libraw_open_file(raw->raw_processor, filename);
	}
	else {
		size_t length;
		const void *data;

		if (!(data = vips_source_map(raw->source, &length)))
			return -1;
		result = libraw_open_buffer(raw->raw_processor, data, length);
	}
	if (result != LIBRAW_SUCCESS) {
		vips_foreign_load_dcraw_error(raw, _("unable to read"), result);
		return -1;
	}

	result = libraw_unpack(raw->raw_processor);
	if (result != LIBRAW_SUCCESS) {
		vips_foreign_load_dcraw_error(raw, _("unable to unpack"), result);
		return -1;
	}

	/* Process the image (demosaicing, white balance, etc.).
	 */
	result = libraw_dcraw_process(raw->raw_processor);
	if (result != LIBRAW_SUCCESS) {
		vips_foreign_load_dcraw_error(raw, _("unable to process"), result);
		return -1;
	}

	if (!(raw->processed =
			libraw_dcraw_make_mem_image(raw->raw_processor, &result))) {
		vips_foreign_load_dcraw_error(raw, _("unable to build image"), result);
		return -1;
	}

	VipsImage *image;
	if (!(image = vips_image_new_from_memory(
			  raw->processed->data, raw->processed->data_size,
			  raw->processed->width, raw->processed->height,
			  raw->processed->colors, VIPS_FORMAT_USHORT)))
		return -1;

	VIPS_SETSTR(image->filename,
		vips_connection_filename(VIPS_CONNECTION(raw->source)));

	/* Set custom metadata.
	 */
	vips_image_set_string(image, "raw-make",
		raw->raw_processor->idata.make);
	vips_image_set_string(image, "raw-model",
		raw->raw_processor->idata.model);
	vips_image_set_double(image, "raw-iso",
		raw->raw_processor->other.iso_speed);
	vips_image_set_double(image, "raw-shutter",
		raw->raw_processor->other.shutter);
	vips_image_set_double(image, "raw-aperture",
		raw->raw_processor->other.aperture);
	vips_image_set_double(image, "raw-focal-length",
		raw->raw_processor->other.focal_len);

	GDateTime *dt;
	if (raw->raw_processor->other.timestamp &&
		(dt = g_date_time_new_from_unix_utc(
			 raw->raw_processor->other.timestamp))) {
		vips_image_set_string(image, "raw-timestamp",
			g_date_time_format_iso8601(dt));
		g_date_time_unref(dt);
	}

	/* What a hack. Remove the @out that's there now and replace it with
	 * our image.
	 */
	VipsImage *x;
	g_object_get(load, "out", &x, NULL);
	g_object_unref(x);
	g_object_unref(x);

	g_object_set(load, "out", image, NULL);

	return 0;
}

static void
vips_foreign_load_dcraw_class_init(VipsForeignLoadDcRawClass *class)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS(class);
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsOperationClass *operation_class = VIPS_OPERATION_CLASS(class);
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->dispose = vips_foreign_load_dcraw_dispose;

	object_class->nickname = "dcrawload_base";
	object_class->description = _("load RAW camera files");
	object_class->build = vips_foreign_load_dcraw_build;

	operation_class->flags |= VIPS_OPERATION_UNTRUSTED;

	load_class->get_flags = vips_foreign_load_dcraw_get_flags;
	load_class->header = vips_foreign_load_dcraw_header;
	load_class->load = NULL;
}

static void
vips_foreign_load_dcraw_init(VipsForeignLoadDcRaw *raw)
{
}

typedef struct _VipsForeignLoadDcRawFile {
	VipsForeignLoadDcRaw parent_object;

	/* Filename for load.
	 */
	char *filename;

} VipsForeignLoadDcRawFile;

typedef VipsForeignLoadDcRawClass VipsForeignLoadDcRawFileClass;

G_DEFINE_TYPE(VipsForeignLoadDcRawFile, vips_foreign_load_dcraw_file,
	vips_foreign_load_dcraw_get_type());

static int
vips_foreign_load_dcraw_file_build(VipsObject *object)
{
	VipsForeignLoadDcRaw *raw = VIPS_FOREIGN_LOAD_DCRAW(object);
	VipsForeignLoadDcRawFile *file = (VipsForeignLoadDcRawFile *) object;

	if (file->filename &&
		!(raw->source = vips_source_new_from_file(file->filename)))
		return -1;

	return VIPS_OBJECT_CLASS(vips_foreign_load_dcraw_file_parent_class)
		->build(object);
}

static VipsForeignFlags
vips_foreign_load_dcraw_file_get_flags_filename(const char *filename)
{
	return 0;
}

static void
vips_foreign_load_dcraw_file_class_init(VipsForeignLoadDcRawFileClass *class)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS(class);
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "dcrawload";
	object_class->description = _("load RAW with libraw");
	object_class->build = vips_foreign_load_dcraw_file_build;

	foreign_class->suffs = vips_foreign_dcraw_suffs;

	load_class->get_flags_filename =
		vips_foreign_load_dcraw_file_get_flags_filename;

	VIPS_ARG_STRING(class, "filename", 1,
		_("Filename"),
		_("Filename to load from"),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET(VipsForeignLoadDcRawFile, filename),
		NULL);
}

static void
vips_foreign_load_dcraw_file_init(VipsForeignLoadDcRawFile *file)
{
}

#endif /*HAVE_LIBRAW*/

/**
 * vips_dcrawload:
 * @filename: file to load
 * @out: (out): output image
 * @...: `NULL`-terminated list of optional named arguments
 *
 * Read a RAW camera file using LibRaw.
 *
 * This loader supports the most RAW formats including:
 * ARW, CR2, CR3, CRW, DNG, NEF, NRW, ORF, PEF, RAF, RAW, RW2, SRW, X3F, ...
 *
 * The loader applies demosaicing and basic processing to produce an RGB or
 * grayscale image suitable for further processing.
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_dcrawload(const char *filename, VipsImage **out, ...)
{
	va_list ap;
	int result;

	va_start(ap, out);
	result = vips_call_split("dcrawload", ap, filename, out);
	va_end(ap);

	return result;
}
