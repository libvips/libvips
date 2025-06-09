/* load a RAW with libraw
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
#define VERBOSE
#define VIPS_DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#ifdef HAVE_LIBRAW

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vips/vips.h>
#include <vips/buf.h>
#include <vips/internal.h>
#include <vips/debug.h>

#include <libraw/libraw.h>

#define VIPS_TYPE_FOREIGN_LOAD_DCRAW (vips_foreign_load_dcraw_get_type())
#define VIPS_FOREIGN_LOAD_DCRAW(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST((obj), \
		VIPS_TYPE_FOREIGN_LOAD_DCRAW, VipsForeignLoadDcRaw))

static const char *vips_foreign_dcraw_suffs[] = {
	".arw", ".cr2", ".cr3", ".crw", ".dng", ".nef", ".nrw",
	".orf", ".pef", ".raf", ".raw", ".rw2", ".srw", ".x3f",
	".erf", ".kdc", ".mdc", ".mos", ".pxn", ".srf",
	NULL
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

typedef struct _VipsForeignLoadDcRawFile {
	VipsForeignLoadDcRaw parent_object;

	/* Filename for load.
	 */
	char *filename;

} VipsForeignLoadDcRawFile;

typedef VipsForeignLoadDcRawClass VipsForeignLoadDcRawFileClass;

G_DEFINE_TYPE(VipsForeignLoadDcRawFile, vips_foreign_load_dcraw_file,
	vips_foreign_load_dcraw_get_type());

static void
vips_foreign_load_dcraw_dispose(GObject *gobject)
{
	VipsForeignLoadDcRaw *raw = (VipsForeignLoadDcRaw *) gobject;

	if (raw->processed) {
		libraw_dcraw_clear_mem(raw->processed);
		raw->processed = NULL;
	}

	if (raw->raw_processor) {
		libraw_close(raw->raw_processor);
		raw->raw_processor = NULL;
	}

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

	if (VIPS_OBJECT_CLASS(vips_foreign_load_dcraw_parent_class)->build(object))
		return -1;

	return 0;
}

static VipsForeignFlags
vips_foreign_load_dcraw_get_flags_filename(const char *filename)
{
	return 0;
}

static VipsForeignFlags
vips_foreign_load_dcraw_get_flags(VipsForeignLoad *load)
{
	return 0;
}

static int
vips_foreign_load_dcraw_load(VipsForeignLoad *load)
{
	VipsForeignLoadDcRaw *raw = (VipsForeignLoadDcRaw *) load;
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS(raw);
	int result;

	const void *data;
	size_t length;

	g_assert(raw->source);

	/* Use the source object as a buffer for libraw.
	 */

	data = vips_source_map(raw->source, &length);
	if (!data)
		return -1;

	raw->raw_processor->params.output_bps = 16;
	raw->raw_processor->params.use_auto_wb = 1;

	result = libraw_open_buffer(raw->raw_processor, data, length);

	if (result != LIBRAW_SUCCESS) {
		vips_error(class->nickname, "%s : %s",
			_("unable to read the source"),
			libraw_strerror(result));
		return -1;
	}

	result = libraw_unpack(raw->raw_processor);
	if (result != LIBRAW_SUCCESS) {
		vips_error(class->nickname, "%s : %s",
			_("unable to unpack the source"),
			libraw_strerror(result));
		return -1;
	}

	/* Process the image (demosaicing, white balance, etc.)
	 */
	result = libraw_dcraw_process(raw->raw_processor);

	if (result != LIBRAW_SUCCESS) {
		vips_error(class->nickname,
			"Error processing RAW data: %s\n", libraw_strerror(result));
		return -1;
	}

	raw->processed = libraw_dcraw_make_mem_image(raw->raw_processor, &result);
	if (!raw->processed) {
		vips_error(class->nickname,
			"Error creating processed image: %s\n", libraw_strerror(result));
		return -1;
	}

	int bands = raw->processed->colors;
	VipsBandFormat format = raw->processed->bits == 16 ? VIPS_FORMAT_USHORT : VIPS_FORMAT_UCHAR;

	vips_image_init_fields(load->out,
		raw->processed->width, raw->processed->height, bands,
		format, VIPS_CODING_NONE,
		bands == 3 ? VIPS_INTERPRETATION_sRGB : VIPS_INTERPRETATION_B_W,
		1.0, 1.0);

	/* Set custom metadata.
	 */
	vips_image_set_string(load->out, "raw-make",
		raw->raw_processor->idata.make);
	vips_image_set_string(load->out, "raw-model",
		raw->raw_processor->idata.model);
	vips_image_set_int(load->out, "raw-iso",
		raw->raw_processor->other.iso_speed);
	vips_image_set_double(load->out, "raw-shutter",
		raw->raw_processor->other.shutter);
	vips_image_set_double(load->out, "raw-aperture",
		raw->raw_processor->other.aperture);
	vips_image_set_double(load->out, "raw-focal-length",
		raw->raw_processor->other.focal_len);

	if (raw->raw_processor->other.timestamp)
		vips_image_set_int(load->out, "raw-timestamp",
			raw->raw_processor->other.timestamp);

	VipsImage *im = vips_image_new_from_memory(
		raw->processed->data,
		raw->processed->data_size,
		raw->processed->width,
		raw->processed->height,
		bands,
		/* raw->processed->colors, */
		/* raw->processed->bits == 16 ? VIPS_FORMAT_USHORT : VIPS_FORMAT_UCHAR */
		format);

	if (!im) {
		vips_error(class->nickname, "image from memory");

		return -1;
	}

	if (vips_image_write(im, load->real)) {
		vips_error(class->nickname, "writing image failed");
		g_object_unref(im);
		return -1;
	}
	g_object_unref(im);

	return 0;
}

static void
vips_foreign_load_dcraw_class_init(VipsForeignLoadDcRawClass *class)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS(class);
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->dispose = vips_foreign_load_dcraw_dispose;

	object_class->nickname = "dcrawload_base";
	object_class->description = _("load raw camera files");
	object_class->build = vips_foreign_load_dcraw_build;

	load_class->get_flags = vips_foreign_load_dcraw_get_flags;
	load_class->load = vips_foreign_load_dcraw_load;
}

static void
vips_foreign_load_dcraw_init(VipsForeignLoadDcRaw *raw)
{
}

static int
vips_foreign_load_dcraw_file_build(VipsObject *object)
{
	VipsForeignLoadDcRaw *raw = VIPS_FOREIGN_LOAD_DCRAW(object);
	VipsForeignLoadDcRawFile *file = (VipsForeignLoadDcRawFile *) object;
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS(raw);

	if (file->filename)
		if (!(raw->source = vips_source_new_from_file(file->filename))) {
			vips_error(class->nickname, _("Can not read the input file into a source"));
			return -1;
		}

	if (VIPS_OBJECT_CLASS(vips_foreign_load_dcraw_file_parent_class)->build(object))
		return -1;

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

	load_class->get_flags_filename = vips_foreign_load_dcraw_get_flags_filename;

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
 * @...: %NULL-terminated list of optional named arguments
 *
 *
 * Read a RAW camera file using libraw.
 *
 * This loader supports most RAW formats including:
 * ARW, CR2, CR3, CRW, DNG, NEF, NRW, ORF, PEF, RAF, RAW, RW2, SRW, X3F,...
 *
 * The loader applies demosaicing and basic processing to produce an RGB or
 * grayscale image suitable for further processing.
 *
 *
 * Example:
 * |[
 * VipsImage *image;
 * if (vips_rawload("photo.cr2", &image, NULL))
 *     error_handling();
 * ]|
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_dcrawload(const char *filename, VipsImage **out, ...)
{
	va_list ap;
	int result;

	va_start(ap, out);
	result = vips_call_split("dcrawload", ap, filename, out, NULL);
	va_end(ap);

	return result;
}
