/* save with libuhdr
 *
 * 25/8/25
 * 	- from heifsave.c
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
#define DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <glib/gi18n-lib.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vips/vips.h>
#include <vips/internal.h>

#include "pforeign.h"

#ifdef HAVE_UHDR

#include <ultrahdr_api.h>

const char *vips__uhdr_error_str(uhdr_codec_err_t err);
void vips__uhdr_error(uhdr_error_info_t *error);

#ifdef DEBUG
const char *vips__img_fmt_str(uhdr_img_fmt_t fmt);
const char *vips__color_gamut_str(uhdr_color_gamut_t cg);
const char *vips__color_transfer_str(uhdr_color_transfer_t ct);
const char *vips__color_range_str(uhdr_color_range_t range);
void vips__print_raw(uhdr_raw_image_t *raw);
#endif /*DEBUG*/

typedef struct _VipsForeignSaveUhdr {
	VipsForeignSave parent_object;

	/* Where to write (set by subclasses).
	 */
	VipsTarget *target;

	uhdr_codec_private_t *enc;
	uhdr_raw_image_t *raw_image;
	uhdr_raw_image_t *gainmap_image;

} VipsForeignSaveUhdr;

typedef VipsForeignSaveClass VipsForeignSaveUhdrClass;

G_DEFINE_ABSTRACT_TYPE(VipsForeignSaveUhdr, vips_foreign_save_uhdr,
	VIPS_TYPE_FOREIGN_SAVE);

static void
vips_foreign_save_uhdr_dispose(GObject *gobject)
{
	VipsForeignSaveUhdr *uhdr = (VipsForeignSaveUhdr *) gobject;

	VIPS_UNREF(uhdr->target);
	VIPS_FREEF(uhdr_release_encoder, uhdr->enc);

	G_OBJECT_CLASS(vips_foreign_save_uhdr_parent_class)->dispose(gobject);
}

static int
image_get_float(VipsImage *image, const char *name, float *f)
{
	double d;
	if (vips_image_get_double(image, name, &d))
		return -1;
	*f = d;

	return 0;
}

// pass in the array to fill, size must match
static int
image_get_array_float(VipsImage *image, const char *name,
	float *out, int n_out)
{
	double *d;
	int n;
	if (vips_image_get_array_double(image, name, &d, &n))
		return -1;
	if (n != n_out) {
		vips_error("image_get_array_float", _("bad size"));
		return -1;
	}

	for (int i = 0; i < n; i++)
		out[i] = d[i];

	return 0;
}

// save hdr, no gain map
static int
vips_foreign_save_uhdr_hdr(VipsForeignSaveUhdr *uhdr, VipsImage *image)
{
	return 0;
}

// save sdr + gainmap
static int
vips_foreign_save_uhdr_sdr(VipsForeignSaveUhdr *uhdr, VipsImage *image)
{
	uhdr_error_info_t error_info;
	const void *data;
	size_t length;

	if (vips_image_get_blob(image, "gainmap", &data, &length))
		return -1;
	uhdr_compressed_image_t gainmap_image = {
		.data = (void *) data,
		.data_sz = length,
		.capacity = length,
	};

	uhdr_gainmap_metadata_t metadata;
	if (image_get_array_float(image,
			"gainmap-max-content-boost", &metadata.max_content_boost[0], 3) ||
	    image_get_array_float(image,
			"gainmap-min-content-boost", &metadata.min_content_boost[0], 3) ||
	    image_get_array_float(image,
			"gainmap-gamma", &metadata.gamma[0], 3) ||
	    image_get_array_float(image,
			"gainmap-offset-sdr", &metadata.offset_sdr[0], 3) ||
	    image_get_array_float(image,
			"gainmap-offset-hdr", &metadata.offset_hdr[0], 3) ||
	    image_get_float(image,
			"gainmap-hdr-capacity-min", &metadata.hdr_capacity_min) ||
	    image_get_float(image,
			"gainmap-hdr-capacity-max", &metadata.hdr_capacity_max) ||
	    vips_image_get_int(image,
			"gainmap-use-base-cg", &metadata.use_base_cg))
		return -1;

	error_info =
		uhdr_enc_set_gainmap_image(uhdr->enc, &gainmap_image, &metadata);
	if (error_info.error_code) {
		vips__uhdr_error(&error_info);
		return -1;
	}

	VipsTarget *temp;
	VipsSource *sdr;

	if (!(temp = vips_target_new_temp(uhdr->target)))
		return -1;

	if (vips_jpegsave_target(image, temp, NULL)) {
		VIPS_UNREF(temp);
		return -1;
	}

	if (!(sdr = vips_source_new_from_target(temp))) {
		VIPS_UNREF(temp);
		return -1;
	}

	VIPS_UNREF(temp);

	if (!(data = vips_source_map(sdr, &length))) {
		VIPS_UNREF(sdr);
		return -1;
	}

	uhdr_compressed_image_t sdr_image = {
		.data = (void *) data,
		.data_sz = length,
		.capacity = length,
	};
	error_info =
		uhdr_enc_set_compressed_image(uhdr->enc, &sdr_image, UHDR_SDR_IMG);
	if (error_info.error_code) {
		VIPS_UNREF(sdr);
		vips__uhdr_error(&error_info);
		return -1;
	}

	error_info = uhdr_encode(uhdr->enc);
	if (error_info.error_code) {
		VIPS_UNREF(sdr);
		vips__uhdr_error(&error_info);
		return -1;
	}

	VIPS_UNREF(sdr);

	uhdr_compressed_image_t *output = uhdr_get_encoded_stream(uhdr->enc);
	if (!output) {
		vips__uhdr_error(NULL);
		return -1;
	}

	if (vips_target_write(uhdr->target, output->data, output->data_sz))
		return -1;

	return 0;
}

static int
vips_foreign_save_uhdr_build(VipsObject *object)
{
	VipsForeignSave *save = VIPS_FOREIGN_SAVE(object);
	VipsForeignSaveUhdr *uhdr = (VipsForeignSaveUhdr *) object;

	if (VIPS_OBJECT_CLASS(vips_foreign_save_uhdr_parent_class)->build(object))
		return -1;

	uhdr->enc = uhdr_create_encoder();

	if (save->ready->Type == VIPS_INTERPRETATION_scRGB &&
		save->ready->BandFmt == VIPS_FORMAT_FLOAT) {
		if (vips_foreign_save_uhdr_hdr(uhdr, save->ready))
			return -1;
	}
	else {
		if (vips_foreign_save_uhdr_sdr(uhdr, save->ready))
			return -1;
	}

	if (vips_target_end(uhdr->target))
		return -1;

	VIPS_FREEF(uhdr_release_encoder, uhdr->enc);

	return 0;
}

#define UC VIPS_FORMAT_UCHAR
#define F VIPS_FORMAT_FLOAT

static VipsBandFormat vips_uhdr_bandfmt[10] = {
	/* Band format:  UC  C   US  S   UI  I   F   X   D   DX */
	/* Promotion: */ UC, UC, UC, UC, UC, UC, F,  F,  F,  F
};

static void
vips_foreign_save_uhdr_class_init(VipsForeignSaveUhdrClass *class)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS(class);
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignSaveClass *save_class = (VipsForeignSaveClass *) class;

	gobject_class->dispose = vips_foreign_save_uhdr_dispose;
	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "uhdrsave_base";
	object_class->description = _("save image in UltraHDR format");
	object_class->build = vips_foreign_save_uhdr_build;

	save_class->saveable = VIPS_FOREIGN_SAVEABLE_RGB;
	save_class->format_table = vips_uhdr_bandfmt;

}

static void
vips_foreign_save_uhdr_init(VipsForeignSaveUhdr *uhdr)
{

}

typedef struct _VipsForeignSaveUhdrFile {
	VipsForeignSaveUhdr parent_object;

	/* Filename for save.
	 */
	char *filename;

} VipsForeignSaveUhdrFile;

typedef VipsForeignSaveUhdrClass VipsForeignSaveUhdrFileClass;

G_DEFINE_TYPE(VipsForeignSaveUhdrFile, vips_foreign_save_uhdr_file,
	vips_foreign_save_uhdr_get_type());

static int
vips_foreign_save_uhdr_file_build(VipsObject *object)
{
	VipsForeignSaveUhdr *uhdr = (VipsForeignSaveUhdr *) object;
	VipsForeignSaveUhdrFile *file = (VipsForeignSaveUhdrFile *) object;

	if (file->filename &&
		!(uhdr->target = vips_target_new_to_file(file->filename)))
		return -1;

	return VIPS_OBJECT_CLASS(vips_foreign_save_uhdr_file_parent_class)
		->build(object);
}

static void
vips_foreign_save_uhdr_file_class_init(VipsForeignSaveUhdrFileClass *class)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS(class);
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "uhdrsave";
	object_class->build = vips_foreign_save_uhdr_file_build;

	foreign_class->suffs = vips__uhdr_suffs;

	VIPS_ARG_STRING(class, "filename", 1,
		_("Filename"),
		_("Filename to save to"),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET(VipsForeignSaveUhdrFile, filename),
		NULL);
}

static void
vips_foreign_save_uhdr_file_init(VipsForeignSaveUhdrFile *file)
{
}

typedef struct _VipsForeignSaveUhdrBuffer {
	VipsForeignSaveUhdr parent_object;

	/* Save to a buffer.
	 */
	VipsArea *buf;

} VipsForeignSaveUhdrBuffer;

typedef VipsForeignSaveUhdrClass VipsForeignSaveUhdrBufferClass;

G_DEFINE_TYPE(VipsForeignSaveUhdrBuffer, vips_foreign_save_uhdr_buffer,
	vips_foreign_save_uhdr_get_type());

static int
vips_foreign_save_uhdr_buffer_build(VipsObject *object)
{
	VipsForeignSaveUhdr *uhdr = (VipsForeignSaveUhdr *) object;
	VipsForeignSaveUhdrBuffer *buffer = (VipsForeignSaveUhdrBuffer *) object;

	VipsBlob *blob;

	if (!(uhdr->target = vips_target_new_to_memory()))
		return -1;

	if (VIPS_OBJECT_CLASS(vips_foreign_save_uhdr_buffer_parent_class)
			->build(object))
		return -1;

	g_object_get(uhdr->target, "blob", &blob, NULL);
	g_object_set(buffer, "buffer", blob, NULL);
	vips_area_unref(VIPS_AREA(blob));

	return 0;
}

static void
vips_foreign_save_uhdr_buffer_class_init(
	VipsForeignSaveUhdrBufferClass *class)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS(class);
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "uhdrsave_buffer";
	object_class->build = vips_foreign_save_uhdr_buffer_build;

	foreign_class->suffs = vips__uhdr_suffs;

	VIPS_ARG_BOXED(class, "buffer", 1,
		_("Buffer"),
		_("Buffer to save to"),
		VIPS_ARGUMENT_REQUIRED_OUTPUT,
		G_STRUCT_OFFSET(VipsForeignSaveUhdrBuffer, buf),
		VIPS_TYPE_BLOB);
}

static void
vips_foreign_save_uhdr_buffer_init(VipsForeignSaveUhdrBuffer *buffer)
{
}

typedef struct _VipsForeignSaveUhdrTarget {
	VipsForeignSaveUhdr parent_object;

	VipsTarget *target;
} VipsForeignSaveUhdrTarget;

typedef VipsForeignSaveUhdrClass VipsForeignSaveUhdrTargetClass;

G_DEFINE_TYPE(VipsForeignSaveUhdrTarget, vips_foreign_save_uhdr_target,
	vips_foreign_save_uhdr_get_type());

static int
vips_foreign_save_uhdr_target_build(VipsObject *object)
{
	VipsForeignSaveUhdr *uhdr = (VipsForeignSaveUhdr *) object;
	VipsForeignSaveUhdrTarget *target = (VipsForeignSaveUhdrTarget *) object;

	if (target->target) {
		uhdr->target = target->target;
		g_object_ref(uhdr->target);
	}

	return VIPS_OBJECT_CLASS(vips_foreign_save_uhdr_target_parent_class)
		->build(object);
}

static void
vips_foreign_save_uhdr_target_class_init(
	VipsForeignSaveUhdrTargetClass *class)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS(class);
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "uhdrsave_target";
	object_class->build = vips_foreign_save_uhdr_target_build;

	foreign_class->suffs = vips__uhdr_suffs;

	VIPS_ARG_OBJECT(class, "target", 1,
		_("Target"),
		_("Target to save to"),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET(VipsForeignSaveUhdrTarget, target),
		VIPS_TYPE_TARGET);
}

static void
vips_foreign_save_uhdr_target_init(VipsForeignSaveUhdrTarget *target)
{
}

#endif /*HAVE_UHDR*/

/**
 * vips_uhdrsave: (method)
 * @in: image to save
 * @filename: file to write to
 * @...: `NULL`-terminated list of optional named arguments
 *
 * ::: seealso
 *     [method@Image.write_to_file], [ctor@Image.uhdrload].
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_uhdrsave(VipsImage *in, const char *filename, ...)
{
	va_list ap;
	int result;

	va_start(ap, filename);
	result = vips_call_split("uhdrsave", ap, in, filename);
	va_end(ap);

	return result;
}

/**
 * vips_uhdrsave_buffer: (method)
 * @in: image to save
 * @buf: (array length=len) (element-type guint8): return output buffer here
 * @len: (type gsize): return output length here
 * @...: `NULL`-terminated list of optional named arguments
 *
 * As [method@Image.uhdrsave], but save to a memory buffer.
 *
 * ::: seealso
 *     [method@Image.uhdrsave], [method@Image.write_to_file].
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_uhdrsave_buffer(VipsImage *in, void **buf, size_t *len, ...)
{
	va_list ap;
	VipsArea *area;
	int result;

	area = NULL;

	va_start(ap, len);
	result = vips_call_split("uhdrsave_buffer", ap, in, &area);
	va_end(ap);

	if (!result &&
		area) {
		if (buf) {
			*buf = area->data;
			area->free_fn = NULL;
		}
		if (len)
			*len = area->length;

		vips_area_unref(area);
	}

	return result;
}

/**
 * vips_uhdrsave_target: (method)
 * @in: image to save
 * @target: save image to this target
 * @...: `NULL`-terminated list of optional named arguments
 *
 * As [method@Image.uhdrsave], but save to a target.
 *
 * ::: seealso
 *     [method@Image.uhdrsave], [method@Image.write_to_target].
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_uhdrsave_target(VipsImage *in, VipsTarget *target, ...)
{
	va_list ap;
	int result;

	va_start(ap, target);
	result = vips_call_split("uhdrsave_target", ap, in, target);
	va_end(ap);

	return result;
}

