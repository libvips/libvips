/* save to raw
 *
 * Write raw image data to file. Useful when defining new formats...
 *
 * Jesper Friis
 *
 * 10/06/08 JF
 * 	- initial code based on im_vips2ppm()
 * 04/07/08 JF
 * 	- replaced FILE with plain file handlers for reducing
 * 	  confusion about binary vs. non-binary file modes.
 * 4/2/10
 * 	- gtkdoc
 * 15/12/11
 * 	- rework as a class
 * 	- added save raw to filename
 * 21/04/24 akash-akya
 * 	- reworked based on ppmsave.c
 * 	- added save to target
 * 	- added save to buffer
 * 	- deprecate vips_rawsave_fd()
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
#define VIPS_DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <glib/gi18n-lib.h>

#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <string.h>

#include <vips/vips.h>
#include <vips/internal.h>

typedef struct _VipsForeignSaveRaw {
	VipsForeignSave parent_object;

	VipsTarget *target;
} VipsForeignSaveRaw;

typedef VipsForeignSaveClass VipsForeignSaveRawClass;

G_DEFINE_ABSTRACT_TYPE(VipsForeignSaveRaw, vips_foreign_save_raw,
	VIPS_TYPE_FOREIGN_SAVE);

static void
vips_foreign_save_raw_dispose(GObject *gobject)
{
	VipsForeignSaveRaw *raw = (VipsForeignSaveRaw *) gobject;

	VIPS_UNREF(raw->target);

	G_OBJECT_CLASS(vips_foreign_save_raw_parent_class)->dispose(gobject);
}

static int
vips_foreign_save_raw_block(VipsRegion *region, VipsRect *area, void *a)
{
	VipsForeignSaveRaw *raw = (VipsForeignSaveRaw *) a;

	for (int y = 0; y < area->height; y++)
		if (vips_target_write(raw->target,
			VIPS_REGION_ADDR(region, area->left, area->top + y),
			VIPS_IMAGE_SIZEOF_PEL(region->im) * area->width))
			return -1;

	return 0;
}

static int
vips_foreign_save_raw_build(VipsObject *object)
{
	VipsForeignSave *save = (VipsForeignSave *) object;
	VipsForeignSaveRaw *raw = (VipsForeignSaveRaw *) object;

	if (VIPS_OBJECT_CLASS(vips_foreign_save_raw_parent_class)->build(object))
		return -1;

	if (vips_image_pio_input(save->in) ||
		vips_sink_disc(save->in, vips_foreign_save_raw_block, raw))
		return -1;

	if (vips_target_end(raw->target))
		return -1;

	return 0;
}

static void
vips_foreign_save_raw_class_init(VipsForeignSaveRawClass *class)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS(class);
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignSaveClass *save_class = (VipsForeignSaveClass *) class;

	gobject_class->dispose = vips_foreign_save_raw_dispose;
	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "rawsave_base";
	object_class->description = _("save image to raw");
	object_class->build = vips_foreign_save_raw_build;

	save_class->saveable = VIPS_FOREIGN_SAVEABLE_ANY;
}

static void
vips_foreign_save_raw_init(VipsForeignSaveRaw *raw)
{
}

typedef struct _VipsForeignSaveRawFile {
	VipsForeignSaveRaw parent_object;

	char *filename;
} VipsForeignSaveRawFile;

typedef VipsForeignSaveRawClass VipsForeignSaveRawFileClass;

G_DEFINE_TYPE(VipsForeignSaveRawFile, vips_foreign_save_raw_file,
	vips_foreign_save_raw_get_type());

static int
vips_foreign_save_raw_file_build(VipsObject *object)
{
	VipsForeignSaveRaw *raw = (VipsForeignSaveRaw *) object;
	VipsForeignSaveRawFile *file = (VipsForeignSaveRawFile *) object;

	if (file->filename &&
		!(raw->target = vips_target_new_to_file(file->filename)))
		return -1;

	return VIPS_OBJECT_CLASS(vips_foreign_save_raw_file_parent_class)
		->build(object);
}

static const char *vips_foreign_save_raw_suffs[] = {
	".raw",
	NULL
};

static void
vips_foreign_save_raw_file_class_init(VipsForeignSaveRawFileClass *class)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS(class);
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "rawsave";
	object_class->description = _("save image to raw file");
	object_class->build = vips_foreign_save_raw_file_build;

	foreign_class->suffs = vips_foreign_save_raw_suffs;

	VIPS_ARG_STRING(class, "filename", 1,
		_("Filename"),
		_("Filename to save to"),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET(VipsForeignSaveRawFile, filename),
		NULL);
}

static void
vips_foreign_save_raw_file_init(VipsForeignSaveRawFile *raw)
{
}

typedef struct _VipsForeignSaveRawTarget {
	VipsForeignSaveRaw parent_object;

	VipsTarget *target;
} VipsForeignSaveRawTarget;

typedef VipsForeignSaveRawClass VipsForeignSaveRawTargetClass;

G_DEFINE_TYPE(VipsForeignSaveRawTarget, vips_foreign_save_raw_target,
	vips_foreign_save_raw_get_type());

static int
vips_foreign_save_raw_target_build(VipsObject *object)
{
	VipsForeignSaveRaw *raw = (VipsForeignSaveRaw *) object;
	VipsForeignSaveRawTarget *target = (VipsForeignSaveRawTarget *) object;

	if (target->target) {
		raw->target = target->target;
		g_object_ref(raw->target);
	}

	return VIPS_OBJECT_CLASS(vips_foreign_save_raw_target_parent_class)
		->build(object);
}

static void
vips_foreign_save_raw_target_class_init(
	VipsForeignSaveRawTargetClass *class)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS(class);
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "rawsave_target";
	object_class->description = _("write raw image to target");
	object_class->build = vips_foreign_save_raw_target_build;

	foreign_class->suffs = vips_foreign_save_raw_suffs;

	VIPS_ARG_OBJECT(class, "target", 1,
		_("Target"),
		_("Target to save to"),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET(VipsForeignSaveRawTarget, target),
		VIPS_TYPE_TARGET);
}

static void
vips_foreign_save_raw_target_init(VipsForeignSaveRawTarget *target)
{
}

typedef struct _VipsForeignSaveRawBuffer {
	VipsForeignSaveRaw parent_object;

	VipsArea *buf;
} VipsForeignSaveRawBuffer;

typedef VipsForeignSaveRawClass VipsForeignSaveRawBufferClass;

G_DEFINE_TYPE(VipsForeignSaveRawBuffer, vips_foreign_save_raw_buffer,
	vips_foreign_save_raw_get_type());

static int
vips_foreign_save_raw_buffer_build(VipsObject *object)
{
	VipsForeignSaveRaw *raw = (VipsForeignSaveRaw *) object;
	VipsForeignSaveRawBuffer *buffer = (VipsForeignSaveRawBuffer *) object;

	VipsBlob *blob;

	if (!(raw->target = vips_target_new_to_memory()))
		return -1;

	if (VIPS_OBJECT_CLASS(vips_foreign_save_raw_buffer_parent_class)
			->build(object))
		return -1;

	g_object_get(raw->target, "blob", &blob, NULL);
	g_object_set(buffer, "buffer", blob, NULL);
	vips_area_unref(VIPS_AREA(blob));

	return 0;
}

static void
vips_foreign_save_raw_buffer_class_init(VipsForeignSaveRawBufferClass *class)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS(class);
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "rawsave_buffer";
	object_class->description = _("write raw image to buffer");
	object_class->build = vips_foreign_save_raw_buffer_build;

	foreign_class->suffs = vips_foreign_save_raw_suffs;

	VIPS_ARG_BOXED(class, "buffer", 1,
		_("Buffer"),
		_("Buffer to save to"),
		VIPS_ARGUMENT_REQUIRED_OUTPUT,
		G_STRUCT_OFFSET(VipsForeignSaveRawBuffer, buf),
		VIPS_TYPE_BLOB);
}

static void
vips_foreign_save_raw_buffer_init(VipsForeignSaveRawBuffer *buffer)
{
}

/**
 * vips_rawsave: (method)
 * @in: image to save
 * @filename: file to write to
 * @...: `NULL`-terminated list of optional named arguments
 *
 * Writes the pixels in @in to the file @filename with no header or other
 * metadata.
 *
 * ::: seealso
 *     [method@Image.write_to_file].
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_rawsave(VipsImage *in, const char *filename, ...)
{
	va_list ap;
	int result;

	va_start(ap, filename);
	result = vips_call_split("rawsave", ap, in, filename);
	va_end(ap);

	return result;
}

/**
 * vips_rawsave_buffer: (method)
 * @in: image to save
 * @buf: (array length=len) (element-type guint8): return output buffer here
 * @len: (type gsize): return output length here
 * @...: `NULL`-terminated list of optional named arguments
 *
 * As [method@Image.rawsave], but save to a memory buffer.
 *
 * The address of the buffer is returned in @buf, the length of the buffer in
 * @len. You are responsible for freeing the buffer with [func@GLib.free] when you
 * are done with it.
 *
 * ::: seealso
 *     [method@Image.rawsave], [method@Image.write_to_memory], [method@Image.write_to_file].
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_rawsave_buffer(VipsImage *in, void **buf, size_t *len, ...)
{
	va_list ap;
	VipsArea *area;
	int result;

	area = NULL;

	va_start(ap, len);
	result = vips_call_split("rawsave_buffer", ap, in, &area);
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
 * vips_rawsave_target: (method)
 * @in: image to save
 * @target: save image to this target
 * @...: `NULL`-terminated list of optional named arguments
 *
 * As [method@Image.rawsave], but save to a target.
 *
 * ::: seealso
 *     [method@Image.rawsave].
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_rawsave_target(VipsImage *in, VipsTarget *target, ...)
{
	va_list ap;
	int result;

	va_start(ap, target);
	result = vips_call_split("rawsave_target", ap, in, target);
	va_end(ap);

	return result;
}
