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

	int bitdepth;

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

static void
vips_foreign_load_dcraw_close(VipsImage *image,
	libraw_processed_image_t *processed)
{
	VIPS_FREEF(libraw_dcraw_clear_mem, processed);
}

static int
vips_foreign_load_dcraw_set_metadata(VipsForeignLoadDcRaw *raw,
	VipsImage *image)
{
	VIPS_SETSTR(image->filename,
		vips_connection_filename(VIPS_CONNECTION(raw->source)));

	/* Set custom metadata.
	 */
	vips_image_set_string(image, "raw-make",
		raw->raw_processor->idata.make);
	vips_image_set_string(image, "raw-model",
		raw->raw_processor->idata.model);
	vips_image_set_string(image, "raw-software",
		raw->raw_processor->idata.software);
	vips_image_set_double(image, "raw-iso",
		raw->raw_processor->other.iso_speed);
	vips_image_set_double(image, "raw-shutter",
		raw->raw_processor->other.shutter);
	vips_image_set_double(image, "raw-aperture",
		raw->raw_processor->other.aperture);
	vips_image_set_double(image, "raw-focal-length",
		raw->raw_processor->other.focal_len);

	GDateTime *dt =
		g_date_time_new_from_unix_utc(raw->raw_processor->other.timestamp);
	if (dt) {
		char *str = g_date_time_format_iso8601(dt);
		if (str) {
			vips_image_set_string(image, "raw-timestamp", str);

			g_free(str);
		}

		g_date_time_unref(dt);
	}

	if (raw->raw_processor->idata.xmpdata)
		vips_image_set_blob_copy(image, VIPS_META_XMP_NAME,
			raw->raw_processor->idata.xmpdata,
			raw->raw_processor->idata.xmplen);

	vips_image_set_string(image, "raw-lens",
		raw->raw_processor->lens.Lens);

	if (raw->raw_processor->color.profile)
		vips_image_set_blob_copy(image, VIPS_META_ICC_NAME,
			raw->raw_processor->color.profile,
			raw->raw_processor->color.profile_length);

	/* Search the available thumbnails for the largest that's smaller than
	 * the main image and has a known type.
	 */
	libraw_image_sizes_t *sizes = &raw->raw_processor->sizes;
	libraw_thumbnail_list_t *thumbs_list = &raw->raw_processor->thumbs_list;

	int thumb_index;

	thumb_index = -1;
	for (int i = 0; i < thumbs_list->thumbcount; i++) {
		libraw_thumbnail_item_t *best = thumb_index == -1 ?
			NULL : &thumbs_list->thumblist[thumb_index];
		libraw_thumbnail_item_t *this = &thumbs_list->thumblist[i];

		// only support JPEG thumbnails for now
		if (this->tformat != LIBRAW_INTERNAL_THUMBNAIL_JPEG)
			continue;

		// useless thumbnails the same size as the main image are very
		// common
		if (this->twidth >= sizes->iwidth &&
			this->theight >= sizes->iheight)
			continue;

		// must be 8-bit, must match the main image in bands
		int bpp = this->tmisc & ((1 << 5) - 1);
		int bands = this->tmisc >> 5;
		if (bpp != 8 ||
			bands != raw->raw_processor->idata.colors)
			continue;

		// size must be sane (under 1mb).
		if (this->tlength > 1024 * 1024)
			continue;

		if (!best ||
			this->twidth > best->twidth ||
			this->theight > best->theight)
			thumb_index = i;
	}

	if (thumb_index != -1) {
		int result;
		result = libraw_unpack_thumb_ex(raw->raw_processor, thumb_index);
		if (result != LIBRAW_SUCCESS) {
			vips_foreign_load_dcraw_error(raw,
				_("unable to unpack thumbnail"), result);
			return -1;
		}

		vips_image_set_blob_copy(image, "raw-thumbnail-data",
			raw->raw_processor->thumbnail.thumb,
			raw->raw_processor->thumbnail.tlength);
	}

	return 0;
}

static int
vips_foreign_load_dcraw_header(VipsForeignLoad *load)
{
	VipsForeignLoadDcRaw *raw = (VipsForeignLoadDcRaw *) load;
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS(raw);

	int result;

	raw->raw_processor = libraw_init(0);
	if (!raw->raw_processor) {
		vips_error(class->nickname, "%s", _("unable to initialize libraw"));
		return -1;
	}

	if (raw->bitdepth != 8 &&
		raw->bitdepth != 16) {
		vips_error(class->nickname, "%s", _("bad bitdepth"));
		return -1;
	}
	raw->raw_processor->params.output_bps = raw->bitdepth;

	/* Apply camera white balance.
	 */
	raw->raw_processor->params.use_camera_wb = 1;

	/* We can use the libraw file interface for filename sources. This
	 * interface can often read more metadata, since it can open secondary
	 * files.
	 */
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

	vips_image_init_fields(load->out,
		raw->raw_processor->sizes.iwidth,
		raw->raw_processor->sizes.iheight,
		raw->raw_processor->idata.colors,
		raw->bitdepth > 8 ?
			VIPS_FORMAT_USHORT : VIPS_FORMAT_UCHAR,
		VIPS_CODING_NONE,
		VIPS_INTERPRETATION_ERROR,
		1.0, 1.0);
	load->out->Type = vips_image_guess_interpretation(load->out);

	if (vips_foreign_load_dcraw_set_metadata(raw, load->out))
		return -1;

	return 0;
}

static int
vips_foreign_load_dcraw_load(VipsForeignLoad *load)
{
	VipsForeignLoadDcRaw *raw = (VipsForeignLoadDcRaw *) load;

	int result;

	g_assert(raw->raw_processor);

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
		raw->processed->colors,
		raw->bitdepth > 8 ?
			VIPS_FORMAT_USHORT : VIPS_FORMAT_UCHAR)))
		return -1;
	image->Type = vips_image_guess_interpretation(image);

	if (vips_foreign_load_dcraw_set_metadata(raw, image)) {
		VIPS_UNREF(image);
		return -1;
	}

	/* We must only free the memory when this image closes.
	 */
	g_signal_connect(image, "close",
		G_CALLBACK(vips_foreign_load_dcraw_close), raw->processed);
	raw->processed = NULL;

	if (vips_image_write(image, load->real)) {
		VIPS_UNREF(image);
		return -1;
	}

	VIPS_UNREF(image);

	return 0;
}

static void
vips_foreign_load_dcraw_class_init(VipsForeignLoadDcRawClass *class)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS(class);
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsOperationClass *operation_class = VIPS_OPERATION_CLASS(class);
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->dispose = vips_foreign_load_dcraw_dispose;
	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "dcrawload_base";
	object_class->description = _("load RAW camera files");

	operation_class->flags |= VIPS_OPERATION_UNTRUSTED;

	/* We need to be ahead of JPEG and TIFF, since many cameras use those
	 * formats as containers. We are very slow to open, but we only test the
	 * filename suffix, so that's fine.
	 */
	foreign_class->priority = 100;

	load_class->get_flags = vips_foreign_load_dcraw_get_flags;
	load_class->header = vips_foreign_load_dcraw_header;
	load_class->load = vips_foreign_load_dcraw_load;

	VIPS_ARG_INT(class, "bitdepth", 12,
		_("Bit depth"),
		_("Number of bits per pixel"),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET(VipsForeignLoadDcRaw, bitdepth),
		8, 16, 8);

}

static void
vips_foreign_load_dcraw_init(VipsForeignLoadDcRaw *raw)
{
	raw->bitdepth = 8;
}

typedef struct _VipsForeignLoadDcRawSource {
	VipsForeignLoadDcRaw parent_object;

	/* Load from a source.
	 */
	VipsSource *source;

} VipsForeignLoadDcRawSource;

typedef VipsForeignLoadDcRawClass VipsForeignLoadDcRawSourceClass;

G_DEFINE_TYPE(VipsForeignLoadDcRawSource, vips_foreign_load_dcraw_source,
	vips_foreign_load_dcraw_get_type());

static int
vips_foreign_load_dcraw_source_build(VipsObject *object)
{
	VipsForeignLoadDcRaw *dcraw = (VipsForeignLoadDcRaw *) object;
	VipsForeignLoadDcRawSource *source = (VipsForeignLoadDcRawSource *) object;

	if (source->source) {
		dcraw->source = source->source;
		g_object_ref(dcraw->source);
	}

	return VIPS_OBJECT_CLASS(vips_foreign_load_dcraw_source_parent_class)
		->build(object);
}

static void
vips_foreign_load_dcraw_source_class_init(
	VipsForeignLoadDcRawSourceClass *class)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS(class);
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsOperationClass *operation_class = VIPS_OPERATION_CLASS(class);

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "dcrawload_source";
	object_class->build = vips_foreign_load_dcraw_source_build;

	operation_class->flags |= VIPS_OPERATION_NOCACHE;

	VIPS_ARG_OBJECT(class, "source", 1,
		_("Source"),
		_("Source to load from"),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET(VipsForeignLoadDcRawSource, source),
		VIPS_TYPE_SOURCE);
}

static void
vips_foreign_load_dcraw_source_init(VipsForeignLoadDcRawSource *source)
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

typedef struct _VipsForeignLoadRawBuffer {
	VipsForeignLoadDcRaw parent_object;

	/* Load from a buffer.
	 */
	VipsBlob *blob;

} VipsForeignLoadDcRawBuffer;

typedef VipsForeignLoadDcRawClass VipsForeignLoadDcRawBufferClass;

G_DEFINE_TYPE(VipsForeignLoadDcRawBuffer, vips_foreign_load_dcraw_buffer,
	vips_foreign_load_dcraw_get_type());

static int
vips_foreign_load_dcraw_buffer_build(VipsObject *object)
{
	VipsForeignLoadDcRaw *raw = (VipsForeignLoadDcRaw *) object;
	VipsForeignLoadDcRawBuffer *buffer = (VipsForeignLoadDcRawBuffer *) object;

	if (buffer->blob &&
		!(raw->source = vips_source_new_from_memory(
			  VIPS_AREA(buffer->blob)->data,
			  VIPS_AREA(buffer->blob)->length)))
		return -1;

	return VIPS_OBJECT_CLASS(vips_foreign_load_dcraw_buffer_parent_class)
		->build(object);
}

static void
vips_foreign_load_dcraw_buffer_class_init(
	VipsForeignLoadDcRawBufferClass *class)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS(class);
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "rawload_buffer";
	object_class->build = vips_foreign_load_dcraw_buffer_build;

	VIPS_ARG_BOXED(class, "buffer", 1,
		_("Buffer"),
		_("Buffer to load from"),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET(VipsForeignLoadDcRawBuffer, blob),
		VIPS_TYPE_BLOB);
}

static void
vips_foreign_load_dcraw_buffer_init(VipsForeignLoadDcRawBuffer *buffer)
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
 * This loader supports the most RAW formats, including
 * ARW, CR2, CR3, CRW, DNG, NEF, NRW, ORF, PEF, RAF, RAW, RW2, SRW, X3F, and
 * many others.
 *
 * The loader applies demosaicing and basic processing to produce an RGB or
 * grayscale image suitable for further processing. It attaches XMP and ICC
 * metadata, if present.
 *
 * ::: tip "Optional arguments"
 *     * @bitdepth: `gint`, load as 8 or 16 bit data
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

/**
 * vips_dcrawload_source:
 * @source: source to load from
 * @out: (out): image to write
 * @...: `NULL`-terminated list of optional named arguments
 *
 * Exactly as [ctor@Image.dcrawload], but read from a source.
 *
 * ::: tip "Optional arguments"
 *     * @bitdepth: `gint`, load as 8 or 16 bit data
 *
 * ::: seealso
 *     [ctor@Image.dcrawload].
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_dcrawload_source(VipsSource *source, VipsImage **out, ...)
{
	va_list ap;
	int result;

	va_start(ap, out);
	result = vips_call_split("dcrawload_source", ap, source, out);
	va_end(ap);

	return result;
}

/**
 * vips_dcrawload_buffer:
 * @buf: (array length=len) (element-type guint8): memory area to load
 * @len: (type gsize): size of memory area
 * @out: (out): output image
 * @...: `NULL`-terminated list of optional named arguments
 *
 * Exactly as [ctor@Image.dcrawload], but read from a buffer.
 *
 * ::: tip "Optional arguments"
 *     * @bitdepth: `gint`, load as 8 or 16 bit data
 *
 * ::: seealso
 *     [ctor@Image.dcrawload].
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_dcrawload_buffer(void *buf, size_t len, VipsImage **out, ...)
{
	va_list ap;
	VipsBlob *blob;
	int result;

	/* We don't take a copy of the data or free it.
	 */
	blob = vips_blob_new(NULL, buf, len);

	va_start(ap, out);
	result = vips_call_split("dcrawload_buffer", ap, blob, out);
	va_end(ap);

	vips_area_unref(VIPS_AREA(blob));

	return result;
}
