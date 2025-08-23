/* load UltraHDR images with libuhdr
 *
 * 19/1/19
 * 	- from uhdrload.c
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
 */
#define DEBUG

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <glib/gi18n-lib.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vips/vips.h>
#include <vips/debug.h>
#include <vips/internal.h>

#ifdef HAVE_UHDR

#include "pforeign.h"

const char *vips__uhdr_suffs[] = {
	".jpg",
	NULL
};

#include <ultrahdr_api.h>

#define VIPS_TYPE_FOREIGN_LOAD_UHDR (vips_foreign_load_uhdr_get_type())
#define VIPS_FOREIGN_LOAD_UHDR(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST((obj), \
		VIPS_TYPE_FOREIGN_LOAD_UHDR, VipsForeignLoadUhdr))
#define VIPS_FOREIGN_LOAD_UHDR_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), \
		VIPS_TYPE_FOREIGN_LOAD_UHDR, VipsForeignLoadUhdrClass))
#define VIPS_IS_FOREIGN_LOAD_UHDR(obj) \
	(G_TYPE_CHECK_INSTANCE_TYPE((obj), VIPS_TYPE_FOREIGN_LOAD_UHDR))
#define VIPS_IS_FOREIGN_LOAD_UHDR_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE((klass), VIPS_TYPE_FOREIGN_LOAD_UHDR))
#define VIPS_FOREIGN_LOAD_UHDR_GET_CLASS(obj) \
	(G_TYPE_INSTANCE_GET_CLASS((obj), \
		VIPS_TYPE_FOREIGN_LOAD_UHDR, VipsForeignLoadUhdrClass))

typedef struct _VipsForeignLoadUhdr {
	VipsForeignLoad parent_object;

	/* Set from subclasses.
	 */
	VipsSource *source;

	// decoder
	uhdr_codec_private_t *dec;

	uhdr_raw_image_t *raw_image;
	uhdr_raw_image_t *gainmap_image;

} VipsForeignLoadUhdr;

typedef struct _VipsForeignLoadUhdrClass {
	VipsForeignLoadClass parent_class;

} VipsForeignLoadUhdrClass;

G_DEFINE_ABSTRACT_TYPE(VipsForeignLoadUhdr, vips_foreign_load_uhdr,
	VIPS_TYPE_FOREIGN_LOAD);

static const char *
vips__uhdr_error_str(uhdr_codec_err_t err)
{
	switch (err) {
	case UHDR_CODEC_OK:
		return "UHDR_CODEC_OK";

	case UHDR_CODEC_ERROR:
		return "UHDR_CODEC_ERROR";

	case UHDR_CODEC_UNKNOWN_ERROR:
		return "UHDR_CODEC_UNKNOWN_ERROR";

	case UHDR_CODEC_INVALID_PARAM:
		return "UHDR_CODEC_INVALID_PARAM";

	case UHDR_CODEC_MEM_ERROR:
		return "UHDR_CODEC_MEM_ERROR";

	case UHDR_CODEC_INVALID_OPERATION:
		return "UHDR_CODEC_INVALID_OPERATION";

	case UHDR_CODEC_UNSUPPORTED_FEATURE:
		return "UHDR_CODEC_UNSUPPORTED_FEATURE";

	default:
		return "<unknown error code>";
	}
}

void
vips__uhdr_error(uhdr_error_info_t *error)
{
	if (error &&
		error->has_detail)
		vips_error("uhdr", "%s (%s, %d)",
			error->detail,
			vips__uhdr_error_str(error->error_code),
			error->error_code);
	else if (error)
		vips_error("uhdr", "%s, %d",
			vips__uhdr_error_str(error->error_code),
			error->error_code);
	else
		vips_error("uhdr", "error");
}

typedef unsigned short half;

/* From ILM's halfToFloat().
 */
unsigned int
vips__half_to_float(half y)
{
    int s = (y >> 15) & 0x00000001;
    int e = (y >> 10) & 0x0000001f;
    int m =  y        & 0x000003ff;

    if (e == 0) {
		if (m == 0) {
			// Plus or minus zero
			return s << 31;
		}
		else {
			// Denormalized number -- renormalize it
			while (!(m & 0x00000400)) {
				m <<= 1;
				e -=  1;
			}

			e += 1;
			m &= ~0x00000400;
		}
    }
    else if (e == 31) {
		if (m == 0) {
			// Positive or negative infinity
			return (s << 31) | 0x7f800000;
		}
		else {
			// Nan -- preserve sign and significand bits
			return (s << 31) | 0x7f800000 | (m << 13);
		}
    }

    // Normalized number
    e = e + (127 - 15);
    m = m << 13;

    // Assemble s, e and m.
    return (s << 31) | (e << 23) | m;
}

static void
vips_foreign_load_uhdr_dispose(GObject *gobject)
{
	VipsForeignLoadUhdr *uhdr = (VipsForeignLoadUhdr *) gobject;

	VIPS_FREEF(uhdr_release_decoder, uhdr->dec);
	VIPS_UNREF(uhdr->source);

	G_OBJECT_CLASS(vips_foreign_load_uhdr_parent_class)->dispose(gobject);
}

static int
vips_foreign_load_uhdr_build(VipsObject *object)
{
	VipsForeignLoadUhdr *uhdr = (VipsForeignLoadUhdr *) object;

#ifdef DEBUG
	printf("vips_foreign_load_uhdr_build:\n");
#endif /*DEBUG*/

	if (uhdr->source &&
		vips_source_rewind(uhdr->source))
		return -1;

	if (!uhdr->dec &&
		!(uhdr->dec = uhdr_create_decoder())) {
		vips__uhdr_error(NULL);
		return -1;
	}

	return VIPS_OBJECT_CLASS(vips_foreign_load_uhdr_parent_class)
		->build(object);
}

static VipsForeignFlags
vips_foreign_load_uhdr_get_flags(VipsForeignLoad *load)
{
	// since we always decode the whole thing to memory
	return VIPS_FOREIGN_PARTIAL;
}

static int
vips_foreign_load_uhdr_generate(VipsRegion *out_region,
	void *seq, void *a, void *b, gboolean *stop)
{
	VipsRect *r = &out_region->valid;
	VipsForeignLoadUhdr *uhdr = VIPS_FOREIGN_LOAD_UHDR(a);
	half *base = (half *) uhdr->raw_image->planes[0];

	for (int y = 0; y < r->height; y++) {
		half *p = base +
			4 * uhdr->raw_image->stride[0] * (r->top + y) +
			4 * r->left;
		unsigned int *q =
			(unsigned int *) VIPS_REGION_ADDR(out_region, r->left, r->top + y);

		for (int x = 0; x < r->width; x++) {
			q[0] = vips__half_to_float(p[0]);
			q[1] = vips__half_to_float(p[1]);
			q[2] = vips__half_to_float(p[2]);
			q[3] = vips__half_to_float(p[3]);

			p += 4;
			q += 4;
		}
	}

	return 0;
}

#ifdef DEBUG
const char *
img_fmt_str(uhdr_img_fmt_t fmt)
{
	switch (fmt) {
	case UHDR_IMG_FMT_UNSPECIFIED:
		return "UHDR_IMG_FMT_UNSPECIFIED";

	case UHDR_IMG_FMT_24bppYCbCrP010:
		return "UHDR_IMG_FMT_24bppYCbCrP010";

	case UHDR_IMG_FMT_12bppYCbCr420:
		return "UHDR_IMG_FMT_12bppYCbCr420";

	case UHDR_IMG_FMT_8bppYCbCr400:
		return "UHDR_IMG_FMT_8bppYCbCr400";

	case UHDR_IMG_FMT_32bppRGBA8888:
		return "UHDR_IMG_FMT_32bppRGBA8888";

	case UHDR_IMG_FMT_64bppRGBAHalfFloat:
		return "UHDR_IMG_FMT_64bppRGBAHalfFloat";

	case UHDR_IMG_FMT_32bppRGBA1010102:
		return "UHDR_IMG_FMT_32bppRGBA1010102";

	case UHDR_IMG_FMT_24bppYCbCr444:
		return "UHDR_IMG_FMT_24bppYCbCr444";

	case UHDR_IMG_FMT_16bppYCbCr422:
		return "UHDR_IMG_FMT_16bppYCbCr422";

	case UHDR_IMG_FMT_16bppYCbCr440:
		return "UHDR_IMG_FMT_16bppYCbCr440";

	case UHDR_IMG_FMT_12bppYCbCr411:
		return "UHDR_IMG_FMT_12bppYCbCr411";

	case UHDR_IMG_FMT_10bppYCbCr410:
		return "UHDR_IMG_FMT_10bppYCbCr410";

	case UHDR_IMG_FMT_24bppRGB888:
		return "UHDR_IMG_FMT_24bppRGB888";

	case UHDR_IMG_FMT_30bppYCbCr444:
		return "UHDR_IMG_FMT_30bppYCbCr444";

	default:
		return "<unknown format>";
	}
}

const char *
color_gamut_str(uhdr_color_gamut_t cg)
{
	switch (cg) {
	case UHDR_CG_UNSPECIFIED:
		return "UHDR_CG_UNSPECIFIED";

	case UHDR_CG_BT_709:
		return "UHDR_CG_BT_709";

	case UHDR_CG_DISPLAY_P3:
		return "UHDR_CG_DISPLAY_P3";

	case UHDR_CG_BT_2100:
		return "UHDR_CG_BT_2100";

	default:
		return "<unknown gamut>";
	}
}

const char *
color_transfer_str(uhdr_color_transfer_t ct)
{
	switch (ct) {
	case UHDR_CT_UNSPECIFIED:
		return "UHDR_CT_UNSPECIFIED";

	case UHDR_CT_LINEAR:
		return "UHDR_CT_LINEAR";

	case UHDR_CT_HLG:
		return "UHDR_CT_HLG";

	case UHDR_CT_PQ:
		return "UHDR_CT_PQ";

	case UHDR_CT_SRGB:
		return "UHDR_CT_SRGB";

	default:
		return "<unknown transfer>";
	}
}

const char *
color_range_str(uhdr_color_range_t range)
{
	switch (range) {
	case UHDR_CR_UNSPECIFIED:
		return "UHDR_CR_UNSPECIFIED";

	case UHDR_CR_LIMITED_RANGE:
		return "UHDR_CR_LIMITED_RANGE";

	case UHDR_CR_FULL_RANGE:
		return "UHDR_CR_FULL_RANGE";

	default:
		return "<unknown range>";
	}
}

static void
print_raw(uhdr_raw_image_t *raw)
{
	printf("\traw->fmt = %s\n", img_fmt_str(raw->fmt));
	printf("\traw->cg = %s\n", color_gamut_str(raw->cg));
	printf("\traw->ct = %s\n", color_transfer_str(raw->ct));
	printf("\traw->range = %s\n", color_range_str(raw->range));
	printf("\traw->w = %d\n", raw->w);
	printf("\traw->h = %d\n", raw->h);
	printf("\traw->planes[0] = %p\n", raw->planes[0]);
	printf("\traw->planes[1] = %p\n", raw->planes[1]);
	printf("\traw->planes[2] = %p\n", raw->planes[2]);
	printf("\traw->stride[0] = %d\n", raw->stride[0]);
	printf("\traw->stride[1] = %d\n", raw->stride[1]);
	printf("\traw->stride[2] = %d\n", raw->stride[2]);
}
#endif /*DEBUG*/

static int
vips_foreign_load_uhdr_header(VipsForeignLoad *load)
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS(load);
	VipsForeignLoadUhdr *uhdr = (VipsForeignLoadUhdr *) load;

	uhdr_error_info_t error_info;

#ifdef DEBUG
	printf("vips_foreign_load_uhdr_header:\n");
#endif /*DEBUG*/

	const void *data;
	size_t size;
	if (!(data = vips_source_map(uhdr->source, &size)))
		return -1;

	if (!is_uhdr_image((void *) data, size)) {
		vips_error(class->nickname, "%s", _("not an UltraHDR image"));
		return -1;
	}

	uhdr_compressed_image_t compressed_image = {
		(void *) data,
		size,
		.capacity = size,
		.cg = UHDR_CG_UNSPECIFIED,
		.ct = UHDR_CT_UNSPECIFIED,
		.range = UHDR_CR_UNSPECIFIED,
	};
	error_info = uhdr_dec_set_image(uhdr->dec, &compressed_image);
	if (error_info.error_code) {
		vips__uhdr_error(&error_info);
		return -1;
	}

	error_info = uhdr_dec_set_out_img_format(uhdr->dec,
		UHDR_IMG_FMT_64bppRGBAHalfFloat);
	if (error_info.error_code) {
		vips__uhdr_error(&error_info);
		return -1;
	}

	error_info = uhdr_dec_set_out_color_transfer(uhdr->dec, UHDR_CT_LINEAR);
	if (error_info.error_code) {
		vips__uhdr_error(&error_info);
		return -1;
	}

	error_info = uhdr_decode(uhdr->dec);
	if (error_info.error_code) {
		vips__uhdr_error(&error_info);
		return -1;
	}

	vips_source_minimise(uhdr->source);

	uhdr->raw_image = uhdr_get_decoded_image(uhdr->dec);
	if (!uhdr->raw_image) {
		vips__uhdr_error(NULL);
		return -1;
	}
#ifdef DEBUG
	printf("vips_foreign_load_uhdr_header: decoded image\n");
	print_raw(uhdr->raw_image);
#endif /*DEBUG*/

	uhdr->gainmap_image = uhdr_get_decoded_gainmap_image(uhdr->dec);
	if (!uhdr->gainmap_image) {
		vips__uhdr_error(NULL);
		return -1;
	}
#ifdef DEBUG
	printf("vips_foreign_load_uhdr_header: gainmap image\n");
	print_raw(uhdr->gainmap_image);
#endif /*DEBUG*/

	vips_image_init_fields(load->out,
		uhdr->raw_image->w, uhdr->raw_image->h, 4,
		VIPS_FORMAT_FLOAT,
		VIPS_CODING_NONE, VIPS_INTERPRETATION_scRGB, 1.0, 1.0);

	VIPS_SETSTR(load->out->filename,
		vips_connection_filename(VIPS_CONNECTION(uhdr->source)));

	if (vips_image_pipelinev(load->out, VIPS_DEMAND_STYLE_FATSTRIP, NULL))
		return -1;

	if (vips_image_generate(load->out,
			NULL, vips_foreign_load_uhdr_generate, NULL,
			uhdr, NULL))
		return -1;

	return 0;
}

static void
vips_foreign_load_uhdr_class_init(VipsForeignLoadUhdrClass *class)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS(class);
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->dispose = vips_foreign_load_uhdr_dispose;
	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "uhdrload_base";
	object_class->description = _("load a UHDR image");
	object_class->build = vips_foreign_load_uhdr_build;

	load_class->get_flags = vips_foreign_load_uhdr_get_flags;
	load_class->header = vips_foreign_load_uhdr_header;

}

static void
vips_foreign_load_uhdr_init(VipsForeignLoadUhdr *uhdr)
{
}

typedef struct _VipsForeignLoadUhdrFile {
	VipsForeignLoadUhdr parent_object;

	/* Filename for load.
	 */
	char *filename;

} VipsForeignLoadUhdrFile;

typedef VipsForeignLoadUhdrClass VipsForeignLoadUhdrFileClass;

G_DEFINE_TYPE(VipsForeignLoadUhdrFile, vips_foreign_load_uhdr_file,
	vips_foreign_load_uhdr_get_type());

static int
vips_foreign_load_uhdr_file_build(VipsObject *object)
{
	VipsForeignLoadUhdr *uhdr = (VipsForeignLoadUhdr *) object;
	VipsForeignLoadUhdrFile *file = (VipsForeignLoadUhdrFile *) object;

	if (file->filename &&
		!(uhdr->source = vips_source_new_from_file(file->filename)))
		return -1;

	return VIPS_OBJECT_CLASS(vips_foreign_load_uhdr_file_parent_class)
		->build(object);
}

static void
vips_foreign_load_uhdr_file_class_init(VipsForeignLoadUhdrFileClass *class)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS(class);
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "uhdrload";
	object_class->build = vips_foreign_load_uhdr_file_build;

	foreign_class->suffs = vips__uhdr_suffs;

	VIPS_ARG_STRING(class, "filename", 1,
		_("Filename"),
		_("Filename to load from"),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET(VipsForeignLoadUhdrFile, filename),
		NULL);
}

static void
vips_foreign_load_uhdr_file_init(VipsForeignLoadUhdrFile *file)
{
}

typedef struct _VipsForeignLoadUhdrBuffer {
	VipsForeignLoadUhdr parent_object;

	/* Load from a buffer.
	 */
	VipsArea *buf;

} VipsForeignLoadUhdrBuffer;

typedef VipsForeignLoadUhdrClass VipsForeignLoadUhdrBufferClass;

G_DEFINE_TYPE(VipsForeignLoadUhdrBuffer, vips_foreign_load_uhdr_buffer,
	vips_foreign_load_uhdr_get_type());

static int
vips_foreign_load_uhdr_buffer_build(VipsObject *object)
{
	VipsForeignLoadUhdr *uhdr = (VipsForeignLoadUhdr *) object;
	VipsForeignLoadUhdrBuffer *buffer =
		(VipsForeignLoadUhdrBuffer *) object;

	if (buffer->buf &&
		!(uhdr->source = vips_source_new_from_memory(
			VIPS_AREA(buffer->buf)->data,
			VIPS_AREA(buffer->buf)->length)))
		return -1;

	return VIPS_OBJECT_CLASS(vips_foreign_load_uhdr_buffer_parent_class)
		->build(object);
}

static void
vips_foreign_load_uhdr_buffer_class_init(
	VipsForeignLoadUhdrBufferClass *class)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS(class);
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "uhdrload_buffer";
	object_class->build = vips_foreign_load_uhdr_buffer_build;

	VIPS_ARG_BOXED(class, "buffer", 1,
		_("Buffer"),
		_("Buffer to load from"),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET(VipsForeignLoadUhdrBuffer, buf),
		VIPS_TYPE_BLOB);
}

static void
vips_foreign_load_uhdr_buffer_init(VipsForeignLoadUhdrBuffer *buffer)
{
}

typedef struct _VipsForeignLoadUhdrSource {
	VipsForeignLoadUhdr parent_object;

	/* Load from a source.
	 */
	VipsSource *source;

} VipsForeignLoadUhdrSource;

typedef VipsForeignLoadUhdrClass VipsForeignLoadUhdrSourceClass;

G_DEFINE_TYPE(VipsForeignLoadUhdrSource, vips_foreign_load_uhdr_source,
	vips_foreign_load_uhdr_get_type());

static int
vips_foreign_load_uhdr_source_build(VipsObject *object)
{
	VipsForeignLoadUhdr *uhdr = (VipsForeignLoadUhdr *) object;
	VipsForeignLoadUhdrSource *source =
		(VipsForeignLoadUhdrSource *) object;

	if (source->source) {
		uhdr->source = source->source;
		g_object_ref(uhdr->source);
	}

	return VIPS_OBJECT_CLASS(vips_foreign_load_uhdr_source_parent_class)
		->build(object);
}

static void
vips_foreign_load_uhdr_source_class_init(
	VipsForeignLoadUhdrSourceClass *class)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS(class);
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsOperationClass *operation_class = VIPS_OPERATION_CLASS(class);

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "uhdrload_source";
	object_class->build = vips_foreign_load_uhdr_source_build;

	operation_class->flags |= VIPS_OPERATION_NOCACHE;

	VIPS_ARG_OBJECT(class, "source", 1,
		_("Source"),
		_("Source to load from"),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET(VipsForeignLoadUhdrSource, source),
		VIPS_TYPE_SOURCE);
}

static void
vips_foreign_load_uhdr_source_init(VipsForeignLoadUhdrSource *source)
{
}

#endif /*HAVE_UHDR*/

/**
 * vips_uhdrload:
 * @filename: file to load
 * @out: (out): decompressed image
 * @...: `NULL`-terminated list of optional named arguments
 *
 * Read an UltraHDR image.
 *
 * ::: seealso
 *     [ctor@Image.new_from_file].
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_uhdrload(const char *filename, VipsImage **out, ...)
{
	va_list ap;
	int result;

	va_start(ap, out);
	result = vips_call_split("uhdrload", ap, filename, out);
	va_end(ap);

	return result;
}

/**
 * vips_uhdrload_buffer:
 * @buf: (array length=len) (element-type guint8): memory area to load
 * @len: (type gsize): size of memory area
 * @out: (out): image to write
 * @...: `NULL`-terminated list of optional named arguments
 *
 * Exactly as [ctor@Image.uhdrload], but read from a buffer.
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_uhdrload_buffer(void *buf, size_t len, VipsImage **out, ...)
{
	va_list ap;
	VipsBlob *blob;
	int result;

	/* We don't take a copy of the data or free it.
	 */
	blob = vips_blob_new(NULL, buf, len);

	va_start(ap, out);
	result = vips_call_split("uhdrload_buffer", ap, blob, out);
	va_end(ap);

	vips_area_unref(VIPS_AREA(blob));

	return result;
}

/**
 * vips_uhdrload_source:
 * @source: source to load from
 * @out: (out): decompressed image
 * @...: `NULL`-terminated list of optional named arguments
 *
 * Exactly as [ctor@Image.uhdrload], but read from a source.
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_uhdrload_source(VipsSource *source, VipsImage **out, ...)
{
	va_list ap;
	int result;

	va_start(ap, out);
	result = vips_call_split("uhdrload_source", ap, source, out);
	va_end(ap);

	return result;
}
