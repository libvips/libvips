/* load jpeg-xl
 *
 * 18/3/20
 * 	- from heifload.c
 * 1/10/21
 * 	- reset read point for _load
 * 13/3/23 MathemanFlo
 * 	- add bits per sample metadata
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
#include <vips/debug.h>
#include <vips/internal.h>

#ifdef HAVE_LIBJXL

#include <jxl/decode.h>
#include <jxl/thread_parallel_runner.h>

#include "pforeign.h"

/* TODO:
 *
 * - add metadata support
 *
 * - add animation support
 *
 * - add "shrink" option to read out 8x shrunk image?
 *
 * - fix scRGB gamma
 */

#define INPUT_BUFFER_SIZE (4096)

typedef struct _VipsForeignLoadJxl {
	VipsForeignLoad parent_object;

	/* Source to load from (set by subclasses).
	 */
	VipsSource *source;

	/* Shrink by this much during load.
	 */
	int shrink;

	/* Load this page (frame number).
	 */
	int page;

	/* Load this many pages.
	 */
	int n;

	/* Base image properties.
	 */
	JxlBasicInfo info;
	JxlPixelFormat format;
	size_t icc_size;
	uint8_t *icc_data;
	size_t exif_size;
	uint8_t *exif_data;
	size_t xmp_size;
	uint8_t *xmp_data;

	int frame_count;
	GArray *delay;

	/* JXL multipage and animated images are the same, but multipage has
	 * all the frame delays set to -1 (duration 0xffffffff).
	 */
	gboolean is_animated;

	/* The current accumulated frame as a VipsImage. These are the pixels
	 * we send to the output. It's a info->xsize * info->ysize memory
	 * image.
	 */
	VipsImage *frame;

	/* The frame number currently in @frame. Numbered from 1, so 0 means
	 * before the first frame.
	 */
	int frame_no;

	/* Decompress state.
	 */
	void *runner;
	JxlDecoder *decoder;

	/* Our input buffer.
	 */
	uint8_t input_buffer[INPUT_BUFFER_SIZE];
	size_t bytes_in_buffer;

	/* Pointers to fields where box size and box data should be written to
	 */
	size_t *box_size;
	uint8_t **box_data;

	/* Number of errors reported during load -- use this to block load of
	 * corrupted images.
	 */
	int n_errors;

	/* If we need to upsample tiles read from opj.
	 */
	gboolean upsample;

	/* If we need to do ycc->rgb conversion on load.
	 */
	gboolean ycc_to_rgb;
} VipsForeignLoadJxl;

typedef VipsForeignLoadClass VipsForeignLoadJxlClass;

G_DEFINE_ABSTRACT_TYPE(VipsForeignLoadJxl, vips_foreign_load_jxl,
	VIPS_TYPE_FOREIGN_LOAD);

static void
vips_foreign_load_jxl_dispose(GObject *gobject)
{
	VipsForeignLoadJxl *jxl = (VipsForeignLoadJxl *) gobject;

#ifdef DEBUG
	printf("vips_foreign_load_jxl_dispose:\n");
#endif /*DEBUG*/

	VIPS_FREEF(JxlThreadParallelRunnerDestroy, jxl->runner);
	VIPS_FREEF(JxlDecoderDestroy, jxl->decoder);
	VIPS_FREE(jxl->icc_data);
	VIPS_FREE(jxl->exif_data);
	VIPS_FREE(jxl->xmp_data);
	VIPS_FREEF(g_array_unref, jxl->delay);
	VIPS_UNREF(jxl->frame);
	VIPS_UNREF(jxl->source);

	G_OBJECT_CLASS(vips_foreign_load_jxl_parent_class)->dispose(gobject);
}

static void
vips_foreign_load_jxl_error(VipsForeignLoadJxl *jxl, const char *details)
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS(jxl);

	/* TODO ... jxl has no way to get error messages at the moment.
	 */
	vips_error(class->nickname, "error %s", details);
}

static int
vips_foreign_load_jxl_build(VipsObject *object)
{
	VipsForeignLoadJxl *jxl = (VipsForeignLoadJxl *) object;

#ifdef DEBUG
	printf("vips_foreign_load_jxl_build:\n");
#endif /*DEBUG*/

	jxl->runner = JxlThreadParallelRunnerCreate(NULL, vips_concurrency_get());
	jxl->decoder = JxlDecoderCreate(NULL);

	if (JxlDecoderSetParallelRunner(jxl->decoder,
			JxlThreadParallelRunner, jxl->runner)) {
		vips_foreign_load_jxl_error(jxl, "JxlDecoderSetParallelRunner");
		return -1;
	}

	if (VIPS_OBJECT_CLASS(vips_foreign_load_jxl_parent_class)->build(object))
		return -1;

	return 0;
}

static gboolean
vips_foreign_load_jxl_is_a_source(VipsSource *source)
{
	const unsigned char *p;
	JxlSignature sig;

	return (p = vips_source_sniff(source, 12)) &&
		(sig = JxlSignatureCheck(p, 12)) != JXL_SIG_INVALID &&
		sig != JXL_SIG_NOT_ENOUGH_BYTES;
}

static VipsForeignFlags
vips_foreign_load_jxl_get_flags(VipsForeignLoad *load)
{
	/* FIXME .. could support random access for non-animated images.
	 */
	return VIPS_FOREIGN_SEQUENTIAL;
}

static int
vips_foreign_load_jxl_set_box_buffer(VipsForeignLoadJxl *jxl)
{
	if (!jxl->box_data || !jxl->box_size)
		return 0;

	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS(jxl);

	uint8_t *new_data;
	size_t new_size;
	size_t box_size = *jxl->box_size;

	new_size = box_size + INPUT_BUFFER_SIZE;
	new_data = g_try_realloc(*jxl->box_data, new_size);

	if (!new_data) {
		vips_error(class->nickname, "%s", _("out of memory"));
		return -1;
	}

	*jxl->box_data = new_data;

	JxlDecoderSetBoxBuffer(jxl->decoder,
		new_data + box_size, INPUT_BUFFER_SIZE);

	return 0;
}

static int
vips_foreign_load_jxl_release_box_buffer(VipsForeignLoadJxl *jxl)
{
	if (!jxl->box_data || !jxl->box_size)
		return 0;

	size_t remaining = JxlDecoderReleaseBoxBuffer(jxl->decoder);
	*jxl->box_size += INPUT_BUFFER_SIZE - remaining;

	return 0;
}

static int
vips_foreign_load_jxl_fill_input(VipsForeignLoadJxl *jxl,
	size_t bytes_remaining)
{
	gint64 bytes_read;

#ifdef DEBUG_VERBOSE
	printf("vips_foreign_load_jxl_fill_input: %zd bytes requested\n",
		INPUT_BUFFER_SIZE - bytes_remaining);
#endif /*DEBUG_VERBOSE*/

	memmove(jxl->input_buffer,
		jxl->input_buffer + jxl->bytes_in_buffer - bytes_remaining,
		bytes_remaining);
	bytes_read = vips_source_read(jxl->source,
		jxl->input_buffer + bytes_remaining,
		INPUT_BUFFER_SIZE - bytes_remaining);

	/* Read error.
	 */
	if (bytes_read < 0)
		return -1;

	jxl->bytes_in_buffer = bytes_read + bytes_remaining;

#ifdef DEBUG_VERBOSE
	printf("vips_foreign_load_jxl_fill_input: %zd bytes read\n",
		bytes_read);
#endif /*DEBUG_VERBOSE*/

	return bytes_read;
}

#ifdef DEBUG
static void
vips_foreign_load_jxl_print_status(JxlDecoderStatus status)
{
	switch (status) {
	case JXL_DEC_SUCCESS:
		printf("JXL_DEC_SUCCESS\n");
		break;

	case JXL_DEC_ERROR:
		printf("JXL_DEC_ERROR\n");
		break;

	case JXL_DEC_NEED_MORE_INPUT:
		printf("JXL_DEC_NEED_MORE_INPUT\n");
		break;

	case JXL_DEC_NEED_PREVIEW_OUT_BUFFER:
		printf("JXL_DEC_NEED_PREVIEW_OUT_BUFFER\n");
		break;

	case JXL_DEC_NEED_IMAGE_OUT_BUFFER:
		printf("JXL_DEC_NEED_IMAGE_OUT_BUFFER\n");
		break;

	case JXL_DEC_JPEG_NEED_MORE_OUTPUT:
		printf("JXL_DEC_JPEG_NEED_MORE_OUTPUT\n");
		break;

	case JXL_DEC_BOX_NEED_MORE_OUTPUT:
		printf("JXL_DEC_BOX_NEED_MORE_OUTPUT\n");
		break;

	case JXL_DEC_BASIC_INFO:
		printf("JXL_DEC_BASIC_INFO\n");
		break;

	case JXL_DEC_EXTENSIONS:
		printf("JXL_DEC_EXTENSIONS\n");
		break;

	case JXL_DEC_COLOR_ENCODING:
		printf("JXL_DEC_COLOR_ENCODING\n");
		break;

	case JXL_DEC_PREVIEW_IMAGE:
		printf("JXL_DEC_PREVIEW_IMAGE\n");
		break;

	case JXL_DEC_FRAME:
		printf("JXL_DEC_FRAME\n");
		break;

	case JXL_DEC_FULL_IMAGE:
		printf("JXL_DEC_FULL_IMAGE\n");
		break;

	case JXL_DEC_JPEG_RECONSTRUCTION:
		printf("JXL_DEC_JPEG_RECONSTRUCTION\n");
		break;

	case JXL_DEC_BOX:
		printf("JXL_DEC_BOX\n");
		break;

	default:
		printf("JXL_DEC_<unknown>\n");
		break;
	}
}

static void
vips_foreign_load_jxl_print_info(JxlBasicInfo *info)
{
	printf("JxlBasicInfo:\n");
	printf("    have_container = %d\n", info->have_container);
	printf("    xsize = %d\n", info->xsize);
	printf("    ysize = %d\n", info->ysize);
	printf("    bits_per_sample = %d\n", info->bits_per_sample);
	printf("    exponent_bits_per_sample = %d\n",
		info->exponent_bits_per_sample);
	printf("    intensity_target = %g\n", info->intensity_target);
	printf("    min_nits = %g\n", info->min_nits);
	printf("    relative_to_max_display = %d\n",
		info->relative_to_max_display);
	printf("    linear_below = %g\n", info->linear_below);
	printf("    uses_original_profile = %d\n",
		info->uses_original_profile);
	printf("    have_preview = %d\n", info->have_preview);
	printf("    have_animation = %d\n", info->have_animation);
	printf("    orientation = %d\n", info->orientation);
	printf("    num_color_channels = %d\n", info->num_color_channels);
	printf("    num_extra_channels = %d\n", info->num_extra_channels);
	printf("    alpha_bits = %d\n", info->alpha_bits);
	printf("    alpha_exponent_bits = %d\n", info->alpha_exponent_bits);
	printf("    alpha_premultiplied = %d\n", info->alpha_premultiplied);
	printf("    preview.xsize = %d\n", info->preview.xsize);
	printf("    preview.ysize = %d\n", info->preview.ysize);
	printf("    animation.tps_numerator = %d\n",
		info->animation.tps_numerator);
	printf("    animation.tps_denominator = %d\n",
		info->animation.tps_denominator);
	printf("    animation.num_loops = %d\n", info->animation.num_loops);
	printf("    animation.have_timecodes = %d\n",
		info->animation.have_timecodes);
}

static void
vips_foreign_load_jxl_print_format(JxlPixelFormat *format)
{
	printf("JxlPixelFormat:\n");
	printf("    data_type = ");
	switch (format->data_type) {
	case JXL_TYPE_UINT8:
		printf("JXL_TYPE_UINT8");
		break;

	case JXL_TYPE_UINT16:
		printf("JXL_TYPE_UINT16");
		break;

	case JXL_TYPE_FLOAT:
		printf("JXL_TYPE_FLOAT");
		break;

	default:
		printf("(unknown)");
		break;
	}
	printf("\n");
	printf("    num_channels = %d\n", format->num_channels);
	printf("    endianness = %d\n", format->endianness);
	printf("    align = %zd\n", format->align);
}

static const char *
vips_foreign_load_jxl_blend_mode(JxlBlendMode blendmode)
{
	switch (blendmode) {
	case JXL_BLEND_REPLACE:
		return "JXL_BLEND_REPLACE";

	case JXL_BLEND_ADD:
		return "JXL_BLEND_ADD";

	case JXL_BLEND_BLEND:
		return "JXL_BLEND_BLEND";

	case JXL_BLEND_MULADD:
		return "JXL_BLEND_MULADD";

	case JXL_BLEND_MUL:
		return "JXL_BLEND_MUL";

	default:
		return "<unknown JxlBlendMode";
	}
}

static void
vips_foreign_load_jxl_print_frame_header(JxlFrameHeader *h)
{
	printf("JxlFrameHeader:\n");
	printf("    duration = %u\n", h->duration);
	printf("    timecode = %u\n", h->timecode);
	printf("    name_length = %u\n", h->name_length);
	printf("    is_last = %s\n", h->is_last ? "TRUE" : "FALSE");
	printf("    layer_info.have_crop = %s\n",
		h->layer_info.have_crop ? "TRUE" : "FALSE");
	printf("    layer_info.crop_x0 = %d\n", h->layer_info.crop_x0);
	printf("    layer_info.crop_y0 = %d\n", h->layer_info.crop_y0);
	printf("    layer_info.xsize = %u\n", h->layer_info.xsize);
	printf("    layer_info.ysize = %u\n", h->layer_info.ysize);
	printf("    layer_info.blend_info.blendmode = %s\n",
		vips_foreign_load_jxl_blend_mode(h->layer_info.blend_info.blendmode));
	printf("    layer_info.blend_info.source = %u\n",
		h->layer_info.blend_info.source);
	printf("    layer_info.blend_info.alpha = %u\n",
		h->layer_info.blend_info.alpha);
	printf("    layer_info.blend_info.clamp = %s\n",
		h->layer_info.blend_info.clamp ? "TRUE" : "FALSE");
	printf("    layer_info.save_as_reference = %u\n",
		h->layer_info.save_as_reference);
}
#endif /*DEBUG*/

static JxlDecoderStatus
vips_foreign_load_jxl_process(VipsForeignLoadJxl *jxl)
{
	JxlDecoderStatus status;

#ifdef DEBUG
	printf("vips_foreign_load_jxl_process: starting ...\n");
#endif /*DEBUG*/

	while ((status = JxlDecoderProcessInput(jxl->decoder)) ==
		JXL_DEC_NEED_MORE_INPUT) {
		size_t bytes_remaining;
		int bytes_read;

#ifdef DEBUG_VERBOSE
		printf("vips_foreign_load_jxl_process: reading ...\n");
#endif /*DEBUG_VERBOSE*/

		bytes_remaining = JxlDecoderReleaseInput(jxl->decoder);
		bytes_read = vips_foreign_load_jxl_fill_input(jxl, bytes_remaining);

		if (bytes_read < 0)
			return JXL_DEC_ERROR;

		if (jxl->bytes_in_buffer)
			JxlDecoderSetInput(jxl->decoder,
				jxl->input_buffer, jxl->bytes_in_buffer);

		if (!bytes_read)
			JxlDecoderCloseInput(jxl->decoder);
	}

#ifdef DEBUG
	printf("vips_foreign_load_jxl_process: seen ");
	vips_foreign_load_jxl_print_status(status);
#endif /*DEBUG*/

	return status;
}

static int
vips_foreign_load_jxl_read_frame(VipsForeignLoadJxl *jxl, VipsImage *frame,
	int frame_no)
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS(jxl);

	size_t buffer_size;
	JxlDecoderStatus status;

	if (jxl->frame_no >= frame_no)
		return 0;

	int skip = frame_no - jxl->frame_no - 1;
	if (skip > 0) {
#ifdef DEBUG_VERBOSE
		printf("vips_foreign_load_jxl_read_frame: skipping %d frames\n", skip);
#endif /*DEBUG_VERBOSE*/

		JxlDecoderSkipFrames(jxl->decoder, skip);
		jxl->frame_no += skip;
	}

	/* Read to the end of the image.
	 */
	do {
		switch ((status = vips_foreign_load_jxl_process(jxl))) {
		case JXL_DEC_ERROR:
			vips_foreign_load_jxl_error(jxl, "JxlDecoderProcessInput");
			return -1;

		case JXL_DEC_FRAME:
			jxl->frame_no++;
			break;

		case JXL_DEC_NEED_IMAGE_OUT_BUFFER:
			if (JxlDecoderImageOutBufferSize(jxl->decoder,
					&jxl->format, &buffer_size)) {
				vips_foreign_load_jxl_error(jxl,
					"JxlDecoderImageOutBufferSize");
				return -1;
			}
			if (buffer_size != VIPS_IMAGE_SIZEOF_IMAGE(frame)) {
				vips_error(class->nickname, "%s", _("bad buffer size"));
				return -1;
			}
			if (JxlDecoderSetImageOutBuffer(jxl->decoder, &jxl->format,
					VIPS_IMAGE_ADDR(frame, 0, 0),
					VIPS_IMAGE_SIZEOF_IMAGE(frame))) {
				vips_foreign_load_jxl_error(jxl, "JxlDecoderSetImageOutBuffer");
				return -1;
			}
			break;

		case JXL_DEC_FULL_IMAGE:
			/* We decoded the required frame and can return
			 */
			if (jxl->frame_no >= frame_no)
				return 0;

			break;

		default:
			break;
		}
	} while (status != JXL_DEC_SUCCESS);

	/* We didn't find the required frame
	 */
	vips_error(class->nickname, "%s", _("not enough frames"));
	return -1;
}

static int
vips_foreign_load_jxl_generate(VipsRegion *out_region,
	void *seq, void *a, void *b, gboolean *stop)
{
	VipsRect *r = &out_region->valid;
	VipsForeignLoadJxl *jxl = (VipsForeignLoadJxl *) a;

	/* jxl>frame_no numbers from 1.
	 */
	int frame = 1 + r->top / jxl->info.ysize + jxl->page;
	int line = r->top % jxl->info.ysize;

#ifdef DEBUG_VERBOSE
	printf("vips_foreign_load_jxl_generate: line %d\n", r->top);
#endif /*DEBUG_VERBOSE*/

	g_assert(r->height == 1);

	if (vips_foreign_load_jxl_read_frame(jxl, jxl->frame, frame))
		return -1;

	memcpy(VIPS_REGION_ADDR(out_region, 0, r->top),
		VIPS_IMAGE_ADDR(jxl->frame, 0, line),
		VIPS_IMAGE_SIZEOF_LINE(jxl->frame));

	return 0;
}

/* JPEG XL stores EXIF data without leading "Exif\0\0" with offset
 */
static int
vips_foreign_load_jxl_fix_exif(VipsForeignLoadJxl *jxl)
{
	if (!jxl->exif_data ||
		vips_isprefix("Exif", (char *) jxl->exif_data))
		return 0;

	if (jxl->exif_size < 4) {
		g_warning("invalid data in EXIF box");
		return -1;
	}

	/* Offset is stored in big-endian
	 */
	size_t offset = GUINT32_FROM_BE(*((guint32 *) jxl->exif_data));
	if (offset > jxl->exif_size - 4) {
		g_warning("invalid data in EXIF box");
		return -1;
	}

	size_t new_size = jxl->exif_size - 4 - offset + 6;
	uint8_t *new_data;
	if (!(new_data = VIPS_MALLOC(NULL, new_size)))
		return -1;

	memcpy(new_data, "Exif\0\0", 6);
	memcpy(new_data + 6, jxl->exif_data + 4 + offset, new_size - 6);

	VIPS_FREE(jxl->exif_data);
	jxl->exif_size = new_size;
	jxl->exif_data = new_data;

	return 0;
}

static int
vips_foreign_load_jxl_set_header(VipsForeignLoadJxl *jxl, VipsImage *out)
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS(jxl);

	VipsBandFormat format;
	VipsInterpretation interpretation;

	if (jxl->info.xsize >= VIPS_MAX_COORD ||
		jxl->info.ysize >= VIPS_MAX_COORD) {
		vips_error(class->nickname, "%s", _("image size out of bounds"));
		return -1;
	}

	switch (jxl->format.data_type) {
	case JXL_TYPE_UINT8:
		format = VIPS_FORMAT_UCHAR;
		break;

	case JXL_TYPE_UINT16:
		format = VIPS_FORMAT_USHORT;
		break;

	case JXL_TYPE_FLOAT:
		format = VIPS_FORMAT_FLOAT;
		break;

	default:
		g_assert_not_reached();
	}

	switch (jxl->info.num_color_channels) {
	case 1:
		switch (format) {
		case VIPS_FORMAT_UCHAR:
			interpretation = VIPS_INTERPRETATION_B_W;
			break;

		case VIPS_FORMAT_USHORT:
			interpretation = VIPS_INTERPRETATION_GREY16;
			break;

		default:
			interpretation = VIPS_INTERPRETATION_B_W;
			break;
		}
		break;

	case 3:
		switch (format) {
		case VIPS_FORMAT_UCHAR:
			interpretation = VIPS_INTERPRETATION_sRGB;
			break;

		case VIPS_FORMAT_USHORT:
			interpretation = VIPS_INTERPRETATION_RGB16;
			break;

		case VIPS_FORMAT_FLOAT:
			interpretation = VIPS_INTERPRETATION_scRGB;
			break;

		default:
			interpretation = VIPS_INTERPRETATION_sRGB;
			break;
		}
		break;

	default:
		interpretation = VIPS_INTERPRETATION_MULTIBAND;
		break;
	}

	if (jxl->frame_count > 1) {
		if (jxl->n == -1)
			jxl->n = jxl->frame_count - jxl->page; // FIXME: Invalidates operation cache

		if (jxl->page < 0 ||
			jxl->n <= 0 ||
			jxl->page + jxl->n > jxl->frame_count) {
			vips_error(class->nickname, "%s", _("bad page number"));
			return -1;
		}

		vips_image_set_int(out, VIPS_META_N_PAGES, jxl->frame_count);

		if (jxl->n > 1)
			vips_image_set_int(out, VIPS_META_PAGE_HEIGHT, jxl->info.ysize);

		if (jxl->is_animated) {
			int *delay = (int *) jxl->delay->data;

			vips_image_set_array_int(out, "delay", delay, jxl->frame_count);

			/* gif uses centiseconds for delays
			 */
			vips_image_set_int(out, "gif-delay", rint(delay[0] / 10.0));

			vips_image_set_int(out, "loop", jxl->info.animation.num_loops);
		}
	}
	else {
		jxl->n = 1; // FIXME: Invalidates operation cache
		jxl->page = 0; // FIXME: Invalidates operation cache
	}

	/* Init jxl->frame only when we need to decode multiple frames.
	 * Otherwise, we can decode the frame right to the output
	 */
	if (jxl->n > 1 && !jxl->frame) {
		jxl->frame = vips_image_new_memory();
		vips_image_init_fields(jxl->frame,
			jxl->info.xsize, jxl->info.ysize, jxl->format.num_channels,
			format, VIPS_CODING_NONE, interpretation, 1.0, 1.0);
		if (vips_image_pipelinev(jxl->frame,
				VIPS_DEMAND_STYLE_THINSTRIP, NULL) ||
			vips_image_write_prepare(jxl->frame))
			return -1;
	}

	vips_image_init_fields(out,
		jxl->info.xsize, jxl->info.ysize * jxl->n, jxl->format.num_channels,
		format, VIPS_CODING_NONE, interpretation, 1.0, 1.0);

	/* Even though this is a full image reader, we hint thinstrip since
	 * we are quite happy serving that if anything downstream
	 * would like it.
	 */
	if (vips_image_pipelinev(out, VIPS_DEMAND_STYLE_THINSTRIP, NULL))
		return -1;

	if (jxl->icc_data &&
		jxl->icc_size > 0) {
		vips_image_set_blob(out, VIPS_META_ICC_NAME,
			(VipsCallbackFn) vips_area_free_cb, jxl->icc_data, jxl->icc_size);
		jxl->icc_data = NULL;
		jxl->icc_size = 0;
	}

	if (jxl->exif_data &&
		jxl->exif_size > 0) {
		vips_image_set_blob(out, VIPS_META_EXIF_NAME,
			(VipsCallbackFn) vips_area_free_cb, jxl->exif_data, jxl->exif_size);
		jxl->exif_data = NULL;
		jxl->exif_size = 0;
	}

	if (jxl->xmp_data &&
		jxl->xmp_size > 0) {
		vips_image_set_blob(out, VIPS_META_XMP_NAME,
			(VipsCallbackFn) vips_area_free_cb, jxl->xmp_data, jxl->xmp_size);
		jxl->xmp_data = NULL;
		jxl->xmp_size = 0;
	}

	vips_image_set_int(out, VIPS_META_ORIENTATION, jxl->info.orientation);

	vips_image_set_int(out, VIPS_META_BITS_PER_SAMPLE,
		jxl->info.bits_per_sample);

	return 0;
}

static int
vips_foreign_load_jxl_header(VipsForeignLoad *load)
{
	VipsForeignLoadJxl *jxl = (VipsForeignLoadJxl *) load;

	JxlDecoderStatus status;
	JXL_BOOL decompress_boxes = JXL_TRUE;
	JxlFrameHeader h;

#ifdef DEBUG
	printf("vips_foreign_load_jxl_header:\n");
#endif /*DEBUG*/

	if (vips_source_rewind(jxl->source))
		return -1;

	JxlDecoderRewind(jxl->decoder);
	if (JxlDecoderSubscribeEvents(jxl->decoder,
			JXL_DEC_COLOR_ENCODING |
				JXL_DEC_BASIC_INFO |
				JXL_DEC_BOX |
				JXL_DEC_FRAME)) {
		vips_foreign_load_jxl_error(jxl, "JxlDecoderSubscribeEvents");
		return -1;
	}

	if (JxlDecoderSetDecompressBoxes(jxl->decoder, JXL_TRUE) != JXL_DEC_SUCCESS)
		decompress_boxes = JXL_FALSE;

	if (vips_foreign_load_jxl_fill_input(jxl, 0) < 0)
		return -1;
	JxlDecoderSetInput(jxl->decoder, jxl->input_buffer, jxl->bytes_in_buffer);

	jxl->frame_count = 0;

	/* Read to the end of the header.
	 */
	do {
		switch ((status = vips_foreign_load_jxl_process(jxl))) {
		case JXL_DEC_ERROR:
			vips_foreign_load_jxl_error(jxl, "JxlDecoderProcessInput");
			return -1;

		case JXL_DEC_BOX:
			/* Flush previous box data if any
			 */
			if (vips_foreign_load_jxl_release_box_buffer(jxl))
				return -1;

			JxlBoxType type;
			if (JxlDecoderGetBoxType(
					jxl->decoder, type, decompress_boxes) != JXL_DEC_SUCCESS) {
				vips_foreign_load_jxl_error(jxl, "JxlDecoderGetBoxType");
				return -1;
			}

#ifdef DEBUG
			const char type_s[] = { type[0], type[1], type[2], type[3], 0 };
			printf("vips_foreign_load_jxl_header found box %s\n", type_s);
#endif /*DEBUG*/

			if (!memcmp(type, "Exif", 4)) {
				jxl->box_size = &jxl->exif_size;
				jxl->box_data = &jxl->exif_data;
			}
			else if (!memcmp(type, "xml ", 4)) {
				jxl->box_size = &jxl->xmp_size;
				jxl->box_data = &jxl->xmp_data;
			}
			else {
				jxl->box_size = NULL;
				jxl->box_data = NULL;
			}

			if (vips_foreign_load_jxl_set_box_buffer(jxl))
				return -1;

			break;

		case JXL_DEC_BOX_NEED_MORE_OUTPUT:
			if (vips_foreign_load_jxl_release_box_buffer(jxl) ||
				vips_foreign_load_jxl_set_box_buffer(jxl))
				return -1;

			break;

		case JXL_DEC_BASIC_INFO:
			if (JxlDecoderGetBasicInfo(jxl->decoder,
					&jxl->info)) {
				vips_foreign_load_jxl_error(jxl,
					"JxlDecoderGetBasicInfo");
				return -1;
			}
#ifdef DEBUG
			vips_foreign_load_jxl_print_info(&jxl->info);
#endif /*DEBUG*/

			/* Pick a pixel format to decode to.
			 */
			jxl->format.num_channels =
				jxl->info.num_color_channels +
				jxl->info.num_extra_channels;
			if (jxl->info.exponent_bits_per_sample > 0 ||
				jxl->info.alpha_exponent_bits > 0)
				jxl->format.data_type = JXL_TYPE_FLOAT;
			else if (jxl->info.bits_per_sample > 8)
				jxl->format.data_type = JXL_TYPE_UINT16;
			else
				jxl->format.data_type = JXL_TYPE_UINT8;
			jxl->format.endianness = JXL_NATIVE_ENDIAN;
			jxl->format.align = 0;

#ifdef DEBUG
			vips_foreign_load_jxl_print_format(&jxl->format);
#endif /*DEBUG*/

			break;

		case JXL_DEC_COLOR_ENCODING:
			if (JxlDecoderGetICCProfileSize(jxl->decoder,
					JXL_COLOR_PROFILE_TARGET_DATA, &jxl->icc_size)) {
				vips_foreign_load_jxl_error(jxl, "JxlDecoderGetICCProfileSize");
				return -1;
			}

#ifdef DEBUG
			printf("vips_foreign_load_jxl_header: %zd byte profile\n",
				jxl->icc_size);
#endif /*DEBUG*/
			if (!(jxl->icc_data = vips_malloc(NULL, jxl->icc_size)))
				return -1;

			if (JxlDecoderGetColorAsICCProfile(jxl->decoder,
					JXL_COLOR_PROFILE_TARGET_DATA,
					jxl->icc_data, jxl->icc_size)) {
				vips_foreign_load_jxl_error(jxl,
					"JxlDecoderGetColorAsICCProfile");
				return -1;
			}
			break;

		case JXL_DEC_FRAME:
			if (JxlDecoderGetFrameHeader(jxl->decoder, &h) != JXL_DEC_SUCCESS) {
				vips_foreign_load_jxl_error(jxl, "JxlDecoderGetFrameHeader");
				return -1;
			}

#ifdef DEBUG
			vips_foreign_load_jxl_print_frame_header(&h);
#endif /*DEBUG*/

			if (jxl->info.have_animation) {
				// tick duration in seconds
				double tick = (double) jxl->info.animation.tps_denominator /
					jxl->info.animation.tps_numerator;
				// this duration in ms
				int ms = rint(1000.0 * h.duration * tick);
				// h.duration of 0xffffffff is used for multipage JXL ... map
				// this to -1 in delay
				int duration = h.duration == 0xffffffff ? -1 : ms;

				jxl->delay = g_array_append_vals(jxl->delay, &duration, 1);
			}

			jxl->frame_count++;

			break;

		default:
			break;
		}
	} while (status != JXL_DEC_SUCCESS);

	/* Detect JXL multipage (rather than animated).
	 */
	int *delay = (int *) jxl->delay->data;
	for (int i = 0; i < jxl->delay->len; i++)
		if (delay[i] != -1) {
			jxl->is_animated = TRUE;
			break;
		}

	/* Flush box data if any
	 */
	if (vips_foreign_load_jxl_release_box_buffer(jxl))
		return -1;

	if (vips_foreign_load_jxl_fix_exif(jxl))
		return -1;

	if (vips_foreign_load_jxl_set_header(jxl, load->out))
		return -1;

	VIPS_SETSTR(load->out->filename,
		vips_connection_filename(VIPS_CONNECTION(jxl->source)));

	return 0;
}

static int
vips_foreign_load_jxl_load(VipsForeignLoad *load)
{
	VipsForeignLoadJxl *jxl = (VipsForeignLoadJxl *) load;
	VipsImage **t = (VipsImage **)
		vips_object_local_array(VIPS_OBJECT(load), 3);

	VipsImage *out;

#ifdef DEBUG
	printf("vips_foreign_load_jxl_load:\n");
#endif /*DEBUG*/

	t[0] = vips_image_new();
	if (vips_foreign_load_jxl_set_header(jxl, t[0]))
		return -1;

	/* We have to rewind ... we can't be certain the header
	 * decoder left the input in the correct place.
	 */
	if (vips_source_rewind(jxl->source))
		return -1;

	JxlDecoderRewind(jxl->decoder);
	if (JxlDecoderSubscribeEvents(jxl->decoder,
				JXL_DEC_FRAME | JXL_DEC_FULL_IMAGE)) {
		vips_foreign_load_jxl_error(jxl,
			"JxlDecoderSubscribeEvents");
		return -1;
	}

	if (vips_foreign_load_jxl_fill_input(jxl, 0) < 0)
		return -1;
	JxlDecoderSetInput(jxl->decoder,
		jxl->input_buffer, jxl->bytes_in_buffer);

	if (jxl->n > 1) {
		if (vips_image_generate(t[0],
				NULL, vips_foreign_load_jxl_generate, NULL, jxl, NULL) ||
			vips_sequential(t[0], &t[1], NULL))
			return -1;

		out = t[1];
	}
	else {
		/* We need only a single frame, we can read it right to the output
		 */
		if (vips_image_write_prepare(t[0]) ||
			vips_foreign_load_jxl_read_frame(jxl, t[0], jxl->page + 1))
			return -1;

		out = t[0];
	}

	if (vips_image_write(out, load->real))
		return -1;

	/* Switch to pixel decode.
	 */
	if (vips_source_decode(jxl->source))
		return -1;

	return 0;
}

static void
vips_foreign_load_jxl_class_init(VipsForeignLoadJxlClass *class)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS(class);
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsOperationClass *operation_class = VIPS_OPERATION_CLASS(class);
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->dispose = vips_foreign_load_jxl_dispose;
	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "jxlload_base";
	object_class->description = _("load JPEG-XL image");
	object_class->build = vips_foreign_load_jxl_build;

	/* libjxl is fuzzed, but it's relatively young and bugs are
	 * still being found in jan 2022. Revise this status soon.
	 */
	operation_class->flags |= VIPS_OPERATION_UNTRUSTED;

	load_class->get_flags = vips_foreign_load_jxl_get_flags;
	load_class->header = vips_foreign_load_jxl_header;
	load_class->load = vips_foreign_load_jxl_load;

	VIPS_ARG_INT(class, "page", 20,
		_("Page"),
		_("First page to load"),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET(VipsForeignLoadJxl, page),
		0, 100000, 0);

	VIPS_ARG_INT(class, "n", 21,
		_("n"),
		_("Number of pages to load, -1 for all"),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET(VipsForeignLoadJxl, n),
		-1, 100000, 1);
}

static void
vips_foreign_load_jxl_init(VipsForeignLoadJxl *jxl)
{
	jxl->n = 1;
	jxl->delay = g_array_new(FALSE, FALSE, sizeof(int));
}

typedef struct _VipsForeignLoadJxlFile {
	VipsForeignLoadJxl parent_object;

	/* Filename for load.
	 */
	char *filename;

} VipsForeignLoadJxlFile;

typedef VipsForeignLoadJxlClass VipsForeignLoadJxlFileClass;

G_DEFINE_TYPE(VipsForeignLoadJxlFile, vips_foreign_load_jxl_file,
	vips_foreign_load_jxl_get_type());

static int
vips_foreign_load_jxl_file_build(VipsObject *object)
{
	VipsForeignLoadJxl *jxl = (VipsForeignLoadJxl *) object;
	VipsForeignLoadJxlFile *file = (VipsForeignLoadJxlFile *) object;

	if (file->filename &&
		!(jxl->source = vips_source_new_from_file(file->filename)))
		return -1;

	if (VIPS_OBJECT_CLASS(vips_foreign_load_jxl_file_parent_class)->build(object))
		return -1;

	return 0;
}

const char *vips__jxl_suffs[] = { ".jxl", NULL };

static int
vips_foreign_load_jxl_is_a(const char *filename)
{
	VipsSource *source;
	gboolean result;

	if (!(source = vips_source_new_from_file(filename)))
		return FALSE;
	result = vips_foreign_load_jxl_is_a_source(source);
	VIPS_UNREF(source);

	return result;
}

static void
vips_foreign_load_jxl_file_class_init(VipsForeignLoadJxlFileClass *class)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS(class);
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "jxlload";
	object_class->build = vips_foreign_load_jxl_file_build;

	foreign_class->suffs = vips__jxl_suffs;

	load_class->is_a = vips_foreign_load_jxl_is_a;

	VIPS_ARG_STRING(class, "filename", 1,
		_("Filename"),
		_("Filename to load from"),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET(VipsForeignLoadJxlFile, filename),
		NULL);
}

static void
vips_foreign_load_jxl_file_init(VipsForeignLoadJxlFile *jxl)
{
}

typedef struct _VipsForeignLoadJxlBuffer {
	VipsForeignLoadJxl parent_object;

	/* Load from a buffer.
	 */
	VipsArea *buf;

} VipsForeignLoadJxlBuffer;

typedef VipsForeignLoadJxlClass VipsForeignLoadJxlBufferClass;

G_DEFINE_TYPE(VipsForeignLoadJxlBuffer, vips_foreign_load_jxl_buffer,
	vips_foreign_load_jxl_get_type());

static int
vips_foreign_load_jxl_buffer_build(VipsObject *object)
{
	VipsForeignLoadJxl *jxl = (VipsForeignLoadJxl *) object;
	VipsForeignLoadJxlBuffer *buffer =
		(VipsForeignLoadJxlBuffer *) object;

	if (buffer->buf)
		if (!(jxl->source = vips_source_new_from_memory(
				  VIPS_AREA(buffer->buf)->data,
				  VIPS_AREA(buffer->buf)->length)))
			return -1;

	if (VIPS_OBJECT_CLASS(vips_foreign_load_jxl_file_parent_class)->build(object))
		return -1;

	return 0;
}

static gboolean
vips_foreign_load_jxl_buffer_is_a(const void *buf, size_t len)
{
	VipsSource *source;
	gboolean result;

	if (!(source = vips_source_new_from_memory(buf, len)))
		return FALSE;
	result = vips_foreign_load_jxl_is_a_source(source);
	VIPS_UNREF(source);

	return result;
}

static void
vips_foreign_load_jxl_buffer_class_init(VipsForeignLoadJxlBufferClass *class)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS(class);
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "jxlload_buffer";
	object_class->build = vips_foreign_load_jxl_buffer_build;

	load_class->is_a_buffer = vips_foreign_load_jxl_buffer_is_a;

	VIPS_ARG_BOXED(class, "buffer", 1,
		_("Buffer"),
		_("Buffer to load from"),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET(VipsForeignLoadJxlBuffer, buf),
		VIPS_TYPE_BLOB);
}

static void
vips_foreign_load_jxl_buffer_init(VipsForeignLoadJxlBuffer *buffer)
{
}

typedef struct _VipsForeignLoadJxlSource {
	VipsForeignLoadJxl parent_object;

	/* Load from a source.
	 */
	VipsSource *source;

} VipsForeignLoadJxlSource;

typedef VipsForeignLoadJxlClass VipsForeignLoadJxlSourceClass;

G_DEFINE_TYPE(VipsForeignLoadJxlSource, vips_foreign_load_jxl_source,
	vips_foreign_load_jxl_get_type());

static int
vips_foreign_load_jxl_source_build(VipsObject *object)
{
	VipsForeignLoadJxl *jxl = (VipsForeignLoadJxl *) object;
	VipsForeignLoadJxlSource *source =
		(VipsForeignLoadJxlSource *) object;

	if (source->source) {
		jxl->source = source->source;
		g_object_ref(jxl->source);
	}

	if (VIPS_OBJECT_CLASS(vips_foreign_load_jxl_source_parent_class)
			->build(object))
		return -1;

	return 0;
}

static void
vips_foreign_load_jxl_source_class_init(VipsForeignLoadJxlSourceClass *class)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS(class);
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsOperationClass *operation_class = VIPS_OPERATION_CLASS(class);
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "jxlload_source";
	object_class->build = vips_foreign_load_jxl_source_build;

	operation_class->flags |= VIPS_OPERATION_NOCACHE;

	load_class->is_a_source = vips_foreign_load_jxl_is_a_source;

	VIPS_ARG_OBJECT(class, "source", 1,
		_("Source"),
		_("Source to load from"),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET(VipsForeignLoadJxlSource, source),
		VIPS_TYPE_SOURCE);
}

static void
vips_foreign_load_jxl_source_init(VipsForeignLoadJxlSource *jxl)
{
}

#endif /*HAVE_LIBJXL*/

/* The C API wrappers are defined in foreign.c.
 */
