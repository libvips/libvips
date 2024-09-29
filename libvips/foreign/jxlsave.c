/* save as jpeg-xl
 *
 * 18/3/20
 * 	- from heifload.c
 * 21/5/22
 * 	- add ICC profile support
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

#ifdef HAVE_LIBJXL

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vips/vips.h>
#include <vips/internal.h>

#include <jxl/encode.h>
#include <jxl/thread_parallel_runner.h>

#include "pforeign.h"

/* TODO:
 *
 * - libjxl is currently missing error messages (I think)
 *
 * - add support encoding images with > 4 bands.
 *
 *		see FIXME note in _build()
 */

#define OUTPUT_BUFFER_SIZE (4096)

// max number of scanlines for a jxl tile (ysize arg to _data_at()) ... 2048
// plus 8 lines of overlap top and bottom
#define MAX_TILE_HEIGHT (2064)

typedef struct _VipsForeignSaveJxl {
	VipsForeignSave parent_object;

	/* Where to write (set by subclasses).
	 */
	VipsTarget *target;

	/* Encoder options.
	 */
	int tier;
	double distance;
	int effort;
	gboolean lossless;
	int Q;
	gboolean chunked;

	/* Set on API fail.
	 */
	gboolean error;

	/* Animated jxl options.
	 */
	int gif_delay;
	int *delay;
	int delay_length;

	/* Image geometry.
	 */
	int page_height;
	int page_count;
	int page_number;

	/* Base image properties.
	 */
	JxlBasicInfo info;
	JxlColorEncoding color_encoding;
	JxlPixelFormat format;

	/* Encoder state.
	 */
	void *runner;
	JxlEncoder *encoder;

	/* Buffer scanlines to make a line of libjxl tiles.
	 */
	VipsPel *scanline_buffer;
	size_t scanline_size;
	int scanline_y;

	/* Write buffer.
	 */
	uint8_t output_buffer[OUTPUT_BUFFER_SIZE];

	/* Chunk reader.
	 */
	struct JxlChunkedFrameInputSource input_source;

	/* We have a background JxlEncoderAddChunkedFrame() thread running.
	 */
	gboolean add_chunked_frame_running;

	/* The y position the frame encoder is working on.
	 */
	int frame_y;

	/* Set of sempaphores for organising the background frame encode.
	 */
	VipsSemaphore tiles_written;
	VipsSemaphore tiles_available;
	VipsSemaphore frame_complete;

} VipsForeignSaveJxl;

typedef VipsForeignSaveClass VipsForeignSaveJxlClass;

G_DEFINE_ABSTRACT_TYPE(VipsForeignSaveJxl, vips_foreign_save_jxl,
	VIPS_TYPE_FOREIGN_SAVE);

static void *
vips_foreign_save_jxl_get_buffer(void *opaque, size_t *size)
{
	VipsForeignSaveJxl *jxl = (VipsForeignSaveJxl *) opaque;

	*size = OUTPUT_BUFFER_SIZE;
	return jxl->output_buffer;
}

static void
vips_foreign_save_jxl_output_release_buffer(void *opaque, size_t written_bytes)
{
	VipsForeignSaveJxl *jxl = (VipsForeignSaveJxl *) opaque;

	if (vips_target_write(jxl->target, jxl->output_buffer, written_bytes))
		jxl->error = TRUE;
}

static void
vips_foreign_save_jxl_seek(void *opaque, uint64_t position)
{
	VipsForeignSaveJxl *jxl = (VipsForeignSaveJxl *) opaque;

	if (vips_target_seek(jxl->target, position, SEEK_SET))
		jxl->error = TRUE;
}

static void
vips_foreign_save_jxl_set_finalized_position(void *opaque, uint64_t position)
{
	// don't need this
}

static void
vips_foreign_save_jxl_set_output_processor(VipsForeignSaveJxl *jxl)
{
	JxlEncoderSetOutputProcessor(jxl->encoder,
		(struct JxlEncoderOutputProcessor) {
		.opaque = jxl,
		.get_buffer = vips_foreign_save_jxl_get_buffer,
		.release_buffer = vips_foreign_save_jxl_output_release_buffer,
		.seek = vips_foreign_save_jxl_seek,
		.set_finalized_position = vips_foreign_save_jxl_set_finalized_position,
	});
}

static void
vips_foreign_save_jxl_pixel_format(void *opaque, JxlPixelFormat *format)
{
	printf("vips_foreign_save_jxl_pixel_format:\n");

	VipsForeignSaveJxl *jxl = (VipsForeignSaveJxl *) opaque;

	*format = jxl->format;
}

static void
vips_foreign_save_jxl_extra_pixel_format(void *opaque,
	size_t ec_index, JxlPixelFormat *format)
{
	printf("vips_foreign_save_jxl_extra_pixel_format:\n");

	return vips_foreign_save_jxl_pixel_format(opaque, format);
}

static const void *
vips_foreign_save_jxl_data_at(void *opaque,
	size_t xpos, size_t ypos, size_t xsize, size_t ysize,
	size_t *row_offset)
{
	printf("vips_foreign_save_jxl_data_at: "
		"left = %zd, top = %zd, width = %zd, height = %zd\n",
		xpos, ypos, xsize, ysize);

	VipsForeignSaveJxl *jxl = (VipsForeignSaveJxl *) opaque;

	VipsRect rect = { xpos, ypos, xsize, ysize };
	if (vips_region_prepare(jxl->region, &rect))
		jxl->error = TRUE;

	*row_offset = VIPS_REGION_LSKIP(jxl->region);

	return VIPS_REGION_ADDR(jxl->region, xpos, ypos);
}

static const void *
vips_foreign_save_jxl_extra_data_at(void* opaque, size_t ec_index,
	size_t xpos, size_t ypos, size_t xsize, size_t ysize, size_t* row_offset)
{
	printf("vips_foreign_save_jxl_extra_data_at:\n");

	return vips_foreign_save_jxl_data_at(opaque,
		xpos, ypos, xsize, ysize, row_offset);
}

static void
vips_foreign_save_jxl_input_release_buffer(void *opaque, const void *)
{
	// release the pointer from data_at() ... we don't need to do anything,
	// the mem is owned by the region
}

static void
vips_foreign_save_jxl_set_input_source(VipsForeignSaveJxl *jxl)
{
	jxl->input_source = (struct JxlChunkedFrameInputSource) {
		.opaque = jxl,
		.get_color_channels_pixel_format = vips_foreign_save_jxl_pixel_format,
		.get_color_channel_data_at = vips_foreign_save_jxl_data_at,
		.get_extra_channel_pixel_format =
			vips_foreign_save_jxl_extra_pixel_format,
		.get_extra_channel_data_at = vips_foreign_save_jxl_extra_data_at,
		.release_buffer = vips_foreign_save_jxl_input_release_buffer
	};
}

static void
vips_foreign_save_jxl_error(VipsForeignSaveJxl *jxl, const char *details)
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS(jxl);

	/* TODO ... libjxl seems to have no way to get error messages at the
	 * moment.
	 */
	vips_error(class->nickname, "%s error", details);
}

/* Output for sequential write.
 */
static int
vips_foreign_save_jxl_process_output(VipsForeignSaveJxl *jxl)
{
	JxlEncoderStatus status;

	do {
		uint8_t *out = jxl->output_buffer;
		size_t avail_out = OUTPUT_BUFFER_SIZE;
		status = JxlEncoderProcessOutput(jxl->encoder, &out, &avail_out);

		switch (status) {
		case JXL_ENC_SUCCESS:
		case JXL_ENC_NEED_MORE_OUTPUT:
			if (OUTPUT_BUFFER_SIZE > avail_out &&
				vips_target_write(jxl->target, jxl->output_buffer,
					OUTPUT_BUFFER_SIZE - avail_out))
				return -1;
			break;

		default:
			vips_foreign_save_jxl_error(jxl, "JxlEncoderProcessOutput");
#ifdef DEBUG
			vips_foreign_save_jxl_print_status(status);
#endif /*DEBUG*/
			return -1;
		}
	} while (status != JXL_ENC_SUCCESS);

	return 0;
}

/* String-based metadata fields we add.
 */
typedef struct _VipsForeignSaveJxlMetadata {
	const char *name;			/* as understood by libvips */
	JxlBoxType box_type;		/* as understood by libjxl */
} VipsForeignSaveJxlMetadata;

static VipsForeignSaveJxlMetadata libjxl_metadata[] = {
	{ VIPS_META_EXIF_NAME, "Exif" },
	{ VIPS_META_XMP_NAME, "xml " }
};

static void
vips_foreign_save_jxl_dispose(GObject *gobject)
{
	VipsForeignSaveJxl *jxl = (VipsForeignSaveJxl *) gobject;

	// wait for bg thread to exit
	if (jxl->add_chunked_frame_running) {
		vips_semaphore_down(&jxl->frame_complete);
		jxl->add_chunked_frame_running = FALSE;
	}

	VIPS_UNREF(jxl->target);

	VIPS_FREEF(JxlThreadParallelRunnerDestroy, jxl->runner);
	VIPS_FREEF(JxlEncoderDestroy, jxl->encoder);
	VIPS_FREEF(vips_tracked_free, jxl->scanline_buffer);

	vips_semaphore_destroy(&jxl->tiles_written);
	vips_semaphore_destroy(&jxl->tiles_available);
	vips_semaphore_destroy(&jxl->frame_complete);

	G_OBJECT_CLASS(vips_foreign_save_jxl_parent_class)->dispose(gobject);
}

#ifdef DEBUG
static void
vips_foreign_save_jxl_print_info(JxlBasicInfo *info)
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
vips_foreign_save_jxl_print_format(JxlPixelFormat *format)
{
	printf("JxlPixelFormat:\n");
	printf("    num_channels = %d\n", format->num_channels);
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
	printf("    endianness = %d\n", format->endianness);
	printf("    align = %zd\n", format->align);
}

static void
vips_foreign_save_jxl_print_status(JxlEncoderStatus status)
{
	switch (status) {
	case JXL_ENC_SUCCESS:
		printf("JXL_ENC_SUCCESS\n");
		break;

	case JXL_ENC_ERROR:
		printf("JXL_ENC_ERROR\n");
		break;

	case JXL_ENC_NEED_MORE_OUTPUT:
		printf("JXL_ENC_NEED_MORE_OUTPUT\n");
		break;

	case JXL_ENC_NOT_SUPPORTED:
		printf("JXL_ENC_NOT_SUPPORTED\n");
		break;

	default:
		printf("JXL_ENC_<unknown>\n");
		break;
	}
}
#endif /*DEBUG*/

static int
vips_foreign_save_jxl_set_header(VipsForeignSaveJxl *jxl, VipsImage *in)
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS(jxl);

	JxlEncoderInitBasicInfo(&jxl->info);

	switch (in->BandFmt) {
	case VIPS_FORMAT_UCHAR:
		jxl->info.bits_per_sample = 8;
		jxl->info.exponent_bits_per_sample = 0;
		jxl->format.data_type = JXL_TYPE_UINT8;
		break;

	case VIPS_FORMAT_USHORT:
		jxl->info.bits_per_sample = 16;
		jxl->info.exponent_bits_per_sample = 0;
		jxl->format.data_type = JXL_TYPE_UINT16;
		break;

	case VIPS_FORMAT_FLOAT:
		jxl->info.bits_per_sample = 32;
		jxl->info.exponent_bits_per_sample = 8;
		jxl->format.data_type = JXL_TYPE_FLOAT;
		break;

	default:
		g_assert_not_reached();
		break;
	}

	switch (in->Type) {
	case VIPS_INTERPRETATION_B_W:
	case VIPS_INTERPRETATION_GREY16:
		jxl->info.num_color_channels = VIPS_MIN(1, in->Bands);
		break;

	case VIPS_INTERPRETATION_sRGB:
	case VIPS_INTERPRETATION_scRGB:
	case VIPS_INTERPRETATION_RGB16:
		jxl->info.num_color_channels = VIPS_MIN(3, in->Bands);
		break;

	default:
		jxl->info.num_color_channels = in->Bands;
	}
	jxl->info.num_extra_channels = VIPS_MAX(0,
		in->Bands - jxl->info.num_color_channels);

	jxl->info.xsize = in->Xsize;
	jxl->info.ysize = jxl->page_height;
	jxl->format.num_channels = in->Bands;
	jxl->format.endianness = JXL_NATIVE_ENDIAN;
	jxl->format.align = 0;

	if (jxl->page_count > 1) {
		int num_loops = 0;

		if (vips_image_get_typeof(in, "loop"))
			vips_image_get_int(in, "loop", &num_loops);

		jxl->info.have_animation = TRUE;
		jxl->info.animation.tps_numerator = 1000;
		jxl->info.animation.tps_denominator = 1;
		jxl->info.animation.num_loops = num_loops;
		jxl->info.animation.have_timecodes = FALSE;
	}

	if (vips_image_hasalpha(in)) {
		jxl->info.alpha_bits = jxl->info.bits_per_sample;
		jxl->info.alpha_exponent_bits = jxl->info.exponent_bits_per_sample;
	}
	else {
		jxl->info.alpha_exponent_bits = 0;
		jxl->info.alpha_bits = 0;
	}

	if (vips_image_get_typeof(in, "stonits")) {
		double stonits;

		if (vips_image_get_double(in, "stonits", &stonits))
			return -1;
		jxl->info.intensity_target = stonits;
	}

	/* uses_original_profile forces libjxl to not use lossy XYB
	 * colourspace. The name is very confusing.
	 */
	jxl->info.uses_original_profile = jxl->lossless;

	if (JxlEncoderSetBasicInfo(jxl->encoder, &jxl->info)) {
		vips_foreign_save_jxl_error(jxl, "JxlEncoderSetBasicInfo");
		return -1;
	}

	/* Set any ICC profile.
	 */
	if (vips_image_get_typeof(in, VIPS_META_ICC_NAME)) {
		const void *data;
		size_t length;

		if (vips_image_get_blob(in, VIPS_META_ICC_NAME, &data, &length))
			return -1;

#ifdef DEBUG
		printf("attaching %zd bytes of ICC\n", length);
#endif /*DEBUG*/
		if (JxlEncoderSetICCProfile(jxl->encoder, (guint8 *) data, length)) {
			vips_foreign_save_jxl_error(jxl, "JxlEncoderSetColorEncoding");
			return -1;
		}
	}
	else {
		/* If there's no ICC profile, we must set the colour encoding
		 * ourselves.
		 */
		if (in->Type == VIPS_INTERPRETATION_scRGB) {
#ifdef DEBUG
			printf("setting scRGB colourspace\n");
#endif /*DEBUG*/

			JxlColorEncodingSetToLinearSRGB(&jxl->color_encoding,
				jxl->format.num_channels < 3);
		}
		else {
#ifdef DEBUG
			printf("setting sRGB colourspace\n");
#endif /*DEBUG*/

			JxlColorEncodingSetToSRGB(&jxl->color_encoding,
				jxl->format.num_channels < 3);
		}

		if (JxlEncoderSetColorEncoding(jxl->encoder, &jxl->color_encoding)) {
			vips_foreign_save_jxl_error(jxl, "JxlEncoderSetColorEncoding");
			return -1;
		}
	}

	for (int i = 0; i < VIPS_NUMBER(libjxl_metadata); i++)
		if (vips_image_get_typeof(in, libjxl_metadata[i].name)) {
			uint8_t *data;
			size_t length;

#ifdef DEBUG
			printf("attaching %s ..\n", libjxl_metadata[i].name);
#endif /*DEBUG*/

			if (vips_image_get_blob(in,
					libjxl_metadata[i].name, (const void **) &data, &length))
				return -1;

			/* It's safe to call JxlEncoderUseBoxes multiple times
			 */
			if (JxlEncoderUseBoxes(jxl->encoder) != JXL_ENC_SUCCESS) {
				vips_foreign_save_jxl_error(jxl, "JxlEncoderUseBoxes");
				return -1;
			}

			/* JPEG XL stores EXIF data without leading "Exif\0\0" with offset
			 */
			if (!strcmp(libjxl_metadata[i].name, VIPS_META_EXIF_NAME)) {
				if (length >= 6 && vips_isprefix("Exif", (char *) data)) {
					data = data + 6;
					length -= 6;
				}

				size_t exif_size = length + 4;
				uint8_t *exif_data = g_malloc0(exif_size);

				if (!exif_data) {
					vips_error(class->nickname, "%s", _("out of memory"));
					return -1;
				}

				/* The first 4 bytes is offset which is 0 in this case
				 */
				memcpy(exif_data + 4, data, length);

				if (JxlEncoderAddBox(jxl->encoder, libjxl_metadata[i].box_type,
						exif_data, exif_size, JXL_TRUE) != JXL_ENC_SUCCESS) {
					vips_foreign_save_jxl_error(jxl, "JxlEncoderAddBox");
					return -1;
				}

				g_free(exif_data);
			}
			else {
				if (JxlEncoderAddBox(jxl->encoder, libjxl_metadata[i].box_type,
						data, length, JXL_TRUE) != JXL_ENC_SUCCESS) {
					vips_foreign_save_jxl_error(jxl, "JxlEncoderAddBox");
					return -1;
				}
			}
		}

	/* It's safe to call JxlEncoderCloseBoxes even if we don't use boxes
	 */
	JxlEncoderCloseBoxes(jxl->encoder);

	return 0;
}

static int
vips_foreign_save_jxl_add_frame(VipsForeignSaveJxl *jxl)
{
	JxlEncoderFrameSettings *frame_settings;

	frame_settings = JxlEncoderFrameSettingsCreate(jxl->encoder, NULL);
	JxlEncoderFrameSettingsSetOption(frame_settings,
		JXL_ENC_FRAME_SETTING_DECODING_SPEED, jxl->tier);
	JxlEncoderSetFrameDistance(frame_settings, jxl->distance);
	JxlEncoderFrameSettingsSetOption(frame_settings,
		JXL_ENC_FRAME_SETTING_EFFORT, jxl->effort);
	JxlEncoderSetFrameLossless(frame_settings, jxl->lossless);

	if (jxl->info.have_animation) {
		JxlFrameHeader header;
		memset(&header, 0, sizeof(JxlFrameHeader));

		if (jxl->delay && jxl->page_number < jxl->delay_length)
			header.duration = jxl->delay[jxl->page_number];
		else
			header.duration = jxl->gif_delay * 10;

		JxlEncoderSetFrameHeader(frame_settings, &header);
	}

	if (JxlEncoderAddImageFrame(frame_settings, &jxl->format,
			jxl->scanline_buffer, jxl->scanline_size)) {
		vips_foreign_save_jxl_error(jxl, "JxlEncoderAddImageFrame");
		return -1;
	}

	jxl->page_number += 1;

	/* We should close frames before processing the output
	 * if we have written the last frame.
	 */
	if (jxl->page_number == jxl->page_count)
		JxlEncoderCloseFrames(jxl->encoder);

	return vips_foreign_save_jxl_process_output(jxl);
}

/* Another chunk of pixels have arrived from the pipeline. Add to frame, and
 * if the frame completes, compress and write to the target.
 */
static int
vips_foreign_save_jxl_sink_disc(VipsRegion *region, VipsRect *area, void *a)
{
	VipsForeignSaveJxl *jxl = (VipsForeignSaveJxl *) a;
	size_t sz = VIPS_IMAGE_SIZEOF_PEL(region->im) * area->width;

	int i;

	/* Write the new pixels into the frame.
	 */
	for (i = 0; i < area->height; i++) {
		memcpy(jxl->scanline_buffer + sz * jxl->scanline_y,
			VIPS_REGION_ADDR(region, 0, area->top + i),
			sz);

		jxl->scanline_y += 1;

		/* If we've filled the frame, add it to the encoder.
		 */
		if (jxl->scanline_y == jxl->page_height) {
			if (vips_foreign_save_jxl_add_frame(jxl))
				return -1;

			jxl->scanline_y = 0;
		}
	}

	return 0;
}

static int
vips_foreign_save_jxl_save_sequential(VipsForeignSaveJxl *jxl, VipsImage *in)
{
	/* Write the header.
	 */
	if (vips_foreign_save_jxl_process_output(jxl))
		return -1;

	/* RGB(A) frame as a contiguous buffer.
	 */
	jxl->scanline_size = VIPS_IMAGE_SIZEOF_LINE(in) * jxl->page_height;
	if (!(jxl->scanline_buffer = vips_tracked_malloc(jxl->scanline_size)))
		return -1;

	if (vips_sink_disc(in, vips_foreign_save_jxl_sink_disc, jxl))
		return -1;

	/* This function must be called after the final frame and/or box,
	 * otherwise the codestream will not be encoded correctly.
	 */
	JxlEncoderCloseInput(jxl->encoder);

	/* Flush any remaining libjxl writes.
	 */
	if (vips_foreign_save_jxl_process_output(jxl))
		return -1;

	return 0;
}

static int
vips_foreign_save_jxl_save_chunked_page(VipsForeignSaveJxl *jxl,
	int n, VipsImage *page, VipsRegion *region)
{
	jxl->region = region;

	JxlEncoderFrameSettings *frame_settings;
	frame_settings = JxlEncoderFrameSettingsCreate(jxl->encoder, NULL);
	JxlEncoderFrameSettingsSetOption(frame_settings,
		JXL_ENC_FRAME_SETTING_DECODING_SPEED, jxl->tier);
	JxlEncoderSetFrameDistance(frame_settings, jxl->distance);
	JxlEncoderFrameSettingsSetOption(frame_settings,
		JXL_ENC_FRAME_SETTING_EFFORT, jxl->effort);
	JxlEncoderSetFrameLossless(frame_settings, jxl->lossless);

	if (jxl->info.have_animation) {
		JxlFrameHeader header;
		memset(&header, 0, sizeof(JxlFrameHeader));

		if (jxl->delay &&
			n < jxl->delay_length)
			header.duration = jxl->delay[n];
		else
			header.duration = jxl->gif_delay * 10;

		JxlEncoderSetFrameHeader(frame_settings, &header);
	}

	if (JxlEncoderAddChunkedFrame(frame_settings,
		n == jxl->page_count - 1, jxl->input_source)) {
		vips_foreign_save_jxl_error(jxl, "JxlEncoderAddImageFrame");
		return -1;
	}

	return 0;
}

static int
vips_foreign_save_jxl_save_chunked(VipsForeignSaveJxl *jxl, VipsImage *in)
{
	vips_foreign_save_jxl_set_output_processor(jxl);
	vips_foreign_save_jxl_set_input_source(jxl);

	for (int n = 0; n < jxl->page_count; n++) {
		VipsImage *page;
		VipsRegion *region;

		if (vips_crop(in, &page,
			0, n * jxl->page_height, in->Xsize, jxl->page_height, NULL))
			return -1;

		if (!(region = vips_region_new(page))) {
			VIPS_UNREF(page);
			return -1;
		}

		if (vips_foreign_save_jxl_save_chunked_page(jxl, n, page, region)) {
			VIPS_UNREF(region);
			VIPS_UNREF(page);
			return -1;
		}

		VIPS_UNREF(region);
		VIPS_UNREF(page);
	}

	return 0;
}

static int
vips_foreign_save_jxl_build(VipsObject *object)
{
	VipsForeignSave *save = (VipsForeignSave *) object;
	VipsForeignSaveJxl *jxl = (VipsForeignSaveJxl *) object;
	VipsImage **t = (VipsImage **) vips_object_local_array(object, 2);

	VipsImage *in;
	VipsBandFormat format;
	int i;

	if (VIPS_OBJECT_CLASS(vips_foreign_save_jxl_parent_class)->build(object))
		return -1;

	jxl->page_height = vips_image_get_page_height(save->ready);
	jxl->page_count = save->ready->Ysize / jxl->page_height;

	/* If Q is set and distance is not, use Q to set a rough distance
	 * value.
	 */
	if (!vips_object_argument_isset(object, "distance"))
		jxl->distance = JxlEncoderDistanceFromQuality((float) jxl->Q);

	/* Distance 0 is lossless. libjxl will fail for lossy distance 0.
	 */
	if (jxl->distance == 0)
		jxl->lossless = TRUE;

	jxl->runner = JxlThreadParallelRunnerCreate(NULL, vips_concurrency_get());
	jxl->encoder = JxlEncoderCreate(NULL);

	if (JxlEncoderSetParallelRunner(jxl->encoder,
			JxlThreadParallelRunner, jxl->runner)) {
		vips_foreign_save_jxl_error(jxl, "JxlDecoderSetParallelRunner");
		return -1;
	}

	in = save->ready;

	/* Fix the input image format. JXL uses float for 0-1 linear (ie.
	 * scRGB) only. We must convert eg. sRGB float to 8-bit for save.
	 */
	if (in->Type == VIPS_INTERPRETATION_scRGB)
		format = VIPS_FORMAT_FLOAT;
	else if (in->Type == VIPS_INTERPRETATION_RGB16 ||
		in->Type == VIPS_INTERPRETATION_GREY16)
		format = VIPS_FORMAT_USHORT;
	else
		format = VIPS_FORMAT_UCHAR;

	if (vips_cast(in, &t[0], format, NULL))
		return -1;
	in = t[0];

	/* Mimics VIPS_SAVEABLE_RGBA.
	 * FIXME: add support encoding images with > 4 bands.
	 */
	if (in->Bands > 4) {
		if (vips_extract_band(in, &t[1], 0,
				"n", 4,
				NULL))
			return -1;
		in = t[1];
	}

	if (vips_foreign_save_jxl_set_header(jxl, in))
		return -1;

	if (jxl->info.have_animation) {
		/* Get delay array
		 *
		 * There might just be the old gif-delay field. This is centiseconds.
		 */
		jxl->gif_delay = 10;
		if (vips_image_get_typeof(in, "gif-delay") &&
			vips_image_get_int(in, "gif-delay", &jxl->gif_delay))
			return -1;

		/* New images have an array of ints instead.
		 */
		jxl->delay = NULL;
		if (vips_image_get_typeof(in, "delay") &&
			vips_image_get_array_int(in, "delay",
				&jxl->delay, &jxl->delay_length))
			return -1;

		/* Force frames with a small or no duration to 100ms
		 * to be consistent with web browsers and other
		 * transcoding tools.
		 */
		if (jxl->gif_delay <= 1)
			jxl->gif_delay = 10;

		for (i = 0; i < jxl->delay_length; i++)
			if (jxl->delay[i] <= 10)
				jxl->delay[i] = 100;
	}

#ifdef DEBUG
	vips_foreign_save_jxl_print_info(&jxl->info);
	vips_foreign_save_jxl_print_format(&jxl->format);
	printf("JxlEncoderFrameSettings:\n");
	printf("    tier = %d\n", jxl->tier);
	printf("    distance = %g\n", jxl->distance);
	printf("    effort = %d\n", jxl->effort);
	printf("    lossless = %d\n", jxl->lossless);
#endif /*DEBUG*/

	if (jxl->chunked) {
		if (vips_foreign_save_jxl_save_chunked(jxl, in))
			return -1;
	}
	else  {
		if (vips_foreign_save_jxl_save_sequential(jxl, in))
			return -1;
	}

	if (vips_target_end(jxl->target))
		return -1;

	return 0;
}

/* Save a bit of typing.
 */
#define UC VIPS_FORMAT_UCHAR
#define US VIPS_FORMAT_USHORT
#define F VIPS_FORMAT_FLOAT

/* Type promotion for save ... unsigned ints + float + double.
 */
static VipsBandFormat bandfmt_jxl[10] = {
	/* Band format:  UC  C   US  S   UI I  F  X  D DX */
	/* Promotion: */ UC, UC, US, US, F, F, F, F, F, F
};

static void
vips_foreign_save_jxl_class_init(VipsForeignSaveJxlClass *class)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS(class);
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsOperationClass *operation_class = VIPS_OPERATION_CLASS(class);
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;
	VipsForeignSaveClass *save_class = (VipsForeignSaveClass *) class;

	gobject_class->dispose = vips_foreign_save_jxl_dispose;
	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "jxlsave_base";
	object_class->description = _("save image in JPEG-XL format");
	object_class->build = vips_foreign_save_jxl_build;

	/* libjxl is fuzzed, but it's still relatively young and bugs are
	 * still being found in jan 2022. Revise this status soon.
	 */
	operation_class->flags |= VIPS_OPERATION_UNTRUSTED;

	foreign_class->suffs = vips__jxl_suffs;

	save_class->saveable = VIPS_SAVEABLE_ANY;
	save_class->format_table = bandfmt_jxl;

	VIPS_ARG_INT(class, "tier", 10,
		_("Tier"),
		_("Decode speed tier"),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET(VipsForeignSaveJxl, tier),
		0, 4, 0);

	VIPS_ARG_DOUBLE(class, "distance", 11,
		_("Distance"),
		_("Target butteraugli distance"),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET(VipsForeignSaveJxl, distance),
		0.0, 25.0, 1.0);

	VIPS_ARG_INT(class, "effort", 12,
		_("Effort"),
		_("Encoding effort"),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET(VipsForeignSaveJxl, effort),
		1, 9, 7);

	VIPS_ARG_BOOL(class, "lossless", 13,
		_("Lossless"),
		_("Enable lossless compression"),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET(VipsForeignSaveJxl, lossless),
		FALSE);

	VIPS_ARG_INT(class, "Q", 14,
		_("Q"),
		_("Quality factor"),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET(VipsForeignSaveJxl, Q),
		0, 100, 75);

	VIPS_ARG_BOOL(class, "chunked", 15,
		_("Chunked"),
		_("Used chunked write API"),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET(VipsForeignSaveJxl, chunked),
		FALSE);
}

static void
vips_foreign_save_jxl_init(VipsForeignSaveJxl *jxl)
{
	jxl->distance = 1.0;
	jxl->effort = 7;
	jxl->Q = 75;

	vips_semaphore_init(&tiles_written, 0, "tiles_written");
	vips_semaphore_init(&tiles_available, 0, "tiles_available");
	vips_semaphore_init(&frame_complete, 0, "frame_complete");
}

typedef struct _VipsForeignSaveJxlFile {
	VipsForeignSaveJxl parent_object;

	/* Filename for save.
	 */
	char *filename;

} VipsForeignSaveJxlFile;

typedef VipsForeignSaveJxlClass VipsForeignSaveJxlFileClass;

G_DEFINE_TYPE(VipsForeignSaveJxlFile, vips_foreign_save_jxl_file,
	vips_foreign_save_jxl_get_type());

static int
vips_foreign_save_jxl_file_build(VipsObject *object)
{
	VipsForeignSaveJxl *jxl = (VipsForeignSaveJxl *) object;
	VipsForeignSaveJxlFile *file = (VipsForeignSaveJxlFile *) object;

	if (!(jxl->target = vips_target_new_to_file(file->filename)))
		return -1;

	if (VIPS_OBJECT_CLASS(vips_foreign_save_jxl_file_parent_class)->build(object))
		return -1;

	return 0;
}

static void
vips_foreign_save_jxl_file_class_init(VipsForeignSaveJxlFileClass *class)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS(class);
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "jxlsave";
	object_class->build = vips_foreign_save_jxl_file_build;

	VIPS_ARG_STRING(class, "filename", 1,
		_("Filename"),
		_("Filename to save to"),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET(VipsForeignSaveJxlFile, filename),
		NULL);
}

static void
vips_foreign_save_jxl_file_init(VipsForeignSaveJxlFile *file)
{
}

typedef struct _VipsForeignSaveJxlBuffer {
	VipsForeignSaveJxl parent_object;

	/* Save to a buffer.
	 */
	VipsArea *buf;

} VipsForeignSaveJxlBuffer;

typedef VipsForeignSaveJxlClass VipsForeignSaveJxlBufferClass;

G_DEFINE_TYPE(VipsForeignSaveJxlBuffer, vips_foreign_save_jxl_buffer,
	vips_foreign_save_jxl_get_type());

static int
vips_foreign_save_jxl_buffer_build(VipsObject *object)
{
	VipsForeignSaveJxl *jxl = (VipsForeignSaveJxl *) object;
	VipsForeignSaveJxlBuffer *buffer =
		(VipsForeignSaveJxlBuffer *) object;

	VipsBlob *blob;

	if (!(jxl->target = vips_target_new_to_memory()))
		return -1;

	if (VIPS_OBJECT_CLASS(vips_foreign_save_jxl_buffer_parent_class)
			->build(object))
		return -1;

	g_object_get(jxl->target, "blob", &blob, NULL);
	g_object_set(buffer, "buffer", blob, NULL);
	vips_area_unref(VIPS_AREA(blob));

	return 0;
}

static void
vips_foreign_save_jxl_buffer_class_init(
	VipsForeignSaveJxlBufferClass *class)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS(class);
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "jxlsave_buffer";
	object_class->build = vips_foreign_save_jxl_buffer_build;

	VIPS_ARG_BOXED(class, "buffer", 1,
		_("Buffer"),
		_("Buffer to save to"),
		VIPS_ARGUMENT_REQUIRED_OUTPUT,
		G_STRUCT_OFFSET(VipsForeignSaveJxlBuffer, buf),
		VIPS_TYPE_BLOB);
}

static void
vips_foreign_save_jxl_buffer_init(VipsForeignSaveJxlBuffer *buffer)
{
}

typedef struct _VipsForeignSaveJxlTarget {
	VipsForeignSaveJxl parent_object;

	VipsTarget *target;
} VipsForeignSaveJxlTarget;

typedef VipsForeignSaveJxlClass VipsForeignSaveJxlTargetClass;

G_DEFINE_TYPE(VipsForeignSaveJxlTarget, vips_foreign_save_jxl_target,
	vips_foreign_save_jxl_get_type());

static int
vips_foreign_save_jxl_target_build(VipsObject *object)
{
	VipsForeignSaveJxl *jxl = (VipsForeignSaveJxl *) object;
	VipsForeignSaveJxlTarget *target =
		(VipsForeignSaveJxlTarget *) object;

	if (target->target) {
		jxl->target = target->target;
		g_object_ref(jxl->target);
	}

	if (VIPS_OBJECT_CLASS(vips_foreign_save_jxl_target_parent_class)
			->build(object))
		return -1;

	return 0;
}

static void
vips_foreign_save_jxl_target_class_init(
	VipsForeignSaveJxlTargetClass *class)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS(class);
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "jxlsave_target";
	object_class->build = vips_foreign_save_jxl_target_build;

	VIPS_ARG_OBJECT(class, "target", 1,
		_("Target"),
		_("Target to save to"),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET(VipsForeignSaveJxlTarget, target),
		VIPS_TYPE_TARGET);
}

static void
vips_foreign_save_jxl_target_init(VipsForeignSaveJxlTarget *target)
{
}

#endif /*HAVE_LIBJXL*/

/* The C API wrappers are defined in foreign.c.
 */
