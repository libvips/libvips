/* Load/save png image with libpng
 *
 * 28/11/03 JC
 *	- better no-overshoot on tile loop
 * 22/2/05
 *	- read non-interlaced PNG with a line buffer (thanks Michel Brabants)
 * 11/1/06
 * 	- read RGBA palette-ized images more robustly (thanks Tom)
 * 20/4/06
 * 	- auto convert to sRGB/mono (with optional alpha) for save
 * 1/5/06
 * 	- from vips_png.c
 * 8/5/06
 * 	- set RGB16/GREY16 if appropriate
 * 2/11/07
 * 	- use im_wbuffer() API for BG writes
 * 28/2/09
 * 	- small cleanups
 * 4/2/10
 * 	- gtkdoc
 * 	- fixed 16-bit save
 * 12/5/10
 * 	- lololo but broke 8-bit save, fixed again
 * 20/7/10 Tim Elliott
 * 	- added im_vips2bufpng()
 * 8/1/11
 * 	- get set png resolution (thanks Zhiyu Wu)
 * 17/3/11
 * 	- update for libpng-1.5 API changes
 * 	- better handling of palette and 1-bit images
 * 	- ... but we are now png 1.2.9 and later only :-( argh
 * 28/3/11
 * 	- argh gamma was wrong when viewed in firefox
 * 19/12/11
 * 	- rework as a set of fns ready for wrapping as a class
 * 7/2/12
 * 	- mild refactoring
 * 	- add support for sequential reads
 * 23/2/12
 * 	- add a longjmp() to our error handler to stop the default one running
 * 13/3/12
 * 	- add ICC profile read/write
 * 15/3/12
 * 	- better alpha handling
 * 	- sanity check pixel geometry before allowing read
 * 17/6/12
 * 	- more alpha fixes ... some images have no transparency chunk but
 * 	  still set color_type to alpha
 * 16/7/13
 * 	- more robust error handling from libpng
 * 9/8/14
 * 	- don't check profiles, helps with libpng >=1.6.11
 * 27/10/14 Lovell
 * 	- add @filter option
 * 26/2/15
 * 	- close the read down early for a header read ... this saves an
 * 	  fd during file read, handy for large numbers of input images
 * 31/7/16
 * 	- support --strip option
 * 17/1/17
 * 	- invalidate operation on read error
 * 27/2/17
 * 	- use dbuf for buffer output
 * 30/3/17
 * 	- better behaviour for truncated png files, thanks Yury
 * 26/4/17
 * 	- better @fail handling with truncated PNGs
 * 9/4/18
 * 	- set interlaced=1 for interlaced images
 * 20/6/18 [felixbuenemann]
 * 	- support png8 palette write with palette, colours, Q, dither
 * 25/8/18
 * 	- support xmp read/write
 * 20/4/19
 * 	- allow huge xmp metadata
 * 7/10/19
 * 	- restart after minimise
 * 14/10/19
 * 	- revise for connection IO
 * 11/5/20
 * 	- only warn for saving bad profiles, don't fail
 * 19/2/21 781545872
 * 	- read out background, if we can
 * 29/8/21 joshuamsager
 *	-  add "unlimited" flag to png load
 * 13/1/22
 * 	- raise libpng pixel size limit to VIPS_MAX_COORD
 * 17/11/22
 * 	- add exif read/write
 * 3/2/23 MathemanFlo
 * 	- add bits per sample metadata
 * 23/12/25 Starbix
 *  - add support for reading cICP chunk
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
#define VIPS_DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <glib/gi18n-lib.h>

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <vips/vips.h>
#include <vips/internal.h>
#include <vips/debug.h>

#include "pforeign.h"
#include "quantise.h"

/* Shared with spng load/save.
 */
const char *vips__png_suffs[] = { ".png", NULL };

#ifdef HAVE_PNG

#include <png.h>

#if PNG_LIBPNG_VER < 10003
#error "PNG library too old."
#endif

/* Compat defines for APNG constants.
 * libpng 1.8+ uses PNG_fcTL_DISPOSE_OP_NONE etc.
 * libpng 1.6 + APNG patch uses PNG_DISPOSE_OP_NONE etc.
 */
#ifdef PNG_APNG_SUPPORTED
#ifndef PNG_fcTL_DISPOSE_OP_NONE
#define PNG_fcTL_DISPOSE_OP_NONE PNG_DISPOSE_OP_NONE
#define PNG_fcTL_DISPOSE_OP_BACKGROUND PNG_DISPOSE_OP_BACKGROUND
#define PNG_fcTL_DISPOSE_OP_PREVIOUS PNG_DISPOSE_OP_PREVIOUS
#define PNG_fcTL_BLEND_OP_SOURCE PNG_BLEND_OP_SOURCE
#define PNG_fcTL_BLEND_OP_OVER PNG_BLEND_OP_OVER
#endif
#endif /*PNG_APNG_SUPPORTED*/

static void
user_error_function(png_structp png_ptr, png_const_charp error_msg)
{
#ifdef DEBUG
	printf("user_error_function: %s\n", error_msg);
#endif /*DEBUG*/

	g_warning("%s", error_msg);

	/* This function must not return or the default error handler will be
	 * invoked.
	 */
	longjmp(png_jmpbuf(png_ptr), -1);
}

static void
user_warning_function(png_structp png_ptr, png_const_charp warning_msg)
{
#ifdef DEBUG
	printf("user_warning_function: %s\n", warning_msg);
#endif /*DEBUG*/

	g_warning("%s", warning_msg);
}

#define INPUT_BUFFER_SIZE (4096)

/* What we track during a PNG read.
 */
typedef struct {
	char *name;
	VipsImage *out;
	VipsFailOn fail_on;
	gboolean unlimited;

	int y_pos;
	png_structp pPng;
	png_infop pInfo;
	png_bytep *row_pointer;

	VipsSource *source;

	/* read() to this buffer, copy to png as required. libpng does many
	 * very small reads and we want to avoid a syscall for each one.
	 */
	unsigned char input_buffer[INPUT_BUFFER_SIZE];
	unsigned char *next_byte;
	gint64 bytes_in_buffer;

#ifdef PNG_APNG_SUPPORTED
	/* APNG animation fields.
	 */
	int page;		/* first frame to load */
	int n;			/* number of frames to load */

	int frame_count;	/* total frames in file */
	int num_plays;		/* loop count (0 = infinite) */
	gboolean is_animated;	/* TRUE if APNG with multiple frames */

	int *delays;		/* per-frame delay in ms */

	/* Compositing canvas (RGBA or GA, full frame size).
	 */
	VipsImage *canvas;
	int canvas_width;
	int canvas_height;

	/* Current frame number (0-based, relative to file).
	 */
	int frame_no;

	/* Previous frame's dispose method and rect for dispose handling.
	 */
	int dispose_op;
	VipsRect dispose_rect;

	/* Saved canvas data for DISPOSE_OP_PREVIOUS.
	 */
	VipsPel *previous_canvas_data;
	VipsRect previous_rect;

	/* Output bands: canvas always has alpha, but we may strip it.
	 */
	gboolean has_alpha;

	/* Number of bands and format of the canvas.
	 */
	int canvas_bands;
#endif /*PNG_APNG_SUPPORTED*/

} Read;

/* Can be called many times.
 */
static void
read_destroy(Read *read)
{
	/* We never call png_read_end(), perhaps we should. It can fail on
	 * truncated files, so we'd need a setjmp().
	 */

	if (read->pPng)
		png_destroy_read_struct(&read->pPng, &read->pInfo, NULL);
	VIPS_UNREF(read->source);
	VIPS_FREE(read->row_pointer);

#ifdef PNG_APNG_SUPPORTED
	VIPS_FREE(read->delays);
	VIPS_UNREF(read->canvas);
	VIPS_FREE(read->previous_canvas_data);
#endif /*PNG_APNG_SUPPORTED*/
}

static void
read_close_cb(VipsImage *out, Read *read)
{
	read_destroy(read);
}

static void
read_minimise_cb(VipsImage *image, Read *read)
{
	if (read->source)
		vips_source_minimise(read->source);
}

static void
vips_png_read_source(png_structp pPng, png_bytep data, png_size_t length)
{
	Read *read = png_get_io_ptr(pPng);

#ifdef DEBUG
	printf("vips_png_read_source: read %zd bytes\n", length);
#endif /*DEBUG*/

	/* libpng makes many small reads, which hurts performance if you do a
	 * syscall for each one. Read via our own buffer.
	 */
	while (length > 0) {
		gint64 bytes_available;

		if (read->bytes_in_buffer <= 0) {
			gint64 bytes_read;

			bytes_read = vips_source_read(read->source,
				read->input_buffer, INPUT_BUFFER_SIZE);
			if (bytes_read <= 0)
				png_error(pPng, "not enough data");

			read->next_byte = read->input_buffer;
			read->bytes_in_buffer = bytes_read;
		}

		bytes_available = VIPS_MIN(read->bytes_in_buffer, length);
		memcpy(data, read->next_byte, bytes_available);
		data += bytes_available;
		length -= bytes_available;
		read->next_byte += bytes_available;
		read->bytes_in_buffer -= bytes_available;
	}
}

static Read *
read_new(VipsSource *source, VipsImage *out,
	int page, int n, VipsFailOn fail_on, gboolean unlimited)
{
	Read *read;

	if (!(read = VIPS_NEW(out, Read)))
		return NULL;

	read->name = NULL;
	read->fail_on = fail_on;
	read->out = out;
	read->y_pos = 0;
	read->pPng = NULL;
	read->pInfo = NULL;
	read->row_pointer = NULL;
	read->source = source;
	read->unlimited = unlimited;

#ifdef PNG_APNG_SUPPORTED
	read->page = page;
	read->n = n;
	read->frame_count = 0;
	read->num_plays = 0;
	read->is_animated = FALSE;
	read->delays = NULL;
	read->canvas = NULL;
	read->canvas_width = 0;
	read->canvas_height = 0;
	read->frame_no = 0;
	read->dispose_op = PNG_fcTL_DISPOSE_OP_NONE;
	memset(&read->dispose_rect, 0, sizeof(VipsRect));
	read->previous_canvas_data = NULL;
	memset(&read->previous_rect, 0, sizeof(VipsRect));
	read->has_alpha = FALSE;
	read->canvas_bands = 0;
#endif /*PNG_APNG_SUPPORTED*/

	g_object_ref(source);

	g_signal_connect(out, "close",
		G_CALLBACK(read_close_cb), read);
	g_signal_connect(out, "minimise",
		G_CALLBACK(read_minimise_cb), read);

	if (!(read->pPng = png_create_read_struct(
			  PNG_LIBPNG_VER_STRING, NULL,
			  user_error_function, user_warning_function)))
		return NULL;

		/* Prevent libpng (>=1.6.11) verifying sRGB profiles. Many PNGs have
		 * broken profiles, but we still want to be able to open them.
		 */
#ifdef PNG_SKIP_sRGB_CHECK_PROFILE
	png_set_option(read->pPng,
		PNG_SKIP_sRGB_CHECK_PROFILE, PNG_OPTION_ON);
#endif /*PNG_SKIP_sRGB_CHECK_PROFILE*/

	/* In non-fail mode, ignore CRC errors.
	 */
	if (read->fail_on < VIPS_FAIL_ON_ERROR) {
#ifdef PNG_IGNORE_ADLER32
		png_set_option(read->pPng, PNG_IGNORE_ADLER32, PNG_OPTION_ON);
#endif /*PNG_IGNORE_ADLER32*/

		/* Ignore and don't calculate checksums.
		 */
		png_set_crc_action(read->pPng,
			PNG_CRC_QUIET_USE, PNG_CRC_QUIET_USE);
	}

	/* libpng has a default soft limit of 1m pixels per axis.
	 */
	png_set_user_limits(read->pPng, VIPS_MAX_COORD, VIPS_MAX_COORD);

	if (vips_source_rewind(source))
		return NULL;
	png_set_read_fn(read->pPng, read, vips_png_read_source);

	/* Catch PNG errors from png_read_info() etc.
	 */
	if (setjmp(png_jmpbuf(read->pPng)))
		return NULL;

	if (!(read->pInfo = png_create_info_struct(read->pPng)))
		return NULL;

#ifdef HAVE_PNG_SET_CHUNK_MALLOC_MAX

	/* By default, libpng refuses to open files with a metadata chunk
	 * larger than 8mb. We've seen real files with 20mb, so set 50mb.
	 */
	png_set_chunk_malloc_max(read->pPng, 50 * 1024 * 1024);

	/* This limits the number of chunks. The limit from
	 * png_set_chunk_malloc_max() times this value is the maximum
	 * memory use.
	 *
	 * libnpng defaults to 1000, which is rather high.
	 */
	png_set_chunk_cache_max(read->pPng, 100);

#endif /*HAVE_PNG_SET_CHUNK_MALLOC_MAX*/

	png_read_info(read->pPng, read->pInfo);

	return read;
}

static const char *
skip_line(const char *p)
{
	if (!p)
		return NULL;
	while (*p && *p != '\n')
		p++;
	if (*p == '\n')
		p++;
	return p;
}

static const char *
read_length(const char *p, size_t *length)
{
	if (!p)
		return NULL;

	char *q;
	errno = 0;
	gint64 i = g_ascii_strtoll(p, &q, 10);
	// limit the length to 10MB for sanity
	if (errno || q == p || i <= 0 || i > 10 * 1024 * 1024)
		return NULL;

	*length = i;
	return q;
}

static const char *
skip_whitespace(const char *p)
{
	if (p)
		p += strspn(p, " \n");

	return p;
}

static const char *
read_hex_pair(const char *p, uint8_t *value)
{
	if (!p || !p[0] || !p[1])
		return NULL;

	const char val[3] = {p[0], p[1], '\0'};
	char *q;
	errno = 0;
	uint8_t i = (uint8_t) g_ascii_strtoll(val, &q, 16);
	if (errno || q == val)
		return NULL;

	*value = i;
	return p + 2;

}

/* Parse a "Raw profile type exif" text chunk and extract binary EXIF data.
 * Returns a newly allocated buffer with the EXIF data, or NULL on failure.
 * The caller must g_free() the returned buffer.
 *
 * The format is (after zlib decompression by libpng):
 * - A line with the profile type (e.g., "exif")
 * - A line with the byte count in decimal
 * - Hex-encoded binary data (may contain whitespace)
 * source: https://clanmills.com/exiv2/book/ -> "PNG and the Zlib compression library"
 */
static uint8_t *
vips__parse_raw_profile(const char *text, size_t *data_size)
{
	const char *p = text;

	// Raw profile should start with a new line
	p = skip_line(p);
	if (!p) {
		g_warning("pngload: malformed raw profile");
		return NULL;
	}

	// Skip profile type (e.g. "exif")
	p = skip_line(p);

	// number of hex pairs to read
	size_t length;
	p = read_length(p, &length);
	if (!p) {
		g_warning("pngload: malformed raw profile");
		return NULL;
	}

	// Decode EXIF hex string
	uint8_t *data = VIPS_ARRAY(NULL, length, uint8_t);
	if (!data)
		return NULL;

	size_t i;
	for (i = 0; i < length; i++) {
		uint8_t value;

		p = skip_whitespace(p);
		p = read_hex_pair(p, &value);
		if (!p) {
			break;
		}
		data[i] = value;
	}

	if (i < length) {
		g_warning("pngload: malformed raw profile");
		VIPS_FREE(data);
		return NULL;
	}

	*data_size = length;
	return data;
}

/* Set the png text data as metadata on the vips image. These are always
 * null-terminated strings.
 */
static int
vips__set_text(VipsImage *out, int i, const char *key, const char *text)
{
	char name[256];

	if (strcmp(key, "XML:com.adobe.xmp") == 0) {
		/* Save as an XMP tag. This must be a BLOB, for compatibility
		 * for things like the XMP blob that the tiff loader adds.
		 *
		 * Note that this will remove the null-termination from the
		 * string. We must carefully reattach this.
		 */
		vips_image_set_blob_copy(out,
			VIPS_META_XMP_NAME, text, strlen(text));
	}
	else if (strcmp(key, "Raw profile type exif") == 0 ||
		strcmp(key, "Raw profile type APP1") == 0) {
		/* EXIF data stored in ImageMagick/exiftool format.
		 * Only set if we don't already have EXIF from eXIf chunk.
		 */
		if (!vips_image_get_typeof(out, VIPS_META_EXIF_NAME)) {
			size_t exif_length;
			uint8_t *exif_data = vips__parse_raw_profile(text, &exif_length);
			if (exif_data) {
				vips_image_set_blob(out, VIPS_META_EXIF_NAME,
					(VipsCallbackFn) g_free,
					exif_data, exif_length);
			}
		}
	}
	else {
		/* Save as a string comment. Some PNGs have EXIF data as
		 * text segments, but the correct way to support this is with
		 * png_get_eXIf_1().
		 */
		g_snprintf(name, 256, "png-comment-%d-%s", i, key);

		vips_image_set_string(out, name, text);
	}

	return 0;
}

#ifdef PNG_APNG_SUPPORTED

/* Convert APNG delay fraction to milliseconds.
 * Per spec, if delay_den is 0, treat as 100.
 */
static int
apng_delay_to_ms(png_uint_16 delay_num, png_uint_16 delay_den)
{
	if (delay_den == 0)
		delay_den = 100;

	return (int) ((double) delay_num / delay_den * 1000.0 + 0.5);
}

/* Scan raw PNG chunks from the source to extract all fcTL delays.
 * This avoids needing to read pixel data just to get frame timing.
 * Must be called after read->delays is allocated with frame_count entries.
 */
static int
apng_scan_delays(Read *read)
{
	const unsigned char *data;
	size_t size;
	size_t offset;
	int fctl_index = 0;
	int first_frame_hidden;

	data = vips_source_map(read->source, &size);
	if (!data)
		return -1;

	first_frame_hidden = png_get_first_frame_is_hidden(
		read->pPng, read->pInfo);

	/* Skip PNG signature (8 bytes).
	 */
	offset = 8;

	while (offset + 12 <= size &&
		fctl_index < read->frame_count +
			(first_frame_hidden ? 1 : 0)) {
		guint32 chunk_length =
			GUINT32_FROM_BE(*(guint32 *) (data + offset));
		const unsigned char *chunk_type = data + offset + 4;

		if (memcmp(chunk_type, "fcTL", 4) == 0 &&
			chunk_length >= 26 &&
			offset + 8 + chunk_length <= size) {
			const unsigned char *d = data + offset + 8;
			guint16 delay_num =
				GUINT16_FROM_BE(*(guint16 *) (d + 20));
			guint16 delay_den =
				GUINT16_FROM_BE(*(guint16 *) (d + 22));

			/* Skip the hidden first frame's fcTL.
			 */
			if (first_frame_hidden && fctl_index == 0) {
				fctl_index++;
			}
			else {
				int idx = first_frame_hidden
					? fctl_index - 1
					: fctl_index;

				if (idx < read->frame_count)
					read->delays[idx] =
						apng_delay_to_ms(
							delay_num,
							delay_den);
				fctl_index++;
			}
		}

		/* Next chunk: 4 (length) + 4 (type) + data + 4 (CRC).
		 */
		offset += 12 + chunk_length;
	}

	return 0;
}

/* Apply the previous frame's dispose operation to the canvas.
 */
static void
apng_apply_dispose(Read *read)
{
	switch (read->dispose_op) {
	case PNG_fcTL_DISPOSE_OP_NONE:
		/* Leave canvas as-is.
		 */
		break;

	case PNG_fcTL_DISPOSE_OP_BACKGROUND:
	{
		/* Clear the previous frame's region to transparent zeros.
		 */
		int y;
		int ps = VIPS_IMAGE_SIZEOF_PEL(read->canvas);

		for (y = 0; y < read->dispose_rect.height; y++) {
			VipsPel *q = VIPS_IMAGE_ADDR(read->canvas,
				read->dispose_rect.left,
				read->dispose_rect.top + y);
			memset(q, 0,
				(size_t) read->dispose_rect.width * ps);
		}
		break;
	}

	case PNG_fcTL_DISPOSE_OP_PREVIOUS:
		/* Restore previously saved canvas region.
		 */
		if (read->previous_canvas_data) {
			int y;
			int ps = VIPS_IMAGE_SIZEOF_PEL(read->canvas);

			for (y = 0; y < read->previous_rect.height; y++) {
				VipsPel *q = VIPS_IMAGE_ADDR(read->canvas,
					read->previous_rect.left,
					read->previous_rect.top + y);
				memcpy(q,
					read->previous_canvas_data +
						(size_t) y *
							read->previous_rect.width * ps,
					(size_t) read->previous_rect.width * ps);
			}
		}
		break;

	default:
		break;
	}
}

/* Save a region of the canvas for DISPOSE_OP_PREVIOUS.
 */
static int
apng_save_canvas_region(Read *read, VipsRect *rect)
{
	int ps = VIPS_IMAGE_SIZEOF_PEL(read->canvas);
	size_t size = (size_t) rect->width * rect->height * ps;
	int y;

	read->previous_canvas_data = g_realloc(
		read->previous_canvas_data, size);
	read->previous_rect = *rect;

	for (y = 0; y < rect->height; y++) {
		VipsPel *p = VIPS_IMAGE_ADDR(read->canvas,
			rect->left, rect->top + y);
		memcpy(read->previous_canvas_data +
				(size_t) y * rect->width * ps,
			p, (size_t) rect->width * ps);
	}

	return 0;
}

/* Alpha-over composite of a single pixel, 8-bit.
 */
static void
apng_blend_pixel8(VipsPel *restrict bottom, const VipsPel *restrict top,
	int bands)
{
	int aT = top[bands - 1];
	int aB;
	int aR;
	int b;

	if (aT == 0)
		return;

	if (aT == 255) {
		memcpy(bottom, top, bands);
		return;
	}

	aB = bottom[bands - 1];
	/* fac = aB * (255 - aT) / 255, then aR = aT + fac
	 */
	int fac = (aB * (255 - aT) + 127) / 255;
	aR = aT + fac;

	if (aR == 0) {
		memset(bottom, 0, bands);
		return;
	}

	for (b = 0; b < bands - 1; b++)
		bottom[b] = ((top[b] * aT + bottom[b] * fac) * 255 /
						 aR +
					 127) /
			255;
	bottom[bands - 1] = aR;
}

/* Alpha-over composite of a single pixel, 16-bit.
 */
static void
apng_blend_pixel16(VipsPel *restrict bottom_bytes,
	const VipsPel *restrict top_bytes, int bands)
{
	guint16 *bottom = (guint16 *) bottom_bytes;
	const guint16 *top = (const guint16 *) top_bytes;

	guint32 aT = top[bands - 1];
	guint32 aB;
	guint32 aR;
	int b;

	if (aT == 0)
		return;

	if (aT == 65535) {
		memcpy(bottom, top, bands * sizeof(guint16));
		return;
	}

	aB = bottom[bands - 1];
	guint32 fac = (guint32) (aB * (65535 - aT) + 32767) / 65535;
	aR = aT + fac;

	if (aR == 0) {
		memset(bottom, 0, bands * sizeof(guint16));
		return;
	}

	for (b = 0; b < bands - 1; b++)
		bottom[b] = (guint16) ((top[b] * aT + bottom[b] * fac) / aR);
	bottom[bands - 1] = (guint16) aR;
}

/* Composite a decoded sub-frame onto the canvas at the given offset.
 */
static void
apng_composite_frame(Read *read, VipsPel *frame_data,
	int frame_width, int frame_height,
	int x_offset, int y_offset,
	png_byte blend_op, png_byte dispose_op)
{
	int ps = VIPS_IMAGE_SIZEOF_PEL(read->canvas);
	int canvas_bands = read->canvas_bands;
	gboolean is_16bit = read->canvas->BandFmt == VIPS_FORMAT_USHORT;
	VipsRect frame_rect = { x_offset, y_offset, frame_width, frame_height };

	/* If next dispose is PREVIOUS, save the canvas region first.
	 */
	if (dispose_op == PNG_fcTL_DISPOSE_OP_PREVIOUS)
		apng_save_canvas_region(read, &frame_rect);

	if (blend_op == PNG_fcTL_BLEND_OP_SOURCE) {
		/* Direct copy at offset.
		 */
		int y;

		for (y = 0; y < frame_height; y++) {
			VipsPel *q = VIPS_IMAGE_ADDR(read->canvas,
				x_offset, y_offset + y);
			VipsPel *p = frame_data +
				(size_t) y * frame_width * ps;
			memcpy(q, p, (size_t) frame_width * ps);
		}
	}
	else {
		/* BLEND_OP_OVER: alpha-over compositing.
		 */
		int x, y;

		for (y = 0; y < frame_height; y++) {
			VipsPel *q = VIPS_IMAGE_ADDR(read->canvas,
				x_offset, y_offset + y);
			VipsPel *p = frame_data +
				(size_t) y * frame_width * ps;

			for (x = 0; x < frame_width; x++) {
				if (is_16bit)
					apng_blend_pixel16(q, p, canvas_bands);
				else
					apng_blend_pixel8(q, p, canvas_bands);

				q += ps;
				p += ps;
			}
		}
	}
}

/* Read the next frame from the APNG, apply dispose/blend, update canvas.
 */
static int
apng_read_next_frame(Read *read)
{
	png_uint_32 next_frame_width, next_frame_height;
	png_uint_32 next_frame_x_offset, next_frame_y_offset;
	png_uint_16 next_frame_delay_num, next_frame_delay_den;
	png_byte next_frame_dispose_op, next_frame_blend_op;
	int ps = VIPS_IMAGE_SIZEOF_PEL(read->canvas);
	VipsPel *frame_data;
	int y;

	/* Apply previous frame's dispose operation.
	 */
	apng_apply_dispose(read);

	/* Catch PNG errors.
	 */
	if (setjmp(png_jmpbuf(read->pPng)))
		return -1;

	/* Read the frame control information.
	 */
	png_read_frame_head(read->pPng, read->pInfo);
	png_get_next_frame_fcTL(read->pPng, read->pInfo,
		&next_frame_width, &next_frame_height,
		&next_frame_x_offset, &next_frame_y_offset,
		&next_frame_delay_num, &next_frame_delay_den,
		&next_frame_dispose_op, &next_frame_blend_op);

	/* DISPOSE_OP_PREVIOUS on the first frame is treated as
	 * DISPOSE_OP_BACKGROUND per spec.
	 */
	if (read->frame_no == 0 &&
		next_frame_dispose_op == PNG_fcTL_DISPOSE_OP_PREVIOUS)
		next_frame_dispose_op = PNG_fcTL_DISPOSE_OP_BACKGROUND;

	/* Validate sub-frame fits within canvas bounds.
	 */
	if (next_frame_width == 0 ||
		next_frame_height == 0 ||
		next_frame_x_offset + next_frame_width >
			(png_uint_32) read->canvas_width ||
		next_frame_y_offset + next_frame_height >
			(png_uint_32) read->canvas_height) {
		vips_error("pngload", "%s", _("bad APNG frame geometry"));
		return -1;
	}

	/* Read the sub-frame pixel data into a temporary buffer.
	 */
	frame_data = g_malloc((size_t) next_frame_width *
		next_frame_height * ps);

	for (y = 0; y < (int) next_frame_height; y++) {
		png_bytep row = frame_data +
			(size_t) y * next_frame_width * ps;
		png_read_row(read->pPng, row, NULL);
	}

	/* Composite onto canvas.
	 */
	apng_composite_frame(read, frame_data,
		next_frame_width, next_frame_height,
		next_frame_x_offset, next_frame_y_offset,
		next_frame_blend_op, next_frame_dispose_op);

	g_free(frame_data);

	/* Record dispose state for next frame.
	 */
	read->dispose_op = next_frame_dispose_op;
	read->dispose_rect.left = next_frame_x_offset;
	read->dispose_rect.top = next_frame_y_offset;
	read->dispose_rect.width = next_frame_width;
	read->dispose_rect.height = next_frame_height;

	/* Store delay.
	 */
	if (read->delays)
		read->delays[read->frame_no] =
			apng_delay_to_ms(next_frame_delay_num,
				next_frame_delay_den);

	read->frame_no += 1;

	return 0;
}

/* Sequential generate callback for APNG reading, one line at a time.
 */
static int
apng_generate(VipsRegion *out_region,
	void *seq, void *a, void *b, gboolean *stop)
{
	VipsRect *r = &out_region->valid;
	Read *read = (Read *) a;

	/* Frame number (0-based relative to file) for this line.
	 */
	int frame = r->top / read->canvas_height + read->page;
	int line = r->top % read->canvas_height;

#ifdef DEBUG
	printf("apng_generate: line %d, frame %d\n", r->top, frame);
#endif /*DEBUG*/

	g_assert(r->height == 1);

	while (read->frame_no < frame + 1) {
		if (apng_read_next_frame(read))
			return -1;
	}

	/* Copy from canvas to output.
	 */
	if (read->has_alpha) {
		memcpy(VIPS_REGION_ADDR(out_region, 0, r->top),
			VIPS_IMAGE_ADDR(read->canvas, 0, line),
			VIPS_IMAGE_SIZEOF_LINE(read->canvas));
	}
	else {
		/* Strip alpha channel.
		 */
		int x;
		VipsPel *p = VIPS_IMAGE_ADDR(read->canvas, 0, line);
		VipsPel *q = VIPS_REGION_ADDR(out_region, 0, r->top);
		int canvas_bands = read->canvas_bands;
		int out_bands = canvas_bands - 1;

		if (read->canvas->BandFmt == VIPS_FORMAT_USHORT) {
			guint16 *pp = (guint16 *) p;
			guint16 *qq = (guint16 *) q;

			for (x = 0; x < r->width; x++) {
				int b;
				for (b = 0; b < out_bands; b++)
					qq[b] = pp[b];
				pp += canvas_bands;
				qq += out_bands;
			}
		}
		else {
			for (x = 0; x < r->width; x++) {
				int b;
				for (b = 0; b < out_bands; b++)
					q[b] = p[b];
				p += canvas_bands;
				q += out_bands;
			}
		}
	}

	return 0;
}

#endif /*PNG_APNG_SUPPORTED*/

/* Read a png header.
 */
static int
png2vips_header(Read *read, VipsImage *out, gboolean header_only)
{
	png_uint_32 width, height;
	int bitdepth, color_type;
	int interlace_type;

	png_uint_32 res_x, res_y;
	int unit_type;

	png_charp name;
	int compression_type;

	png_textp text_ptr;
	int num_text;

	/* Well thank you, libpng.
	 */
#if PNG_LIBPNG_VER < 10400
	png_charp profile;
#else
	png_bytep profile;
#endif

	png_uint_32 proflen;

	int bands;
	VipsInterpretation interpretation;
	double Xres, Yres;

	if (setjmp(png_jmpbuf(read->pPng)))
		return -1;

	png_get_IHDR(read->pPng, read->pInfo,
		&width, &height, &bitdepth, &color_type,
		&interlace_type, NULL, NULL);

	/* png_get_channels() gives us 1 band for palette images ... so look
	 * at colour_type for output bands.
	 *
	 * Ignore alpha, we detect that separately below.
	 */
	switch (color_type) {
	case PNG_COLOR_TYPE_PALETTE:
		bands = 3;
		break;

	case PNG_COLOR_TYPE_GRAY_ALPHA:
	case PNG_COLOR_TYPE_GRAY:
		bands = 1;
		break;

	case PNG_COLOR_TYPE_RGB:
	case PNG_COLOR_TYPE_RGB_ALPHA:
		bands = 3;
		break;

	default:
		vips_error("png2vips", "%s", _("unsupported color type"));
		return -1;
	}

	if (bitdepth > 8) {
		if (bands < 3)
			interpretation = VIPS_INTERPRETATION_GREY16;
		else
			interpretation = VIPS_INTERPRETATION_RGB16;
	}
	else {
		if (bands < 3)
			interpretation = VIPS_INTERPRETATION_B_W;
		else
			interpretation = VIPS_INTERPRETATION_sRGB;
	}

	/* Expand palette images.
	 */
	if (color_type == PNG_COLOR_TYPE_PALETTE)
		png_set_palette_to_rgb(read->pPng);

	/* Expand transparency.
	 */
	if (png_get_valid(read->pPng, read->pInfo, PNG_INFO_tRNS)) {
		png_set_tRNS_to_alpha(read->pPng);
		bands += 1;
	}
	else if (color_type == PNG_COLOR_TYPE_GRAY_ALPHA ||
		color_type == PNG_COLOR_TYPE_RGB_ALPHA) {
		/* Some images have no transparency chunk, but still set
		 * color_type to alpha.
		 */
		bands += 1;
	}

	/* Expand <8 bit images to full bytes.
	 */
	if (color_type == PNG_COLOR_TYPE_GRAY &&
		bitdepth < 8)
		png_set_expand_gray_1_2_4_to_8(read->pPng);

	/* If we're an INTEL byte order machine and this is 16bits, we need
	 * to swap bytes.
	 */
	if (bitdepth > 8 &&
		!vips_amiMSBfirst())
		png_set_swap(read->pPng);

	/* Get resolution. Default to 72 pixels per inch, the usual png value.
	 */
	unit_type = PNG_RESOLUTION_METER;
	res_x = 72.0 / 2.54 * 100.0;
	res_y = 72.0 / 2.54 * 100.0;
	png_get_pHYs(read->pPng, read->pInfo, &res_x, &res_y, &unit_type);
	switch (unit_type) {
	case PNG_RESOLUTION_METER:
		Xres = res_x / 1000.0;
		Yres = res_y / 1000.0;
		break;

	default:
		Xres = res_x;
		Yres = res_y;
		break;
	}

	/* Set VIPS header.
	 */
	vips_image_init_fields(out,
		width, height, bands,
		bitdepth > 8 ? VIPS_FORMAT_USHORT : VIPS_FORMAT_UCHAR,
		VIPS_CODING_NONE, interpretation,
		Xres, Yres);

	VIPS_SETSTR(out->filename,
		vips_connection_filename(VIPS_CONNECTION(read->source)));

	if (vips_image_pipelinev(out, VIPS_DEMAND_STYLE_THINSTRIP, NULL))
		return -1;

	/* Fetch the ICC profile. @name is useless, something like "icc" or
	 * "ICC Profile" etc. Ignore it.
	 *
	 * @profile was png_charpp in libpngs < 1.5, png_bytepp is the
	 * modern one. Ignore the warning, if any.
	 */
	if (png_get_iCCP(read->pPng, read->pInfo,
			&name, &compression_type, &profile, &proflen)) {
#ifdef DEBUG
		printf("png2vips_header: attaching %d bytes of ICC profile\n",
			proflen);
		printf("png2vips_header: name = \"%s\"\n", name);
#endif /*DEBUG*/

		vips_image_set_blob_copy(out,
			VIPS_META_ICC_NAME, profile, proflen);
	}

	/* Read cICP chunk and set if present.
	 */
#if PNG_LIBPNG_VER >= 10645
	png_byte colour_primaries;
	png_byte transfer_characteristics;
	png_byte matrix_coefficients;
	png_byte full_range_flag;

	if (png_get_cICP(read->pPng, read->pInfo,
		&colour_primaries, &transfer_characteristics,
		&matrix_coefficients, &full_range_flag)) {
		vips_image_set_int(out, "cicp-colour-primaries", colour_primaries);
		vips_image_set_int(out, "cicp-transfer-characteristics", transfer_characteristics);
		vips_image_set_int(out, "cicp-matrix-coefficients", matrix_coefficients);
		vips_image_set_int(out, "cicp-full-range-flag", full_range_flag);
	}
#endif

	/* Some libpng warn you to call png_set_interlace_handling(); here, but
	 * that can actually break interlace on older libpngs.
	 *
	 * Only set this for libpng 1.6+.
	 *
	 * Don't call this for animated reads — APNG frame reading manages
	 * interlace internally via png_read_frame_head/png_read_row.
	 */
#if PNG_LIBPNG_VER > 10600
#ifdef PNG_APNG_SUPPORTED
	if (!read->is_animated)
#endif
		(void) png_set_interlace_handling(read->pPng);
#endif

	/* Sanity-check line size.
	 *
	 * Don't do this for header read, since we don't want to force a
	 * malloc if all we are doing is looking at fields.
	 */
	if (!header_only) {
		png_read_update_info(read->pPng, read->pInfo);
		if (png_get_rowbytes(read->pPng, read->pInfo) !=
			VIPS_IMAGE_SIZEOF_LINE(out)) {
			vips_error("vipspng",
				"%s", _("unable to read PNG header"));
			return -1;
		}
	}

	/* Let our caller know. These are very expensive to decode.
	 */
	if (interlace_type != PNG_INTERLACE_NONE)
		vips_image_set_int(out, "interlaced", 1);

#ifdef PNG_eXIf_SUPPORTED
	{
		png_uint_32 num_exif;
		png_bytep exif;

		if (png_get_eXIf_1(read->pPng, read->pInfo, &num_exif, &exif))
			vips_image_set_blob_copy(out, VIPS_META_EXIF_NAME,
				exif, num_exif);
	}
#endif /*PNG_eXIf_SUPPORTED*/

	if (png_get_text(read->pPng, read->pInfo,
			&text_ptr, &num_text) > 0) {
		int i;

		/* Very large numbers of text chunks are used in DoS
		 * attacks.
		 */
		if (!read->unlimited &&
			num_text > MAX_PNG_TEXT_CHUNKS) {
			g_warning("%d text chunks, only %d text chunks will be loaded",
				num_text, MAX_PNG_TEXT_CHUNKS);
			num_text = MAX_PNG_TEXT_CHUNKS;
		}

		for (i = 0; i < num_text; i++)
			/* .text is always a null-terminated C string.
			 */
			if (vips__set_text(out, i,
					text_ptr[i].key, text_ptr[i].text))
				return -1;
	}

	vips_image_set_int(out, VIPS_META_BITS_PER_SAMPLE, bitdepth);

	if (color_type == PNG_COLOR_TYPE_PALETTE) {
		/* Deprecated "palette-bit-depth" use "bits-per-sample" instead.
		 */
		vips_image_set_int(out, "palette-bit-depth", bitdepth);

		vips_image_set_int(out, VIPS_META_PALETTE, 1);
	}

		/* Note the PNG background colour, if any.
		 */
#ifdef PNG_bKGD_SUPPORTED
	{
		png_color_16 *background;

		if (png_get_bKGD(read->pPng, read->pInfo, &background)) {
			const int scale = out->BandFmt == VIPS_FORMAT_UCHAR ? 1 : 256;

			double array[3];
			int n;

			switch (color_type) {
			case PNG_COLOR_TYPE_GRAY:
			case PNG_COLOR_TYPE_GRAY_ALPHA:
				array[0] = background->gray / scale;
				n = 1;
				break;

			case PNG_COLOR_TYPE_RGB:
			case PNG_COLOR_TYPE_RGB_ALPHA:
				array[0] = background->red / scale;
				array[1] = background->green / scale;
				array[2] = background->blue / scale;
				n = 3;
				break;

			case PNG_COLOR_TYPE_PALETTE:
			default:
				/* Not sure what to do here. I suppose we should read
				 * the palette.
				 */
				n = 0;
				break;
			}

			if (n > 0)
				vips_image_set_array_double(out, "background",
					array, n);
		}
	}
#endif /*PNG_bKGD_SUPPORTED*/

#ifdef PNG_APNG_SUPPORTED
	/* Detect APNG animation.
	 */
	if (png_get_valid(read->pPng, read->pInfo, PNG_INFO_acTL)) {
		png_uint_32 num_frames, num_plays;
		int first_frame_hidden;
		int frame_count;

		png_get_acTL(read->pPng, read->pInfo,
			&num_frames, &num_plays);

		first_frame_hidden =
			png_get_first_frame_is_hidden(read->pPng, read->pInfo);

		frame_count = num_frames;
		if (first_frame_hidden)
			frame_count -= 1;

		/* Sanity-check frame count. We allocate a delays array
		 * of frame_count ints, so reject absurd values early.
		 */
		if (frame_count <= 0 ||
			(guint64) frame_count * height >= VIPS_MAX_COORD) {
			vips_error("png2vips", "%s",
				_("image dimensions too large"));
			return -1;
		}

		/* If frame_count > 1, or if the user explicitly asked for
		 * multiple frames, treat as animated.
		 */
		read->frame_count = frame_count;
		read->num_plays = num_plays;

		/* Resolve n=-1 to mean "all frames from page onwards".
		 */
		if (read->n == -1)
			read->n = frame_count - read->page;

		/* Validate page/n.
		 */
		if (read->page < 0 ||
			read->n <= 0 ||
			read->page + read->n > frame_count) {
			vips_error("png2vips", "%s", _("bad page number"));
			return -1;
		}

		/* Check stacked output height fits in coord range.
		 */
		if ((guint64) read->n * height >= VIPS_MAX_COORD) {
			vips_error("png2vips", "%s",
				_("image dimensions too large"));
			return -1;
		}

		if (frame_count > 1 || read->n > 1) {
			read->is_animated = TRUE;

			/* For animation, we need alpha for compositing.
			 * Force to RGBA or GA.
			 */
			if (bands < 3) {
				/* Greyscale: need GA (2 bands).
				 */
				if (bands == 1) {
					png_set_add_alpha(read->pPng,
						bitdepth > 8 ? 0xFFFF : 0xFF,
						PNG_FILLER_AFTER);
					bands = 2;
				}
				read->canvas_bands = 2;
			}
			else {
				/* RGB: need RGBA (4 bands).
				 */
				if (bands == 3) {
					png_set_add_alpha(read->pPng,
						bitdepth > 8 ? 0xFFFF : 0xFF,
						PNG_FILLER_AFTER);
					bands = 4;
				}
				read->canvas_bands = 4;
			}

			/* Check if the original had alpha.
			 */
			read->has_alpha =
				color_type == PNG_COLOR_TYPE_GRAY_ALPHA ||
				color_type == PNG_COLOR_TYPE_RGB_ALPHA ||
				png_get_valid(read->pPng, read->pInfo,
					PNG_INFO_tRNS);

			read->canvas_width = width;
			read->canvas_height = height;

			/* Re-set the VIPS header for animated output:
			 * height = n * canvas_height, bands may have
			 * changed.
			 */
			vips_image_init_fields(out,
				width, (guint64) read->n * height, bands,
				bitdepth > 8
					? VIPS_FORMAT_USHORT
					: VIPS_FORMAT_UCHAR,
				VIPS_CODING_NONE, interpretation,
				Xres, Yres);

			/* Set animation metadata.
			 */
			vips_image_set_int(out,
				VIPS_META_N_PAGES, frame_count);
			vips_image_set_int(out,
				VIPS_META_PAGE_HEIGHT, height);
			vips_image_set_int(out, "loop", num_plays);

			/* Allocate delays array and scan fcTL chunks from
			 * the raw PNG data to fill it. This lets us know
			 * delays at header time (like GIF/WebP loaders)
			 * without reading pixel data.
			 */
			read->delays = VIPS_ARRAY(NULL, frame_count, int);
			if (!read->delays)
				return -1;
			memset(read->delays, 0,
				frame_count * sizeof(int));
			if (apng_scan_delays(read))
				return -1;
			vips_image_set_array_int(out, "delay",
				read->delays, frame_count);
		}
	}
#endif /*PNG_APNG_SUPPORTED*/

	return 0;
}

/* Out is a huge "t" buffer we decompress to.
 */
static int
png2vips_interlace(Read *read, VipsImage *out)
{
	int y;

#ifdef DEBUG
	printf("png2vips_interlace: reading whole image\n");
#endif /*DEBUG*/

	if (vips_image_write_prepare(out))
		return -1;

	if (setjmp(png_jmpbuf(read->pPng)))
		return -1;

	if (!(read->row_pointer = VIPS_ARRAY(NULL, out->Ysize, png_bytep)))
		return -1;
	for (y = 0; y < out->Ysize; y++)
		read->row_pointer[y] = VIPS_IMAGE_ADDR(out, 0, y);

	png_read_image(read->pPng, read->row_pointer);

	read_destroy(read);

	return 0;
}

static int
png2vips_generate(VipsRegion *out_region,
	void *seq, void *a, void *b, gboolean *stop)
{
	VipsRect *r = &out_region->valid;
	Read *read = (Read *) a;

	int y;

#ifdef DEBUG
	printf("png2vips_generate: line %d, %d rows\n", r->top, r->height);
	printf("png2vips_generate: y_top = %d\n", read->y_pos);
#endif /*DEBUG*/

	/* We're inside a tilecache where tiles are the full image width, so
	 * this should always be true.
	 */
	g_assert(r->left == 0);
	g_assert(r->width == out_region->im->Xsize);
	g_assert(VIPS_RECT_BOTTOM(r) <= out_region->im->Ysize);

	/* Tiles should always be a strip in height, unless it's the final
	 * strip.
	 */
	g_assert(r->height ==
		VIPS_MIN(VIPS__FATSTRIP_HEIGHT, out_region->im->Ysize - r->top));

	/* And check that y_pos is correct. It should be, since we are inside
	 * a vips_sequential().
	 */
	if (r->top != read->y_pos) {
		vips_error("vipspng",
			_("out of order read at line %d"), read->y_pos);
		return -1;
	}

	for (y = 0; y < r->height; y++) {
		png_bytep q = (png_bytep) VIPS_REGION_ADDR(out_region, 0, r->top + y);

		/* We need to catch errors from read_row().
		 */
		if (!setjmp(png_jmpbuf(read->pPng)))
			png_read_row(read->pPng, q, NULL);
		else {
			/* We've failed to read some pixels. Knock this
			 * operation out of cache.
			 */
			vips_foreign_load_invalidate(read->out);

#ifdef DEBUG
			printf(
				"png2vips_generate: png_read_row() failed, "
				"line %d\n",
				r->top + y);
			printf("png2vips_generate: file %s\n", read->name);
			printf("png2vips_generate: thread %p\n",
				g_thread_self());
#endif /*DEBUG*/

			/* And bail if fail is on. We have to add an error
			 * message, since the handler we install just does
			 * g_warning().
			 */
			if (read->fail_on >= VIPS_FAIL_ON_TRUNCATED) {
				vips_error("vipspng",
					"%s", _("libpng read error"));
				return -1;
			}
		}

		read->y_pos += 1;
	}

	return 0;
}

static int
png2vips_image(Read *read, VipsImage *out)
{
	int interlace_type = png_get_interlace_type(read->pPng, read->pInfo);
	VipsImage **t = (VipsImage **)
		vips_object_local_array(VIPS_OBJECT(out), 3);

#ifdef PNG_APNG_SUPPORTED
	/* Read the header first so is_animated is set.
	 */
	t[0] = vips_image_new();
	if (png2vips_header(read, t[0], FALSE))
		return -1;

	if (read->is_animated) {
		int first_frame_hidden;
		int i;

		/* png_read_update_info() was already called in
		 * png2vips_header() when header_only is FALSE.
		 */

		/* Allocate the compositing canvas.
		 */
		read->canvas = vips_image_new_memory();
		vips_image_init_fields(read->canvas,
			read->canvas_width, read->canvas_height,
			read->canvas_bands,
			t[0]->BandFmt,
			VIPS_CODING_NONE, t[0]->Type,
			t[0]->Xres, t[0]->Yres);
		if (vips_image_write_prepare(read->canvas))
			return -1;

		/* Clear canvas to transparent zeros.
		 */
		memset(VIPS_IMAGE_ADDR(read->canvas, 0, 0), 0,
			VIPS_IMAGE_SIZEOF_IMAGE(read->canvas));

		/* If the first frame is hidden (IDAT is not part of the
		 * animation), we need to read and discard it.
		 */
		first_frame_hidden = png_get_first_frame_is_hidden(
			read->pPng, read->pInfo);
		if (first_frame_hidden) {
			if (apng_read_next_frame(read))
				return -1;

			/* Reset canvas and frame_no for the actual animation.
			 */
			memset(VIPS_IMAGE_ADDR(read->canvas, 0, 0), 0,
				VIPS_IMAGE_SIZEOF_IMAGE(read->canvas));
			read->frame_no = 0;
			read->dispose_op = PNG_fcTL_DISPOSE_OP_NONE;
		}

		/* Skip frames before the requested page.
		 */
		for (i = 0; i < read->page; i++) {
			if (apng_read_next_frame(read))
				return -1;
		}

		/* Set up the generate pipeline. Delays are already set
		 * on t[0] by png2vips_header via apng_scan_delays.
		 */
		if (vips_image_generate(t[0],
				NULL, apng_generate, NULL,
				read, NULL) ||
			vips_sequential(t[0], &t[1], NULL) ||
			vips_image_write(t[1], out))
			return -1;

		return 0;
	}

	/* Not animated — fall through to normal read, but we already
	 * called png2vips_header on t[0] (with header_only=FALSE, so
	 * png_read_update_info was called). Don't call it again.
	 */
	if (interlace_type != PNG_INTERLACE_NONE) {
		/* Need a memory image for interlace. Copy fields from
		 * t[0] which already has the header set.
		 */
		t[2] = t[0];
		t[0] = vips_image_new_memory();
		vips_image_init_fields(t[0],
			t[2]->Xsize, t[2]->Ysize, t[2]->Bands,
			t[2]->BandFmt, t[2]->Coding, t[2]->Type,
			t[2]->Xres, t[2]->Yres);
		if (vips_image_write_prepare(t[0]) ||
			png2vips_interlace(read, t[0]) ||
			vips_image_write(t[0], out))
			return -1;
	}
	else {
		if (vips_image_generate(t[0],
				NULL, png2vips_generate, NULL,
				read, NULL) ||
			vips_sequential(t[0], &t[1],
				"tile_height", VIPS__FATSTRIP_HEIGHT,
				NULL) ||
			vips_image_write(t[1], out))
			return -1;
	}

	return 0;
}
#else /*!PNG_APNG_SUPPORTED*/

	if (interlace_type != PNG_INTERLACE_NONE) {
		/* Arg awful interlaced image. We have to load to a huge mem
		 * buffer, then copy to out.
		 */
		t[0] = vips_image_new_memory();
		if (png2vips_header(read, t[0], FALSE) ||
			png2vips_interlace(read, t[0]) ||
			vips_image_write(t[0], out))
			return -1;
	}
	else {
		t[0] = vips_image_new();
		if (png2vips_header(read, t[0], FALSE) ||
			vips_image_generate(t[0],
				NULL, png2vips_generate, NULL,
				read, NULL) ||
			vips_sequential(t[0], &t[1],
				"tile_height", VIPS__FATSTRIP_HEIGHT,
				NULL) ||
			vips_image_write(t[1], out))
			return -1;
	}

	return 0;
}
#endif /*PNG_APNG_SUPPORTED*/

gboolean
vips__png_ispng_source(VipsSource *source)
{
	const unsigned char *p;

	if ((p = vips_source_sniff(source, 8)) &&
		!png_sig_cmp((png_bytep) p, 0, 8))
		return TRUE;

	return FALSE;
}

int
vips__png_header_source(VipsSource *source, VipsImage *out,
	int page, int n, gboolean unlimited)
{
	Read *read;

	if (!(read = read_new(source, out, page, n,
			VIPS_FAIL_ON_NONE, unlimited)) ||
		png2vips_header(read, out, TRUE))
		return -1;

	vips_source_minimise(source);

	return 0;
}

int
vips__png_read_source(VipsSource *source, VipsImage *out,
	int page, int n, VipsFailOn fail_on, gboolean unlimited)
{
	Read *read;

	if (!(read = read_new(source, out, page, n, fail_on, unlimited)) ||
		png2vips_image(read, out) ||
		vips_source_decode(source))
		return -1;

	return 0;
}

/* Interlaced PNGs need to be entirely decompressed into memory then can be
 * served partially from there. Non-interlaced PNGs may be read sequentially.
 */
gboolean
vips__png_isinterlaced_source(VipsSource *source)
{
	VipsImage *image;
	Read *read;
	int interlace_type;

	image = vips_image_new();

	if (!(read = read_new(source, image, 0, 1, VIPS_FAIL_ON_NONE, FALSE))) {
		g_object_unref(image);
		return -1;
	}
	interlace_type = png_get_interlace_type(read->pPng, read->pInfo);
	g_object_unref(image);

	return interlace_type != PNG_INTERLACE_NONE;
}

/* What we track during a PNG write.
 */
typedef struct {
	VipsImage *in;
	VipsImage *memory;

	VipsTarget *target;

	png_structp pPng;
	png_infop pInfo;
	png_bytep *row_pointer;

#ifdef PNG_APNG_SUPPORTED
	/* APNG write state.
	 */
	int page_height;	/* height of each frame */
	int n_frames;		/* number of frames */
	VipsPel *frame_bytes;	/* accumulation buffer for one frame */
	int write_y;		/* current y within frame */
	int page_number;	/* current frame being written */
	int *delays;		/* per-frame delay in ms */
	int delay_length;	/* length of delays array */
	int loop;		/* loop count */
#endif /*PNG_APNG_SUPPORTED*/
} Write;

static void
write_destroy(Write *write)
{
#ifdef DEBUG
	printf("write_destroy: %p\n", write);
#endif /*DEBUG*/

	VIPS_UNREF(write->memory);
	if (write->pPng)
		png_destroy_write_struct(&write->pPng, &write->pInfo);
	VIPS_FREE(write->row_pointer);

#ifdef PNG_APNG_SUPPORTED
	VIPS_FREE(write->frame_bytes);
#endif /*PNG_APNG_SUPPORTED*/

	VIPS_FREE(write);
}

static void
user_write_data(png_structp pPng, png_bytep data, png_size_t length)
{
	Write *write = (Write *) png_get_io_ptr(pPng);

	if (vips_target_write(write->target, data, length))
		png_error(pPng, "not enough data");
}

static Write *
write_new(VipsImage *in, VipsTarget *target)
{
	Write *write;

	if (!(write = VIPS_NEW(NULL, Write)))
		return NULL;
	write->in = in;
	write->target = target;

#ifdef DEBUG
	printf("write_new: %p\n", write);
#endif /*DEBUG*/

	if (!(write->row_pointer = VIPS_ARRAY(NULL, in->Ysize, png_bytep)))
		return NULL;
	if (!(write->pPng = png_create_write_struct(
			  PNG_LIBPNG_VER_STRING, NULL,
			  user_error_function, user_warning_function))) {
		write_destroy(write);
		return NULL;
	}

	/* Prevent libpng (>=1.6.11) verifying sRGB profiles. We are often
	 * asked to copy images containing bad profiles, and this check would
	 * prevent that.
	 */
#ifdef PNG_SKIP_sRGB_CHECK_PROFILE
	png_set_option(write->pPng,
		PNG_SKIP_sRGB_CHECK_PROFILE, PNG_OPTION_ON);
#endif /*PNG_SKIP_sRGB_CHECK_PROFILE*/

	png_set_write_fn(write->pPng, write, user_write_data, NULL);

	/* Catch PNG errors from png_create_info_struct().
	 */
	if (setjmp(png_jmpbuf(write->pPng))) {
		write_destroy(write);
		return NULL;
	}

	if (!(write->pInfo = png_create_info_struct(write->pPng))) {
		write_destroy(write);
		return NULL;
	}

	return write;
}

static int
write_png_block(VipsRegion *region, VipsRect *area, void *a)
{
	Write *write = (Write *) a;

	int i;

	/* The area to write is always a set of complete scanlines.
	 */
	g_assert(area->left == 0);
	g_assert(area->width == region->im->Xsize);
	g_assert(area->top + area->height <= region->im->Ysize);

	/* Catch PNG errors.
	 */
	if (setjmp(png_jmpbuf(write->pPng)))
		return -1;

	for (i = 0; i < area->height; i++)
		write->row_pointer[i] = (png_bytep)
			VIPS_REGION_ADDR(region, 0, area->top + i);

	png_write_rows(write->pPng, write->row_pointer, area->height);

	return 0;
}

static void
vips__png_set_text(png_structp pPng, png_infop pInfo,
	const char *key, const char *value)
{
	png_text text;

	text.compression = 0;
	text.key = (char *) key;
	text.text = (char *) value;
	text.text_length = strlen(value);

	/* Before 1.4, these fields were only there if explicitly enabled.
	 */
#if PNG_LIBPNG_VER > 10400
	text.itxt_length = 0;
	text.lang = NULL;
#endif

	png_set_text(pPng, pInfo, &text, 1);
}

static void *
write_png_comment(VipsImage *image,
	const char *field, GValue *value, void *data)
{
	Write *write = (Write *) data;

	if (vips_isprefix("png-comment-", field)) {
		const char *str;
		int i;
		char key[256];

		if (vips_image_get_string(write->in, field, &str))
			return image;

		if (strlen(field) > 256 ||
			sscanf(field, "png-comment-%d-%80s", &i, key) != 2) {
			vips_error("vips2png",
				"%s", _("bad png comment key"));
			return image;
		}

		vips__png_set_text(write->pPng, write->pInfo, key, str);
	}

	return NULL;
}

static int
vips_png_add_icc(Write *write, const void *data, size_t length)
{
	if (setjmp(png_jmpbuf(write->pPng)))
		g_debug("bad ICC profile not saved");
	else
		png_set_iCCP(write->pPng, write->pInfo,
			"icc", PNG_COMPRESSION_TYPE_BASE,
			(void *) data, length);

	return 0;
}

static int
vips_png_add_custom_icc(Write *write, const char *profile)
{
	VipsBlob *blob;

	if (vips_profile_load(profile, &blob, NULL))
		return -1;

	if (blob) {
		size_t length;
		const void *data = vips_blob_get(blob, &length);

		vips_png_add_icc(write, data, length);

		vips_area_unref((VipsArea *) blob);
	}

	return 0;
}

static int
vips_png_add_original_icc(Write *write)
{
	const void *data;
	size_t length;

	if (vips_image_get_blob(write->in, VIPS_META_ICC_NAME,
			&data, &length))
		return -1;

	vips_png_add_icc(write, data, length);

	return 0;
}

/* Write a VIPS image to PNG.
 */
static int
write_vips(Write *write,
	int compress, int interlace,
	const char *profile, VipsForeignPngFilter filter,
	gboolean palette,
	int Q, double dither,
	int bitdepth, int effort)
{
	VipsImage *in = write->in;

	int color_type;
	int interlace_type;
	int i, nb_passes;

	g_assert(in->BandFmt == VIPS_FORMAT_UCHAR ||
		in->BandFmt == VIPS_FORMAT_USHORT);
	g_assert(in->Coding == VIPS_CODING_NONE);
	g_assert(in->Bands > 0 && in->Bands < 5);

	/* Catch PNG errors.
	 */
	if (setjmp(png_jmpbuf(write->pPng)))
		return -1;

	/* Check input image. If we are writing interlaced, we need to make 7
	 * passes over the image. We advertise ourselves as seq, so to ensure
	 * we only suck once from upstream, switch to WIO.
	 */
	if (interlace) {
		if (!(write->memory = vips_image_copy_memory(in)))
			return -1;
		in = write->memory;
	}
	else {
		if (vips_image_pio_input(in))
			return -1;
	}
	if (compress < 0 ||
		compress > 9) {
		vips_error("vips2png", "%s", _("compress should be in [0,9]"));
		return -1;
	}

	/* Set compression parameters.
	 */
	png_set_compression_level(write->pPng, compress);

	/* Set row filter.
	 */
	png_set_filter(write->pPng, 0, filter);

	switch (in->Bands) {
	case 1:
		color_type = PNG_COLOR_TYPE_GRAY;
		break;
	case 2:
		color_type = PNG_COLOR_TYPE_GRAY_ALPHA;
		break;
	case 3:
		color_type = PNG_COLOR_TYPE_RGB;
		break;
	case 4:
		color_type = PNG_COLOR_TYPE_RGB_ALPHA;
		break;

	default:
		vips_error("vips2png",
			_("can't save %d band image as png"), in->Bands);
		return -1;
	}

#ifdef HAVE_QUANTIZATION
	/* Enable image quantisation to paletted 8bpp PNG if palette is set.
	 */
	if (palette)
		color_type = PNG_COLOR_TYPE_PALETTE;
#else
	if (palette)
		g_warning("ignoring palette (no quantisation support)");
#endif /*HAVE_QUANTIZATION*/

	interlace_type = interlace ? PNG_INTERLACE_ADAM7 : PNG_INTERLACE_NONE;

	/* libpng has a default soft limit of 1m pixels per axis.
	 */
	png_set_user_limits(write->pPng, VIPS_MAX_COORD, VIPS_MAX_COORD);

	png_set_IHDR(write->pPng, write->pInfo,
		in->Xsize, in->Ysize, bitdepth, color_type, interlace_type,
		PNG_COMPRESSION_TYPE_DEFAULT, PNG_FILTER_TYPE_DEFAULT);

	/* Set resolution. libpng uses pixels per meter.
	 */
	png_set_pHYs(write->pPng, write->pInfo,
		rint(in->Xres * 1000), rint(in->Yres * 1000), PNG_RESOLUTION_METER);

	/* Metadata
	 */
	if (vips_image_get_typeof(in, VIPS_META_XMP_NAME)) {
		const void *data;
		size_t length;
		char *str;

		/* XMP is attached as a BLOB with no null-termination.
		 * We must re-add this.
		 */
		if (vips_image_get_blob(in, VIPS_META_XMP_NAME, &data, &length))
			return -1;

		str = g_malloc(length + 1);
		g_strlcpy(str, data, length + 1);
		vips__png_set_text(write->pPng, write->pInfo, "XML:com.adobe.xmp", str);
		g_free(str);
	}

#ifdef PNG_eXIf_SUPPORTED
	if (vips_image_get_typeof(in, VIPS_META_EXIF_NAME)) {
		const void *data;
		size_t length;

		if (vips_image_get_blob(in, VIPS_META_EXIF_NAME, &data, &length))
			return -1;

		/* libpng does not want the JFIF "Exif\0\0" prefix.
		 */
		if (length >= 6 &&
			vips_isprefix("Exif", (char *) data)) {
			data = (char *) data + 6;
			length -= 6;
		}

		png_set_eXIf_1(write->pPng, write->pInfo, length, (png_bytep) data);
	}
#endif /*PNG_eXIf_SUPPORTED*/

	if (vips_image_map(in, write_png_comment, write))
		return -1;

	/* A profile supplied as an argument overrides an embedded
	 * profile.
	 */
	if (profile) {
		if (vips_png_add_custom_icc(write, profile))
			return -1;
	}
	else if (vips_image_get_typeof(in, VIPS_META_ICC_NAME)) {
		if (vips_png_add_original_icc(write))
			return -1;
	}

#if PNG_LIBPNG_VER >= 10645
	int colour_primaries;
	int transfer_characteristics;
	int matrix_coefficients;
	int full_range_flag;

	if (vips_image_get_typeof(in, "cicp-colour-primaries") &&
		!vips_image_get_int(in, "cicp-colour-primaries",
			&colour_primaries) &&
		!vips_image_get_int(in, "cicp-transfer-characteristics",
			&transfer_characteristics) &&
		!vips_image_get_int(in, "cicp-matrix-coefficients",
			&matrix_coefficients) &&
		!vips_image_get_int(in, "cicp-full-range-flag",
			&full_range_flag)) {

		png_set_cICP(write->pPng, write->pInfo,
			(png_byte) colour_primaries,
			(png_byte) transfer_characteristics,
			0, /* PNG pixel data is always RGB */
			(png_byte) full_range_flag);
	}
#endif

	// the profile writers grab the setjmp, restore it
	if (setjmp(png_jmpbuf(write->pPng)))
		return -1;

#ifdef HAVE_QUANTIZATION
	if (palette) {
		VipsImage *im_index;
		VipsImage *im_palette;
		int palette_count;
		png_color *png_palette;
		png_byte *png_trans;
		int trans_count;

		if (vips__quantise_image(in, &im_index, &im_palette,
				1 << bitdepth, Q, dither, effort, FALSE))
			return -1;

		palette_count = im_palette->Xsize;

		g_assert(palette_count <= PNG_MAX_PALETTE_LENGTH);

		png_palette = (png_color *) png_malloc(write->pPng,
			palette_count * sizeof(png_color));
		png_trans = (png_byte *) png_malloc(write->pPng,
			palette_count * sizeof(png_byte));
		trans_count = 0;
		for (i = 0; i < palette_count; i++) {
			VipsPel *p = (VipsPel *) VIPS_IMAGE_ADDR(im_palette, i, 0);
			png_color *col = &png_palette[i];

			col->red = p[0];
			col->green = p[1];
			col->blue = p[2];
			png_trans[i] = p[3];
			if (p[3] != 255)
				trans_count = i + 1;
#ifdef DEBUG
			printf("write_vips: palette[%d] %d %d %d %d\n",
				i + 1, p[0], p[1], p[2], p[3]);
#endif /*DEBUG*/
		}

#ifdef DEBUG
		printf("write_vips: attaching %d color palette\n",
			palette_count);
#endif /*DEBUG*/
		png_set_PLTE(write->pPng, write->pInfo, png_palette, palette_count);
		if (trans_count) {
#ifdef DEBUG
			printf("write_vips: attaching %d alpha values\n",
				trans_count);
#endif /*DEBUG*/
			png_set_tRNS(write->pPng, write->pInfo, png_trans,
				trans_count, NULL);
		}

		png_free(write->pPng, (void *) png_palette);
		png_free(write->pPng, (void *) png_trans);

		VIPS_UNREF(im_palette);

		VIPS_UNREF(write->memory);
		write->memory = im_index;
		in = write->memory;
	}
#endif /*HAVE_QUANTIZATION*/

	png_write_info(write->pPng, write->pInfo);

	/* If we're an intel byte order CPU and this is a 16bit image, we need
	 * to swap bytes.
	 */
	if (bitdepth > 8 &&
		!vips_amiMSBfirst())
		png_set_swap(write->pPng);

	/* If bitdepth is 1/2/4, pack pixels into bytes.
	 */
	png_set_packing(write->pPng);

	if (interlace)
		nb_passes = png_set_interlace_handling(write->pPng);
	else
		nb_passes = 1;

	/* Write data.
	 */
	for (i = 0; i < nb_passes; i++)
		if (vips_sink_disc(in, write_png_block, write))
			return -1;

	/* The setjmp() was held by our background writer: reset it.
	 */
	if (setjmp(png_jmpbuf(write->pPng)))
		return -1;

	png_write_end(write->pPng, write->pInfo);

	return 0;
}

#ifdef PNG_APNG_SUPPORTED

/* sink_disc callback for APNG write: accumulate scanlines into frames.
 */
static int
write_apng_block(VipsRegion *region, VipsRect *area, void *a)
{
	Write *write = (Write *) a;
	int ps = VIPS_IMAGE_SIZEOF_PEL(region->im);
	int i;

	g_assert(area->left == 0);
	g_assert(area->width == region->im->Xsize);

	for (i = 0; i < area->height; i++) {
		memcpy(write->frame_bytes +
				(size_t) write->write_y * region->im->Xsize * ps,
			VIPS_REGION_ADDR(region, 0, area->top + i),
			(size_t) region->im->Xsize * ps);

		write->write_y += 1;

		if (write->write_y >= write->page_height) {
			/* We have a complete frame. Write it out.
			 */
			int delay_ms;
			png_uint_16 delay_num, delay_den;
			int y;

			/* Get delay for this frame.
			 */
			if (write->delays &&
				write->page_number < write->delay_length)
				delay_ms = write->delays[write->page_number];
			else
				delay_ms = 0;
			delay_num = delay_ms;
			delay_den = 1000;

			/* Catch PNG errors.
			 */
			if (setjmp(png_jmpbuf(write->pPng)))
				return -1;

			png_write_frame_head(write->pPng, write->pInfo,
				NULL, /* row_pointers - not needed here */
				region->im->Xsize, /* width */
				write->page_height, /* height */
				0, 0, /* x_offset, y_offset */
				delay_num, delay_den,
				PNG_fcTL_DISPOSE_OP_NONE,
				PNG_fcTL_BLEND_OP_SOURCE);

			for (y = 0; y < write->page_height; y++) {
				png_bytep row = write->frame_bytes +
					(size_t) y * region->im->Xsize * ps;
				png_write_row(write->pPng, row);
			}

			png_write_frame_tail(write->pPng, write->pInfo);

			write->page_number += 1;
			write->write_y = 0;
		}
	}

	return 0;
}

/* Write a VIPS image as APNG.
 */
static int
write_vips_apng(Write *write,
	int compress, const char *profile, VipsForeignPngFilter filter,
	gboolean palette, int Q, double dither, int bitdepth, int effort)
{
	VipsImage *in = write->in;
	int color_type;
	int page_height;
	int n_frames;
	int i;

	page_height = vips_image_get_page_height(in);
	n_frames = in->Ysize / page_height;

	write->page_height = page_height;
	write->n_frames = n_frames;
	write->page_number = 0;
	write->write_y = 0;

	/* Get delay array from metadata.
	 */
	write->delays = NULL;
	write->delay_length = 0;
	if (vips_image_get_typeof(in, "delay")) {
		int *delays;
		int delay_length;

		if (vips_image_get_array_int(in, "delay",
				&delays, &delay_length))
			return -1;
		write->delays = delays;
		write->delay_length = delay_length;
	}

	/* Get loop count.
	 */
	write->loop = 0;
	if (vips_image_get_typeof(in, "loop"))
		vips_image_get_int(in, "loop", &write->loop);

	/* Catch PNG errors.
	 */
	if (setjmp(png_jmpbuf(write->pPng)))
		return -1;

	if (vips_image_pio_input(in))
		return -1;

	/* Set compression parameters.
	 */
	png_set_compression_level(write->pPng, compress);
	png_set_filter(write->pPng, 0, filter);

	switch (in->Bands) {
	case 1:
		color_type = PNG_COLOR_TYPE_GRAY;
		break;
	case 2:
		color_type = PNG_COLOR_TYPE_GRAY_ALPHA;
		break;
	case 3:
		color_type = PNG_COLOR_TYPE_RGB;
		break;
	case 4:
		color_type = PNG_COLOR_TYPE_RGB_ALPHA;
		break;
	default:
		vips_error("vips2png",
			_("can't save %d band image as png"), in->Bands);
		return -1;
	}

#ifdef HAVE_QUANTIZATION
	if (palette)
		color_type = PNG_COLOR_TYPE_PALETTE;
#else
	if (palette)
		g_warning("ignoring palette (no quantisation support)");
#endif /*HAVE_QUANTIZATION*/

	/* libpng has a default soft limit of 1m pixels per axis.
	 */
	png_set_user_limits(write->pPng, VIPS_MAX_COORD, VIPS_MAX_COORD);

	/* IHDR uses page_height as the image height.
	 */
	png_set_IHDR(write->pPng, write->pInfo,
		in->Xsize, page_height, bitdepth, color_type,
		PNG_INTERLACE_NONE,
		PNG_COMPRESSION_TYPE_DEFAULT, PNG_FILTER_TYPE_DEFAULT);

	/* Set resolution.
	 */
	png_set_pHYs(write->pPng, write->pInfo,
		rint(in->Xres * 1000), rint(in->Yres * 1000),
		PNG_RESOLUTION_METER);

	/* Set APNG animation control.
	 */
	png_set_acTL(write->pPng, write->pInfo, n_frames, write->loop);

	/* Metadata.
	 */
	if (vips_image_get_typeof(in, VIPS_META_XMP_NAME)) {
		const void *data;
		size_t length;
		char *str;

		if (vips_image_get_blob(in, VIPS_META_XMP_NAME,
				&data, &length))
			return -1;

		str = g_malloc(length + 1);
		g_strlcpy(str, data, length + 1);
		vips__png_set_text(write->pPng, write->pInfo,
			"XML:com.adobe.xmp", str);
		g_free(str);
	}

#ifdef PNG_eXIf_SUPPORTED
	if (vips_image_get_typeof(in, VIPS_META_EXIF_NAME)) {
		const void *data;
		size_t length;

		if (vips_image_get_blob(in, VIPS_META_EXIF_NAME,
				&data, &length))
			return -1;

		if (length >= 6 &&
			vips_isprefix("Exif", (char *) data)) {
			data = (char *) data + 6;
			length -= 6;
		}

		png_set_eXIf_1(write->pPng, write->pInfo,
			length, (png_bytep) data);
	}
#endif /*PNG_eXIf_SUPPORTED*/

	if (vips_image_map(in, write_png_comment, write))
		return -1;

	/* ICC profile.
	 */
	if (profile) {
		if (vips_png_add_custom_icc(write, profile))
			return -1;
	}
	else if (vips_image_get_typeof(in, VIPS_META_ICC_NAME)) {
		if (vips_png_add_original_icc(write))
			return -1;
	}

	/* Restore setjmp after profile writers.
	 */
	if (setjmp(png_jmpbuf(write->pPng)))
		return -1;

#ifdef HAVE_QUANTIZATION
	if (palette) {
		VipsImage *im_index;
		VipsImage *im_palette;
		int palette_count;
		png_color *png_palette;
		png_byte *png_trans;
		int trans_count;

		if (vips__quantise_image(in, &im_index, &im_palette,
				1 << bitdepth, Q, dither, effort, FALSE))
			return -1;

		palette_count = im_palette->Xsize;

		g_assert(palette_count <= PNG_MAX_PALETTE_LENGTH);

		png_palette = (png_color *) png_malloc(write->pPng,
			palette_count * sizeof(png_color));
		png_trans = (png_byte *) png_malloc(write->pPng,
			palette_count * sizeof(png_byte));
		trans_count = 0;
		for (i = 0; i < palette_count; i++) {
			VipsPel *p =
				(VipsPel *) VIPS_IMAGE_ADDR(im_palette, i, 0);
			png_color *col = &png_palette[i];

			col->red = p[0];
			col->green = p[1];
			col->blue = p[2];
			png_trans[i] = p[3];
			if (p[3] != 255)
				trans_count = i + 1;
		}

		png_set_PLTE(write->pPng, write->pInfo,
			png_palette, palette_count);
		if (trans_count)
			png_set_tRNS(write->pPng, write->pInfo,
				png_trans, trans_count, NULL);

		png_free(write->pPng, (void *) png_palette);
		png_free(write->pPng, (void *) png_trans);

		VIPS_UNREF(im_palette);

		VIPS_UNREF(write->memory);
		write->memory = im_index;
		in = write->memory;
	}
#endif /*HAVE_QUANTIZATION*/

	png_write_info(write->pPng, write->pInfo);

	/* If we're an intel byte order CPU and this is a 16bit image, we need
	 * to swap bytes.
	 */
	if (bitdepth > 8 &&
		!vips_amiMSBfirst())
		png_set_swap(write->pPng);

	/* If bitdepth is 1/2/4, pack pixels into bytes.
	 */
	png_set_packing(write->pPng);

	/* Allocate frame buffer.
	 */
	write->frame_bytes = g_malloc(
		(size_t) in->Xsize * page_height *
		VIPS_IMAGE_SIZEOF_PEL(in));

	/* Write data via sink_disc.
	 */
	if (vips_sink_disc(in, write_apng_block, write))
		return -1;

	/* Reset setjmp after sink_disc.
	 */
	if (setjmp(png_jmpbuf(write->pPng)))
		return -1;

	png_write_end(write->pPng, write->pInfo);

	return 0;
}

#endif /*PNG_APNG_SUPPORTED*/

int
vips__png_write_target(VipsImage *in, VipsTarget *target,
	int compression, int interlace,
	const char *profile, VipsForeignPngFilter filter,
	gboolean palette,
	int Q, double dither,
	int bitdepth, int effort)
{
	Write *write;

	if (!(write = write_new(in, target)))
		return -1;

#ifdef PNG_APNG_SUPPORTED
	/* Detect animation: page_height != image height means we have
	 * multiple pages stacked vertically.
	 */
	{
		int page_height = vips_image_get_page_height(in);

		if (page_height != in->Ysize) {
			if (interlace) {
				g_warning("disabling interlace for animated PNG");
				interlace = FALSE;
			}

			if (write_vips_apng(write,
					compression, profile, filter, palette,
					Q, dither, bitdepth, effort)) {
				write_destroy(write);
				vips_error("vips2png",
					_("unable to write to target %s"),
					vips_connection_nick(
						VIPS_CONNECTION(target)));
				return -1;
			}

			write_destroy(write);

			if (vips_target_end(target))
				return -1;

			return 0;
		}
	}
#endif /*PNG_APNG_SUPPORTED*/

	if (write_vips(write,
			compression, interlace, profile, filter, palette,
			Q, dither, bitdepth, effort)) {
		write_destroy(write);
		vips_error("vips2png", _("unable to write to target %s"),
			vips_connection_nick(VIPS_CONNECTION(target)));
		return -1;
	}

	write_destroy(write);

	if (vips_target_end(target))
		return -1;

	return 0;
}

#endif /*HAVE_PNG*/
