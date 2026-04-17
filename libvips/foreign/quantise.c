/* quantise an image
 *
 * 20/6/18
 * 	  - from vipspng.c
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

#include <vips/vips.h>

#include "quantise.h"

#ifdef HAVE_IMAGEQUANT

VipsQuantiseAttr *
vips__quantise_attr_create(void)
{
	return liq_attr_create();
}

VipsQuantiseError
vips__quantise_set_max_colors(VipsQuantiseAttr *attr, int colors)
{
	return liq_set_max_colors(attr, colors);
}

VipsQuantiseError
vips__quantise_set_quality(VipsQuantiseAttr *attr, int minimum, int maximum)
{
	return liq_set_quality(attr, minimum, maximum);
}

VipsQuantiseError
vips__quantise_set_speed(VipsQuantiseAttr *attr, int speed)
{
	return liq_set_speed(attr, speed);
}

VipsQuantiseImage *
vips__quantise_image_create_rgba(const VipsQuantiseAttr *attr,
	const void *bitmap, int width, int height, double gamma)
{
	return liq_image_create_rgba(attr, bitmap, width, height, gamma);
}

VipsQuantiseError
vips__quantise_image_quantize(VipsQuantiseImage *const input_image,
	VipsQuantiseAttr *const options, VipsQuantiseResult **result_output)
{
	return liq_image_quantize(input_image, options, result_output);
}

/* Like vips__quantise_image_quantize(), but make a fixed palette that won't
 * get remapped during dithering.
 */
VipsQuantiseError
vips__quantise_image_quantize_fixed(VipsQuantiseImage *const input_image,
	VipsQuantiseAttr *const options, VipsQuantiseResult **result_output)
{
	int i;
	liq_result *result;
	const liq_palette *palette;
	liq_error err;
	liq_image *fake_image;
	char fake_image_pixels[4] = { 0 };

	/* First, quantize the image and get its palette.
	 */
	err = liq_image_quantize(input_image, options, &result);
	if (err != LIQ_OK)
		return err;

	palette = liq_get_palette(result);

	/* Now, we need a fake 1 pixel image that will be quantized on the
	 * next step. Its pixel color doesn't matter since we'll add all the
	 * colors from the palette further.
	 */
	fake_image =
		liq_image_create_rgba(options, fake_image_pixels, 1, 1, 0);
	if (!fake_image) {
		liq_result_destroy(result);
		return LIQ_OUT_OF_MEMORY;
	}

	/* Add all the colors from the palette as fixed colors to the fake
	 * image. Since the fixed colors number is the same as required colors
	 * number, no new colors will be added.
	 */
	for (i = 0; i < palette->count; i++)
		liq_image_add_fixed_color(fake_image, palette->entries[i]);

	liq_result_destroy(result);

	/* Finally, quantize the fake image with fixed colors to make a
	 * VipsQuantiseResult with a fixed palette.
	 */
	err = liq_image_quantize(fake_image, options, result_output);

	liq_image_destroy(fake_image);

	return err;
}

VipsQuantiseError
vips__quantise_set_dithering_level(VipsQuantiseResult *res,
	float dither_level)
{
	return liq_set_dithering_level(res, dither_level);
}

const VipsQuantisePalette *
vips__quantise_get_palette(VipsQuantiseResult *result)
{
	return liq_get_palette(result);
}

VipsQuantiseError
vips__quantise_write_remapped_image(VipsQuantiseResult *result,
	VipsQuantiseImage *input_image, void *buffer, size_t buffer_size)
{
	return liq_write_remapped_image(
		result, input_image, buffer, buffer_size);
}

void
vips__quantise_result_destroy(VipsQuantiseResult *result)
{
	liq_result_destroy(result);
}

void
vips__quantise_image_destroy(VipsQuantiseImage *img)
{
	liq_image_destroy(img);
}

void
vips__quantise_attr_destroy(VipsQuantiseAttr *attr)
{
	liq_attr_destroy(attr);
}

#elif defined(HAVE_QUANTIZR) /*!HAVE_IMAGEQUANT*/

VipsQuantiseAttr *
vips__quantise_attr_create(void)
{
	return quantizr_new_options();
}

VipsQuantiseError
vips__quantise_set_max_colors(VipsQuantiseAttr *attr, int colors)
{
	return quantizr_set_max_colors(attr, colors);
}

VipsQuantiseError
vips__quantise_set_quality(VipsQuantiseAttr *attr, int minimum, int maximum)
{
	/* Not supported by quantizr
	 */
	return 0;
}

VipsQuantiseError
vips__quantise_set_speed(VipsQuantiseAttr *attr, int speed)
{
	/* Not supported by quantizr
	 */
	return 0;
}

VipsQuantiseImage *
vips__quantise_image_create_rgba(const VipsQuantiseAttr *attr,
	const void *bitmap, int width, int height, double gamma)
{
	/* attr and gamma ununused by quantizr
	 */
	return quantizr_create_image_rgba(
		(unsigned char *) bitmap, width, height);
}

VipsQuantiseError
vips__quantise_image_quantize(VipsQuantiseImage *const input_image,
	VipsQuantiseAttr *const options, VipsQuantiseResult **result_output)
{
	*result_output = quantizr_quantize(input_image, options);
	return 0;
}

VipsQuantiseError
vips__quantise_image_quantize_fixed(VipsQuantiseImage *const input_image,
	VipsQuantiseAttr *const options, VipsQuantiseResult **result_output)
{
	/* Quantizr doesn't change the palette during remapping, so we don't
	 * need a special implementation for this
	 */
	return vips__quantise_image_quantize(input_image, options,
		result_output);
}

VipsQuantiseError
vips__quantise_set_dithering_level(VipsQuantiseResult *res,
	float dither_level)
{
	return quantizr_set_dithering_level(res, dither_level);
}

const VipsQuantisePalette *
vips__quantise_get_palette(VipsQuantiseResult *result)
{
	return quantizr_get_palette(result);
}

VipsQuantiseError
vips__quantise_write_remapped_image(VipsQuantiseResult *result,
	VipsQuantiseImage *input_image, void *buffer, size_t buffer_size)
{
	return quantizr_remap(result, input_image, buffer, buffer_size);
}

void
vips__quantise_result_destroy(VipsQuantiseResult *result)
{
	quantizr_free_result(result);
}

void
vips__quantise_image_destroy(VipsQuantiseImage *img)
{
	quantizr_free_image(img);
}

void
vips__quantise_attr_destroy(VipsQuantiseAttr *attr)
{
	quantizr_free_options(attr);
}

#else /*!HAVE_IMAGEQUANT && !HAVE_QUANTIZR*/

/* Built-in Wu quantiser wrappers.
 * These implement the VipsQuantise* API using the Wu optimal quantiser
 * from quantise-builtin.c, so that cgifsave and other code that uses
 * the low-level quantisation API works without external libraries.
 */

struct _VipsQuantiseAttr {
	int max_colors;
	int quality_min;
	int quality_max;
	int speed;
};

struct _VipsQuantiseImage {
	const unsigned char *bitmap;
	int width;
	int height;
};

struct _VipsQuantiseResult {
	VipsQuantisePalette palette;
	float dither_level;
	VipsQuantiseAttr attr;
};

VipsQuantiseAttr *
vips__quantise_attr_create(void)
{
	VipsQuantiseAttr *attr = g_new0(VipsQuantiseAttr, 1);

	attr->max_colors = 256;
	attr->quality_min = 0;
	attr->quality_max = 100;
	attr->speed = 4;

	return attr;
}

VipsQuantiseError
vips__quantise_set_max_colors(VipsQuantiseAttr *attr, int colors)
{
	attr->max_colors = colors;
	return 0;
}

VipsQuantiseError
vips__quantise_set_quality(VipsQuantiseAttr *attr, int minimum, int maximum)
{
	attr->quality_min = minimum;
	attr->quality_max = maximum;
	return 0;
}

VipsQuantiseError
vips__quantise_set_speed(VipsQuantiseAttr *attr, int speed)
{
	attr->speed = speed;
	return 0;
}

VipsQuantiseImage *
vips__quantise_image_create_rgba(const VipsQuantiseAttr *attr,
	const void *bitmap, int width, int height, double gamma)
{
	VipsQuantiseImage *image = g_new(VipsQuantiseImage, 1);

	image->bitmap = (const unsigned char *) bitmap;
	image->width = width;
	image->height = height;

	return image;
}

VipsQuantiseError
vips__quantise_image_quantize(VipsQuantiseImage *input_image,
	VipsQuantiseAttr *options, VipsQuantiseResult **result_output)
{
	VipsQuantiseResult *result;

	result = g_new0(VipsQuantiseResult, 1);
	result->dither_level = 1.0;
	result->attr = *options;

	/* Build palette using Wu quantiser.
	 */
	if (vips__builtin_quantise(
			input_image->bitmap,
			input_image->width,
			input_image->height,
			options->max_colors,
			11 - options->speed,
			&result->palette)) {
		g_free(result);
		return 1;
	}

	*result_output = result;
	return 0;
}

VipsQuantiseError
vips__quantise_image_quantize_fixed(VipsQuantiseImage *input_image,
	VipsQuantiseAttr *options, VipsQuantiseResult **result_output)
{
	/* Wu doesn't refine the palette during remapping, so
	 * fixed and normal quantize are the same.
	 */
	return vips__quantise_image_quantize(input_image, options,
		result_output);
}

VipsQuantiseError
vips__quantise_set_dithering_level(VipsQuantiseResult *res,
	float dither_level)
{
	res->dither_level = dither_level;
	return 0;
}

const VipsQuantisePalette *
vips__quantise_get_palette(VipsQuantiseResult *result)
{
	return &result->palette;
}

VipsQuantiseError
vips__quantise_write_remapped_image(VipsQuantiseResult *result,
	VipsQuantiseImage *input_image, void *buffer, size_t buffer_size)
{
	return vips__builtin_remap(
		input_image->bitmap,
		input_image->width,
		input_image->height,
		&result->palette,
		result->dither_level,
		buffer);
}

void
vips__quantise_result_destroy(VipsQuantiseResult *result)
{
	g_free(result);
}

void
vips__quantise_image_destroy(VipsQuantiseImage *img)
{
	g_free(img);
}

void
vips__quantise_attr_destroy(VipsQuantiseAttr *attr)
{
	g_free(attr);
}

#endif /*HAVE_IMAGEQUANT*/

/* Track during a quantisation.
 */
typedef struct _Quantise {
	VipsImage *in;
	VipsImage **index_out;
	VipsImage **palette_out;
	int colours;
	int Q;
	double dither;
	int effort;

	VipsQuantiseAttr *attr;
	VipsQuantiseImage *input_image;
	VipsQuantiseResult *quantisation_result;
	VipsImage *t[5];
} Quantise;

static void
vips__quantise_free(Quantise *quantise)
{
	int i;

	VIPS_FREEF(vips__quantise_result_destroy, quantise->quantisation_result);
	VIPS_FREEF(vips__quantise_image_destroy, quantise->input_image);
	VIPS_FREEF(vips__quantise_attr_destroy, quantise->attr);

	for (i = 0; i < VIPS_NUMBER(quantise->t); i++)
		VIPS_UNREF(quantise->t[i]);

	VIPS_FREE(quantise);
}

static Quantise *
vips__quantise_new(VipsImage *in,
	VipsImage **index_out, VipsImage **palette_out,
	int colours, int Q, double dither, int effort)
{
	Quantise *quantise;
	int i;

	quantise = VIPS_NEW(NULL, Quantise);
	quantise->in = in;
	quantise->index_out = index_out;
	quantise->palette_out = palette_out;
	quantise->colours = colours;
	quantise->Q = Q;
	quantise->dither = dither;
	quantise->effort = effort;
	for (i = 0; i < VIPS_NUMBER(quantise->t); i++)
		quantise->t[i] = NULL;

	return quantise;
}

#ifdef HAVE_IMAGEQUANT
/* Row callback for liq_image_create_custom: reads rows from a
 * VipsImage on demand, applying alpha thresholding if needed.
 * Avoids vips_image_copy_memory for the libimagequant path.
 */
typedef struct {
	VipsImage *im;
	gboolean threshold_alpha;
	gboolean added_alpha;
} LiqRowData;

/* Thread-local VipsRegion for liq row callback.
 * libimagequant calls the callback from rayon worker threads,
 * so each thread needs its own region.
 */
static GPrivate liq_region_key =
	G_PRIVATE_INIT((GDestroyNotify) g_object_unref);

static void
liq_row_cb(liq_color row_out[], int row, int width, void *user_info)
{
	LiqRowData *data = (LiqRowData *) user_info;
	VipsRegion *region;
	VipsRect rect = { 0, row, width, 1 };

	/* Reuse the per-thread region across rows of the same image, but
	 * drop it when a different image comes in. Without this guard,
	 * back-to-back vips__quantise_image() calls on different inputs
	 * would silently re-read the previous image through the cached
	 * region.
	 */
	region = (VipsRegion *) g_private_get(&liq_region_key);
	if (region && region->im != data->im) {
		g_object_unref(region);
		region = NULL;
	}
	if (!region) {
		region = vips_region_new(data->im);
		g_private_set(&liq_region_key, region);
	}

	if (vips_region_prepare(region, &rect)) {
		memset(row_out, 0, width * sizeof(liq_color));
		return;
	}

	const VipsPel *p = VIPS_REGION_ADDR(region, 0, row);

	if (data->threshold_alpha && !data->added_alpha) {
		int x;

		for (x = 0; x < width; x++) {
			row_out[x].r = p[0];
			row_out[x].g = p[1];
			row_out[x].b = p[2];
			row_out[x].a = p[3] > 128 ? 255 : 0;
			p += 4;
		}
	}
	else
		memcpy(row_out, p, width * 4);
}
#endif /*HAVE_IMAGEQUANT*/

/* Forward decl for the n=1 helper. Each backend provides its own
 * implementation further down (libimagequant and quantizr via custom
 * sink passes that reproduce their native single-cluster math; built-in
 * Wu via a thin wrapper around vips__builtin_quantise_stream). Used to
 * skip the wasteful remap step when colours==1.
 */
static int vips__quantise_palette_single(VipsImage *in,
	VipsQuantisePalette *out);

int
vips__quantise_image(VipsImage *in,
	VipsImage **index_out, VipsImage **palette_out,
	int colours, int Q, double dither, int effort,
	gboolean threshold_alpha)
{
	Quantise *quantise;
	VipsImage *index;
	VipsImage *palette;
	const VipsQuantisePalette *lp;
	VipsQuantisePalette builtin_pal;
	gint64 i;
	VipsPel *restrict p;
	gboolean added_alpha;

	quantise = vips__quantise_new(in, index_out, palette_out,
		colours, Q, dither, effort);

	/* Ensure sRGB. Also force the conversion if the input has fewer
	 * than 3 bands (e.g. a 1-band slice tagged sRGB after extract_band):
	 * the quantiser reads 4 bytes per pixel and would walk off the end.
	 */
	if (in->Type != VIPS_INTERPRETATION_sRGB || in->Bands < 3) {
		if (vips_colourspace(in, &quantise->t[0],
				VIPS_INTERPRETATION_sRGB, NULL)) {
			vips__quantise_free(quantise);
			return -1;
		}
		in = quantise->t[0];
	}

	/* Add alpha channel if missing.
	 */
	added_alpha = FALSE;
	if (!vips_image_hasalpha(in)) {
		if (vips_bandjoin_const1(in, &quantise->t[1], 255, NULL)) {
			vips__quantise_free(quantise);
			return -1;
		}
		added_alpha = TRUE;
		in = quantise->t[1];
	}

	/* max_colors == 1: the remap step is a no-op (every pixel maps to
	 * the lone palette entry) so skip it. Each backend's native
	 * single-cluster centroid math lives in vips__quantise_palette_single.
	 *
	 * threshold_alpha is ignored on this path. The only caller that
	 * sets it (cgifsave) goes through the low-level vips__builtin_*
	 * API directly with max_colors >= 2, never via this entry point.
	 */
	if (colours == 1) {
		if (vips__quantise_palette_single(in, &builtin_pal)) {
			vips_error("quantise", "%s",
				_("quantisation failed"));
			vips__quantise_free(quantise);
			return -1;
		}

		index = quantise->t[3] = vips_image_new_memory();
		vips_image_init_fields(index,
			in->Xsize, in->Ysize, 1, VIPS_FORMAT_UCHAR,
			VIPS_CODING_NONE, VIPS_INTERPRETATION_B_W,
			1.0, 1.0);

		if (vips_image_write_prepare(index)) {
			vips__quantise_free(quantise);
			return -1;
		}

		memset(VIPS_IMAGE_ADDR(index, 0, 0), 0,
			VIPS_IMAGE_N_PELS(index));

		lp = &builtin_pal;

		goto build_palette;
	}

#if !defined(HAVE_IMAGEQUANT) && !defined(HAVE_QUANTIZR)
	/* Built-in backend: stream directly from the VipsImage pipeline.
	 * No vips_image_copy_memory needed — the streaming functions use
	 * vips_sink_disc to process the image row by row.
	 *
	 * Alpha thresholding is not applicable here (only used by
	 * cgifsave which calls the low-level API directly).
	 */
	{
		GHashTable *exact_map;

		if (vips__builtin_quantise_stream(in,
				colours, effort, &builtin_pal, &exact_map)) {
			vips_error("quantise", "%s",
				_("quantisation failed"));
			vips__quantise_free(quantise);
			return -1;
		}

		index = quantise->t[3] = vips_image_new_memory();
		vips_image_init_fields(index,
			in->Xsize, in->Ysize, 1, VIPS_FORMAT_UCHAR,
			VIPS_CODING_NONE, VIPS_INTERPRETATION_B_W,
			1.0, 1.0);

		if (vips_image_write_prepare(index)) {
			if (exact_map)
				g_hash_table_destroy(exact_map);
			vips__quantise_free(quantise);
			return -1;
		}

		/* Use exact hash remap if available (few-colours
		 * fast path), otherwise normal streaming remap.
		 */
		if (exact_map) {
			gboolean has_t = FALSE;
			unsigned int j;

			for (j = 0; j < builtin_pal.count; j++)
				if (builtin_pal.entries[j].a == 0) {
					has_t = TRUE;
					break;
				}

			if (vips__builtin_exact_remap_stream(in,
					index, exact_map, has_t)) {
				g_hash_table_destroy(exact_map);
				vips_error("quantise", "%s",
					_("quantisation failed"));
				vips__quantise_free(quantise);
				return -1;
			}

			g_hash_table_destroy(exact_map);
		}
		else if (vips__builtin_remap_stream(in, index,
				&builtin_pal, dither)) {
			vips_error("quantise", "%s",
				_("quantisation failed"));
			vips__quantise_free(quantise);
			return -1;
		}

		lp = &builtin_pal;
	}
#elif defined(HAVE_IMAGEQUANT)
	/* libimagequant: use row callback to avoid vips_image_copy_memory.
	 */
	{
		LiqRowData row_data;

		row_data.im = in;
		row_data.threshold_alpha = threshold_alpha;
		row_data.added_alpha = added_alpha;

		quantise->attr = vips__quantise_attr_create();
		vips__quantise_set_max_colors(quantise->attr, colours);
		vips__quantise_set_quality(quantise->attr, 0, Q);
		vips__quantise_set_speed(quantise->attr, 11 - effort);

		quantise->input_image = liq_image_create_custom(
			quantise->attr, liq_row_cb, &row_data,
			in->Xsize, in->Ysize, 0);

		if (vips__quantise_image_quantize(quantise->input_image,
				quantise->attr,
				&quantise->quantisation_result)) {
			vips_error("quantise", "%s",
				_("quantisation failed"));
			vips__quantise_free(quantise);
			return -1;
		}

		vips__quantise_set_dithering_level(
			quantise->quantisation_result, dither);

		index = quantise->t[3] = vips_image_new_memory();
		vips_image_init_fields(index,
			in->Xsize, in->Ysize, 1, VIPS_FORMAT_UCHAR,
			VIPS_CODING_NONE, VIPS_INTERPRETATION_B_W,
			1.0, 1.0);

		if (vips_image_write_prepare(index)) {
			vips__quantise_free(quantise);
			return -1;
		}

		if (vips__quantise_write_remapped_image(
				quantise->quantisation_result,
				quantise->input_image,
				VIPS_IMAGE_ADDR(index, 0, 0),
				VIPS_IMAGE_N_PELS(index))) {
			vips_error("quantise", "%s",
				_("quantisation failed"));
			vips__quantise_free(quantise);
			return -1;
		}


		lp = vips__quantise_get_palette(
			quantise->quantisation_result);

	}
#else /*!built-in && !HAVE_IMAGEQUANT*/
	/* quantizr needs the full image in contiguous memory.
	 */
	if (!(quantise->t[2] = vips_image_copy_memory(in))) {
		vips__quantise_free(quantise);
		return -1;
	}
	in = quantise->t[2];

	/* Threshold alpha channel.
	 */
	if (threshold_alpha &&
		!added_alpha) {
		const guint64 n_pels = VIPS_IMAGE_N_PELS(in);

		p = VIPS_IMAGE_ADDR(in, 0, 0);
		for (i = 0; i < n_pels; i++) {
			p[3] = p[3] > 128 ? 255 : 0;
			p += 4;
		}
	}

	quantise->attr = vips__quantise_attr_create();
	vips__quantise_set_max_colors(quantise->attr, colours);
	vips__quantise_set_quality(quantise->attr, 0, Q);
	vips__quantise_set_speed(quantise->attr, 11 - effort);

	quantise->input_image = vips__quantise_image_create_rgba(quantise->attr,
		VIPS_IMAGE_ADDR(in, 0, 0), in->Xsize, in->Ysize, 0);

	if (vips__quantise_image_quantize(quantise->input_image, quantise->attr,
			&quantise->quantisation_result)) {
		vips_error("quantise", "%s", _("quantisation failed"));
		vips__quantise_free(quantise);
		return -1;
	}

	vips__quantise_set_dithering_level(quantise->quantisation_result, dither);

	index = quantise->t[3] = vips_image_new_memory();
	vips_image_init_fields(index,
		in->Xsize, in->Ysize, 1, VIPS_FORMAT_UCHAR,
		VIPS_CODING_NONE, VIPS_INTERPRETATION_B_W, 1.0, 1.0);

	if (vips_image_write_prepare(index)) {
		vips__quantise_free(quantise);
		return -1;
	}

	if (vips__quantise_write_remapped_image(quantise->quantisation_result,
			quantise->input_image,
			VIPS_IMAGE_ADDR(index, 0, 0), VIPS_IMAGE_N_PELS(index))) {
		vips_error("quantise", "%s", _("quantisation failed"));
		vips__quantise_free(quantise);
		return -1;
	}

	lp = vips__quantise_get_palette(quantise->quantisation_result);
#endif

build_palette:
	palette = quantise->t[4] = vips_image_new_memory();
	vips_image_init_fields(palette, lp->count, 1, 4,
		VIPS_FORMAT_UCHAR, VIPS_CODING_NONE, VIPS_INTERPRETATION_sRGB,
		1.0, 1.0);

	if (vips_image_write_prepare(palette)) {
		vips__quantise_free(quantise);
		return -1;
	}

	p = VIPS_IMAGE_ADDR(palette, 0, 0);
	for (i = 0; i < lp->count; i++) {
		p[0] = lp->entries[i].r;
		p[1] = lp->entries[i].g;
		p[2] = lp->entries[i].b;
		p[3] = lp->entries[i].a;

		p += 4;
	}

	*index_out = index;
	g_object_ref(index);
	*palette_out = palette;
	g_object_ref(palette);

	vips__quantise_free(quantise);

	return 0;
}

/* n=1 helper: produce a single-entry palette using each backend's own
 * single-cluster centroid math. Called from vips__quantise_image() (and
 * later from vips__quantise_palette()) when colours==1, so that the
 * remap step can be skipped — every pixel maps to index 0 anyway.
 *
 * libimagequant and quantizr both reject max_colors < 2 in their own
 * APIs, so for those backends we reproduce the algorithm directly via a
 * threaded vips_sink pass. The built-in Wu backend supports
 * max_colors=1 natively, so its implementation just calls the existing
 * vips__builtin_quantise_stream() and discards the unused exact_map.
 */
#ifdef HAVE_IMAGEQUANT
/* n=1 for libimagequant backend.
 *
 * libimagequant's set_max_colors rejects values < 2 (src/attr.rs:92-98), so
 * we can't ask the library for a single-colour palette directly. Reproduce
 * exactly what its 1-cluster centroid would be: alpha-premultiplied mean
 * in gamma-1.2539 perceptual space, then unpremultiplied and inverse-
 * gamma'd back to sRGB.
 *
 * Per pixel (α_norm = a/255):
 *     f.r += α_norm * lut[r];  similarly g, b
 *     f.a += α_norm
 * Final (the W_R/W_G/W_B/W_A weights in src/pal.rs cancel for n=1):
 *     r_linear = sum_fr / sum_fa
 *     r_srgb   = round(max(0, r_linear)^(1/1.2539) * 256)  (clamped)
 *     a_srgb   = round(sum_fa / n_pels * 256)
 * Matches src/pal.rs:164-172 (from_rgba) and src/pal.rs:143-162 (to_rgb)
 * with `INTERNAL_GAMMA / user_gamma = 0.57 / 0.45455 ≈ 1.2539`.
 */
#define LIQ_GAMMA_FWD 1.2539

static double liq_gamma_lut[256];
static GOnce liq_gamma_lut_once = G_ONCE_INIT;

static void *
liq_gamma_lut_build(void *user)
{
	int i;

	for (i = 0; i < 256; i++)
		liq_gamma_lut[i] = pow(i / 255.0, LIQ_GAMMA_FWD);

	return NULL;
}

typedef struct {
	double sum_fr, sum_fg, sum_fb, sum_fa;
	guint64 n_pels;
} LiqN1Seq;

static void *
liq_n1_start(VipsImage *im, void *a, void *b)
{
	return g_new0(LiqN1Seq, 1);
}

static int
liq_n1_scan(VipsRegion *region, void *seq, void *a, void *b, gboolean *stop)
{
	LiqN1Seq *thr = (LiqN1Seq *) seq;
	VipsRect *area = &region->valid;
	int y, x;

	for (y = 0; y < area->height; y++) {
		const VipsPel *p = VIPS_REGION_ADDR(region,
			area->left, area->top + y);

		for (x = 0; x < area->width; x++) {
			double alpha = p[3] / 255.0;

			thr->sum_fr += alpha * liq_gamma_lut[p[0]];
			thr->sum_fg += alpha * liq_gamma_lut[p[1]];
			thr->sum_fb += alpha * liq_gamma_lut[p[2]];
			thr->sum_fa += alpha;
			thr->n_pels++;
			p += 4;
		}
	}

	return 0;
}

static int
liq_n1_stop(void *seq, void *a, void *b)
{
	LiqN1Seq *thr = (LiqN1Seq *) seq;
	LiqN1Seq *main = (LiqN1Seq *) b;

	main->sum_fr += thr->sum_fr;
	main->sum_fg += thr->sum_fg;
	main->sum_fb += thr->sum_fb;
	main->sum_fa += thr->sum_fa;
	main->n_pels += thr->n_pels;

	g_free(thr);
	return 0;
}

static inline unsigned char
liq_finalise_channel(double sum_fc, double sum_fa)
{
	double linear = sum_fc / sum_fa;
	double srgb;

	if (linear < 0)
		linear = 0;
	srgb = pow(linear, 1.0 / LIQ_GAMMA_FWD) * 256.0;
	if (srgb < 0)
		srgb = 0;
	if (srgb > 255)
		srgb = 255;

	return (unsigned char) (srgb + 0.5);
}

static int
vips__quantise_palette_single(VipsImage *in, VipsQuantisePalette *out)
{
	LiqN1Seq main = { 0 };
	double mean_fa;

	VIPS_ONCE(&liq_gamma_lut_once, liq_gamma_lut_build, NULL);

	if (vips_sink(in, liq_n1_start, liq_n1_scan, liq_n1_stop, &main, &main))
		return -1;

	out->count = 1;

	if (main.n_pels == 0 || main.sum_fa <= 0) {
		/* No pixels, or fully transparent: collapse to (0,0,0,0). */
		out->entries[0].r = 0;
		out->entries[0].g = 0;
		out->entries[0].b = 0;
		out->entries[0].a = 0;
		return 0;
	}

	out->entries[0].r = liq_finalise_channel(main.sum_fr, main.sum_fa);
	out->entries[0].g = liq_finalise_channel(main.sum_fg, main.sum_fa);
	out->entries[0].b = liq_finalise_channel(main.sum_fb, main.sum_fa);

	mean_fa = (main.sum_fa / (double) main.n_pels) * 256.0;
	if (mean_fa < 0)
		mean_fa = 0;
	if (mean_fa > 255)
		mean_fa = 255;
	out->entries[0].a = (unsigned char) (mean_fa + 0.5);

	return 0;
}
#elif defined(HAVE_QUANTIZR)
/* n=1 for quantizr backend.
 *
 * quantizr's set_max_colors rejects values < 2 (src/options.rs:23-31), so
 * we can't ask the library for a single-colour palette directly. Reproduce
 * exactly what its 1-cluster centroid would be: arithmetic per-band mean
 * over the histogram, where pixels with α=0 are normalised to (0,0,0,0)
 * before accumulation (matches src/histogram.rs:36-50 + src/cluster.rs:38-66
 * + src/colormap.rs:138-145).
 */
typedef struct {
	guint64 sum_r, sum_g, sum_b, sum_a;
	guint64 n_pels;
} QzN1Seq;

static void *
qz_n1_start(VipsImage *im, void *a, void *b)
{
	return g_new0(QzN1Seq, 1);
}

static int
qz_n1_scan(VipsRegion *region, void *seq, void *a, void *b, gboolean *stop)
{
	QzN1Seq *thr = (QzN1Seq *) seq;
	VipsRect *area = &region->valid;
	int y, x;

	for (y = 0; y < area->height; y++) {
		const VipsPel *p = VIPS_REGION_ADDR(region,
			area->left, area->top + y);

		for (x = 0; x < area->width; x++) {
			if (p[3] != 0) {
				thr->sum_r += p[0];
				thr->sum_g += p[1];
				thr->sum_b += p[2];
				thr->sum_a += p[3];
			}
			thr->n_pels++;
			p += 4;
		}
	}

	return 0;
}

static int
qz_n1_stop(void *seq, void *a, void *b)
{
	QzN1Seq *thr = (QzN1Seq *) seq;
	QzN1Seq *main = (QzN1Seq *) b;

	main->sum_r += thr->sum_r;
	main->sum_g += thr->sum_g;
	main->sum_b += thr->sum_b;
	main->sum_a += thr->sum_a;
	main->n_pels += thr->n_pels;

	g_free(thr);
	return 0;
}

static int
vips__quantise_palette_single(VipsImage *in, VipsQuantisePalette *out)
{
	QzN1Seq main = { 0 };

	if (vips_sink(in, qz_n1_start, qz_n1_scan, qz_n1_stop, &main, &main))
		return -1;

	out->count = 1;
	if (main.n_pels == 0) {
		out->entries[0].r = 0;
		out->entries[0].g = 0;
		out->entries[0].b = 0;
		out->entries[0].a = 0;
	}
	else {
		out->entries[0].r = (unsigned char)
			((main.sum_r + main.n_pels / 2) / main.n_pels);
		out->entries[0].g = (unsigned char)
			((main.sum_g + main.n_pels / 2) / main.n_pels);
		out->entries[0].b = (unsigned char)
			((main.sum_b + main.n_pels / 2) / main.n_pels);
		out->entries[0].a = (unsigned char)
			((main.sum_a + main.n_pels / 2) / main.n_pels);
	}

	return 0;
}
#else /*!HAVE_IMAGEQUANT && !HAVE_QUANTIZR*/
/* n=1 for built-in Wu backend.
 *
 * Wu's wu_partition handles n_colors=1 trivially (single global box,
 * loop doesn't run), and the streaming entry point already supports
 * max_colors=1 after the clamp lift in quantise-builtin.c. Just call
 * it and discard the unused exact_map.
 */
static int
vips__quantise_palette_single(VipsImage *in, VipsQuantisePalette *out)
{
	GHashTable *exact_map;

	if (vips__builtin_quantise_stream(in, 1, 0, out, &exact_map))
		return -1;

	if (exact_map)
		g_hash_table_destroy(exact_map);

	return 0;
}
#endif /*HAVE_IMAGEQUANT || HAVE_QUANTIZR*/

int
vips__quantise_palette(VipsImage *in, VipsImage **palette_out,
	int colours, int Q, int effort)
{
	Quantise *quantise;
	VipsImage *palette;
	const VipsQuantisePalette *lp;
	VipsQuantisePalette builtin_pal;
	gint64 i;
	VipsPel *restrict p;

	quantise = vips__quantise_new(in, NULL, palette_out,
		colours, Q, 0, effort);

	/* Ensure sRGB. Also force the conversion if the input has fewer
	 * than 3 bands (e.g. a 1-band slice tagged sRGB after extract_band):
	 * the quantiser reads 4 bytes per pixel and would walk off the end.
	 */
	if (in->Type != VIPS_INTERPRETATION_sRGB || in->Bands < 3) {
		if (vips_colourspace(in, &quantise->t[0],
				VIPS_INTERPRETATION_sRGB, NULL)) {
			vips__quantise_free(quantise);
			return -1;
		}
		in = quantise->t[0];
	}

	/* Add alpha channel if missing.
	 */
	if (!vips_image_hasalpha(in)) {
		if (vips_bandjoin_const1(in, &quantise->t[1], 255, NULL)) {
			vips__quantise_free(quantise);
			return -1;
		}
		in = quantise->t[1];
	}

	/* Cast to 8-bit — the quantiser expects uchar RGBA.
	 */
	if (in->BandFmt != VIPS_FORMAT_UCHAR) {
		if (vips_cast(in, &quantise->t[4], VIPS_FORMAT_UCHAR, NULL)) {
			vips__quantise_free(quantise);
			return -1;
		}
		in = quantise->t[4];
	}

	/* colours == 1: use the per-backend single-cluster helper and
	 * skip the remap/copy_memory steps entirely.
	 */
	if (colours == 1) {
		if (vips__quantise_palette_single(in, &builtin_pal)) {
			vips_error("quantise", "%s",
				_("quantisation failed"));
			vips__quantise_free(quantise);
			return -1;
		}
		lp = &builtin_pal;
	}
	else {
#if !defined(HAVE_IMAGEQUANT) && !defined(HAVE_QUANTIZR)
		/* Built-in backend: stream the histogram pass via vips_sink,
		 * no need to copy the image to memory. Discard the exact_map —
		 * we only want the palette.
		 */
		GHashTable *exact_map;

		if (vips__builtin_quantise_stream(in,
				colours, effort, &builtin_pal, &exact_map)) {
			vips_error("quantise", "%s",
				_("quantisation failed"));
			vips__quantise_free(quantise);
			return -1;
		}

		if (exact_map)
			g_hash_table_destroy(exact_map);

		lp = &builtin_pal;
#else
		if (!(quantise->t[2] = vips_image_copy_memory(in))) {
			vips__quantise_free(quantise);
			return -1;
		}
		in = quantise->t[2];

		quantise->attr = vips__quantise_attr_create();
		vips__quantise_set_max_colors(quantise->attr, colours);
		vips__quantise_set_quality(quantise->attr, 0, Q);
		vips__quantise_set_speed(quantise->attr, 11 - effort);

		quantise->input_image =
			vips__quantise_image_create_rgba(quantise->attr,
				VIPS_IMAGE_ADDR(in, 0, 0),
				in->Xsize, in->Ysize, 0);

		if (vips__quantise_image_quantize(quantise->input_image,
				quantise->attr,
				&quantise->quantisation_result)) {
			vips_error("quantise", "%s",
				_("quantisation failed"));
			vips__quantise_free(quantise);
			return -1;
		}

		/* Extract palette without remapping.
		 */
		lp = vips__quantise_get_palette(quantise->quantisation_result);
#endif
	}

	palette = quantise->t[3] = vips_image_new_memory();
	vips_image_init_fields(palette, lp->count, 1, 4,
		VIPS_FORMAT_UCHAR, VIPS_CODING_NONE, VIPS_INTERPRETATION_sRGB,
		1.0, 1.0);

	if (vips_image_write_prepare(palette)) {
		vips__quantise_free(quantise);
		return -1;
	}

	p = VIPS_IMAGE_ADDR(palette, 0, 0);
	for (i = 0; i < lp->count; i++) {
		p[0] = lp->entries[i].r;
		p[1] = lp->entries[i].g;
		p[2] = lp->entries[i].b;
		p[3] = lp->entries[i].a;
		p += 4;
	}

	*palette_out = palette;
	g_object_ref(palette);

	vips__quantise_free(quantise);

	return 0;
}
