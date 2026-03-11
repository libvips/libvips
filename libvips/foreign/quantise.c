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
