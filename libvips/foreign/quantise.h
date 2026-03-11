/* common defs for image quantisation
 */

/*

	Copyright (C) 1991-2005 The National Gallery

	This library is free software; you can redistribute it and/or
	modify it under the terms of the GNU Lesser General Public
	License as published by the Free Software Foundation; either
	version 2.1 of the License, or (at your option) any later version.

	This library is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
	Lesser General Public License for more details.

	You should have received a copy of the GNU Lesser General Public
	License along with this library; if not, write to the Free Software
	Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
	02110-1301  USA

 */

/*

	These files are distributed with VIPS - http://www.vips.ecs.soton.ac.uk

 */

#ifndef VIPS_QUANTISE_H
#define VIPS_QUANTISE_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

#define HAVE_QUANTIZATION

#if defined(HAVE_IMAGEQUANT)

#include <libimagequant.h>

#define VipsQuantiseAttr liq_attr
#define VipsQuantiseImage liq_image
#define VipsQuantiseResult liq_result
#define VipsQuantisePalette liq_palette
#define VipsQuantiseError liq_error

#elif defined(HAVE_QUANTIZR)

#include <quantizr.h>

#define VipsQuantiseAttr QuantizrOptions
#define VipsQuantiseImage QuantizrImage
#define VipsQuantiseResult QuantizrResult
#define VipsQuantisePalette QuantizrPalette
#define VipsQuantiseError QuantizrError

#else /*!HAVE_IMAGEQUANT && !HAVE_QUANTIZR*/

/* Built-in Wu quantiser opaque types.
 */
typedef struct _VipsQuantiseAttr VipsQuantiseAttr;
typedef struct _VipsQuantiseImage VipsQuantiseImage;
typedef struct _VipsQuantiseResult VipsQuantiseResult;
typedef int VipsQuantiseError;

typedef struct {
	unsigned char r, g, b, a;
} VipsQuantiseColour;

typedef struct {
	unsigned int count;
	VipsQuantiseColour entries[256];
} VipsQuantisePalette;

#endif
VipsQuantiseAttr *vips__quantise_attr_create(void);
VipsQuantiseError vips__quantise_set_max_colors(VipsQuantiseAttr *attr,
	int colors);
VipsQuantiseError vips__quantise_set_quality(VipsQuantiseAttr *attr,
	int minimum, int maximum);
VipsQuantiseError vips__quantise_set_speed(VipsQuantiseAttr *attr, int speed);
VipsQuantiseImage *vips__quantise_image_create_rgba(const VipsQuantiseAttr *attr,
	const void *bitmap, int width, int height, double gamma);
VipsQuantiseError vips__quantise_image_quantize(VipsQuantiseImage *input_image,
	VipsQuantiseAttr *options, VipsQuantiseResult **result_output);
VipsQuantiseError vips__quantise_image_quantize_fixed(VipsQuantiseImage *input_image,
	VipsQuantiseAttr *options, VipsQuantiseResult **result_output);
VipsQuantiseError vips__quantise_set_dithering_level(VipsQuantiseResult *res,
	float dither_level);
const VipsQuantisePalette *vips__quantise_get_palette(VipsQuantiseResult *result);
VipsQuantiseError vips__quantise_write_remapped_image(VipsQuantiseResult *result,
	VipsQuantiseImage *input_image, void *buffer, size_t buffer_size);
void vips__quantise_result_destroy(VipsQuantiseResult *result);
void vips__quantise_image_destroy(VipsQuantiseImage *img);
void vips__quantise_attr_destroy(VipsQuantiseAttr *attr);

int vips__quantise_image(VipsImage *in,
	VipsImage **index_out, VipsImage **palette_out,
	int colours, int Q, double dither, int effort,
	gboolean threshold_alpha);

/* Built-in Wu quantiser low-level API (always available).
 */
int vips__builtin_quantise(const unsigned char *pixels,
	int width, int height, int max_colors, int effort,
	VipsQuantisePalette *palette_out);
int vips__builtin_remap(const unsigned char *pixels,
	int width, int height,
	const VipsQuantisePalette *palette,
	float dither_level, void *index_out);

/* Streaming variants: accept VipsImage, use vips_sink_disc internally.
 */
int vips__builtin_quantise_stream(VipsImage *in,
	int max_colors, int effort,
	VipsQuantisePalette *palette_out,
	GHashTable **exact_map_out);
int vips__builtin_exact_remap_stream(VipsImage *in, VipsImage *index,
	GHashTable *exact_map, gboolean has_transparent);
int vips__builtin_remap_stream(VipsImage *in, VipsImage *index,
	const VipsQuantisePalette *palette,
	float dither_level);
#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*VIPS_QUANTISE_H*/
