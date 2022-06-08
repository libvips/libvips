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

#if defined(HAVE_IMAGEQUANT)
#define HAVE_QUANTIZATION

#include <libimagequant.h>

#define VipsQuantiseAttr liq_attr
#define VipsQuantiseImage liq_image
#define VipsQuantiseResult liq_result
#define VipsQuantisePalette liq_palette
#define VipsQuantiseError liq_error

#elif defined(HAVE_QUANTIZR)
#define HAVE_QUANTIZATION

#include <quantizr.h>

#define VipsQuantiseAttr QuantizrOptions
#define VipsQuantiseImage QuantizrImage
#define VipsQuantiseResult QuantizrResult
#define VipsQuantisePalette QuantizrPalette
#define VipsQuantiseError QuantizrError
#endif

#ifdef HAVE_QUANTIZATION
VipsQuantiseAttr *vips__quantise_attr_create();
VipsQuantiseError vips__quantise_set_max_colors( VipsQuantiseAttr *attr,
	int colors );
VipsQuantiseError vips__quantise_set_quality( VipsQuantiseAttr *attr,
	int minimum, int maximum );
VipsQuantiseError vips__quantise_set_speed( VipsQuantiseAttr *attr, int speed );
VipsQuantiseImage *vips__quantise_image_create_rgba( const VipsQuantiseAttr *attr,
	const void *bitmap, int width, int height, double gamma );
VipsQuantiseError vips__quantise_image_quantize( VipsQuantiseImage *input_image,
	VipsQuantiseAttr *options, VipsQuantiseResult **result_output );
VipsQuantiseError vips__quantise_image_quantize_fixed( VipsQuantiseImage *input_image,
	VipsQuantiseAttr *options, VipsQuantiseResult **result_output );
VipsQuantiseError vips__quantise_set_dithering_level( VipsQuantiseResult *res,
	float dither_level );
const VipsQuantisePalette *vips__quantise_get_palette( VipsQuantiseResult *result );
VipsQuantiseError vips__quantise_write_remapped_image( VipsQuantiseResult *result,
	VipsQuantiseImage *input_image, void *buffer, size_t buffer_size );
void vips__quantise_result_destroy( VipsQuantiseResult *result );
void vips__quantise_image_destroy( VipsQuantiseImage *img );
void vips__quantise_attr_destroy( VipsQuantiseAttr *attr );
#endif /*HAVE_QUANTIZATION*/

int vips__quantise_image( VipsImage *in,
	VipsImage **index_out, VipsImage **palette_out,
	int colours, int Q, double dither, int effort,
	gboolean threshold_alpha );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*VIPS_QUANTISE_H*/
