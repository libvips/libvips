/* reduce an image to n quantised colours
 *
 * 14/4/26
 *	- initial version
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <glib/gi18n-lib.h>

#include <vips/vips.h>

#include "../foreign/quantise.h"
#include "pconversion.h"

typedef struct _VipsReduceColours {
	VipsConversion parent_instance;

	VipsImage *in;
	int n;
	double dither;
	int effort;
} VipsReduceColours;

typedef VipsConversionClass VipsReduceColoursClass;

G_DEFINE_TYPE(VipsReduceColours, vips_reduce_colours, VIPS_TYPE_CONVERSION);

static int
vips_reduce_colours_build(VipsObject *object)
{
	VipsConversion *conversion = VIPS_CONVERSION(object);
	VipsReduceColours *rc = (VipsReduceColours *) object;
	VipsImage **t = (VipsImage **) vips_object_local_array(object, 4);

	VipsImage *index;
	VipsImage *palette;
	VipsImage *lut;
	gboolean all_opaque;

	if (VIPS_OBJECT_CLASS(vips_reduce_colours_parent_class)->build(object))
		return -1;

	/* Q hardcoded to 100; threshold_alpha hardcoded to FALSE.
	 */
	if (vips__quantise_image(rc->in, &index, &palette,
			rc->n, 100, rc->dither, rc->effort, FALSE))
		return -1;
	t[0] = index;
	t[1] = palette;

	/* Detect a fully-opaque palette by walking its alpha column. The
	 * palette is at most 256 entries, so this is trivially cheap.
	 */
	all_opaque = TRUE;
	{
		VipsRect r = { 0, 0, palette->Xsize, 1 };
		VipsRegion *region = vips_region_new(palette);
		const VipsPel *p;
		int i;

		if (vips_region_prepare(region, &r)) {
			g_object_unref(region);
			return -1;
		}
		p = VIPS_REGION_ADDR(region, 0, 0);
		for (i = 0; i < palette->Xsize; i++)
			if (p[i * 4 + 3] != 255) {
				all_opaque = FALSE;
				break;
			}
		g_object_unref(region);
	}

	/* When fully opaque, trim the LUT to RGB so vips_maplut produces a
	 * 3-band output. Otherwise keep the 4-band RGBA LUT.
	 */
	lut = palette;
	if (all_opaque) {
		if (vips_extract_band(palette, &t[2], 0, "n", 3, NULL))
			return -1;
		lut = t[2];
	}

	if (vips_maplut(index, &t[3], lut, NULL) ||
		vips_image_write(t[3], conversion->out))
		return -1;

	return 0;
}

static void
vips_reduce_colours_class_init(VipsReduceColoursClass *class)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS(class);
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS(class);
	VipsOperationClass *operation_class = VIPS_OPERATION_CLASS(class);

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "reduce_colours";
	vobject_class->description =
		_("reduce an image to n quantised colours");
	vobject_class->build = vips_reduce_colours_build;

	operation_class->flags = VIPS_OPERATION_SEQUENTIAL;

	VIPS_ARG_IMAGE(class, "in", 1,
		_("Input"),
		_("Input image"),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET(VipsReduceColours, in));

	VIPS_ARG_INT(class, "n", 2,
		_("N"),
		_("Number of colours"),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET(VipsReduceColours, n),
		2, 256, 256);

	VIPS_ARG_DOUBLE(class, "dither", 3,
		_("Dither"),
		_("Floyd-Steinberg dithering level"),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET(VipsReduceColours, dither),
		0.0, 1.0, 1.0);

	VIPS_ARG_INT(class, "effort", 4,
		_("Effort"),
		_("Quantisation effort"),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET(VipsReduceColours, effort),
		1, 10, 7);
}

static void
vips_reduce_colours_init(VipsReduceColours *rc)
{
	rc->dither = 1.0;
	rc->effort = 7;
}

/**
 * vips_reduce_colours: (method)
 * @in: input image
 * @out: (out): output image
 * @n: number of colours
 * @...: `NULL`-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @dither: dithering level
 * * @effort: quantisation effort
 *
 * Quantise @in to a palette of at most @n colours and remap every pixel to
 * its nearest entry, returning the same-size sRGB(A) uchar image. Uses
 * libimagequant, quantizr, or the built-in Wu quantiser, whichever is
 * available at compile time. @n may be in the range 1 to 256.
 *
 * If every entry of the chosen palette is fully opaque, the output is a
 * 3-band sRGB image; otherwise it has the alpha channel and is 4-band.
 *
 * @dither sets the Floyd-Steinberg dithering level (0 = none, 1 = full).
 * @effort sets the quantiser's speed/quality trade-off (1 = fastest,
 * 10 = best palette).
 *
 * ::: seealso
 *     [method@Image.dominant_colours], [method@Image.maplut].
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_reduce_colours(VipsImage *in, VipsImage **out, int n, ...)
{
	va_list ap;
	int result;

	va_start(ap, n);
	result = vips_call_split("reduce_colours", ap, in, out, n);
	va_end(ap);

	return result;
}
