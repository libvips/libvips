/* Turn uhdr (RGB plus a gainmap) to scRGB colourspace.
 *
 * 26/11/25
 * 	- from XYZ2scRGB.c.c
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <glib/gi18n-lib.h>

#include <stdio.h>
#include <math.h>

#include <vips/vips.h>

#include "pcolour.h"

typedef struct _VipsUhdr2scRGB {
	VipsColour parent;

	VipsImage *in;

	/* Gainmap metadata.
	 */
	float gamma[3];
	float min_content_boost[3];
	float max_content_boost[3];
	float offset_hdr[3];
	float offset_sdr[3];

	/* And the actual map.
	 */
	VipsImage *gainmap;

} VipsUhdr2scRGB;

typedef VipsColourClass VipsUhdr2scRGBClass;

G_DEFINE_TYPE(VipsUhdr2scRGB, vips_uhdr2scRGB, VIPS_TYPE_COLOUR);

/* Derived from the apache-licensed applyGain() method of libuhdr.
 */

/* Monochrome gainmap, colour image. Probably the most common case.
 */
static void
vips_uhdr2scRGB_mono(VipsUhdr2scRGB *uhdr,
	VipsPel *out, VipsPel **in, int width)
{
	VipsPel *restrict p1 = in[0];
	VipsPel *restrict p2 = in[1];
	float *restrict q = (float *) out;

	for (int i = 0; i < width; i++) {
		float r = vips_v2Y_8[p1[0]];
		float g = vips_v2Y_8[p1[1]];
		float b = vips_v2Y_8[p1[2]];
		p1 += 3;

		float gg = vips_v2Y_8[p2[0]];
		p2 += 1;

		if (uhdr->gamma[1] != 1.0f)
			gg = pow(gg, 1.0f / uhdr->gamma[1]);

		float boostg = log2(uhdr->min_content_boost[1]) * (1.0f - gg) +
			log2(uhdr->max_content_boost[1]) * gg;

		float gaing = exp2(boostg);

		q[0] = ((r + uhdr->offset_sdr[1]) * gaing) - uhdr->offset_hdr[1];
		q[1] = ((g + uhdr->offset_sdr[1]) * gaing) - uhdr->offset_hdr[1];
		q[2] = ((b + uhdr->offset_sdr[1]) * gaing) - uhdr->offset_hdr[1];
		q += 3;
	}
}

/* Colour image, colour gainmap. Allowed, but not common.
 */
static void
vips_uhdr2scRGB_rgb(VipsUhdr2scRGB *uhdr, VipsPel *out, VipsPel **in, int width)
{
	VipsPel *restrict p1 = in[0];
	VipsPel *restrict p2 = in[1];
	float *restrict q = (float *) out;

	for (int i = 0; i < width; i++) {
		float r = vips_v2Y_8[p1[0]];
		float g = vips_v2Y_8[p1[1]];
		float b = vips_v2Y_8[p1[2]];
		p1 += 3;

		float gr = vips_v2Y_8[p2[0]];
		float gg = vips_v2Y_8[p2[1]];
		float gb = vips_v2Y_8[p2[2]];
		p2 += 3;

		if (uhdr->gamma[0] != 1.0f)
			gr = pow(gr, 1.0f / uhdr->gamma[0]);
		if (uhdr->gamma[1] != 1.0f)
			gg = pow(gg, 1.0f / uhdr->gamma[1]);
		if (uhdr->gamma[2] != 1.0f)
			gb = pow(gb, 1.0f / uhdr->gamma[2]);

		float boostr = log2(uhdr->min_content_boost[0]) * (1.0f - gr) +
			log2(uhdr->max_content_boost[0]) * gr;
		float boostg = log2(uhdr->min_content_boost[1]) * (1.0f - gg) +
			log2(uhdr->max_content_boost[1]) * gg;
		float boostb = log2(uhdr->min_content_boost[2]) * (1.0f - gb) +
			log2(uhdr->max_content_boost[2]) * gb;

		float gainr = exp2(boostr);
		float gaing = exp2(boostg);
		float gainb = exp2(boostb);

		q[0] = ((r + uhdr->offset_sdr[0]) * gainr) - uhdr->offset_hdr[0];
		q[1] = ((g + uhdr->offset_sdr[1]) * gaing) - uhdr->offset_hdr[1];
		q[2] = ((b + uhdr->offset_sdr[2]) * gainb) - uhdr->offset_hdr[2];
		q += 3;
	}
}

static void
vips_uhdr2scRGB_line(VipsColour *colour, VipsPel *out, VipsPel **in, int width)
{
	VipsUhdr2scRGB *uhdr = (VipsUhdr2scRGB *) colour;

	g_assert(colour->in[0]->Xsize == colour->in[1]->Xsize);
	g_assert(colour->in[0]->Ysize == colour->in[1]->Ysize);

	if (uhdr->gainmap->Bands == 1)
		vips_uhdr2scRGB_mono(uhdr, out, in, width);
	else
		vips_uhdr2scRGB_rgb(uhdr, out, in, width);
}

// pass in the array to fill, size must match
static int
image_get_array_float(VipsImage *image, const char *name,
	float *out, int n_out)
{
	double *d;
	int n;
	if (vips_image_get_array_double(image, name, &d, &n))
		return -1;
	if (n != n_out) {
		vips_error("image_get_array_float", _("bad size"));
		return -1;
	}

	for (int i = 0; i < n; i++)
		out[i] = d[i];

	return 0;
}

static int
vips_uhdr2scRGB_build(VipsObject *object)
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS(object);
	VipsColour *colour = VIPS_COLOUR(object);
	VipsUhdr2scRGB *uhdr = (VipsUhdr2scRGB *) object;

	/* We allow one-band gainmap plus 3 band main image, so we have to turn
	 * off the automatic detach-attach alpha processing.
	 */
	colour->input_bands = 0;

	colour->n = 2;
	colour->in = (VipsImage **) vips_object_local_array(object, 2);

	/* Get the gainmap image metadata.
	 */
	if (uhdr->in) {
		if (vips_check_bands(class->nickname, uhdr->in, 3))
			return -1;
		if (uhdr->in->BandFmt != VIPS_FORMAT_UCHAR) {
			vips_error(class->nickname, "%s", _("image must be uchar"));
			return -1;
		}

		/* Need this for fast srgb -> scRGB.
		 */
		vips_col_make_tables_RGB_8();

		if (image_get_array_float(uhdr->in,
				"gainmap-max-content-boost", &uhdr->max_content_boost[0], 3) ||
			image_get_array_float(uhdr->in,
				"gainmap-min-content-boost", &uhdr->min_content_boost[0], 3) ||
			image_get_array_float(uhdr->in,
				"gainmap-gamma", &uhdr->gamma[0], 3) ||
			image_get_array_float(uhdr->in,
				"gainmap-offset-sdr", &uhdr->offset_sdr[0], 3) ||
			image_get_array_float(uhdr->in,
				"gainmap-offset-hdr", &uhdr->offset_hdr[0], 3))
			return -1;

		VipsImage *gainmap;
		if (!(gainmap = vips_image_get_gainmap(uhdr->in)))
			return -1;
		if (vips_check_bands_1or3(class->nickname, gainmap))
			return -1;

		/* Scale the gainmap image to match the main image 1:1.
		 */
		if (vips_resize(gainmap, &uhdr->gainmap,
				(double) uhdr->in->Xsize / gainmap->Xsize,
				"vscale", (double) uhdr->in->Ysize / gainmap->Ysize,
				"kernel", VIPS_KERNEL_LINEAR,
				NULL))
			return -1;

		colour->in[0] = uhdr->in;
		g_object_ref(uhdr->in);
		colour->in[1] = uhdr->gainmap;
	}

	if (VIPS_OBJECT_CLASS(vips_uhdr2scRGB_parent_class)->build(object))
		return -1;

	return 0;
}

static void
vips_uhdr2scRGB_class_init(VipsUhdr2scRGBClass *class)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS(class);
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsColourClass *colour_class = VIPS_COLOUR_CLASS(class);

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "uhdr2scRGB";
	object_class->description = _("transform XYZ to scRGB");
	object_class->build = vips_uhdr2scRGB_build;

	colour_class->process_line = vips_uhdr2scRGB_line;

	VIPS_ARG_IMAGE(class, "in", 1,
		_("Input"),
		_("Input image"),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET(VipsColourTransform, in));
}

static void
vips_uhdr2scRGB_init(VipsUhdr2scRGB *uhdr)
{
	VipsColour *colour = VIPS_COLOUR(uhdr);

	colour->interpretation = VIPS_INTERPRETATION_scRGB;
	colour->format = VIPS_FORMAT_FLOAT;
	colour->bands = 3;
}

/**
 * vips_uhdr2scRGB: (method)
 * @in: input image
 * @out: (out): output image
 * @...: `NULL`-terminated list of optional named arguments
 *
 * Transform a uhdr image (three band sRGB with an attached gainmap) to
 * scRGB.
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_uhdr2scRGB(VipsImage *in, VipsImage **out, ...)
{
	va_list ap;
	int result;

	va_start(ap, out);
	result = vips_call_split("uhdr2scRGB", ap, in, out);
	va_end(ap);

	return result;
}
