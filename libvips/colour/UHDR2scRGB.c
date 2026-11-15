/* Turn UHDR (RGB plus a gainmap) to scRGB colourspace.
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

gboolean
vips__image_is_uhdr(VipsImage *image)
{
	return
		vips_image_get_typeof(image, "gainmap-max-content-boost") &&
		vips_image_get_typeof(image, "gainmap-min-content-boost") &&
		vips_image_get_typeof(image, "gainmap-gamma") &&
		vips_image_get_typeof(image, "gainmap-offset-sdr") &&
		vips_image_get_typeof(image, "gainmap-offset-hdr");
}

typedef struct _VipsUHDR2scRGB {
	VipsColour parent;

	VipsImage *in;

	/* Gainmap metadata.
	 */
	float gamma[3];
	float min_content_boost[3];
	float max_content_boost[3];
	float offset_hdr[3];
	float offset_sdr[3];

} VipsUHDR2scRGB;

typedef VipsColourClass VipsUHDR2scRGBClass;

G_DEFINE_TYPE(VipsUHDR2scRGB, vips_UHDR2scRGB, VIPS_TYPE_COLOUR);

/* Derived from the apache-licensed applyGain() method of libuhdr.
 */

/* Monochrome gainmap, colour image. Probably the most common case.
 */
static void
vips_UHDR2scRGB_mono(VipsUHDR2scRGB *uhdr,
	VipsPel *out, VipsPel **in, int width)
{
	float *restrict p1 = (float *) in[0];
	VipsPel *restrict p2 = (VipsPel *) in[1];
	float *restrict q = (float *) out;

	for (int i = 0; i < width; i++) {
		float x = p1[0] / VIPS_D65_X0;
		float y = p1[1] / VIPS_D65_Y0;
		float z = p1[2] / VIPS_D65_Z0;
		p1 += 3;

		// gainmaps are already linear
		float gy = p2[0] / 255.0;
		p2 += 1;

		if (uhdr->gamma[1] != 1.0f)
			gy = powf(gy, 1.0f / uhdr->gamma[1]);

		float boosty = log2f(uhdr->min_content_boost[1]) * (1.0f - gy) +
			log2f(uhdr->max_content_boost[1]) * gy;

		float gainy = exp2f(boosty);

		float nx = ((x + uhdr->offset_sdr[1]) * gainy) - uhdr->offset_hdr[1];
		float ny = ((y + uhdr->offset_sdr[1]) * gainy) - uhdr->offset_hdr[1];
		float nz = ((z + uhdr->offset_sdr[1]) * gainy) - uhdr->offset_hdr[1];

		// back to scrgb
		q[0] =  3.240625F * nx + -1.537208F * ny + -0.498629F * nz;
		q[1] = -0.968931F * nx +  1.875756F * ny +  0.041518F * nz;
		q[2] =  0.055710F * nx + -0.204021F * ny +  1.056996F * nz;
		q += 3;
	}
}

/* Colour image, colour gainmap. Allowed, but not common.
 */
static void
vips_UHDR2scRGB_rgb(VipsUHDR2scRGB *uhdr, VipsPel *out, VipsPel **in, int width)
{
	float *restrict p1 = (float *) in[0];
	VipsPel *restrict p2 = (VipsPel *) in[1];
	float *restrict q = (float *) out;

	for (int i = 0; i < width; i++) {
		float x = p1[0] / VIPS_D65_X0;
		float y = p1[1] / VIPS_D65_Y0;
		float z = p1[2] / VIPS_D65_Z0;
		p1 += 3;

		// gainmaps are already linear
		float gx = p2[0] / 255.0;
		float gy = p2[1] / 255.0;
		float gz = p2[2] / 255.0;
		p2 += 3;

		if (uhdr->gamma[0] != 1.0f)
			gx = powf(gx, 1.0f / uhdr->gamma[0]);
		if (uhdr->gamma[1] != 1.0f)
			gy = powf(gy, 1.0f / uhdr->gamma[1]);
		if (uhdr->gamma[2] != 1.0f)
			gz = powf(gz, 1.0f / uhdr->gamma[2]);

		float boostx = log2f(uhdr->min_content_boost[0]) * (1.0f - gx) +
			log2f(uhdr->max_content_boost[0]) * gx;
		float boosty = log2f(uhdr->min_content_boost[1]) * (1.0f - gy) +
			log2f(uhdr->max_content_boost[1]) * gy;
		float boostz = log2f(uhdr->min_content_boost[2]) * (1.0f - gz) +
			log2f(uhdr->max_content_boost[2]) * gz;

		float gainx = exp2f(boostx);
		float gainy = exp2f(boosty);
		float gainz = exp2f(boostz);

		float nx = VIPS_D65_X0 / 100.0F *
			(((x + uhdr->offset_sdr[0]) * gainx) - uhdr->offset_hdr[0]);
		float ny = VIPS_D65_Y0 / 100.0F *
			(((y + uhdr->offset_sdr[1]) * gainy) - uhdr->offset_hdr[1]);
		float nz = VIPS_D65_Z0 / 100.0F *
			(((z + uhdr->offset_sdr[2]) * gainz) - uhdr->offset_hdr[2]);

		// back to scrgb
		q[0] =  3.240625F * nx + -1.537208F * ny + -0.498629F * nz;
		q[1] = -0.968931F * nx +  1.875756F * ny +  0.041518F * nz;
		q[2] =  0.055710F * nx + -0.204021F * ny +  1.056996F * nz;
		q += 3;
	}
}

static void
vips_UHDR2scRGB_line(VipsColour *colour, VipsPel *out, VipsPel **in, int width)
{
	VipsUHDR2scRGB *uhdr = (VipsUHDR2scRGB *) colour;

	g_assert(colour->in[0]->Xsize == colour->in[1]->Xsize);
	g_assert(colour->in[0]->Ysize == colour->in[1]->Ysize);

	if (colour->in[1]->Bands == 1)
		vips_UHDR2scRGB_mono(uhdr, out, in, width);
	else
		vips_UHDR2scRGB_rgb(uhdr, out, in, width);
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
vips_UHDR2scRGB_build(VipsObject *object)
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS(object);
	VipsColour *colour = VIPS_COLOUR(object);
	VipsUHDR2scRGB *uhdr = (VipsUHDR2scRGB *) object;

	/* We allow one-band gainmap plus 3 band main image, so we have to turn
	 * off the automatic detach-attach alpha processing.
	 */
	colour->input_bands = 0;

	colour->n = 2;
	colour->in = (VipsImage **) vips_object_local_array(object, 2);

	/* Helpful error if this is not a UHDR image.
	 *
	 * UHDR images can also be missing fields if we've been built without
	 * UHDR support.
	 */
	if (uhdr->in &&
		!vips__image_is_uhdr(uhdr->in)) {
		vips_error(class->nickname, "%s", _("not a UHDR image, "
				"or UHDR is not enabled"));
		return -1;
	}

	/* Get the gainmap image metadata.
	 */
	if (uhdr->in) {
		if (vips_check_bands(class->nickname, uhdr->in, 3))
			return -1;
		if (uhdr->in->BandFmt != VIPS_FORMAT_UCHAR) {
			vips_error(class->nickname, "%s", _("image must be uchar"));
			return -1;
		}

		/* Import the main image to XYZ to get linear light.
		 */
		if (vips_icc_import(uhdr->in, &colour->in[0],
			"embedded", TRUE,
			"pcs", VIPS_PCS_XYZ,
			"input_profile", "srgb",
			NULL))
			return -1;

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
		if (vips_check_bands_1or3(class->nickname, gainmap)) {
			VIPS_UNREF(gainmap);
			return -1;
		}

		/* And now scale the gainmap image to match the main image 1:1.
		 */
		if (vips_resize(gainmap, &colour->in[1],
			(double) uhdr->in->Xsize / gainmap->Xsize,
			"vscale", (double) uhdr->in->Ysize / gainmap->Ysize,
			"kernel", VIPS_KERNEL_LINEAR,
			NULL)) {
			VIPS_UNREF(gainmap);
			return -1;
		}
		VIPS_UNREF(gainmap);
	}

	if (VIPS_OBJECT_CLASS(vips_UHDR2scRGB_parent_class)->build(object))
		return -1;

	return 0;
}

static void
vips_UHDR2scRGB_class_init(VipsUHDR2scRGBClass *class)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS(class);
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsColourClass *colour_class = VIPS_COLOUR_CLASS(class);

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "UHDR2scRGB";
	object_class->description = _("transform UHDR to scRGB");
	object_class->build = vips_UHDR2scRGB_build;

	colour_class->process_line = vips_UHDR2scRGB_line;

	VIPS_ARG_IMAGE(class, "in", 1,
		_("Input"),
		_("Input image"),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET(VipsColourTransform, in));
}

static void
vips_UHDR2scRGB_init(VipsUHDR2scRGB *uhdr)
{
	VipsColour *colour = VIPS_COLOUR(uhdr);

	colour->interpretation = VIPS_INTERPRETATION_scRGB;
	colour->format = VIPS_FORMAT_FLOAT;
	colour->bands = 3;
}

/**
 * vips_UHDR2scRGB: (method)
 * @in: input image
 * @out: (out): output image
 * @...: `NULL`-terminated list of optional named arguments
 *
 * Transform a UHDR image (three band sRGB with an attached gainmap) to
 * scRGB.
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_UHDR2scRGB(VipsImage *in, VipsImage **out, ...)
{
	va_list ap;
	int result;

	va_start(ap, out);
	result = vips_call_split("UHDR2scRGB", ap, in, out);
	va_end(ap);

	return result;
}

/* Kept for compat. Use vips_UHDR2scRGB() instead.
 */
typedef VipsUHDR2scRGB VipsUhdr2scRGB;
typedef VipsColourClass VipsUhdr2scRGBClass;

G_DEFINE_TYPE(VipsUhdr2scRGB, vips_uhdr2scRGB, VIPS_TYPE_COLOUR);

static void
vips_uhdr2scRGB_class_init(VipsUhdr2scRGBClass *class)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS(class);
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsOperationClass *operation_class = (VipsOperationClass *) class;
	VipsColourClass *colour_class = VIPS_COLOUR_CLASS(class);

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "uhdr2scRGB";
	object_class->description = _("transform uhdr to scRGB");
	object_class->build = vips_UHDR2scRGB_build;

	operation_class->flags |= VIPS_OPERATION_DEPRECATED;

	colour_class->process_line = vips_UHDR2scRGB_line;

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

	colour->interpretation = VIPS_INTERPRETATION_XYZ;
	colour->format = VIPS_FORMAT_FLOAT;
	colour->bands = 3;
}

/**
 * vips_uhdr2scRGB: (skip)
 * @in: input image
 * @out: (out): output image
 * @...: `NULL`-terminated list of optional named arguments
 *
 * Deprecated, please use [method@Image.UHDR2scRGB].
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
