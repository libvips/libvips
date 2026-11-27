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

	/* XYZ to the linear RGB the gains apply in, and that RGB to scRGB.
	 */
	float to_gamut[9];
	float from_gamut[9];

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
		float x = p1[0];
		float y = p1[1];
		float z = p1[2];
		p1 += 3;

		/* XYZ -> sRGB, including scale down from 100.
		 */
		float r =  0.03240626F * x +  -0.01537208F * y +  -0.004986286F * z;
		float g = -0.009689307F * x +  0.01875756F * y +   0.000415175F * z;
		float b =  0.000557101F * x + -0.002040211F * y +  0.01056996F * z;

		// gainmaps are already linear
		float gg = p2[0] / 255.0;
		p2 += 1;

		if (uhdr->gamma[1] != 1.0f)
			gg = powf(gg, 1.0f / uhdr->gamma[1]);

		float boostg = log2f(uhdr->min_content_boost[1]) * (1.0f - gg) +
			log2f(uhdr->max_content_boost[1]) * gg;

		float gaing = exp2f(boostg);

		q[0] = ((r + uhdr->offset_sdr[1]) * gaing) - uhdr->offset_hdr[1];
		q[1] = ((g + uhdr->offset_sdr[1]) * gaing) - uhdr->offset_hdr[1];
		q[2] = ((b + uhdr->offset_sdr[1]) * gaing) - uhdr->offset_hdr[1];
		q += 3;
	}
}

/* Colour image, colour gainmap. Allowed, but not common.
 */
static void
vips_UHDR2scRGB_rgb(VipsUHDR2scRGB *uhdr, VipsPel *out, VipsPel **in, int width)
{
	const float *m = uhdr->to_gamut;
	const float *n = uhdr->from_gamut;

	float *restrict p1 = (float *) in[0];
	VipsPel *restrict p2 = (VipsPel *) in[1];
	float *restrict q = (float *) out;

	for (int i = 0; i < width; i++) {
		float x = p1[0];
		float y = p1[1];
		float z = p1[2];
		p1 += 3;

		float r = m[0] * x + m[1] * y + m[2] * z;
		float g = m[3] * x + m[4] * y + m[5] * z;
		float b = m[6] * x + m[7] * y + m[8] * z;

		// gainmaps are already linear
		float gr = p2[0] / 255.0;
		float gg = p2[1] / 255.0;
		float gb = p2[2] / 255.0;
		p2 += 3;

		if (uhdr->gamma[0] != 1.0f)
			gr = powf(gr, 1.0f / uhdr->gamma[0]);
		if (uhdr->gamma[1] != 1.0f)
			gg = powf(gg, 1.0f / uhdr->gamma[1]);
		if (uhdr->gamma[2] != 1.0f)
			gb = powf(gb, 1.0f / uhdr->gamma[2]);

		float boostr = log2f(uhdr->min_content_boost[0]) * (1.0f - gr) +
			log2f(uhdr->max_content_boost[0]) * gr;
		float boostg = log2f(uhdr->min_content_boost[1]) * (1.0f - gg) +
			log2f(uhdr->max_content_boost[1]) * gg;
		float boostb = log2f(uhdr->min_content_boost[2]) * (1.0f - gb) +
			log2f(uhdr->max_content_boost[2]) * gb;

		float gainr = exp2f(boostr);
		float gaing = exp2f(boostg);
		float gainb = exp2f(boostb);

		r = ((r + uhdr->offset_sdr[0]) * gainr) - uhdr->offset_hdr[0];
		g = ((g + uhdr->offset_sdr[1]) * gaing) - uhdr->offset_hdr[1];
		b = ((b + uhdr->offset_sdr[2]) * gainb) - uhdr->offset_hdr[2];

		q[0] = n[0] * r + n[1] * g + n[2] * b;
		q[1] = n[3] * r + n[4] * g + n[5] * b;
		q[2] = n[6] * r + n[7] * g + n[8] * b;
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

/* The RGB -> XYZ matrix of the profile on an image.
 */
static VipsImage *
vips_UHDR2scRGB_primaries(VipsImage *image)
{
	const void *data;
	size_t length;

	if (vips_image_get_typeof(image, VIPS_META_ICC_NAME) &&
		!vips_image_get_blob(image, VIPS_META_ICC_NAME, &data, &length) &&
		vips_icc_is_compatible_profile(image, data, length))
		return vips__icc_primaries(data, length);

	return NULL;
}

/* RGB gainmaps apply in the RGB of the base image or of the gainmap.
 */
static int
vips_UHDR2scRGB_set_gamut(VipsUHDR2scRGB *uhdr, VipsImage *gainmap)
{
	VipsImage **t =
		(VipsImage **) vips_object_local_array(VIPS_OBJECT(uhdr), 4);

	int use_base_cg = 1;
	if (vips_image_get_typeof(uhdr->in, "gainmap-use-base-cg"))
		(void) vips_image_get_int(uhdr->in,
			"gainmap-use-base-cg", &use_base_cg);

	if (!use_base_cg)
		t[0] = vips_UHDR2scRGB_primaries(gainmap);
	if (!t[0])
		t[0] = vips_UHDR2scRGB_primaries(uhdr->in);
	if (!t[0]) {
		VipsBlob *srgb;
		const void *data;
		size_t length;

		if (vips_profile_load("srgb", &srgb, NULL))
			return -1;
		data = vips_blob_get(srgb, &length);
		t[0] = vips__icc_primaries(data, length);
		vips_area_unref(VIPS_AREA(srgb));
	}

	/* XYZ -> sRGB, including scale down from 100.
	 */
	t[2] = vips_image_new_matrixv(3, 3,
		0.03240626, -0.01537208, -0.004986286,
		-0.009689307, 0.01875756, 0.000415175,
		0.000557101, -0.002040211, 0.01056996);

	if (!t[0] ||
		!t[2] ||
		vips_matrixinvert(t[0], &t[1], NULL) ||
		vips_matrixmultiply(t[2], t[0], &t[3], NULL))
		return -1;

	for (int y = 0; y < 3; y++)
		for (int x = 0; x < 3; x++) {
			uhdr->to_gamut[3 * y + x] = *VIPS_MATRIX(t[1], x, y);
			uhdr->from_gamut[3 * y + x] = *VIPS_MATRIX(t[3], x, y);
		}

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
		if (vips_check_bands(class->nickname, uhdr->in, 3) ||
			vips_check_u8or16(class->nickname, uhdr->in))
			return -1;

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

		/* One gain for all three channels gives the same result in any RGB.
		 */
		if (gainmap->Bands == 3 &&
			vips_UHDR2scRGB_set_gamut(uhdr, gainmap)) {
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

	colour->interpretation = VIPS_INTERPRETATION_scRGB;
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
