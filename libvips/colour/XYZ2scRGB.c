/* Turn XYZ to scRGB colourspace.
 *
 * 11/12/12
 * 	- from Yxy2XYZ.c
 * 1/7/13
 * 	- remove any ICC profile
 * 25/11/14
 * 	- oh argh, revert the above
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

/* We can't use VipsColourCode as our parent class. We want to handle
 * alpha ourselves.
 */

typedef struct _VipsXYZ2scRGB {
	VipsOperation parent_instance;

	VipsImage *in;
	VipsImage *out;
} VipsXYZ2scRGB;

typedef VipsOperationClass VipsXYZ2scRGBClass;

G_DEFINE_TYPE(VipsXYZ2scRGB, vips_XYZ2scRGB, VIPS_TYPE_OPERATION);

/* We used to have the comment:

	 * We've converted to sRGB without a profile. We must remove any ICC
	 * profile left over from import or there will be a mismatch between
	 * pixel values and the attached profile.

   But this isn't right, we often call things sRGB that we know are not true
   sRGB, for example:

	vips sharpen k2.jpg x.jpg

   sharpen will treat k2 as being in sRGB space even if that image has a
   profile. If we drop the profile, x.jpg is suddenly untagged.

 */

static void
vips_XYZ2scRGB_line(float *restrict q, float *restrict p,
	int extra_bands, int width)
{
	int i, j;

	for (i = 0; i < width; i++) {
		const float X = p[0];
		const float Y = p[1];
		const float Z = p[2];

		float R, G, B;

		p += 3;

		vips_col_XYZ2scRGB(X, Y, Z, &R, &G, &B);

		q[0] = R;
		q[1] = G;
		q[2] = B;

		q += 3;

		for (j = 0; j < extra_bands; j++)
			q[j] = VIPS_CLIP(0, p[j] / 255.0, 1.0);
		p += extra_bands;
		q += extra_bands;
	}
}

static int
vips_XYZ2scRGB_gen(VipsRegion *out_region,
	void *seq, void *a, void *b, gboolean *stop)
{
	VipsRegion *ir = (VipsRegion *) seq;
	VipsRect *r = &out_region->valid;
	VipsImage *in = ir->im;

	int y;

	if (vips_region_prepare(ir, r))
		return -1;

	VIPS_GATE_START("vips_XYZ2scRGB: work");

	for (y = 0; y < r->height; y++) {
		float *p = (float *)
			VIPS_REGION_ADDR(ir, r->left, r->top + y);
		float *q = (float *)
			VIPS_REGION_ADDR(out_region, r->left, r->top + y);

		vips_XYZ2scRGB_line(q, p, in->Bands - 3, r->width);
	}

	VIPS_GATE_STOP("vips_XYZ2scRGB: work");

	return 0;
}

static int
vips_XYZ2scRGB_build(VipsObject *object)
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS(object);
	VipsXYZ2scRGB *XYZ2scRGB = (VipsXYZ2scRGB *) object;

	VipsImage **t = (VipsImage **) vips_object_local_array(object, 2);

	VipsImage *in;
	VipsImage *out;

	if (VIPS_OBJECT_CLASS(vips_XYZ2scRGB_parent_class)->build(object))
		return -1;

	in = XYZ2scRGB->in;
	if (vips_check_bands_atleast(class->nickname, in, 3))
		return -1;

	if (vips_cast_float(in, &t[0], NULL))
		return -1;
	in = t[0];

	out = vips_image_new();
	if (vips_image_pipelinev(out,
			VIPS_DEMAND_STYLE_THINSTRIP, in, NULL)) {
		g_object_unref(out);
		return -1;
	}
	out->Type = VIPS_INTERPRETATION_scRGB;
	out->BandFmt = VIPS_FORMAT_FLOAT;

	if (vips_image_generate(out,
			vips_start_one, vips_XYZ2scRGB_gen, vips_stop_one,
			in, XYZ2scRGB)) {
		g_object_unref(out);
		return -1;
	}

	g_object_set(object, "out", out, NULL);

	return 0;
}

static void
vips_XYZ2scRGB_class_init(VipsXYZ2scRGBClass *class)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS(class);
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsOperationClass *operation_class = VIPS_OPERATION_CLASS(class);

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "XYZ2scRGB";
	object_class->description = _("transform XYZ to scRGB");
	object_class->build = vips_XYZ2scRGB_build;

	operation_class->flags = VIPS_OPERATION_SEQUENTIAL;

	VIPS_ARG_IMAGE(class, "in", 1,
		_("Input"),
		_("Input image"),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET(VipsXYZ2scRGB, in));

	VIPS_ARG_IMAGE(class, "out", 100,
		_("Output"),
		_("Output image"),
		VIPS_ARGUMENT_REQUIRED_OUTPUT,
		G_STRUCT_OFFSET(VipsXYZ2scRGB, out));
}

static void
vips_XYZ2scRGB_init(VipsXYZ2scRGB *XYZ2scRGB)
{
}

/**
 * vips_XYZ2scRGB: (method)
 * @in: input image
 * @out: (out): output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Turn XYZ to scRGB.
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_XYZ2scRGB(VipsImage *in, VipsImage **out, ...)
{
	va_list ap;
	int result;

	va_start(ap, out);
	result = vips_call_split("XYZ2scRGB", ap, in, out);
	va_end(ap);

	return result;
}
