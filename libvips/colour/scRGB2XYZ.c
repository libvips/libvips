/* Turn scRGB to XYZ colourspace.
 *
 * Modified:
 * 29/5/02 JC
 *	- from lab2xyz
 * 2/11/09
 * 	- gtkdoc
 * 	- cleanups
 * 20/9/12
 * 	redo as a class
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

typedef struct _VipsscRGB2XYZ {
	VipsOperation parent_instance;

	VipsImage *in;
	VipsImage *out;
} VipsscRGB2XYZ;

typedef VipsOperationClass VipsscRGB2XYZClass;

G_DEFINE_TYPE(VipsscRGB2XYZ, vips_scRGB2XYZ, VIPS_TYPE_OPERATION);

static void
vips_scRGB2XYZ_line(float *restrict q, float *restrict p,
	int extra_bands, int width)
{
	int i, j;

	for (i = 0; i < width; i++) {
		const float R = p[0] * VIPS_D65_Y0;
		const float G = p[1] * VIPS_D65_Y0;
		const float B = p[2] * VIPS_D65_Y0;

		/* Manually inlined logic from the vips_col_scRGB2XYZ function
		 * as the original is defined in a separate file and is part of
		 * the public API so a compiler will not inline.
		 */
		q[0] = 0.4124F * R +
			0.3576F * G +
			0.1805F * B;
		q[1] = 0.2126F * R +
			0.7152F * G +
			0.0722F * B;
		q[2] = 0.0193F * R +
			0.1192F * G +
			0.9505F * B;

		p += 3;
		q += 3;

		for (j = 0; j < extra_bands; j++)
			q[j] = VIPS_FCLIP(0, p[j] * 255.0, 255.0);
		p += extra_bands;
		q += extra_bands;
	}
}

static int
vips_scRGB2XYZ_gen(VipsRegion *out_region,
	void *seq, void *a, void *b, gboolean *stop)
{
	VipsRegion *ir = (VipsRegion *) seq;
	VipsRect *r = &out_region->valid;
	VipsImage *in = ir->im;

	int y;

	if (vips_region_prepare(ir, r))
		return -1;

	VIPS_GATE_START("vips_scRGB2XYZ_gen: work");

	for (y = 0; y < r->height; y++) {
		float *p = (float *)
			VIPS_REGION_ADDR(ir, r->left, r->top + y);
		float *q = (float *)
			VIPS_REGION_ADDR(out_region, r->left, r->top + y);

		vips_scRGB2XYZ_line(q, p, in->Bands - 3, r->width);
	}

	VIPS_GATE_STOP("vips_scRGB2XYZ_gen: work");

	return 0;
}

static int
vips_scRGB2XYZ_build(VipsObject *object)
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS(object);
	VipsscRGB2XYZ *scRGB2XYZ = (VipsscRGB2XYZ *) object;

	VipsImage **t = (VipsImage **) vips_object_local_array(object, 2);

	VipsImage *in;
	VipsImage *out;

	if (VIPS_OBJECT_CLASS(vips_scRGB2XYZ_parent_class)->build(object))
		return -1;

	in = scRGB2XYZ->in;
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
	out->Type = VIPS_INTERPRETATION_XYZ;
	out->BandFmt = VIPS_FORMAT_FLOAT;

	if (vips_image_generate(out,
			vips_start_one, vips_scRGB2XYZ_gen, vips_stop_one,
			in, scRGB2XYZ)) {
		g_object_unref(out);
		return -1;
	}

	g_object_set(object, "out", out, NULL);

	return 0;
}

static void
vips_scRGB2XYZ_class_init(VipsscRGB2XYZClass *class)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS(class);
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsOperationClass *operation_class = VIPS_OPERATION_CLASS(class);

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "scRGB2XYZ";
	object_class->description = _("transform scRGB to XYZ");
	object_class->build = vips_scRGB2XYZ_build;

	operation_class->flags = VIPS_OPERATION_SEQUENTIAL;

	VIPS_ARG_IMAGE(class, "in", 1,
		_("Input"),
		_("Input image"),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET(VipsscRGB2XYZ, in));

	VIPS_ARG_IMAGE(class, "out", 100,
		_("Output"),
		_("Output image"),
		VIPS_ARGUMENT_REQUIRED_OUTPUT,
		G_STRUCT_OFFSET(VipsscRGB2XYZ, out));
}

static void
vips_scRGB2XYZ_init(VipsscRGB2XYZ *scRGB2XYZ)
{
}

/**
 * vips_scRGB2XYZ: (method)
 * @in: input image
 * @out: (out): output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Turn XYZ to scRGB.
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_scRGB2XYZ(VipsImage *in, VipsImage **out, ...)
{
	va_list ap;
	int result;

	va_start(ap, out);
	result = vips_call_split("scRGB2XYZ", ap, in, out);
	va_end(ap);

	return result;
}
