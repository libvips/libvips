/* Edge detector
 *
 * 12/4/23
 * 	- from vips_sobel()
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
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <glib/gi18n-lib.h>

#include <stdio.h>
#include <stdlib.h>
#include <math.h>

#include <vips/vips.h>

typedef struct _VipsEdge {
	VipsOperation parent_instance;

	VipsImage *in;
	VipsImage *out;
	VipsImage *mask;

	/* Need an image vector for start_many.
	 */
	VipsImage *args[3];
} VipsEdge;

typedef VipsOperationClass VipsEdgeClass;

G_DEFINE_ABSTRACT_TYPE(VipsEdge, vips_edge, VIPS_TYPE_OPERATION);

static void
vips_edge_dispose(GObject *gobject)
{
	VipsEdge *edge = (VipsEdge *) gobject;

	VIPS_UNREF(edge->mask);

	G_OBJECT_CLASS(vips_edge_parent_class)->dispose(gobject);
}

static int
vips_edge_uchar_gen(VipsRegion *out_region,
	void *vseq, void *a, void *b, gboolean *stop)
{
	VipsRegion **in = (VipsRegion **) vseq;
	VipsRect *r = &out_region->valid;
	int sz = r->width * in[0]->im->Bands;

	int x, y;

	if (vips_reorder_prepare_many(out_region->im, in, r))
		return -1;

	for (y = 0; y < r->height; y++) {
		VipsPel *p1 = (VipsPel *restrict)
			VIPS_REGION_ADDR(in[0], r->left, r->top + y);
		VipsPel *p2 = (VipsPel *restrict)
			VIPS_REGION_ADDR(in[1], r->left, r->top + y);
		VipsPel *q = (VipsPel *restrict)
			VIPS_REGION_ADDR(out_region, r->left, r->top + y);

		for (x = 0; x < sz; x++) {
			int v1 = 2 * (p1[x] - 128);
			int v2 = 2 * (p2[x] - 128);
			/* Avoid the sqrt() for uchar.
			 */
			int v = VIPS_ABS(v1) + VIPS_ABS(v2);

			q[x] = v > 255 ? 255 : v;
		}
	}

	return 0;
}

/* Fast uchar path.
 */
static int
vips_edge_build_uchar(VipsEdge *edge)
{
	VipsImage **t = (VipsImage **)
		vips_object_local_array(VIPS_OBJECT(edge), 20);

	g_info("vips_edge: uchar path");

	/* For uchar, use 128 as the zero and divide the result by 2 to
	 * prevent overflow.
	 */
	if (vips_copy(edge->mask, &t[1], NULL))
		return -1;
	vips_image_set_double(t[1], "offset", 128.0);
	vips_image_set_double(t[1], "scale", 2.0);
	if (vips_conv(edge->in, &t[3], t[1],
			"precision", VIPS_PRECISION_INTEGER,
			NULL))
		return -1;

	if (vips_rot90(t[1], &t[5], NULL) ||
		vips_conv(edge->in, &t[7], t[5],
			"precision", VIPS_PRECISION_INTEGER,
			NULL))
		return -1;

	g_object_set(edge, "out", vips_image_new(), NULL);

	edge->args[0] = t[3];
	edge->args[1] = t[7];
	edge->args[2] = NULL;
	if (vips_image_pipeline_array(edge->out,
			VIPS_DEMAND_STYLE_FATSTRIP, edge->args))
		return -1;

	if (vips_image_generate(edge->out,
			vips_start_many, vips_edge_uchar_gen, vips_stop_many,
			edge->args, NULL))
		return -1;

	return 0;
}

/* Accurate but slow path.
 */
static int
vips_edge_build_float(VipsEdge *edge)
{
	VipsImage **t = (VipsImage **)
		vips_object_local_array(VIPS_OBJECT(edge), 20);

	g_info("vips_edge: float path");

	if (vips_rot90(edge->mask, &t[0], NULL) ||
		vips_conv(edge->in, &t[1], edge->mask, NULL) ||
		vips_conv(edge->in, &t[2], t[0], NULL))
		return -1;

	if (vips_multiply(t[1], t[1], &t[3], NULL) ||
		vips_multiply(t[2], t[2], &t[4], NULL) ||
		vips_add(t[3], t[4], &t[5], NULL) ||
		vips_pow_const1(t[5], &t[6], 0.5, NULL) ||
		vips_cast_uchar(t[6], &t[7], NULL))
		return -1;

	g_object_set(edge, "out", vips_image_new(), NULL);

	if (vips_image_write(t[7], edge->out))
		return -1;

	return 0;
}

static int
vips_edge_build(VipsObject *object)
{
	VipsEdge *edge = (VipsEdge *) object;

	if (edge->in->BandFmt == VIPS_FORMAT_UCHAR) {
		if (vips_edge_build_uchar(edge))
			return -1;
	}
	else {
		if (vips_edge_build_float(edge))
			return -1;
	}

	return 0;
}

static void
vips_edge_class_init(VipsEdgeClass *class)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS(class);
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	gobject_class->dispose = vips_edge_dispose;
	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "edge";
	object_class->description = _("Edge detector");
	object_class->build = vips_edge_build;

	VIPS_ARG_IMAGE(class, "in", 1,
		_("Input"),
		_("Input image"),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET(VipsEdge, in));

	VIPS_ARG_IMAGE(class, "out", 2,
		_("Output"),
		_("Output image"),
		VIPS_ARGUMENT_REQUIRED_OUTPUT,
		G_STRUCT_OFFSET(VipsEdge, out));
}

static void
vips_edge_init(VipsEdge *edge)
{
}

typedef VipsEdge VipsSobel;
typedef VipsEdgeClass VipsSobelClass;

G_DEFINE_TYPE(VipsSobel, vips_sobel, vips_edge_get_type());

static int
vips_sobel_build(VipsObject *object)
{
	VipsEdge *edge = (VipsEdge *) object;

	edge->mask = vips_image_new_matrixv(3, 3,
		1.0, 2.0, 1.0,
		0.0, 0.0, 0.0,
		-1.0, -2.0, -1.0);

	return VIPS_OBJECT_CLASS(vips_sobel_parent_class)->build(object);
}

static void
vips_sobel_class_init(VipsSobelClass *class)
{
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	object_class->nickname = "sobel";
	object_class->description = _("Sobel edge detector");
	object_class->build = vips_sobel_build;
}

static void
vips_sobel_init(VipsEdge *sobel)
{
}

typedef VipsEdge VipsScharr;
typedef VipsEdgeClass VipsScharrClass;

G_DEFINE_TYPE(VipsScharr, vips_scharr, vips_edge_get_type());

static int
vips_scharr_build(VipsObject *object)
{
	VipsEdge *edge = (VipsEdge *) object;

	edge->mask = vips_image_new_matrixv(3, 3,
		-3.0, 0.0, 3.0,
		-10.0, 0.0, 10.0,
		-3.0, 0.0, 3.0);

	return VIPS_OBJECT_CLASS(vips_scharr_parent_class)->build(object);
}

static void
vips_scharr_class_init(VipsSobelClass *class)
{
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	object_class->nickname = "scharr";
	object_class->description = _("Scharr edge detector");
	object_class->build = vips_scharr_build;
}

static void
vips_scharr_init(VipsScharr *scharr)
{
}

typedef VipsEdge VipsPrewitt;
typedef VipsEdgeClass VipsPrewittClass;

G_DEFINE_TYPE(VipsPrewitt, vips_prewitt, vips_edge_get_type());

static int
vips_prewitt_build(VipsObject *object)
{
	VipsEdge *edge = (VipsEdge *) object;

	edge->mask = vips_image_new_matrixv(3, 3,
		-1.0, 0.0, 1.0,
		-1.0, 0.0, 1.0,
		-1.0, 0.0, 1.0);

	return VIPS_OBJECT_CLASS(vips_prewitt_parent_class)->build(object);
}

static void
vips_prewitt_class_init(VipsSobelClass *class)
{
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	object_class->nickname = "prewitt";
	object_class->description = _("Prewitt edge detector");
	object_class->build = vips_prewitt_build;
}

static void
vips_prewitt_init(VipsPrewitt *prewitt)
{
}

/**
 * vips_sobel: (method)
 * @in: input image
 * @out: (out): output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Sobel edge detector.
 *
 * uchar images are computed using a fast, low-precision path. Cast to float
 * for a high-precision implementation.
 *
 * See also: vips_canny(), vips_sobel(), vips_prewitt(), vips_scharr().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_sobel(VipsImage *in, VipsImage **out, ...)
{
	va_list ap;
	int result;

	va_start(ap, out);
	result = vips_call_split("sobel", ap, in, out);
	va_end(ap);

	return result;
}

/**
 * vips_scharr: (method)
 * @in: input image
 * @out: (out): output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Scharr edge detector.
 *
 * uchar images are computed using a fast, low-precision path. Cast to float
 * for a high-precision implementation.
 *
 * See also: vips_canny(), vips_sobel(), vips_prewitt(), vips_scharr().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_scharr(VipsImage *in, VipsImage **out, ...)
{
	va_list ap;
	int result;

	va_start(ap, out);
	result = vips_call_split("scharr", ap, in, out);
	va_end(ap);

	return result;
}

/**
 * vips_prewitt: (method)
 * @in: input image
 * @out: (out): output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Prewitt edge detector.
 *
 * uchar images are computed using a fast, low-precision path. Cast to float
 * for a high-precision implementation.
 *
 * See also: vips_canny(), vips_sobel(), vips_prewitt(), vips_scharr().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_prewitt(VipsImage *in, VipsImage **out, ...)
{
	va_list ap;
	int result;

	va_start(ap, out);
	result = vips_call_split("prewitt", ap, in, out);
	va_end(ap);

	return result;
}
