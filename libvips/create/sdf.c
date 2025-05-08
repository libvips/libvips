/* make various signed distance fields
 *
 * 16/6/24
 * 	- from xyz.c
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
#define VIPS_DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <glib/gi18n-lib.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <vips/vips.h>
#include <vips/internal.h>
#include <vips/debug.h>

#include "pcreate.h"

typedef struct _VipsSdf VipsSdf;

typedef float (*PointFn)(VipsSdf *, int x, int y);

struct _VipsSdf {
	VipsCreate parent_instance;

	int width;
	int height;
	VipsSdfShape shape;

	double *a;					// two vec2
	double *b;
	double r;
	double *corners;			// corner radii

	float cx;					// centre
	float cy;
	float dx;					// difference
	float dy;
	float sx;					// half size
	float sy;

	VipsArea *corners_area;
	VipsArea *a_area;
	VipsArea *b_area;

	PointFn point;
};

typedef VipsCreateClass VipsSdfClass;

G_DEFINE_TYPE(VipsSdf, vips_sdf, VIPS_TYPE_CREATE);

/* SDF functions derived from
 *
 * https://iquilezles.org/articles/distfunctions2d/
 */

static float
vips_sdf_circle(VipsSdf *sdf, int x, int y)
{
	return hypotf(x - sdf->a[0], y - sdf->a[1]) - sdf->r;
}

static float
vips_sdf_box(VipsSdf *sdf, int x, int y)
{
	float px = x - sdf->cx;
	float py = y - sdf->cy;

	float dx = fabsf(px) - sdf->sx;
	float dy = fabsf(py) - sdf->sy;

	return hypotf(VIPS_MAX(dx, 0), VIPS_MAX(dy, 0)) +
		VIPS_MIN(VIPS_MAX(dx, dy), 0);
}

static float
vips_sdf_rounded_box(VipsSdf *sdf, int x, int y)
{
	float px = x - sdf->cx;
	float py = y - sdf->cy;

	// radius of nearest corner
	float r_top = px > 0 ? sdf->corners[0] : sdf->corners[2];
	float r_bottom = px > 0 ? sdf->corners[1] : sdf->corners[3];
	float r = py > 0 ? r_top : r_bottom;

	float qx = fabsf(px) - sdf->sx + r;
	float qy = fabsf(py) - sdf->sy + r;

	return hypotf(VIPS_MAX(qx, 0), VIPS_MAX(qy, 0)) +
		VIPS_MIN(VIPS_MAX(qx, qy), 0) - r;
}

static float
vips_sdf_line(VipsSdf *sdf, int px, int py)
{
	float pax = px - sdf->a[0];
	float pay = py - sdf->a[1];

	float dot_paba = pax * sdf->dx + pay * sdf->dy;
	float dot_baba = sdf->dx * sdf->dx + sdf->dy * sdf->dy;
	float h = VIPS_FCLIP(0, dot_paba / dot_baba, 1);

	float dx = pax - h * sdf->dx;
	float dy = pay - h * sdf->dy;

	return hypotf(dx, dy);
}

static int
vips_sdf_gen(VipsRegion *out_region,
	void *seq, void *a, void *b, gboolean *stop)
{
	VipsSdf *sdf = (VipsSdf *) a;
	VipsRect *r = &out_region->valid;

	for (int y = 0; y < r->height; y++) {
		int ay = y + r->top;
		float *q = (float *) VIPS_REGION_ADDR(out_region, r->left, ay);

		for (int x = 0; x < r->width; x++)
			q[x] = sdf->point(sdf, x + r->left, ay);
	}

	return 0;
}

static int
vips_sdf_build(VipsObject *object)
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS(object);
	VipsCreate *create = VIPS_CREATE(object);
	VipsSdf *sdf = (VipsSdf *) object;

	if (VIPS_OBJECT_CLASS(vips_sdf_parent_class)->build(object))
		return -1;

	switch (sdf->shape) {
	case VIPS_SDF_SHAPE_CIRCLE:
		if (!vips_object_argument_isset(object, "a") ||
			!vips_object_argument_isset(object, "r")) {
			vips_error(class->nickname, "%s",
				_("circle needs a, r to be set"));
			return -1;
		}
		if (sdf->a_area->n != 2) {
			vips_error(class->nickname, "%s",
				_("rounded-box needs 2 values for a"));
			return -1;
		}

		sdf->a = (double *) sdf->a_area->data;
		sdf->point = vips_sdf_circle;

		break;

	case VIPS_SDF_SHAPE_BOX:
		if (!vips_object_argument_isset(object, "a") ||
			!vips_object_argument_isset(object, "b")) {
			vips_error(class->nickname, "%s",
				_("box needs a, b to be set"));
			return -1;
		}
		if (sdf->a_area->n != 2 ||
			sdf->b_area->n != 2) {
			vips_error(class->nickname, "%s",
				_("box needs 2 values for a, b"));
			return -1;
		}

		sdf->a = (double *) sdf->a_area->data;
		sdf->b = (double *) sdf->b_area->data;
		sdf->point = vips_sdf_box;

		break;

	case VIPS_SDF_SHAPE_ROUNDED_BOX:
		if (!vips_object_argument_isset(object, "a") ||
			!vips_object_argument_isset(object, "b")) {
			vips_error(class->nickname, "%s",
				_("rounded-box needs a, b to be set"));
			return -1;
		}
		if (sdf->a_area->n != 2 ||
			sdf->b_area->n != 2) {
			vips_error(class->nickname, "%s",
				_("rounded-box needs 2 values for a, b"));
			return -1;
		}
		if (sdf->corners_area->n != 4) {
			vips_error(class->nickname, "%s",
				_("rounded-box needs 4 values for corners"));
			return -1;
		}

		sdf->a = (double *) sdf->a_area->data;
		sdf->b = (double *) sdf->b_area->data;
		sdf->corners = (double *) sdf->corners_area->data;
		sdf->point = vips_sdf_rounded_box;

		break;

	case VIPS_SDF_SHAPE_LINE:
		if (!vips_object_argument_isset(object, "a") ||
			!vips_object_argument_isset(object, "b")) {
			vips_error(class->nickname, "%s",
				_("line needs sx, sy to be set"));
			return -1;
		}
		if (sdf->a_area->n != 2 ||
			sdf->b_area->n != 2) {
			vips_error(class->nickname, "%s",
				_("line needs 2 values for a, b"));
			return -1;
		}

		sdf->a = (double *) sdf->a_area->data;
		sdf->b = (double *) sdf->b_area->data;
		sdf->point = vips_sdf_line;

		break;

	default:
		vips_error(class->nickname, _("unknown SDF %d"), sdf->shape);
		return -1;
	}

	if (sdf->a &&
		sdf->b) {
		// centre
		sdf->cx = (sdf->a[0] + sdf->b[0]) / 2.0;
		sdf->cy = (sdf->a[1] + sdf->b[1]) / 2.0;

		// difference
		sdf->dx = sdf->b[0] - sdf->a[0];
		sdf->dy = sdf->b[1] - sdf->a[1];

		// half size
		sdf->sx = sdf->dx / 2.0;
		sdf->sy = sdf->dy / 2.0;
	}

	vips_image_init_fields(create->out,
		sdf->width, sdf->height, 1,
		VIPS_FORMAT_FLOAT, VIPS_CODING_NONE, VIPS_INTERPRETATION_B_W, 1.0, 1.0);
	if (vips_image_pipelinev(create->out, VIPS_DEMAND_STYLE_ANY, NULL) ||
		vips_image_generate(create->out, NULL, vips_sdf_gen, NULL, sdf, NULL))
		return -1;

	return 0;
}

static void
vips_sdf_class_init(VipsSdfClass *class)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS(class);
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS(class);

	VIPS_DEBUG_MSG("vips_sdf_class_init\n");

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "sdf";
	vobject_class->description = _("create an SDF image");
	vobject_class->build = vips_sdf_build;

	VIPS_ARG_INT(class, "width", 2,
		_("Width"),
		_("Image width in pixels"),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET(VipsSdf, width),
		1, VIPS_MAX_COORD, 1);

	VIPS_ARG_INT(class, "height", 3,
		_("Height"),
		_("Image height in pixels"),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET(VipsSdf, height),
		1, VIPS_MAX_COORD, 1);

	VIPS_ARG_ENUM(class, "shape", 8,
		_("Shape"),
		_("SDF shape to create"),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET(VipsSdf, shape),
		VIPS_TYPE_SDF_SHAPE, VIPS_SDF_SHAPE_CIRCLE);

	VIPS_ARG_DOUBLE(class, "r", 9,
		_("r"),
		_("Radius"),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET(VipsSdf, r),
		0.0, VIPS_MAX_COORD, 50);

	VIPS_ARG_BOXED(class, "a", 13,
		_("a"),
		_("Point a"),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET(VipsSdf, a_area),
		VIPS_TYPE_ARRAY_DOUBLE);

	VIPS_ARG_BOXED(class, "b", 14,
		_("b"),
		_("Point b"),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET(VipsSdf, b_area),
		VIPS_TYPE_ARRAY_DOUBLE);

	VIPS_ARG_BOXED(class, "corners", 15,
		_("corners"),
		_("Corner radii"),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET(VipsSdf, corners_area),
		VIPS_TYPE_ARRAY_DOUBLE);

}

static void
vips_sdf_init(VipsSdf *sdf)
{
	sdf->corners_area = vips_area_new_array(G_TYPE_DOUBLE, sizeof(double), 4);
}

/**
 * vips_sdf:
 * @out: (out): output image
 * @width: horizontal size
 * @height: vertical size
 * @shape: SDF to create
 * @...: `NULL`-terminated list of optional named arguments
 *
 * Create a signed distance field (SDF) image of the given @shape.
 *
 * Different
 * shapes use different combinations of the optional arguments, see below.
 *
 * @shape [enum@Vips.SdfShape.CIRCLE]: create a circle centred on @a, radius @r.
 *
 * @shape [enum@Vips.SdfShape.BOX]: create a box with top-left corner @a and
 * bottom-right corner @b.
 *
 * @shape [enum@Vips.SdfShape.ROUNDED_BOX]: create a box with top-left corner @a
 * and bottom-right corner @b, whose four corners are
 * rounded by the four-element float array @corners. @corners will default to
 * 0.0.
 *
 * @shape [enum@Vips.SdfShape.LINE]: draw a line from @a to @b.
 *
 * ::: tip "Optional arguments"
 *     * @a: [struct@ArrayDouble], first point
 *     * @b: [struct@ArrayDouble], second point
 *     * @r: `gdouble`, radius
 *     * @corners: [struct@ArrayDouble], corner radii
 *
 * ::: seealso
 *     [ctor@Image.grey], [method@Image.grid], [ctor@Image.xyz].
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_sdf(VipsImage **out, int width, int height, VipsSdfShape shape, ...)
{
	va_list ap;
	int result;

	va_start(ap, shape);
	result = vips_call_split("sdf", ap, out, width, height, shape);
	va_end(ap);

	return result;
}
