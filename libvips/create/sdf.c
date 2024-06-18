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
	char *name;

	double cx;
	double cy;
	double r;
	double sx;					// size in x and y
	double sy;
	double *corners;			// corner radii

	VipsArea *corners_area;

	PointFn point;
};

typedef VipsCreateClass VipsSdfClass;

G_DEFINE_TYPE(VipsSdf, vips_sdf, VIPS_TYPE_CREATE);

static float
vips_sdf_circle(VipsSdf *sdf, int x, int y)
{
	return hypot(x, y) - sdf->r;
}

static float
vips_sdf_box(VipsSdf *sdf, int x, int y)
{
	float qx = abs(x) - sdf->sx;
	float qy = abs(y) - sdf->sy;

	return VIPS_MIN(VIPS_MAX(qx, qy), 0) +
		hypot(VIPS_MAX(qx, 0), VIPS_MAX(qy, 0));
}

static float
vips_sdf_rounded_box(VipsSdf *sdf, int x, int y)
{
	// radius of nearest corner
	float r_top = x > 0 ? sdf->corners[0] : sdf->corners[2];
	float r_bottom = x > 0 ? sdf->corners[1] : sdf->corners[3];
	float r = y > 0 ? r_top : r_bottom;

	float qx = abs(x) - sdf->sx + r;
	float qy = abs(y) - sdf->sy + r;

	return VIPS_MIN(VIPS_MAX(qx, qy), 0) +
		hypot(VIPS_MAX(qx, 0), VIPS_MAX(qy, 0)) - r;
}

static int
vips_sdf_gen(VipsRegion *out_region,
	void *seq, void *a, void *b, gboolean *stop)
{
	VipsSdf *sdf = (VipsSdf *) a;
	VipsRect *r = &out_region->valid;

	for (int y = 0; y < r->height; y++) {
		float *q = (float *) VIPS_REGION_ADDR(out_region, r->left, r->top + y);

		int ay = r->top + y - sdf->cy;
		for (int x = 0; x < r->width; x++)
			q[x] = sdf->point(sdf, r->left + x - sdf->cx, ay);
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

	// cx/cy default to the centre of the image
	if (!vips_object_argument_isset(object, "cx"))
		sdf->cx = sdf->width / 2;
	if (!vips_object_argument_isset(object, "cy"))
		sdf->cy = sdf->height / 2;

	if (g_str_equal(sdf->name, "circle")) {
		if (!vips_object_argument_isset(object, "r")) {
			vips_error(class->nickname, "%s",
				_("circle needs r to be set"));
			return -1;
		}
		sdf->point = vips_sdf_circle;
	}
	else if (g_str_equal(sdf->name, "box")) {
		if (!vips_object_argument_isset(object, "sx") ||
			!vips_object_argument_isset(object, "sy")) {
			vips_error(class->nickname, "%s",
				_("box needs sx, sy to be set"));
			return -1;
		}
		sdf->point = vips_sdf_box;
	}
	else if (g_str_equal(sdf->name, "rounded-box")) {
		if (!vips_object_argument_isset(object, "sx") ||
			!vips_object_argument_isset(object, "sy")) {
			vips_error(class->nickname, "%s",
				_("rounded-box needs sx, sy to be set"));
			return -1;
		}
		if (sdf->corners_area->n != 4) {
			vips_error(class->nickname, "%s",
				_("rounded-box needs 4 values for corners"));
			return -1;
		}

		sdf->corners = (double *) sdf->corners_area->data;
		sdf->point = vips_sdf_rounded_box;
	}
	else {
		vips_error(class->nickname, _("unknown SDF %s"), sdf->name);
		return -1;
	}

	vips_image_init_fields(create->out,
		sdf->width, sdf->height, 1,
		VIPS_FORMAT_FLOAT, VIPS_CODING_NONE, VIPS_INTERPRETATION_B_W, 1.0, 1.0);
	if (vips_image_pipelinev(create->out, VIPS_DEMAND_STYLE_ANY, NULL) ||
		vips_image_generate(create->out,
			NULL, vips_sdf_gen, NULL, sdf, NULL))
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

	VIPS_ARG_STRING(class, "name", 6,
		_("Name"),
		_("Name of SDF to create"),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET(VipsSdf, name),
		NULL);

	VIPS_ARG_DOUBLE(class, "cx", 7,
		_("cx"),
		_("X of centre"),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET(VipsSdf, cx),
		0.0, VIPS_MAX_COORD, 100);

	VIPS_ARG_DOUBLE(class, "cy", 8,
		_("cy"),
		_("Y of centre"),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET(VipsSdf, cy),
		0.0, VIPS_MAX_COORD, 100);

	VIPS_ARG_DOUBLE(class, "r", 9,
		_("r"),
		_("Radius"),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET(VipsSdf, r),
		0.0, VIPS_MAX_COORD, 50);

	VIPS_ARG_DOUBLE(class, "sx", 10,
		_("sx"),
		_("Size in X"),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET(VipsSdf, sx),
		0.0, VIPS_MAX_COORD, 100);

	VIPS_ARG_DOUBLE(class, "sy", 11,
		_("sy"),
		_("Size in Y"),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET(VipsSdf, sy),
		0.0, VIPS_MAX_COORD, 100);

	VIPS_ARG_BOXED(class, "corners", 12,
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
 * @name: name of SDF to create
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @cx: %gfloat, x of centre
 * * @cy: %gfloat, y of centre
 * * @r: %gfloat, radius
 *
 * Create a signed distance field (SDF) image of the named type. Different
 * fields use different combinations of the optional arguments, see below.
 *
 * @name `circle`: create a circle image centred at (@cx, @cy), radius @r.
 *
 * See also: vips_grey(), vips_grid(), vips_xyz().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_sdf(VipsImage **out, int width, int height, const char *name, ...)
{
	va_list ap;
	int result;

	va_start(ap, name);
	result = vips_call_split("sdf", ap, out, width, height, name);
	va_end(ap);

	return result;
}
