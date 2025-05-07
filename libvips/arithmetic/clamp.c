/* clamp pixels to range
 *
 * 17/6/24
 * 	- from abs.c
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

#include "unary.h"

typedef struct _VipsClamp {
	VipsUnary parent_instance;

	double min;
	double max;
} VipsClamp;

typedef VipsUnaryClass VipsClampClass;

G_DEFINE_TYPE(VipsClamp, vips_clamp, VIPS_TYPE_UNARY);

#define CLAMP_LINE(TYPE) \
	{ \
		TYPE *restrict p = (TYPE *) in[0]; \
		TYPE *restrict q = (TYPE *) out; \
\
		for (int x = 0; x < sz; x++) \
			q[x] = VIPS_CLIP(clamp->min, p[x], clamp->max); \
	}

static void
vips_clamp_buffer(VipsArithmetic *arithmetic,
	VipsPel *out, VipsPel **in, int width)
{
	VipsClamp *clamp = (VipsClamp *) arithmetic;
	VipsImage *im = arithmetic->ready[0];
	const int bands = vips_image_get_bands(im);
	int sz = width * bands * (vips_band_format_iscomplex(im->BandFmt) ? 2 : 1);

	switch (vips_image_get_format(im)) {
	case VIPS_FORMAT_CHAR:
		CLAMP_LINE(signed char);
		break;

	case VIPS_FORMAT_UCHAR:
		CLAMP_LINE(unsigned char);
		break;

	case VIPS_FORMAT_SHORT:
		CLAMP_LINE(signed short);
		break;

	case VIPS_FORMAT_USHORT:
		CLAMP_LINE(unsigned short);
		break;

	case VIPS_FORMAT_INT:
		CLAMP_LINE(signed int);
		break;

	case VIPS_FORMAT_UINT:
		CLAMP_LINE(unsigned int);
		break;

	case VIPS_FORMAT_FLOAT:
		CLAMP_LINE(float);
		break;

	case VIPS_FORMAT_DOUBLE:
		CLAMP_LINE(double);
		break;

	case VIPS_FORMAT_COMPLEX:
		CLAMP_LINE(float);
		break;

	case VIPS_FORMAT_DPCOMPLEX:
		CLAMP_LINE(double);
		break;

	default:
		g_assert_not_reached();
	}
}

#define UC VIPS_FORMAT_UCHAR
#define C VIPS_FORMAT_CHAR
#define US VIPS_FORMAT_USHORT
#define S VIPS_FORMAT_SHORT
#define UI VIPS_FORMAT_UINT
#define I VIPS_FORMAT_INT
#define F VIPS_FORMAT_FLOAT
#define X VIPS_FORMAT_COMPLEX
#define D VIPS_FORMAT_DOUBLE
#define DX VIPS_FORMAT_DPCOMPLEX

/* Format doesn't change with clamp.
 */
static const VipsBandFormat vips_clamp_format_table[10] = {
	/* Band format:  UC  C  US  S  UI  I  F  X  D  DX */
	/* Promotion: */ UC, C, US, S, UI, I, F, X, D, DX
};

static void
vips_clamp_class_init(VipsClampClass *class)
{
	GObjectClass *gobject_class = (GObjectClass *) class;
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsArithmeticClass *aclass = VIPS_ARITHMETIC_CLASS(class);

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "clamp";
	object_class->description = _("clamp values of an image");

	aclass->process_line = vips_clamp_buffer;

	vips_arithmetic_set_format_table(aclass, vips_clamp_format_table);

	VIPS_ARG_DOUBLE(class, "min", 10,
		_("Min"),
		_("Minimum value"),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET(VipsClamp, min),
		-INFINITY, INFINITY, 0.0);

	VIPS_ARG_DOUBLE(class, "max", 11,
		_("Max"),
		_("Maximum value"),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET(VipsClamp, max),
		-INFINITY, INFINITY, 1.0);
}

static void
vips_clamp_init(VipsClamp *clamp)
{
	clamp->min = 0.0;
	clamp->max = 1.0;
}

/**
 * vips_clamp: (method)
 * @in: input [class@Image]
 * @out: (out): output [class@Image]
 * @...: `NULL`-terminated list of optional named arguments
 *
 * This operation clamps pixel values to a range, by default 0 - 1.
 *
 * Use @min and @max to change the range.
 *
 * ::: tip "Optional arguments"
 *     * @min: `gdouble`, minimum value
 *     * @max: `gdouble`, maximum value
 *
 * ::: seealso
 *     [method@Image.sign], [method@Image.abs], [ctor@Image.sdf].
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_clamp(VipsImage *in, VipsImage **out, ...)
{
	va_list ap;
	int result;

	va_start(ap, out);
	result = vips_call_split("clamp", ap, in, out);
	va_end(ap);

	return result;
}
