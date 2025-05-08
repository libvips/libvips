/* max of a pair of images
 *
 * 18/6/24
 * 	- from add.c
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

#include "binary.h"

typedef VipsBinary VipsMaxpair;
typedef VipsBinaryClass VipsMaxpairClass;

G_DEFINE_TYPE(VipsMaxpair, vips_maxpair, VIPS_TYPE_BINARY);

#define LOOP(TYPE) \
	{ \
		TYPE *restrict left = (TYPE *) in[0]; \
		TYPE *restrict right = (TYPE *) in[1]; \
		TYPE *restrict q = (TYPE *) out; \
\
		for (int x = 0; x < sz; x++) \
			q[x] = VIPS_MAX(left[x], right[x]); \
	}

#define FLOOP(TYPE) \
	{ \
		TYPE *restrict left = (TYPE *) in[0]; \
		TYPE *restrict right = (TYPE *) in[1]; \
		TYPE *restrict q = (TYPE *) out; \
\
		for (int x = 0; x < sz; x++) \
			q[x] = fmax(left[x], right[x]); \
	}

static void
maxpair_buffer(VipsArithmetic *arithmetic,
	VipsPel *out, VipsPel **in, int width)
{
	VipsImage *im = arithmetic->ready[0];
	int bands = vips_image_get_bands(im);
	VipsBandFormat format = vips_image_get_format(im);
	int sz = width * bands * (vips_band_format_iscomplex(format) ? 2 : 1);

	/* Maxpair all input types. Keep types here in sync with
	 * vips_maxpair_format_table[] below.
	 */
	switch (vips_image_get_format(im)) {
	case VIPS_FORMAT_UCHAR:
		LOOP(unsigned char);
		break;

	case VIPS_FORMAT_CHAR:
		LOOP(signed char);
		break;

	case VIPS_FORMAT_USHORT:
		LOOP(unsigned short);
		break;

	case VIPS_FORMAT_SHORT:
		LOOP(signed short);
		break;

	case VIPS_FORMAT_UINT:
		LOOP(unsigned int);
		break;

	case VIPS_FORMAT_INT:
		LOOP(signed int);
		break;

	case VIPS_FORMAT_FLOAT:
	case VIPS_FORMAT_COMPLEX:
		FLOOP(float);
		break;

	case VIPS_FORMAT_DOUBLE:
	case VIPS_FORMAT_DPCOMPLEX:
		FLOOP(double);
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

static const VipsBandFormat vips_maxpair_format_table[10] = {
	/* Band format:  UC  C  US  S  UI  I  F  X  D  DX */
	/* Promotion: */ UC, C, US, S, UI, I, F, X, D, DX
};

static void
vips_maxpair_class_init(VipsMaxpairClass *class)
{
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsArithmeticClass *aclass = VIPS_ARITHMETIC_CLASS(class);

	object_class->nickname = "maxpair";
	object_class->description = _("maximum of a pair of images");

	aclass->process_line = maxpair_buffer;

	vips_arithmetic_set_format_table(aclass, vips_maxpair_format_table);
}

static void
vips_maxpair_init(VipsMaxpair *maxpair)
{
}

/**
 * vips_maxpair: (method)
 * @left: input image
 * @right: input image
 * @out: (out): output image
 * @...: `NULL`-terminated list of optional named arguments
 *
 * For each pixel, pick the maximum of a pair of images.
 *
 * ::: seealso
 *     [method@Image.minpair].
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_maxpair(VipsImage *left, VipsImage *right, VipsImage **out, ...)
{
	va_list ap;
	int result;

	va_start(ap, out);
	result = vips_call_split("maxpair", ap, left, right, out);
	va_end(ap);

	return result;
}
