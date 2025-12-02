/* Transform XYZ to Oklab coordinates
 *
 * 2/12/25
 *	- from XYZ2scRGB.c
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

typedef VipsColourTransform VipsXYZ2Oklab;
typedef VipsColourTransformClass VipsXYZ2OklabClass;

G_DEFINE_TYPE(VipsXYZ2Oklab, vips_XYZ2Oklab, VIPS_TYPE_COLOUR_TRANSFORM);

static void
vips_XYZ2Oklab_line(VipsColour *colour, VipsPel *out, VipsPel **in, int width)
{
	float *restrict p = (float *) in[0];
	float *restrict q = (float *) out;

	for (int i = 0; i < width; i++) {
		const float X = p[0];
		const float Y = p[1];
		const float Z = p[2];

		p += 3;

		float L, a, b;

		q[0] = L;
		q[1] = a;
		q[2] = b;

		q += 3;
	}
}

static void
vips_XYZ2Oklab_class_init(VipsXYZ2OklabClass *class)
{
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsColourClass *colour_class = VIPS_COLOUR_CLASS(class);

	object_class->nickname = "XYZ2Oklab";
	object_class->description = _("transform XYZ to Oklab");

	colour_class->process_line = vips_XYZ2Oklab_line;
}

static void
vips_XYZ2Oklab_init(VipsXYZ2Oklab *XYZ2Oklab)
{
	VipsColour *colour = VIPS_COLOUR(XYZ2Oklab);

	colour->interpretation = VIPS_INTERPRETATION_OKLAB;
}

/**
 * vips_XYZ2Oklab: (method)
 * @in: input image
 * @out: (out): output image
 * @...: `NULL`-terminated list of optional named arguments
 *
 * Transform XYZ to Oklab.
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_XYZ2Oklab(VipsImage *in, VipsImage **out, ...)
{
	va_list ap;
	int result;

	va_start(ap, out);
	result = vips_call_split("XYZ2Oklab", ap, in, out);
	va_end(ap);

	return result;
}
