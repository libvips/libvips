/* Turn Oklab to Oklch
 *
 * 3/12/25
 * 	- from Lab2LCh.c
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

typedef VipsColourTransform VipsOklab2Oklch;
typedef VipsColourTransformClass VipsOklab2OklchClass;

G_DEFINE_TYPE(VipsOklab2Oklch, vips_Oklab2Oklch, VIPS_TYPE_COLOUR_TRANSFORM);

static void
vips_Oklab2Oklch_line(VipsColour *colour, VipsPel *out, VipsPel **in, int width)
{
	float *restrict p = (float *) in[0];
	float *restrict q = (float *) out;

	for (int x = 0; x < width; x++) {
		float L = p[0];
		float a = p[1];
		float b = p[2];
		p += 3;

		q[0] = L;
		q[1] = sqrtf(a * a + b * b);
		q[2] = vips_col_ab2h(a, b);
		q += 3;
	}
}

static void
vips_Oklab2Oklch_class_init(VipsOklab2OklchClass *class)
{
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsColourClass *colour_class = VIPS_COLOUR_CLASS(class);

	object_class->nickname = "Oklab2Oklch";
	object_class->description = _("transform Oklab to Oklch");

	colour_class->process_line = vips_Oklab2Oklch_line;
}

static void
vips_Oklab2Oklch_init(VipsOklab2Oklch *Oklab2Oklch)
{
	VipsColour *colour = VIPS_COLOUR(Oklab2Oklch);

	colour->interpretation = VIPS_INTERPRETATION_OKLCH;
}

/**
 * vips_Oklab2Oklch: (method)
 * @in: input image
 * @out: (out): output image
 * @...: `NULL`-terminated list of optional named arguments
 *
 * Turn Oklab to Oklch.
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_Oklab2Oklch(VipsImage *in, VipsImage **out, ...)
{
	va_list ap;
	int result;

	va_start(ap, out);
	result = vips_call_split("Oklab2Oklch", ap, in, out);
	va_end(ap);

	return result;
}
