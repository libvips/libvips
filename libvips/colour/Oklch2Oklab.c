/* _Oklch2Oklab
 *
 * 3/12/25
 * 	- from LCh2Lab.c
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

typedef VipsColourTransform VipsOklch2Oklab;
typedef VipsColourTransformClass VipsOklch2OklabClass;

G_DEFINE_TYPE(VipsOklch2Oklab, vips_Oklch2Oklab, VIPS_TYPE_COLOUR_TRANSFORM);

/* Process a buffer of data.
 */
static void
vips_Oklch2Oklab_line(VipsColour *colour, VipsPel *out, VipsPel **in, int width)
{
	float *restrict p = (float *) in[0];
	float *restrict q = (float *) out;

	for (int x = 0; x < width; x++) {
		float L = p[0];
		float C = p[1];
		float h = p[2];
		p += 3;

		float a, b;
		vips_col_Ch2ab(C, h, &a, &b);

		q[0] = L;
		q[1] = a;
		q[2] = b;
		q += 3;
	}
}

static void
vips_Oklch2Oklab_class_init(VipsOklch2OklabClass *class)
{
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsColourClass *colour_class = VIPS_COLOUR_CLASS(class);

	object_class->nickname = "Oklch2Oklab";
	object_class->description = _("transform Oklch to Oklab");

	colour_class->process_line = vips_Oklch2Oklab_line;
}

static void
vips_Oklch2Oklab_init(VipsOklch2Oklab *Oklch2Oklab)
{
	VipsColour *colour = VIPS_COLOUR(Oklch2Oklab);

	colour->interpretation = VIPS_INTERPRETATION_OKLAB;
}

/**
 * vips_Oklch2Oklab: (method)
 * @in: input image
 * @out: (out): output image
 * @...: `NULL`-terminated list of optional named arguments
 *
 * Turn Oklch to Oklab.
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_Oklch2Oklab(VipsImage *in, VipsImage **out, ...)
{
	va_list ap;
	int result;

	va_start(ap, out);
	result = vips_call_split("Oklch2Oklab", ap, in, out);
	va_end(ap);

	return result;
}
