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

typedef VipsColourTransform VipsscRGB2XYZ;
typedef VipsColourTransformClass VipsscRGB2XYZClass;

G_DEFINE_TYPE(VipsscRGB2XYZ, vips_scRGB2XYZ, VIPS_TYPE_COLOUR_TRANSFORM);

static void
vips_scRGB2XYZ_line(VipsColour *colour, VipsPel *out, VipsPel **in, int width)
{
	float *restrict p = (float *) in[0];
	float *restrict q = (float *) out;

	for (int i = 0; i < width; i++) {
		const float R = p[0] * VIPS_D65_Y0;
		const float G = p[1] * VIPS_D65_Y0;
		const float B = p[2] * VIPS_D65_Y0;

		/* Manually inlined logic from the vips_col_scRGB2XYZ function
		 * as the original is defined in a separate file and is part of
		 * the public API so a compiler will not inline.
		 */
		q[0] = 0.4124F * R + 0.3576F * G + 0.1805F * B;
		q[1] = 0.2126F * R + 0.7152F * G + 0.0722F * B;
		q[2] = 0.0193F * R + 0.1192F * G + 0.9505F * B;

		p += 3;
		q += 3;
	}
}

static void
vips_scRGB2XYZ_class_init(VipsscRGB2XYZClass *class)
{
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsColourClass *colour_class = VIPS_COLOUR_CLASS(class);

	object_class->nickname = "scRGB2XYZ";
	object_class->description = _("transform scRGB to XYZ");

	colour_class->process_line = vips_scRGB2XYZ_line;
}

static void
vips_scRGB2XYZ_init(VipsscRGB2XYZ *scRGB2XYZ)
{
	VipsColour *colour = VIPS_COLOUR(scRGB2XYZ);

	colour->interpretation = VIPS_INTERPRETATION_XYZ;
}

/**
 * vips_scRGB2XYZ: (method)
 * @in: input image
 * @out: (out): output image
 * @...: `NULL`-terminated list of optional named arguments
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
