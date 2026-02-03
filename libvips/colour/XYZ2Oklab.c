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

// see https://en.wikipedia.org/wiki/Oklab_color_space#Conversion_from_CIE_XYZ
static void
vips_XYZ2Oklab_line(VipsColour *colour, VipsPel *out, VipsPel **in, int width)
{
	float *restrict p = (float *) in[0];
	float *restrict q = (float *) out;

	for (int i = 0; i < width; i++) {
		// to D65 normalised XYZ ... M1 already has D65_X0 included etc.
		const float X = p[0] / 100.0;
		const float Y = p[1] / 100.0;
		const float Z = p[2] / 100.0;
		p += 3;

		// convert to LMS
		const float l = X * 0.8189330101 + Y * 0.3618667424 + Z * -0.1288597137;
		const float m = X * 0.0329845436 + Y * 0.9293118715 + Z *  0.0361456387;
		const float s = X * 0.0482003018 + Y * 0.2643662691 + Z *  0.6338517070;

		// cube root ... possibly LUT this?
		const float lp = cbrtf(l);
		const float mp = cbrtf(m);
		const float sp = cbrtf(s);

		// to Oklab
		q[0] = lp * 0.2104542553 + mp *  0.7936177850 + sp * -0.0040720468;
		q[1] = lp * 1.9779984951 + mp * -2.4285922050 + sp *  0.4505937099;
		q[2] = lp * 0.0259040371 + mp *  0.7827717662 + sp * -0.8086757660;
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
 * Transform XYZ to Oklab assuming D65 illuminant.
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
