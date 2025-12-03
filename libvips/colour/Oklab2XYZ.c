/* Oklab to XYZ.
 *
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
#include <math.h>

#include <vips/vips.h>
#include <vips/debug.h>

#include "pcolour.h"

typedef VipsColourTransform VipsOklab2XYZ;
typedef VipsColourTransformClass VipsOklab2XYZClass;

G_DEFINE_TYPE(VipsOklab2XYZ, vips_Oklab2XYZ, VIPS_TYPE_COLOUR_TRANSFORM);

/* Process a buffer of data.
 */
static void
vips_Oklab2XYZ_line(VipsColour *colour, VipsPel *out, VipsPel **in, int width)
{
	float *restrict p = (float *) in[0];
	float *restrict q = (float *) out;

	for (int x = 0; x < width; x++) {
		const float L = p[0];
		const float a = p[1];
		const float b = p[2];
		p += 3;

		// M2 inv to get LMS prime
		const float lp = L * 1.         + a *  0.39633779 + b *  0.21580376;
		const float mp = L * 1.00000001 + a * -0.10556134 + b * -0.06385417;
		const float sp = L * 1.00000005 + a * -0.08948418 + b * -1.29148554;

		// back to lms
		const float l = lp * lp * lp;
		const float m = mp * mp * mp;
		const float s = sp * sp * sp;

		// M1 inv to get D65 normalised XYZ
		q[0] = l *  1.22701385 + m * -0.55779998 + s *  0.28125615;
		q[1] = l * -0.04058018 + m *  1.11225687 + s * -0.07167668;
		q[2] = l * -0.07638128 + m * -0.42148198 + s *  1.58616322;
		q += 3;
	}
}

static void
vips_Oklab2XYZ_class_init(VipsOklab2XYZClass *class)
{
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsColourClass *colour_class = VIPS_COLOUR_CLASS(class);

	object_class->nickname = "Oklab2XYZ";
	object_class->description = _("transform Oklab to XYZ");

	colour_class->process_line = vips_Oklab2XYZ_line;
}

static void
vips_Oklab2XYZ_init(VipsOklab2XYZ *Oklab2XYZ)
{
	VipsColour *colour = VIPS_COLOUR(Oklab2XYZ);

	colour->interpretation = VIPS_INTERPRETATION_XYZ;
}

/**
 * vips_Oklab2XYZ: (method)
 * @in: input image
 * @out: (out): output image
 * @...: `NULL`-terminated list of optional named arguments
 *
 * Transform Oklab to XYZ using D65 illuminant.
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_Oklab2XYZ(VipsImage *in, VipsImage **out, ...)
{
	va_list ap;
	int result;

	va_start(ap, out);
	result = vips_call_split("Oklab2XYZ", ap, in, out);
	va_end(ap);

	return result;
}
