/* to sRGB from HSV
 *
 * 9/6/15
 * 	- from sRGB2HSV.c
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

#define SIXTH_OF_CHAR (42.5)

typedef VipsColourCode VipsHSV2sRGB;
typedef VipsColourCodeClass VipsHSV2sRGBClass;

G_DEFINE_TYPE(VipsHSV2sRGB, vips_HSV2sRGB, VIPS_TYPE_COLOUR_CODE);

static void
vips_HSV2sRGB_line(VipsColour *colour, VipsPel *out, VipsPel **in, int width)
{
	unsigned char *p = (unsigned char *) in[0];
	unsigned char *q = (unsigned char *) out;

	int i;

	for (i = 0; i < width; i++) {
		float c, x, m;

		c = p[2] * p[1] / 255.0;
		x = c * (1 - VIPS_FABS(fmod(p[0] / SIXTH_OF_CHAR, 2) - 1));
		m = p[2] - c;

		if (p[0] < (int) SIXTH_OF_CHAR) {
			q[0] = c + m;
			q[1] = x + m;
			q[2] = 0 + m;
		}
		else if (p[0] < (int) (2 * SIXTH_OF_CHAR)) {
			q[0] = x + m;
			q[1] = c + m;
			q[2] = 0 + m;
		}
		else if (p[0] < (int) (3 * SIXTH_OF_CHAR)) {
			q[0] = 0 + m;
			q[1] = c + m;
			q[2] = x + m;
		}
		else if (p[0] < (int) (4 * SIXTH_OF_CHAR)) {
			q[0] = 0 + m;
			q[1] = x + m;
			q[2] = c + m;
		}
		else if (p[0] < (int) (5 * SIXTH_OF_CHAR)) {
			q[0] = x + m;
			q[1] = 0 + m;
			q[2] = c + m;
		}
		else {
			q[0] = c + m;
			q[1] = 0 + m;
			q[2] = x + m;
		}

		p += 3;
		q += 3;
	}
}

static void
vips_HSV2sRGB_class_init(VipsHSV2sRGBClass *class)
{
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsColourClass *colour_class = VIPS_COLOUR_CLASS(class);

	object_class->nickname = "HSV2sRGB";
	object_class->description = _("transform HSV to sRGB");

	colour_class->process_line = vips_HSV2sRGB_line;
}

static void
vips_HSV2sRGB_init(VipsHSV2sRGB *HSV2sRGB)
{
	VipsColour *colour = VIPS_COLOUR(HSV2sRGB);
	VipsColourCode *code = VIPS_COLOUR_CODE(HSV2sRGB);

	colour->interpretation = VIPS_INTERPRETATION_sRGB;
	colour->format = VIPS_FORMAT_UCHAR;
	colour->bands = 3;
	colour->input_bands = 3;

	code->input_coding = VIPS_CODING_NONE;
	code->input_format = VIPS_FORMAT_UCHAR;
	code->input_interpretation = VIPS_INTERPRETATION_HSV;
}

/**
 * vips_HSV2sRGB: (method)
 * @in: input image
 * @out: (out): output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Convert HSV to sRGB.
 *
 * HSV is a crude polar coordinate system for RGB images. It is provided for
 * compatibility with other image processing systems. See vips_Lab2LCh() for a
 * much better colour space.
 *
 * See also: vips_sRGB2HSV().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_HSV2sRGB(VipsImage *in, VipsImage **out, ...)
{
	va_list ap;
	int result;

	va_start(ap, out);
	result = vips_call_split("HSV2sRGB", ap, in, out);
	va_end(ap);

	return result;
}
