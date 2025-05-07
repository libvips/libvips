/* Turn displayable rgb files to scRGB.
 *
 * Modified:
 * 15/11/94 JC
 *	- memory leak fixed
 *	- error message added
 * 16/11/94 JC
 *	- partialed
 * 21/9/12
 * 	- redone as a class
 * 	- sRGB only, support for other RGBs is now via lcms
 * 6/11/12
 * 	- add 16-bit sRGB import
 * 11/12/12
 * 	- cut about to make sRGB2scRGB.c
 * 12/2/15
 * 	- add 16-bit alpha handling
 * 26/2/16
 * 	- look for RGB16 tag, not just ushort, for the 16-bit path
 * 24/11/17 lovell
 * 	- special path for 3 and 4 band images
 * 16/4/25
 *	- move on top of ColourCode
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

typedef VipsColourCode VipssRGB2scRGB;
typedef VipsColourCodeClass VipssRGB2scRGBClass;

G_DEFINE_TYPE(VipssRGB2scRGB, vips_sRGB2scRGB, VIPS_TYPE_COLOUR_CODE);

static void
vips_sRGB2scRGB_line(VipsColour *colour, VipsPel *out, VipsPel **in, int width)
{
	if (colour->in[0]->BandFmt == VIPS_FORMAT_UCHAR) {
		float *restrict q;
		VipsPel *restrict p;

		q = (float *) out;
		p = in[0];
		for (int i = 0; i < width; i++) {
			q[0] = vips_v2Y_8[p[0]];
			q[1] = vips_v2Y_8[p[1]];
			q[2] = vips_v2Y_8[p[2]];

			p += 3;
			q += 3;
		}
	}
	else if (colour->in[0]->BandFmt == VIPS_FORMAT_USHORT) {
		float *restrict q;
		unsigned short *restrict p;

		q = (float *) out;
		p = (unsigned short *) in[0];
		for (int i = 0; i < width; i++) {
			q[0] = vips_v2Y_16[p[0]];
			q[1] = vips_v2Y_16[p[1]];
			q[2] = vips_v2Y_16[p[2]];

			p += 3;
			q += 3;
		}
	}
	else
		g_assert_not_reached();
}

static int
vips_sRGB2scRGB_build(VipsObject *object)
{
	VipsColour *colour = (VipsColour *) object;
	VipsColourCode *code = (VipsColourCode *) object;

	// input image we want
	if (vips_object_argument_isset(object, "in") &&
		code->in->Type == VIPS_INTERPRETATION_RGB16) {
		vips_col_make_tables_RGB_16();
		code->input_format = VIPS_FORMAT_USHORT;
	}
	else {
		vips_col_make_tables_RGB_8();
		code->input_format = VIPS_FORMAT_UCHAR;
	}
	colour->input_bands = 3;

	// output image we make
	colour->interpretation = VIPS_INTERPRETATION_scRGB;
	colour->format = VIPS_FORMAT_FLOAT;
	colour->bands = 3;

	return VIPS_OBJECT_CLASS(vips_sRGB2scRGB_parent_class)->build(object);
}

static void
vips_sRGB2scRGB_class_init(VipssRGB2scRGBClass *class)
{
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsColourClass *colour_class = VIPS_COLOUR_CLASS(class);

	object_class->nickname = "sRGB2scRGB";
	object_class->description = _("convert an sRGB image to scRGB");
	object_class->build = vips_sRGB2scRGB_build;

	colour_class->process_line = vips_sRGB2scRGB_line;
}

static void
vips_sRGB2scRGB_init(VipssRGB2scRGB *sRGB2scRGB)
{
}

/**
 * vips_sRGB2scRGB: (method)
 * @in: input image
 * @out: (out): output image
 * @...: `NULL`-terminated list of optional named arguments
 *
 * Convert an sRGB image to scRGB.
 *
 * RGB16 images are also handled.
 *
 * ::: seealso
 *     [method@Image.scRGB2XYZ], [method@Image.scRGB2sRGB],
 *     [method@Image.rad2float].
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_sRGB2scRGB(VipsImage *in, VipsImage **out, ...)
{
	va_list ap;
	int result;

	va_start(ap, out);
	result = vips_call_split("sRGB2scRGB", ap, in, out);
	va_end(ap);

	return result;
}
