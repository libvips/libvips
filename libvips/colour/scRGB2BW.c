/* Turn scRGB into greyscale.
 *
 * 17/4/15
 * 	- from scRGB2BW.c
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

typedef struct _VipsscRGB2BW {
	VipsColourCode parent_instance;

	int depth;
} VipsscRGB2BW;

typedef VipsColourCodeClass VipsscRGB2BWClass;

G_DEFINE_TYPE(VipsscRGB2BW, vips_scRGB2BW, VIPS_TYPE_COLOUR_CODE);

static void
vips_scRGB2BW_line(VipsColour *colour, VipsPel *out, VipsPel **in, int width)
{
	VipsscRGB2BW *scRGB2BW = (VipsscRGB2BW *) colour;

	if (scRGB2BW->depth == 16) {
		unsigned short *restrict q;
	   	float *restrict p;

		q = (unsigned short *) out;
	   	p = (float *) in[0];
		for (int i = 0; i < width; i++) {
			const float R = p[0];
			const float G = p[1];
			const float B = p[2];

			int g;
			int og;
			vips_col_scRGB2BW_16(R, G, B, &g, &og);

			q[0] = g;

			p += 3;
			q += 1;
		}
	}
	else {
		unsigned char *restrict q;
	   	float *restrict p;

		q = (unsigned char *) out;
	   	p = (float *) in[0];
		for (int i = 0; i < width; i++) {
			const float R = p[0];
			const float G = p[1];
			const float B = p[2];

			int g;
			int og;
			vips_col_scRGB2BW_8(R, G, B, &g, &og);

			q[0] = g;

			p += 3;
			q += 1;
		}
	}
}

static int
vips_scRGB2BW_build(VipsObject *object)
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS(object);
	VipsscRGB2BW *scRGB2BW = (VipsscRGB2BW *) object;
	VipsColour *colour = (VipsColour *) object;
	VipsColourCode *code = (VipsColourCode *) object;

	// input image we want

	code->input_format = VIPS_FORMAT_FLOAT;
	colour->input_bands = 3;

	// output image we make

	switch (scRGB2BW->depth) {
	case 16:
		colour->interpretation = VIPS_INTERPRETATION_GREY16;
		colour->format = VIPS_FORMAT_USHORT;
		break;

	case 8:
		colour->interpretation = VIPS_INTERPRETATION_B_W;
		colour->format = VIPS_FORMAT_UCHAR;
		break;

	default:
		vips_error(class->nickname, "%s", _("depth must be 8 or 16"));
		return -1;
	}

	colour->bands = 1;

	return VIPS_OBJECT_CLASS(vips_scRGB2BW_parent_class)->build(object);
}

static void
vips_scRGB2BW_class_init(VipsscRGB2BWClass *class)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS(class);
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsColourClass *colour_class = VIPS_COLOUR_CLASS(class);

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "scRGB2BW";
	object_class->description = _("convert scRGB to BW");
	object_class->build = vips_scRGB2BW_build;

	colour_class->process_line = vips_scRGB2BW_line;

	VIPS_ARG_INT(class, "depth", 130,
		_("Depth"),
		_("Output device space depth in bits"),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET(VipsscRGB2BW, depth),
		8, 16, 8);
}

static void
vips_scRGB2BW_init(VipsscRGB2BW *scRGB2BW)
{
	scRGB2BW->depth = 8;
}

/**
 * vips_scRGB2BW: (method)
 * @in: input image
 * @out: (out): output image
 * @...: `NULL`-terminated list of optional named arguments
 *
 * Convert an scRGB image to greyscale. Set @depth to 16 to get 16-bit output.
 *
 * ::: tip "Optional arguments"
 *     * @depth: depth of output image in bits
 *
 * ::: seealso
 *     [method@Image.LabS2LabQ], [method@Image.sRGB2scRGB],
 *     [method@Image.rad2float].
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_scRGB2BW(VipsImage *in, VipsImage **out, ...)
{
	va_list ap;
	int result;

	va_start(ap, out);
	result = vips_call_split("scRGB2BW", ap, in, out);
	va_end(ap);

	return result;
}
