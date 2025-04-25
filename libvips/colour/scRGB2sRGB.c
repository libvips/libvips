/* Turn scRGB files into displayable rgb.
 *
 * Author: J-P. Laurent
 * Modified:
 * 15/11/94 JC
 *	- error message added
 *	- out->Type set to IM_TYPE_RGB
 *	- memory leak fixed
 * 16/11/94 JC
 *	- uses im_wrapone()
 * 15/2/95 JC
 *	- oops! now uses PEL, not float for output pointer
 * 2/1/96 JC
 *	- sometimes produced incorrect result at extrema
 *	- reformatted
 *	- now uses IM_RINT() and clip()
 * 18/9/96 JC
 *	- some speed-ups ... 3x faster
 *	- slightly less accurate, but who cares
 *	- added out-of-mem check for table build
 * 21/9/12
 * 	- redone as a class
 * 	- sRGB only, support for other RGBs is now via lcms
 * 6/11/12
 * 	- added 16-bit option
 * 11/12/12
 * 	- cut about to make scRGB2sRGB.c
 * 12/2/15
 * 	- add 16-bit alpha handling
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

typedef struct _VipsscRGB2sRGB {
	VipsColourCode parent_instance;

	int depth;
} VipsscRGB2sRGB;

typedef VipsColourCodeClass VipsscRGB2sRGBClass;

G_DEFINE_TYPE(VipsscRGB2sRGB, vips_scRGB2sRGB, VIPS_TYPE_COLOUR_CODE);

static void
vips_scRGB2sRGB_line(VipsColour *colour, VipsPel *out, VipsPel **in, int width)
{
	VipsscRGB2sRGB *scRGB2sRGB = (VipsscRGB2sRGB *) colour;

	if (scRGB2sRGB->depth == 16) {
		unsigned short *restrict q;
	   	float *restrict p;

		q = (unsigned short *) out;
	   	p = (float *) in[0];
		for (int i = 0; i < width; i++) {
			const float R = p[0];
			const float G = p[1];
			const float B = p[2];

			int r, g, b;
			vips_col_scRGB2sRGB_16(R, G, B, &r, &g, &b, NULL);

			q[0] = r;
			q[1] = g;
			q[2] = b;

			p += 3;
			q += 3;
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

			int r, g, b;
			vips_col_scRGB2sRGB_8(R, G, B, &r, &g, &b, NULL);

			q[0] = r;
			q[1] = g;
			q[2] = b;

			p += 3;
			q += 3;
		}
	}
}

static int
vips_scRGB2sRGB_build(VipsObject *object)
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS(object);
	VipsscRGB2sRGB *scRGB2sRGB = (VipsscRGB2sRGB *) object;
	VipsColour *colour = (VipsColour *) object;
	VipsColourCode *code = (VipsColourCode *) object;

	// input image we want

	code->input_format = VIPS_FORMAT_FLOAT;
	colour->input_bands = 3;

	// output image we make

	switch (scRGB2sRGB->depth) {
	case 16:
		colour->interpretation = VIPS_INTERPRETATION_RGB16;
		colour->format = VIPS_FORMAT_USHORT;
		break;

	case 8:
		colour->interpretation = VIPS_INTERPRETATION_sRGB;
		colour->format = VIPS_FORMAT_UCHAR;
		break;

	default:
		vips_error(class->nickname, "%s", _("depth must be 8 or 16"));
		return -1;
	}

	colour->bands = 3;

	return VIPS_OBJECT_CLASS(vips_scRGB2sRGB_parent_class)->build(object);
}

static void
vips_scRGB2sRGB_class_init(VipsscRGB2sRGBClass *class)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS(class);
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsColourClass *colour_class = VIPS_COLOUR_CLASS(class);

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "scRGB2sRGB";
	object_class->description = _("convert scRGB to sRGB");
	object_class->build = vips_scRGB2sRGB_build;

	colour_class->process_line = vips_scRGB2sRGB_line;

	VIPS_ARG_INT(class, "depth", 130,
		_("Depth"),
		_("Output device space depth in bits"),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET(VipsscRGB2sRGB, depth),
		8, 16, 8);
}

static void
vips_scRGB2sRGB_init(VipsscRGB2sRGB *scRGB2sRGB)
{
	scRGB2sRGB->depth = 8;
}

/**
 * vips_scRGB2sRGB: (method)
 * @in: input image
 * @out: (out): output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Convert an scRGB image to sRGB. Set @depth to 16 to get 16-bit output.
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
vips_scRGB2sRGB(VipsImage *in, VipsImage **out, ...)
{
	va_list ap;
	int result;

	va_start(ap, out);
	result = vips_call_split("scRGB2sRGB", ap, in, out);
	va_end(ap);

	return result;
}
