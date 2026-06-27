/* Extract the N most dominant colours from an image.
 *
 * 29/3/26
 *	- initial version
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <glib/gi18n-lib.h>

#include <vips/vips.h>

#include "../foreign/quantise.h"

typedef struct _VipsDominantColours {
	VipsOperation parent_instance;

	VipsImage *in;
	VipsImage *out;
	int n;
} VipsDominantColours;

typedef VipsOperationClass VipsDominantColoursClass;

G_DEFINE_TYPE(VipsDominantColours, vips_dominant_colours,
	VIPS_TYPE_OPERATION);

static int
vips_dominant_colours_build(VipsObject *object)
{
	VipsDominantColours *dc = (VipsDominantColours *) object;
	VipsImage *palette;

	if (VIPS_OBJECT_CLASS(vips_dominant_colours_parent_class)->build(object))
		return -1;

	/* Q=100 (best quality), effort=10 (max k-means refinement) —
	 * palette extraction runs once and isn't on a hot path.
	 */
	if (vips__quantise_palette(dc->in, &palette, dc->n, 100, 10))
		return -1;

	g_object_set(object, "out", palette, NULL);

	return 0;
}

static void
vips_dominant_colours_class_init(VipsDominantColoursClass *class)
{
	GObjectClass *gobject_class = (GObjectClass *) class;
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "dominant_colours";
	object_class->description =
		_("find the dominant colours in an image");
	object_class->build = vips_dominant_colours_build;

	VIPS_ARG_IMAGE(class, "in", 1,
		_("Input"),
		_("Input image"),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET(VipsDominantColours, in));

	VIPS_ARG_IMAGE(class, "out", 2,
		_("Output"),
		_("Output palette"),
		VIPS_ARGUMENT_REQUIRED_OUTPUT,
		G_STRUCT_OFFSET(VipsDominantColours, out));

	VIPS_ARG_INT(class, "n", 3,
		_("N"),
		_("Number of dominant colours to find"),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET(VipsDominantColours, n),
		2, 256, 8);
}

static void
vips_dominant_colours_init(VipsDominantColours *dc)
{
}

/**
 * vips_dominant_colours: (method)
 * @in: input image
 * @out: (out): output palette image
 * @n: number of dominant colours to find
 * @...: `NULL`-terminated list of optional named arguments
 *
 * Find the @n most dominant colours in @in using colour quantisation.
 * The output is an @n x 1 RGBA uchar image where each pixel is one
 * dominant colour. The actual number of colours returned may be less
 * than @n.
 *
 * The input image is converted to sRGB before quantisation. An alpha
 * channel is added if missing.
 *
 * ::: seealso
 *     [method@Image.hist_find], [method@Image.stats].
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_dominant_colours(VipsImage *in, VipsImage **out, int n, ...)
{
	va_list ap;
	int result;

	va_start(ap, n);
	result = vips_call_split("dominant_colours", ap, in, out, n);
	va_end(ap);

	return result;
}
