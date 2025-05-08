/* Add an appropriate alpha band.
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
#include <stdlib.h>

#include <vips/vips.h>
#include <vips/internal.h>

#include "pconversion.h"

typedef struct _VipsAddAlpha {
	VipsConversion parent_instance;

	VipsImage *in;

} VipsAddAlpha;

typedef VipsConversionClass VipsAddAlphaClass;

G_DEFINE_TYPE(VipsAddAlpha, vips_addalpha, VIPS_TYPE_CONVERSION);

static int
vips_addalpha_build(VipsObject *object)
{
	VipsAddAlpha *addalpha = (VipsAddAlpha *) object;
	VipsConversion *conversion = VIPS_CONVERSION(object);
	VipsImage **t = (VipsImage **) vips_object_local_array(object, 2);
	double max_alpha = vips_interpretation_max_alpha(addalpha->in->Type);

	if (VIPS_OBJECT_CLASS(vips_addalpha_parent_class)->build(object))
		return -1;

	if (vips_bandjoin_const1(addalpha->in, &t[0], max_alpha, NULL) ||
		vips_image_write(t[0], conversion->out))
		return -1;

	return 0;
}

static void
vips_addalpha_class_init(VipsAddAlphaClass *class)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS(class);
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS(class);
	VipsOperationClass *operation_class = VIPS_OPERATION_CLASS(class);

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "addalpha";
	vobject_class->description = _("append an alpha channel");
	vobject_class->build = vips_addalpha_build;

	operation_class->flags = VIPS_OPERATION_SEQUENTIAL;

	VIPS_ARG_IMAGE(class, "in", 0,
		_("Input"),
		_("Input image"),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET(VipsAddAlpha, in));
}

static void
vips_addalpha_init(VipsAddAlpha *addalpha)
{
}

/**
 * vips_addalpha: (method)
 * @in: input image
 * @out: (out): output image
 * @...: `NULL`-terminated list of optional named arguments
 *
 * Append an alpha channel.
 *
 * ::: seealso
 *     [method@Image.hasalpha].
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_addalpha(VipsImage *in, VipsImage **out, ...)
{
	va_list ap;
	int result;

	va_start(ap, out);
	result = vips_call_split("addalpha", ap, in, out);
	va_end(ap);

	return result;
}
