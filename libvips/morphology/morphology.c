/* base class for all morphological operations
 *
 * properties:
 * 	- one input image
 */

/*

	Copyright (C) 1991-2005 The National Gallery

	This library is free software; you can redistribute it and/or
	modify it under the terms of the GNU Lesser General Public
	License as published by the Free Software Foundation; either
	version 2.1 of the License, or (at your option) any later version.

	This library is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
	Lesser General Public License for more details.

	You should have received a copy of the GNU Lesser General Public
	License along with this library; if not, write to the Free Software
	Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
	02110-1301  USA

 */

/*

	These files are distributed with VIPS - http://www.vips.ecs.soton.ac.uk

 */

/*
#define DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <glib/gi18n-lib.h>

#include <stdio.h>
#include <stdlib.h>
#include <math.h>

#include <vips/vips.h>
#include <vips/internal.h>

#include "pmorphology.h"

G_DEFINE_ABSTRACT_TYPE(VipsMorphology, vips_morphology,
	VIPS_TYPE_OPERATION);

static void
vips_morphology_class_init(VipsMorphologyClass *class)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS(class);
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS(class);

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "morphology";
	vobject_class->description = _("morphological operations");

	/* Inputs set by subclassess.
	 */

	VIPS_ARG_IMAGE(class, "in", 0,
		_("Input"),
		_("Input image argument"),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET(VipsMorphology, in));
}

static void
vips_morphology_init(VipsMorphology *morphology)
{
}

/* Called from iofuncs to init all operations in this dir. Use a plugin system
 * instead?
 */
void
vips_morphology_operation_init(void)
{
	extern GType vips_morph_get_type(void);
	extern GType vips_rank_get_type(void);
	extern GType vips_countlines_get_type(void);
	extern GType vips_labelregions_get_type(void);
	extern GType vips_fill_nearest_get_type(void);

	vips_morph_get_type();
	vips_rank_get_type();
	vips_countlines_get_type();
	vips_labelregions_get_type();
	vips_fill_nearest_get_type();
}
