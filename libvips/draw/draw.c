/* base class for drawing operations
 *
 * 27/9/10
 *	- from im_draw_circle()
 * 17/11/10
 * 	- oops, scanline clipping was off by 1
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

#include <string.h>

#include <vips/vips.h>
#include <vips/internal.h>

#include "pdraw.h"

/**
 * VipsCombineMode:
 * @VIPS_COMBINE_MODE_SET: set pixels to the new value
 * @VIPS_COMBINE_MODE_ADD: add pixels
 *
 * See vips_draw_image() and so on.
 *
 * Operations like vips_draw_image() need to be told how to combine images
 * from two sources.
 *
 * See also: vips_join().
 */

G_DEFINE_ABSTRACT_TYPE(VipsDraw, vips_draw, VIPS_TYPE_OPERATION);

static int
vips_draw_build(VipsObject *object)
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS(object);
	VipsDraw *draw = VIPS_DRAW(object);

#ifdef DEBUG
	printf("vips_draw_build: ");
	vips_object_print_name(object);
	printf("\n");
#endif /*DEBUG*/

	if (VIPS_OBJECT_CLASS(vips_draw_parent_class)->build(object))
		return -1;

	if (vips_check_coding_known(class->nickname, draw->image) ||
		vips_image_inplace(draw->image))
		return -1;

	draw->lsize = VIPS_IMAGE_SIZEOF_LINE(draw->image);
	draw->psize = VIPS_IMAGE_SIZEOF_PEL(draw->image);
	draw->noclip = FALSE;

	return 0;
}

static void
vips_draw_class_init(VipsDrawClass *class)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS(class);
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS(class);
	VipsOperationClass *operation_class = VIPS_OPERATION_CLASS(class);

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "draw";
	vobject_class->description = _("draw operations");
	vobject_class->build = vips_draw_build;

	// no draw operation is cached
	operation_class->flags |= VIPS_OPERATION_NOCACHE;

	VIPS_ARG_IMAGE(class, "image", 1,
		_("Image"),
		_("Image to draw on"),
		VIPS_ARGUMENT_REQUIRED_INPUT | VIPS_ARGUMENT_MODIFY,
		G_STRUCT_OFFSET(VipsDraw, image));
}

static void
vips_draw_init(VipsDraw *draw)
{
}

void
vips_draw_operation_init(void)
{
	extern GType vips_draw_rect_get_type(void);
	extern GType vips_draw_image_get_type(void);
	extern GType vips_draw_mask_get_type(void);
	extern GType vips_draw_line_get_type(void);
	extern GType vips_draw_circle_get_type(void);
	extern GType vips_draw_flood_get_type(void);
	extern GType vips_draw_smudge_get_type(void);

	vips_draw_rect_get_type();
	vips_draw_image_get_type();
	vips_draw_mask_get_type();
	vips_draw_line_get_type();
	vips_draw_circle_get_type();
	vips_draw_flood_get_type();
	vips_draw_smudge_get_type();
}
