/* load matlab from a file
 *
 * 5/12/11
 * 	- from tiffload.c
 * 3/7/13
 * 	- lower priority to reduce segvs from Mat_Open()
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
#define DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <glib/gi18n-lib.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vips/vips.h>
#include <vips/buf.h>
#include <vips/internal.h>

#ifdef HAVE_MATIO

#include "pforeign.h"

typedef struct _VipsForeignLoadMat {
	VipsForeignLoad parent_object;

	/* Filename for load.
	 */
	char *filename;

} VipsForeignLoadMat;

typedef VipsForeignLoadClass VipsForeignLoadMatClass;

G_DEFINE_TYPE(VipsForeignLoadMat, vips_foreign_load_mat,
	VIPS_TYPE_FOREIGN_LOAD);

static VipsForeignFlags
vips_foreign_load_mat_get_flags_filename(const char *filename)
{
	return 0;
}

static VipsForeignFlags
vips_foreign_load_mat_get_flags(VipsForeignLoad *load)
{
	VipsForeignLoadMat *mat = (VipsForeignLoadMat *) load;

	return vips_foreign_load_mat_get_flags_filename(mat->filename);
}

static int
vips_foreign_load_mat_header(VipsForeignLoad *load)
{
	VipsForeignLoadMat *mat = (VipsForeignLoadMat *) load;

	if (vips__mat_header(mat->filename, load->out))
		return -1;

	VIPS_SETSTR(load->out->filename, mat->filename);

	return 0;
}

static int
vips_foreign_load_mat_load(VipsForeignLoad *load)
{
	VipsForeignLoadMat *mat = (VipsForeignLoadMat *) load;

	if (vips__mat_load(mat->filename, load->real))
		return -1;

	return 0;
}

static void
vips_foreign_load_mat_class_init(VipsForeignLoadMatClass *class)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS(class);
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsOperationClass *operation_class = VIPS_OPERATION_CLASS(class);
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "matload";
	object_class->description = _("load mat from file");

	/* libmatio is fuzzed, but not by us.
	 */
	operation_class->flags |= VIPS_OPERATION_UNTRUSTED;

	foreign_class->suffs = vips__mat_suffs;

	load_class->is_a = vips__mat_ismat;
	load_class->get_flags_filename =
		vips_foreign_load_mat_get_flags_filename;
	load_class->get_flags = vips_foreign_load_mat_get_flags;
	load_class->header = vips_foreign_load_mat_header;
	load_class->load = vips_foreign_load_mat_load;

	VIPS_ARG_STRING(class, "filename", 1,
		_("Filename"),
		_("Filename to load from"),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET(VipsForeignLoadMat, filename),
		NULL);
}

static void
vips_foreign_load_mat_init(VipsForeignLoadMat *mat)
{
}

#endif /*HAVE_MATIO*/

/**
 * vips_matload:
 * @filename: file to load
 * @out: (out): output image
 * @...: `NULL`-terminated list of optional named arguments
 *
 * Read a Matlab save file into a VIPS image.
 *
 * This operation searches the save
 * file for the first array variable with between 1 and 3 dimensions and loads
 * it as an image. It will not handle complex images. It does not handle
 * sparse matrices.
 *
 * ::: seealso
 *     [ctor@Image.new_from_file].
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_matload(const char *filename, VipsImage **out, ...)
{
	va_list ap;
	int result;

	va_start(ap, out);
	result = vips_call_split("matload", ap, filename, out);
	va_end(ap);

	return result;
}
