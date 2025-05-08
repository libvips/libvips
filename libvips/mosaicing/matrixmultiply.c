/* Multiply two matrices.
 *
 * Copyright: 1990, K. Martinez and J. Cupitt
 *
 * 23/10/10
 * 	- gtk-doc
 * 31/1/25
 *	- wrapped as a class
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

#include <vips/vips.h>

/* Our state.
 */
typedef struct _VipsMatrixmultiply {
	VipsOperation parent_instance;

	VipsImage *left;
	VipsImage *right;
	VipsImage *out;

	VipsImage *mat1;
	VipsImage *mat2;

} VipsMatrixmultiply;

typedef VipsOperationClass VipsMatrixmultiplyClass;

G_DEFINE_TYPE(VipsMatrixmultiply, vips_matrixmultiply, VIPS_TYPE_OPERATION);

static void
vips_matrixmultiply_dispose(GObject *gobject)
{
	VipsMatrixmultiply *matrix = (VipsMatrixmultiply *) gobject;

	VIPS_UNREF(matrix->mat1);
	VIPS_UNREF(matrix->mat2);

	G_OBJECT_CLASS(vips_matrixmultiply_parent_class)->dispose(gobject);
}

static int
vips_matrixmultiply_build(VipsObject *object)
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS(object);
	VipsMatrixmultiply *matrix = (VipsMatrixmultiply *) object;

	if (VIPS_OBJECT_CLASS(vips_matrixmultiply_parent_class)->build(object))
		return -1;

	if (vips_check_matrix(class->nickname, matrix->left, &matrix->mat1) ||
		vips_check_matrix(class->nickname, matrix->right, &matrix->mat2))
		return -1;

	if (matrix->mat1->Xsize != matrix->mat2->Ysize) {
		vips_error(class->nickname, "%s", _("bad sizes"));
		return -1;
	}

	g_object_set(matrix,
		"out", vips_image_new_matrix(matrix->mat2->Xsize, matrix->mat1->Ysize),
		NULL);

	/* Multiply.
	 */
	double *out;
	double *s1;

	s1 = VIPS_MATRIX(matrix->mat1, 0, 0);
	out = VIPS_MATRIX(matrix->out, 0, 0);
	for (int yc = 0; yc < matrix->mat1->Ysize; yc++) {
		double *s2 = VIPS_MATRIX(matrix->mat2, 0, 0);

		for (int col = 0; col < matrix->mat2->Xsize; col++) {
			/* Get ready to sweep a row.
			 */
			double *a = s1;
			double *b = s2;

			double sum;

			sum = 0.0;
			for (int xc = 0; xc < matrix->mat1->Xsize; xc++) {
				sum += *a++ * *b;
				b += matrix->mat2->Xsize;
			}

			*out++ = sum;
			s2 += 1;
		}

		s1 += matrix->mat1->Xsize;
	}

	return 0;
}

static void
vips_matrixmultiply_class_init(VipsMatrixmultiplyClass *class)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS(class);
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS(class);

	gobject_class->dispose = vips_matrixmultiply_dispose;
	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "matrixmultiply";
	vobject_class->description = _("multiply two matrices");
	vobject_class->build = vips_matrixmultiply_build;

	VIPS_ARG_IMAGE(class, "left", 1,
		_("Left"),
		_("First matrix to multiply"),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET(VipsMatrixmultiply, left));

	VIPS_ARG_IMAGE(class, "right", 2,
		_("Right"),
		_("Second matrix to multiply"),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET(VipsMatrixmultiply, right));

	VIPS_ARG_IMAGE(class, "out", 3,
		_("Output"),
		_("Output matrix"),
		VIPS_ARGUMENT_REQUIRED_OUTPUT,
		G_STRUCT_OFFSET(VipsMatrixmultiply, out));
}

static void
vips_matrixmultiply_init(VipsMatrixmultiply *matrix)
{
}

/**
 * vips_matrixmultiply: (method)
 * @left: input matrix
 * @right: input matrix
 * @out: (out): output matrix
 * @...: `NULL`-terminated list of optional named arguments
 *
 * Multiplies two matrix images.
 *
 * The scale and offset members of @left and @right are ignored.
 *
 * ::: seealso
 *     [method@Image.matrixinvert].
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_matrixmultiply(VipsImage *left, VipsImage *right, VipsImage **out, ...)
{
	va_list ap;
	int result;

	va_start(ap, out);
	result = vips_call_split("matrixmultiply", ap, left, right, out);
	va_end(ap);

	return result;
}
