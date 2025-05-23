/* complex.c ... various complex operations
 *
 * Copyright: 1990, N. Dessipris.
 *
 * Author: Nicos Dessipris
 * Written on: 12/02/1990
 * Modified on : 09/05/1990
 * 15/6/93 JC
 *	- stupid stupid includes and externs fixed
 *	- I have been editing for 1 1/2 hours and I'm still drowning in
 *	  rubbish extetrnshh
 * 13/12/94 JC
 *	- modernised
 * 9/7/02 JC
 *	- degree output, for consistency
 *	- slightly better behaviour in edge cases
 * 27/1/10
 * 	- modernised
 * 	- gtk-doc
 * 19/11/11
 * 	- redo as a class
 * 21/11/11
 * 	- add vips_complexget()
 * 29/9/15
 * 	- return 0 for cross-product where one arg is zero
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

#include "unary.h"
#include "binary.h"

typedef struct _VipsComplex {
	VipsUnary parent_instance;

	VipsOperationComplex cmplx;

} VipsComplex;

typedef VipsUnaryClass VipsComplexClass;

G_DEFINE_TYPE(VipsComplex, vips_complex, VIPS_TYPE_UNARY);

#define LOOP(IN, OUT, OP) \
	{ \
		IN *restrict p = (IN *) in[0]; \
		OUT *restrict q = (OUT *) out; \
\
		for (x = 0; x < sz; x++) { \
			OP(q, p[x], 0.0); \
\
			q += 2; \
		} \
	}

#define CLOOP(IN, OUT, OP) \
	{ \
		IN *restrict p = (IN *) in[0]; \
		OUT *restrict q = (OUT *) out; \
\
		for (x = 0; x < sz; x++) { \
			OP(q, p[0], p[1]); \
\
			p += 2; \
			q += 2; \
		} \
	}

#define SWITCH(OP) \
	switch (vips_image_get_format(im)) { \
	case VIPS_FORMAT_UCHAR: \
		LOOP(unsigned char, float, OP); \
		break; \
	case VIPS_FORMAT_CHAR: \
		LOOP(signed char, float, OP); \
		break; \
	case VIPS_FORMAT_USHORT: \
		LOOP(unsigned short, float, OP); \
		break; \
	case VIPS_FORMAT_SHORT: \
		LOOP(signed short, float, OP); \
		break; \
	case VIPS_FORMAT_UINT: \
		LOOP(unsigned int, float, OP); \
		break; \
	case VIPS_FORMAT_INT: \
		LOOP(signed int, float, OP); \
		break; \
	case VIPS_FORMAT_FLOAT: \
		LOOP(float, float, OP); \
		break; \
	case VIPS_FORMAT_DOUBLE: \
		LOOP(double, double, OP); \
		break; \
	case VIPS_FORMAT_COMPLEX: \
		CLOOP(float, float, OP); \
		break; \
	case VIPS_FORMAT_DPCOMPLEX: \
		CLOOP(double, double, OP); \
		break; \
\
	default: \
		g_assert_not_reached(); \
	}

static double
vips_complex_atan2(double a, double b)
{
	double h;

	h = VIPS_DEG(atan2(b, a));
	if (h < 0.0)
		h += 360;

	return h;
}

#define POLAR(Q, X, Y) \
	{ \
		double re = (X); \
		double im = (Y); \
		double am, ph; \
\
		am = hypot(re, im); \
		ph = vips_complex_atan2(re, im); \
\
		Q[0] = am; \
		Q[1] = ph; \
	}

#define RECT(Q, X, Y) \
	{ \
		double am = (X); \
		double ph = (Y); \
		double re, im; \
\
		re = am * cos(VIPS_RAD(ph)); \
		im = am * sin(VIPS_RAD(ph)); \
\
		Q[0] = re; \
		Q[1] = im; \
	}

#define CONJ(Q, X, Y) \
	{ \
		double re = (X); \
		double im = (Y); \
\
		im *= -1; \
\
		Q[0] = re; \
		Q[1] = im; \
	}

static void
vips_complex_buffer(VipsArithmetic *arithmetic,
	VipsPel *out, VipsPel **in, int width)
{
	VipsComplex *cmplx = (VipsComplex *) arithmetic;
	VipsImage *im = arithmetic->ready[0];
	const int sz = width * vips_image_get_bands(im);

	int x;

	switch (cmplx->cmplx) {
	case VIPS_OPERATION_COMPLEX_POLAR:
		SWITCH(POLAR);
		break;
	case VIPS_OPERATION_COMPLEX_RECT:
		SWITCH(RECT);
		break;
	case VIPS_OPERATION_COMPLEX_CONJ:
		SWITCH(CONJ);
		break;

	default:
		g_assert_not_reached();
	}
}

/* Save a bit of typing.
 */
#define UC VIPS_FORMAT_UCHAR
#define C VIPS_FORMAT_CHAR
#define US VIPS_FORMAT_USHORT
#define S VIPS_FORMAT_SHORT
#define UI VIPS_FORMAT_UINT
#define I VIPS_FORMAT_INT
#define F VIPS_FORMAT_FLOAT
#define X VIPS_FORMAT_COMPLEX
#define D VIPS_FORMAT_DOUBLE
#define DX VIPS_FORMAT_DPCOMPLEX

static const VipsBandFormat vips_complex_format_table[10] = {
	/* Band format:  UC C  US S  UI I  F  X  D   DX */
	/* Promotion: */ X, X, X, X, X, X, X, X, DX, DX
};

static void
vips_complex_class_init(VipsComplexClass *class)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS(class);
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsArithmeticClass *aclass = VIPS_ARITHMETIC_CLASS(class);

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "complex";
	object_class->description =
		_("perform a complex operation on an image");

	aclass->process_line = vips_complex_buffer;

	vips_arithmetic_set_format_table(aclass, vips_complex_format_table);

	VIPS_ARG_ENUM(class, "cmplx", 200,
		_("Operation"),
		_("Complex to perform"),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET(VipsComplex, cmplx),
		VIPS_TYPE_OPERATION_COMPLEX, VIPS_OPERATION_COMPLEX_POLAR);
}

static void
vips_complex_init(VipsComplex *cmplx)
{
}

static int
vips_complexv(VipsImage *in, VipsImage **out,
	VipsOperationComplex cmplx, va_list ap)
{
	return vips_call_split("complex", ap, in, out, cmplx);
}

/**
 * vips_complex: (method)
 * @in: input [class@Image]
 * @out: (out): output [class@Image]
 * @cmplx: complex operation to perform
 * @...: `NULL`-terminated list of optional named arguments
 *
 * Perform various operations on complex images.
 *
 * Angles are expressed in degrees. The output type is complex unless the
 * input is double or dpcomplex, in which case the output is dpcomplex.
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_complex(VipsImage *in, VipsImage **out, VipsOperationComplex cmplx, ...)
{
	va_list ap;
	int result;

	va_start(ap, cmplx);
	result = vips_complexv(in, out, cmplx, ap);
	va_end(ap);

	return result;
}

/**
 * vips_polar: (method)
 * @in: input [class@Image]
 * @out: (out): output [class@Image]
 * @...: `NULL`-terminated list of optional named arguments
 *
 * Perform [enum@Vips.OperationComplex.POLAR] on an image. See [method@Image.complex].
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_polar(VipsImage *in, VipsImage **out, ...)
{
	va_list ap;
	int result;

	va_start(ap, out);
	result = vips_complexv(in, out, VIPS_OPERATION_COMPLEX_POLAR, ap);
	va_end(ap);

	return result;
}

/**
 * vips_rect: (method)
 * @in: input [class@Image]
 * @out: (out): output [class@Image]
 * @...: `NULL`-terminated list of optional named arguments
 *
 * Perform [enum@Vips.OperationComplex.RECT] on an image. See [method@Image.complex].
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_rect(VipsImage *in, VipsImage **out, ...)
{
	va_list ap;
	int result;

	va_start(ap, out);
	result = vips_complexv(in, out, VIPS_OPERATION_COMPLEX_RECT, ap);
	va_end(ap);

	return result;
}

/**
 * vips_conj: (method)
 * @in: input [class@Image]
 * @out: (out): output [class@Image]
 * @...: `NULL`-terminated list of optional named arguments
 *
 * Perform [enum@Vips.OperationComplex.CONJ] on an image. See [method@Image.complex].
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_conj(VipsImage *in, VipsImage **out, ...)
{
	va_list ap;
	int result;

	va_start(ap, out);
	result = vips_complexv(in, out, VIPS_OPERATION_COMPLEX_CONJ, ap);
	va_end(ap);

	return result;
}

typedef struct _VipsComplex2 {
	VipsBinary parent_instance;

	VipsOperationComplex2 cmplx;

} VipsComplex2;

typedef VipsBinaryClass VipsComplex2Class;

G_DEFINE_TYPE(VipsComplex2, vips_complex2, VIPS_TYPE_BINARY);

#define LOOP2(IN, OUT, OP) \
	{ \
		IN *p1 = (IN *) in[0]; \
		IN *p2 = (IN *) in[1]; \
		OUT *q = (OUT *) out; \
\
		for (x = 0; x < sz; x++) { \
			OP(q, p1[x], 0.0, p2[x], 0.0); \
\
			q += 2; \
		} \
	}

#define CLOOP2(IN, OUT, OP) \
	{ \
		IN *p1 = (IN *) in[0]; \
		IN *p2 = (IN *) in[1]; \
		OUT *q = (OUT *) out; \
\
		for (x = 0; x < sz; x++) { \
			OP(q, p1[0], p1[1], p2[0], p2[1]); \
\
			p1 += 2; \
			p2 += 2; \
			q += 2; \
		} \
	}

#define SWITCH2(OP) \
	switch (vips_image_get_format(im)) { \
	case VIPS_FORMAT_UCHAR: \
		LOOP2(unsigned char, float, OP); \
		break; \
	case VIPS_FORMAT_CHAR: \
		LOOP2(signed char, float, OP); \
		break; \
	case VIPS_FORMAT_USHORT: \
		LOOP2(unsigned short, float, OP); \
		break; \
	case VIPS_FORMAT_SHORT: \
		LOOP2(signed short, float, OP); \
		break; \
	case VIPS_FORMAT_UINT: \
		LOOP2(unsigned int, float, OP); \
		break; \
	case VIPS_FORMAT_INT: \
		LOOP2(signed int, float, OP); \
		break; \
	case VIPS_FORMAT_FLOAT: \
		LOOP2(float, float, OP); \
		break; \
	case VIPS_FORMAT_DOUBLE: \
		LOOP2(double, double, OP); \
		break; \
	case VIPS_FORMAT_COMPLEX: \
		CLOOP2(float, float, OP); \
		break; \
	case VIPS_FORMAT_DPCOMPLEX: \
		CLOOP2(double, double, OP); \
		break; \
\
	default: \
		g_assert_not_reached(); \
	}

#define CROSS(Q, X1, Y1, X2, Y2) \
	{ \
		if (((X1) == 0.0 && (Y1) == 0.0) || \
			((X2) == 0.0 && (Y2) == 0.0) || \
			((Y1) == 0.0 && (Y2) == 0.0)) { \
			Q[0] = 0.0; \
			Q[1] = 0.0; \
		} \
		else if (ABS(Y1) > ABS(Y2)) { \
			double y1 = Y1; /* this suppress C2142 (division by zero) error on MSVC */ \
			double a = Y2 / y1; \
			double b = Y1 + Y2 * a; \
			double re = (X1 + X2 * a) / b; \
			double im = (X2 - X1 * a) / b; \
			double mod = hypot(re, im); \
\
			Q[0] = re / mod; \
			Q[1] = im / mod; \
		} \
		else { \
			double y2 = Y2; \
			double a = Y1 / y2; \
			double b = Y2 + Y1 * a; \
			double re = (X1 * a + X2) / b; \
			double im = (X2 * a - X1) / b; \
			double mod = hypot(re, im); \
\
			Q[0] = re / mod; \
			Q[1] = im / mod; \
		} \
	}

static void
vips_complex2_buffer(VipsArithmetic *arithmetic,
	VipsPel *out, VipsPel **in, int width)
{
	VipsComplex2 *cmplx = (VipsComplex2 *) arithmetic;
	VipsImage *im = arithmetic->ready[0];
	const int sz = width * vips_image_get_bands(im);

	int x;

	switch (cmplx->cmplx) {
	case VIPS_OPERATION_COMPLEX2_CROSS_PHASE:
		SWITCH2(CROSS);
		break;

	default:
		g_assert_not_reached();
	}
}

/* Save a bit of typing.
 */
#define UC VIPS_FORMAT_UCHAR
#define C VIPS_FORMAT_CHAR
#define US VIPS_FORMAT_USHORT
#define S VIPS_FORMAT_SHORT
#define UI VIPS_FORMAT_UINT
#define I VIPS_FORMAT_INT
#define F VIPS_FORMAT_FLOAT
#define X VIPS_FORMAT_COMPLEX
#define D VIPS_FORMAT_DOUBLE
#define DX VIPS_FORMAT_DPCOMPLEX

static const VipsBandFormat vips_complex2_format_table[10] = {
	/* Band format:  UC C  US S  UI I  F  X  D   DX */
	/* Promotion: */ X, X, X, X, X, X, X, X, DX, DX
};

static void
vips_complex2_class_init(VipsComplex2Class *class)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS(class);
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsArithmeticClass *aclass = VIPS_ARITHMETIC_CLASS(class);

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "complex2";
	object_class->description =
		_("complex binary operations on two images");

	aclass->process_line = vips_complex2_buffer;

	vips_arithmetic_set_format_table(aclass, vips_complex2_format_table);

	VIPS_ARG_ENUM(class, "cmplx", 200,
		_("Operation"),
		_("Binary complex operation to perform"),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET(VipsComplex2, cmplx),
		VIPS_TYPE_OPERATION_COMPLEX2,
		VIPS_OPERATION_COMPLEX2_CROSS_PHASE);
}

static void
vips_complex2_init(VipsComplex2 *cmplx)
{
}

static int
vips_complex2v(VipsImage *left, VipsImage *right, VipsImage **out,
	VipsOperationComplex2 cmplx, va_list ap)
{
	return vips_call_split("complex2", ap, left, right, out, cmplx);
}

/**
 * vips_complex2: (method)
 * @left: input [class@Image]
 * @right: input [class@Image]
 * @out: (out): output [class@Image]
 * @cmplx: complex2 operation to perform
 * @...: `NULL`-terminated list of optional named arguments
 *
 * Perform various binary operations on complex images.
 *
 * Angles are expressed in degrees. The output type is complex unless the
 * input is double or dpcomplex, in which case the output is dpcomplex.
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_complex2(VipsImage *left, VipsImage *right, VipsImage **out,
	VipsOperationComplex2 cmplx, ...)
{
	va_list ap;
	int result;

	va_start(ap, cmplx);
	result = vips_complex2v(left, right, out, cmplx, ap);
	va_end(ap);

	return result;
}

/**
 * vips_cross_phase: (method)
 * @left: input [class@Image]
 * @right: input [class@Image]
 * @out: (out): output [class@Image]
 * @...: `NULL`-terminated list of optional named arguments
 *
 * Perform [enum@Vips.OperationComplex2.CROSS_PHASE] on an image.
 * See [method@Image.complex2].
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_cross_phase(VipsImage *left, VipsImage *right, VipsImage **out, ...)
{
	va_list ap;
	int result;

	va_start(ap, out);
	result = vips_complex2v(left, right, out,
		VIPS_OPERATION_COMPLEX2_CROSS_PHASE, ap);
	va_end(ap);

	return result;
}

typedef struct _VipsComplexget {
	VipsUnary parent_instance;

	VipsOperationComplexget get;

} VipsComplexget;

typedef VipsUnaryClass VipsComplexgetClass;

G_DEFINE_TYPE(VipsComplexget, vips_complexget, VIPS_TYPE_UNARY);

static int
vips_complexget_build(VipsObject *object)
{
	VipsUnary *unary = (VipsUnary *) object;
	VipsComplexget *complexget = (VipsComplexget *) object;

	if (unary->in &&
		!vips_band_format_iscomplex(unary->in->BandFmt) &&
		complexget->get == VIPS_OPERATION_COMPLEXGET_REAL)
		return vips_unary_copy(unary);

	if (VIPS_OBJECT_CLASS(vips_complexget_parent_class)->build(object))
		return -1;

	return 0;
}

#define GETLOOP(TYPE, OP) \
	{ \
		TYPE *p G_GNUC_UNUSED = (TYPE *) in[0]; \
		TYPE *q = (TYPE *) out; \
\
		for (x = 0; x < sz; x++) { \
			OP(q[x], p[x], 0.0); \
		} \
	}

#define CGETLOOP(TYPE, OP) \
	{ \
		TYPE *p G_GNUC_UNUSED = (TYPE *) in[0]; \
		TYPE *q = (TYPE *) out; \
\
		for (x = 0; x < sz; x++) { \
			OP(q[x], p[0], p[1]); \
\
			p += 2; \
		} \
	}

#define GETSWITCH(OP) \
	switch (vips_image_get_format(im)) { \
	case VIPS_FORMAT_UCHAR: \
		GETLOOP(unsigned char, OP); \
		break; \
	case VIPS_FORMAT_CHAR: \
		GETLOOP(signed char, OP); \
		break; \
	case VIPS_FORMAT_USHORT: \
		GETLOOP(unsigned short, OP); \
		break; \
	case VIPS_FORMAT_SHORT: \
		GETLOOP(signed short, OP); \
		break; \
	case VIPS_FORMAT_UINT: \
		GETLOOP(unsigned int, OP); \
		break; \
	case VIPS_FORMAT_INT: \
		GETLOOP(signed int, OP); \
		break; \
	case VIPS_FORMAT_FLOAT: \
		GETLOOP(float, OP); \
		break; \
	case VIPS_FORMAT_DOUBLE: \
		GETLOOP(double, OP); \
		break; \
	case VIPS_FORMAT_COMPLEX: \
		CGETLOOP(float, OP); \
		break; \
	case VIPS_FORMAT_DPCOMPLEX: \
		CGETLOOP(double, OP); \
		break; \
\
	default: \
		g_assert_not_reached(); \
	}

#define REAL(Q, X, Y) \
	{ \
		Q = X; \
	}

#define IMAG(Q, X, Y) \
	{ \
		Q = Y; \
	}

static void
vips_complexget_buffer(VipsArithmetic *arithmetic,
	VipsPel *out, VipsPel **in, int width)
{
	VipsComplexget *complexget = (VipsComplexget *) arithmetic;
	VipsImage *im = arithmetic->ready[0];
	const int sz = width * vips_image_get_bands(im);

	int x;

	switch (complexget->get) {
	case VIPS_OPERATION_COMPLEXGET_REAL:
		GETSWITCH(REAL);
		break;
	case VIPS_OPERATION_COMPLEXGET_IMAG:
		GETSWITCH(IMAG);
		break;

	default:
		g_assert_not_reached();
	}
}

/* Save a bit of typing.
 */
#define UC VIPS_FORMAT_UCHAR
#define C VIPS_FORMAT_CHAR
#define US VIPS_FORMAT_USHORT
#define S VIPS_FORMAT_SHORT
#define UI VIPS_FORMAT_UINT
#define I VIPS_FORMAT_INT
#define F VIPS_FORMAT_FLOAT
#define X VIPS_FORMAT_COMPLEX
#define D VIPS_FORMAT_DOUBLE
#define DX VIPS_FORMAT_DPCOMPLEX

static const VipsBandFormat vips_complexget_format_table[10] = {
	/* Band format:  UC  C  US  S  UI  I  F  X  D  DX */
	/* Promotion: */ UC, C, US, S, UI, I, F, F, D, D
};

static void
vips_complexget_class_init(VipsComplexgetClass *class)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS(class);
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsArithmeticClass *aclass = VIPS_ARITHMETIC_CLASS(class);

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "complexget";
	object_class->description = _("get a component from a complex image");
	object_class->build = vips_complexget_build;

	aclass->process_line = vips_complexget_buffer;

	vips_arithmetic_set_format_table(aclass,
		vips_complexget_format_table);

	VIPS_ARG_ENUM(class, "get", 200,
		_("Operation"),
		_("Complex to perform"),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET(VipsComplexget, get),
		VIPS_TYPE_OPERATION_COMPLEXGET,
		VIPS_OPERATION_COMPLEXGET_REAL);
}

static void
vips_complexget_init(VipsComplexget *complexget)
{
}

static int
vips_complexgetv(VipsImage *in, VipsImage **out,
	VipsOperationComplexget get, va_list ap)
{
	return vips_call_split("complexget", ap, in, out, get);
}

/**
 * vips_complexget: (method)
 * @in: input [class@Image]
 * @out: (out): output [class@Image]
 * @get: complex operation to perform
 * @...: `NULL`-terminated list of optional named arguments
 *
 * Get components of complex images.
 *
 * The output type is the same as the input type, except [enum@Vips.BandFormat.COMPLEX]
 * becomes [enum@Vips.BandFormat.FLOAT] and [enum@Vips.BandFormat.DPCOMPLEX] becomes
 * [enum@Vips.BandFormat.DOUBLE].
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_complexget(VipsImage *in, VipsImage **out,
	VipsOperationComplexget get, ...)
{
	va_list ap;
	int result;

	va_start(ap, get);
	result = vips_complexgetv(in, out, get, ap);
	va_end(ap);

	return result;
}

/**
 * vips_real: (method)
 * @in: input [class@Image]
 * @out: (out): output [class@Image]
 * @...: `NULL`-terminated list of optional named arguments
 *
 * Perform [enum@Vips.OperationComplexget.REAL] on an image. See [method@Image.complexget].
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_real(VipsImage *in, VipsImage **out, ...)
{
	va_list ap;
	int result;

	va_start(ap, out);
	result = vips_complexgetv(in, out,
		VIPS_OPERATION_COMPLEXGET_REAL, ap);
	va_end(ap);

	return result;
}

/**
 * vips_imag: (method)
 * @in: input [class@Image]
 * @out: (out): output [class@Image]
 * @...: `NULL`-terminated list of optional named arguments
 *
 * Perform [enum@Vips.OperationComplexget.IMAG] on an image. See [method@Image.complexget].
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_imag(VipsImage *in, VipsImage **out, ...)
{
	va_list ap;
	int result;

	va_start(ap, out);
	result = vips_complexgetv(in, out,
		VIPS_OPERATION_COMPLEXGET_IMAG, ap);
	va_end(ap);

	return result;
}

typedef VipsBinary VipsComplexform;
typedef VipsBinaryClass VipsComplexformClass;

G_DEFINE_TYPE(VipsComplexform, vips_complexform, VIPS_TYPE_BINARY);

static int
vips_complexform_build(VipsObject *object)
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS(object);
	VipsBinary *binary = (VipsBinary *) object;

	if (binary->left &&
		vips_check_noncomplex(class->nickname, binary->left))
		return -1;
	if (binary->right &&
		vips_check_noncomplex(class->nickname, binary->right))
		return -1;

	if (VIPS_OBJECT_CLASS(vips_complexform_parent_class)->build(object))
		return -1;

	return 0;
}

#define CFORM(IN, OUT) \
	{ \
		IN *left = (IN *) in[0]; \
		IN *right = (IN *) in[1]; \
		OUT *q = (OUT *) out; \
\
		for (x = 0; x < sz; x++) { \
			q[0] = left[x]; \
			q[1] = right[x]; \
\
			q += 2; \
		} \
	}

static void
vips_complexform_buffer(VipsArithmetic *arithmetic,
	VipsPel *out, VipsPel **in, int width)
{
	VipsImage *im = arithmetic->ready[0];
	const int sz = width * vips_image_get_bands(im);

	int x;

	/* Keep types here in sync with bandfmt_complexform[]
	 * below.
	 */
	switch (vips_image_get_format(im)) {
	case VIPS_FORMAT_UCHAR:
		CFORM(unsigned char, float);
		break;
	case VIPS_FORMAT_CHAR:
		CFORM(signed char, float);
		break;
	case VIPS_FORMAT_USHORT:
		CFORM(unsigned short, float);
		break;
	case VIPS_FORMAT_SHORT:
		CFORM(signed short, float);
		break;
	case VIPS_FORMAT_UINT:
		CFORM(unsigned int, float);
		break;
	case VIPS_FORMAT_INT:
		CFORM(signed int, float);
		break;
	case VIPS_FORMAT_FLOAT:
		CFORM(float, float);
		break;
	case VIPS_FORMAT_DOUBLE:
		CFORM(double, double);
		break;

	default:
		g_assert_not_reached();
	}
}

/* Save a bit of typing.
 */
#define UC VIPS_FORMAT_UCHAR
#define C VIPS_FORMAT_CHAR
#define US VIPS_FORMAT_USHORT
#define S VIPS_FORMAT_SHORT
#define UI VIPS_FORMAT_UINT
#define I VIPS_FORMAT_INT
#define F VIPS_FORMAT_FLOAT
#define X VIPS_FORMAT_COMPLEX
#define D VIPS_FORMAT_DOUBLE
#define DX VIPS_FORMAT_DPCOMPLEX

/* Type promotion for form complex. Sign and value preserving. Make sure
 * these match the case statement in complexform_buffer() above.
 */
static VipsBandFormat vips_complexform_format_table[10] = {
	/* Band format:  UC C  US S  UI I  F  X  D   DX */
	/* Promotion: */ X, X, X, X, X, X, X, X, DX, DX
};

static void
vips_complexform_class_init(VipsComplexformClass *class)
{
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsArithmeticClass *aclass = VIPS_ARITHMETIC_CLASS(class);

	object_class->nickname = "complexform";
	object_class->description =
		_("form a complex image from two real images");
	object_class->build = vips_complexform_build;

	aclass->process_line = vips_complexform_buffer;

	vips_arithmetic_set_format_table(aclass,
		vips_complexform_format_table);
}

static void
vips_complexform_init(VipsComplexform *complexform)
{
}

/**
 * vips_complexform: (method)
 * @left: input image
 * @right: input image
 * @out: (out): output image
 * @...: `NULL`-terminated list of optional named arguments
 *
 * Compose two real images to make a complex image. If either @left or @right
 * are [enum@Vips.BandFormat.DOUBLE], @out is [enum@Vips.BandFormat.DPCOMPLEX]. Otherwise @out
 * is [enum@Vips.BandFormat.COMPLEX]. @left becomes the real component of @out and
 * @right the imaginary.
 *
 * If the number of bands differs, one of the images
 * must have one band. In this case, an n-band image is formed from the
 * one-band image by joining n copies of the one-band image together, and then
 * the two n-band images are operated upon.
 *
 * ::: seealso
 *     [method@Image.complexget].
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_complexform(VipsImage *left, VipsImage *right, VipsImage **out, ...)
{
	va_list ap;
	int result;

	va_start(ap, out);
	result = vips_call_split("complexform", ap, left, right, out);
	va_end(ap);

	return result;
}
