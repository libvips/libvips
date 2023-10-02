/* base class for all arithmetic operations
 *
 * properties:
 * 	- one output image, one or more inputs
 * 	- cast input images to match
 * 	- output is large enough to hold output values (value preserving)
 * 	- point-to-point operations (ie. each pixel depends only on the
 * 	  corresponding pixel in the input)
 * 	- LUT-able: ie. arithmetic (image) can be exactly replaced by
 * 	  maplut (image, arithmetic (lut)) for 8/16 bit int images
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

#include "parithmetic.h"

/**
 * SECTION: arithmetic
 * @short_description: pixel arithmetic, trig, log, statistics
 * @stability: Stable
 * @include: vips/vips.h
 *
 * These operations perform pixel arithmetic, that is, they perform an
 * arithmetic operation, such as addition, on every pixel in an image or a
 * pair of images. All (except in a few cases noted below) will work with
 * images of any type or any mixture of types, of any size and of any number
 * of bands.
 *
 * For binary operations, if the number of bands differs, one of the images
 * must have one band. In this case, an n-band image is formed from the
 * one-band image by joining n copies of the one-band image together, and then
 * the two n-band images are operated upon.
 *
 * In the same way, for operations that take an array constant, such as
 * vips_remainder_const(), you can mix single-element arrays or single-band
 * images freely.
 *
 * Arithmetic operations try to preserve precision by increasing the number of
 * bits in the output image when necessary. Generally, this follows the ANSI C
 * conventions for type promotion, so multiplying two
 * #VIPS_FORMAT_UCHAR images together, for example, produces a
 * #VIPS_FORMAT_USHORT image, and taking the vips_cos() of a
 * #VIPS_FORMAT_USHORT image produces #VIPS_FORMAT_FLOAT image.
 *
 * After processing, use vips_cast() and friends to take then format back down
 * again. vips_cast_uchar(), for example, will cast any image down to 8-bit
 * unsigned.
 *
 * Images have an *interpretation*: a meaning for the pixel values. With
 * #VIPS_INTERPRETATION_sRGB, for example, the first three bands will be
 * interpreted (for example, by a saver like vips_jpegsave()) as R, G and B,
 * with values in 0 - 255, and any fourth band will be interpreted as an
 * alpha channel.
 *
 * After arithmetic, you may wish to change the interpretation (for example to
 * save as 16-bit PNG). Use vips_copy() to change the interpretation without
 * changing pixels.
 *
 * For binary arithmetic operations, type promotion occurs in two stages.
 * First, the two input images are cast up to the smallest common format,
 * that is, the type with the smallest range that can represent the full
 * range of both inputs. This conversion can be represented as a table:
 *
 * <table>
 *   <title>Smallest common format</title>
 *   <tgroup cols='10' align='left' colsep='1' rowsep='1'>
 *     <thead>
 *       <row>
 *         <entry>@in2/@in1</entry>
 *         <entry>uchar</entry>
 *         <entry>char</entry>
 *         <entry>ushort</entry>
 *         <entry>short</entry>
 *         <entry>uint</entry>
 *         <entry>int</entry>
 *         <entry>float</entry>
 *         <entry>double</entry>
 *         <entry>complex</entry>
 *         <entry>double complex</entry>
 *       </row>
 *     </thead>
 *     <tbody>
 *       <row>
 *         <entry>uchar</entry>
 *         <entry>ushort</entry>
 *         <entry>short</entry>
 *         <entry>ushort</entry>
 *         <entry>short</entry>
 *         <entry>uint</entry>
 *         <entry>int</entry>
 *         <entry>float</entry>
 *         <entry>double</entry>
 *         <entry>complex</entry>
 *         <entry>double complex</entry>
 *       </row>
 *       <row>
 *         <entry>char</entry>
 *         <entry>short</entry>
 *         <entry>short</entry>
 *         <entry>short</entry>
 *         <entry>short</entry>
 *         <entry>int</entry>
 *         <entry>int</entry>
 *         <entry>float</entry>
 *         <entry>double</entry>
 *         <entry>complex</entry>
 *         <entry>double complex</entry>
 *       </row>
 *       <row>
 *         <entry>ushort</entry>
 *         <entry>ushort</entry>
 *         <entry>short</entry>
 *         <entry>ushort</entry>
 *         <entry>short</entry>
 *         <entry>uint</entry>
 *         <entry>int</entry>
 *         <entry>float</entry>
 *         <entry>double</entry>
 *         <entry>complex</entry>
 *         <entry>double complex</entry>
 *       </row>
 *       <row>
 *         <entry>short</entry>
 *         <entry>short</entry>
 *         <entry>short</entry>
 *         <entry>short</entry>
 *         <entry>short</entry>
 *         <entry>int</entry>
 *         <entry>int</entry>
 *         <entry>float</entry>
 *         <entry>double</entry>
 *         <entry>complex</entry>
 *         <entry>double complex</entry>
 *       </row>
 *       <row>
 *         <entry>uint</entry>
 *         <entry>uint</entry>
 *         <entry>int</entry>
 *         <entry>uint</entry>
 *         <entry>int</entry>
 *         <entry>uint</entry>
 *         <entry>int</entry>
 *         <entry>float</entry>
 *         <entry>double</entry>
 *         <entry>complex</entry>
 *         <entry>double complex</entry>
 *       </row>
 *       <row>
 *         <entry>int</entry>
 *         <entry>int</entry>
 *         <entry>int</entry>
 *         <entry>int</entry>
 *         <entry>int</entry>
 *         <entry>int</entry>
 *         <entry>int</entry>
 *         <entry>float</entry>
 *         <entry>double</entry>
 *         <entry>complex</entry>
 *         <entry>double complex</entry>
 *       </row>
 *       <row>
 *         <entry>float</entry>
 *         <entry>float</entry>
 *         <entry>float</entry>
 *         <entry>float</entry>
 *         <entry>float</entry>
 *         <entry>float</entry>
 *         <entry>float</entry>
 *         <entry>float</entry>
 *         <entry>double</entry>
 *         <entry>complex</entry>
 *         <entry>double complex</entry>
 *       </row>
 *       <row>
 *         <entry>double</entry>
 *         <entry>double</entry>
 *         <entry>double</entry>
 *         <entry>double</entry>
 *         <entry>double</entry>
 *         <entry>double</entry>
 *         <entry>double</entry>
 *         <entry>double</entry>
 *         <entry>double</entry>
 *         <entry>double complex</entry>
 *         <entry>double complex</entry>
 *       </row>
 *       <row>
 *         <entry>complex</entry>
 *         <entry>complex</entry>
 *         <entry>complex</entry>
 *         <entry>complex</entry>
 *         <entry>complex</entry>
 *         <entry>complex</entry>
 *         <entry>complex</entry>
 *         <entry>complex</entry>
 *         <entry>double complex</entry>
 *         <entry>complex</entry>
 *         <entry>double complex</entry>
 *       </row>
 *       <row>
 *         <entry>double complex</entry>
 *         <entry>double complex</entry>
 *         <entry>double complex</entry>
 *         <entry>double complex</entry>
 *         <entry>double complex</entry>
 *         <entry>double complex</entry>
 *         <entry>double complex</entry>
 *         <entry>double complex</entry>
 *         <entry>double complex</entry>
 *         <entry>double complex</entry>
 *         <entry>double complex</entry>
 *       </row>
 *     </tbody>
 *   </tgroup>
 * </table>
 *
 * In the second stage, the operation is performed between the two identical
 * types to form the output. The details vary between operations, but
 * generally the principle is that the output type should be large enough to
 * represent the whole range of possible values, except that int never becomes
 * float.
 */

G_DEFINE_ABSTRACT_TYPE(VipsArithmetic, vips_arithmetic, VIPS_TYPE_OPERATION);

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

/* For two integer types, the "largest", ie. one which can represent the
 * full range of both.
 */
static VipsBandFormat format_largest[6][6] = {
	/* UC  C   US  S   UI  I */
	/* UC */ { UC, S, US, S, UI, I },
	/* C */ { S, C, I, S, I, I },
	/* US */ { US, I, US, I, UI, I },
	/* S */ { S, S, I, S, I, I },
	/* UI */ { UI, I, UI, I, UI, I },
	/* I */ { I, I, I, I, I, I }
};

/* For two formats, find one which can represent the full range of both.
 */
static VipsBandFormat
vips_format_common(VipsBandFormat a, VipsBandFormat b)
{
	if (vips_band_format_iscomplex(a) ||
		vips_band_format_iscomplex(b)) {
		if (a == VIPS_FORMAT_DPCOMPLEX ||
			b == VIPS_FORMAT_DPCOMPLEX)
			return VIPS_FORMAT_DPCOMPLEX;
		else
			return VIPS_FORMAT_COMPLEX;
	}
	else if (vips_band_format_isfloat(a) ||
		vips_band_format_isfloat(b)) {
		if (a == VIPS_FORMAT_DOUBLE ||
			b == VIPS_FORMAT_DOUBLE)
			return VIPS_FORMAT_DOUBLE;
		else
			return VIPS_FORMAT_FLOAT;
	}
	else
		return format_largest[a][b];
}

int
vips__formatalike_vec(VipsImage **in, VipsImage **out, int n)
{
	int i;
	VipsBandFormat format;

	g_assert(n >= 1);

	format = in[0]->BandFmt;
	for (i = 1; i < n; i++)
		format = vips_format_common(format, in[i]->BandFmt);

	for (i = 0; i < n; i++)
		if (in[i]->BandFmt == format) {
			/* Already in the right format ... just copy the image
			 * pointer and add a ref.
			 */
			out[i] = in[i];
			g_object_ref(in[i]);
		}
		else {
			if (vips_cast(in[i], &out[i], format, NULL))
				return -1;
		}

	return 0;
}

int
vips__sizealike_vec(VipsImage **in, VipsImage **out, int n)
{
	int i;
	int width_max;
	int height_max;

	g_assert(n >= 1);

	width_max = in[0]->Xsize;
	height_max = in[0]->Ysize;
	for (i = 1; i < n; i++) {
		width_max = VIPS_MAX(width_max, in[i]->Xsize);
		height_max = VIPS_MAX(height_max, in[i]->Ysize);
	}

	for (i = 0; i < n; i++)
		if (in[i]->Xsize == width_max &&
			in[i]->Ysize == height_max) {
			/* Already the right size ... just copy the image
			 * pointer and add a ref.
			 */
			out[i] = in[i];
			g_object_ref(in[i]);
		}
		else {
			if (vips_embed(in[i], &out[i],
					0, 0, width_max, height_max, NULL))
				return -1;
		}

	return 0;
}

/* Make an n-band image. Input 1 or n bands.
 */
int
vips__bandup(const char *domain, VipsImage *in, VipsImage **out, int n)
{
	VipsImage **bands;
	int i;
	int result;

	if (in->Bands == n)
		return vips_copy(in, out, NULL);
	if (in->Bands != 1) {
		vips_error(domain, _("not one band or %d bands"), n);
		return -1;
	}
	if (n > VIPS_MAX_COORD ||
		n < 1) {
		vips_error(domain, "%s", _("bad bands"));
		return -1;
	}

	if (!(bands = VIPS_ARRAY(NULL, n, VipsImage *)))
		return -1;
	for (i = 0; i < n; i++)
		bands[i] = in;
	result = vips_bandjoin(bands, out, n, NULL);
	VIPS_FREE(bands);

	return result;
}

/* base_bands is the default minimum.
 *
 * Handy for example, if you have VipsLinear with
 * a 3-element vector of constants and a 1-band input image, you need to cast
 * the image up to three bands.
 */
int
vips__bandalike_vec(const char *domain,
	VipsImage **in, VipsImage **out, int n, int base_bands)
{
	int i;
	int max_bands;
	VipsInterpretation interpretation;

	g_assert(n >= 1);

	/* We try to set the interpretation of the output images from the
	 * interpretation of the n-band input. For example, if we are matching
	 * a set of BW images to an RGB image, we want the BW images to be
	 * tagged as RGB.
	 */
	max_bands = base_bands;
	interpretation = VIPS_INTERPRETATION_ERROR;
	for (i = 0; i < n; i++) {
		/* >= so we can pick up interpretation if base_bands is equal
		 * to the number of bands of the largest image.
		 */
		if (in[i]->Bands >= max_bands) {
			max_bands = in[i]->Bands;
			interpretation = in[i]->Type;
		}
	}

	for (i = 0; i < n; i++)
		if (in[i]->Bands == max_bands) {
			/* Already the right number of bands ... just copy the
			 * image pointer and add a ref.
			 */
			out[i] = in[i];
			g_object_ref(in[i]);
		}
		else {
			if (vips__bandup(domain, in[i], &out[i], max_bands))
				return -1;

			if (interpretation != VIPS_INTERPRETATION_ERROR)
				out[i]->Type = interpretation;
		}

	return 0;
}

int
vips__formatalike(VipsImage *in1, VipsImage *in2,
	VipsImage **out1, VipsImage **out2)
{
	VipsImage *in[2];
	VipsImage *out[2];

	in[0] = in1;
	in[1] = in2;

	if (vips__formatalike_vec(in, out, 2))
		return -1;

	*out1 = out[0];
	*out2 = out[1];

	return 0;
}

int
vips__sizealike(VipsImage *in1, VipsImage *in2,
	VipsImage **out1, VipsImage **out2)
{
	VipsImage *in[2];
	VipsImage *out[2];

	in[0] = in1;
	in[1] = in2;

	if (vips__sizealike_vec(in, out, 2))
		return -1;

	*out1 = out[0];
	*out2 = out[1];

	return 0;
}

int
vips__bandalike(const char *domain,
	VipsImage *in1, VipsImage *in2, VipsImage **out1, VipsImage **out2)
{
	VipsImage *in[2];
	VipsImage *out[2];

	in[0] = in1;
	in[1] = in2;

	if (vips__bandalike_vec(domain, in, out, 2, 1))
		return -1;

	*out1 = out[0];
	*out2 = out[1];

	return 0;
}

/* Our sequence value.
 */
typedef struct {
	VipsArithmetic *arithmetic;

	/* Set of input regions.
	 */
	VipsRegion **ir;

	/* For each input, an input pointer.
	 */
	VipsPel **p;

} VipsArithmeticSequence;

static int
vips_arithmetic_stop(void *vseq, void *a, void *b)
{
	VipsArithmeticSequence *seq = (VipsArithmeticSequence *) vseq;

	if (seq->ir) {
		int i;

		for (i = 0; seq->ir[i]; i++)
			VIPS_UNREF(seq->ir[i]);
		VIPS_FREE(seq->ir);
	}

	VIPS_FREE(seq->p);

	VIPS_FREE(seq);

	return 0;
}

static void *
vips_arithmetic_start(VipsImage *out, void *a, void *b)
{
	VipsImage **in = (VipsImage **) a;
	VipsArithmetic *arithmetic = (VipsArithmetic *) b;

	VipsArithmeticSequence *seq;
	int i, n;

	if (!(seq = VIPS_NEW(NULL, VipsArithmeticSequence)))
		return NULL;

	seq->arithmetic = arithmetic;
	seq->ir = NULL;
	seq->p = NULL;

	/* How many images?
	 */
	for (n = 0; in[n]; n++)
		;

	/* Allocate space for region array.
	 */
	if (!(seq->ir = VIPS_ARRAY(NULL, n + 1, VipsRegion *))) {
		vips_arithmetic_stop(seq, NULL, NULL);
		return NULL;
	}

	/* Create a set of regions.
	 */
	for (i = 0; i < n; i++)
		if (!(seq->ir[i] = vips_region_new(in[i]))) {
			vips_arithmetic_stop(seq, NULL, NULL);
			return NULL;
		}
	seq->ir[n] = NULL;

	/* Input pointers.
	 */
	if (!(seq->p = VIPS_ARRAY(NULL, n + 1, VipsPel *))) {
		vips_arithmetic_stop(seq, NULL, NULL);
		return NULL;
	}

	return seq;
}

static int
vips_arithmetic_gen(VipsRegion *out_region,
	void *vseq, void *a, void *b, gboolean *stop)
{
	VipsArithmeticSequence *seq = (VipsArithmeticSequence *) vseq;
	VipsRegion **ir = seq->ir;
	VipsArithmetic *arithmetic = VIPS_ARITHMETIC(b);
	VipsArithmeticClass *class = VIPS_ARITHMETIC_GET_CLASS(arithmetic);
	VipsRect *r = &out_region->valid;

	VipsPel *q;
	int i, y;

	/* Prepare all input regions and make buffer pointers.
	 */
	if (vips_reorder_prepare_many(out_region->im, ir, r))
		return -1;
	for (i = 0; ir[i]; i++)
		seq->p[i] = (VipsPel *)
			VIPS_REGION_ADDR(ir[i], r->left, r->top);
	seq->p[i] = NULL;
	q = (VipsPel *) VIPS_REGION_ADDR(out_region, r->left, r->top);

	VIPS_GATE_START("vips_arithmetic_gen: work");

	for (y = 0; y < r->height; y++) {
		class->process_line(arithmetic, q, seq->p, r->width);

		for (i = 0; ir[i]; i++)
			seq->p[i] += VIPS_REGION_LSKIP(ir[i]);
		q += VIPS_REGION_LSKIP(out_region);
	}

	VIPS_GATE_STOP("vips_arithmetic_gen: work");

	VIPS_COUNT_PIXELS(out_region, VIPS_OBJECT_CLASS(class)->nickname);

	return 0;
}

static int
vips_arithmetic_build(VipsObject *object)
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS(object);
	VipsArithmetic *arithmetic = VIPS_ARITHMETIC(object);
	VipsArithmeticClass *aclass = VIPS_ARITHMETIC_GET_CLASS(arithmetic);

	VipsImage **decode;
	VipsImage **format;
	VipsImage **band;
	VipsImage **size;
	int i;

#ifdef DEBUG
	printf("vips_arithmetic_build: ");
	vips_object_print_name(object);
	printf("\n");
#endif /*DEBUG*/

	if (VIPS_OBJECT_CLASS(vips_arithmetic_parent_class)->build(object))
		return -1;

	g_object_set(arithmetic, "out", vips_image_new(), NULL);

	decode = (VipsImage **)
		vips_object_local_array(object, arithmetic->n);
	format = (VipsImage **)
		vips_object_local_array(object, arithmetic->n);
	band = (VipsImage **)
		vips_object_local_array(object, arithmetic->n);
	size = (VipsImage **)
		vips_object_local_array(object, arithmetic->n);

	/* Decode RAD/LABQ etc.
	 */
	for (i = 0; i < arithmetic->n; i++)
		if (vips_image_decode(arithmetic->in[i], &decode[i]))
			return -1;

	/* Cast our input images up to a common format, bands and size.
	 */
	if (vips__formatalike_vec(decode, format, arithmetic->n) ||
		vips__bandalike_vec(class->nickname,
			format, band, arithmetic->n, arithmetic->base_bands) ||
		vips__sizealike_vec(band, size, arithmetic->n))
		return -1;

	/* Keep a copy of the processed images here for subclasses.
	 */
	arithmetic->ready = size;

	if (vips_image_pipeline_array(arithmetic->out,
			VIPS_DEMAND_STYLE_THINSTRIP, arithmetic->ready))
		return -1;

	arithmetic->out->Bands = arithmetic->ready[0]->Bands;
	if (arithmetic->format != VIPS_FORMAT_NOTSET)
		arithmetic->out->BandFmt = arithmetic->format;
	else
		arithmetic->out->BandFmt =
			aclass->format_table[arithmetic->ready[0]->BandFmt];

	if (vips_image_generate(arithmetic->out,
			vips_arithmetic_start,
			vips_arithmetic_gen,
			vips_arithmetic_stop,
			arithmetic->ready, arithmetic))
		return -1;

	return 0;
}

static void
vips_arithmetic_class_init(VipsArithmeticClass *class)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS(class);
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS(class);
	VipsOperationClass *operation_class = VIPS_OPERATION_CLASS(class);

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "arithmetic";
	vobject_class->description = _("arithmetic operations");
	vobject_class->build = vips_arithmetic_build;

	operation_class->flags = VIPS_OPERATION_SEQUENTIAL;

	VIPS_ARG_IMAGE(class, "out", 100,
		_("Output"),
		_("Output image"),
		VIPS_ARGUMENT_REQUIRED_OUTPUT,
		G_STRUCT_OFFSET(VipsArithmetic, out));
}

static void
vips_arithmetic_init(VipsArithmetic *arithmetic)
{
	arithmetic->base_bands = 1;
	arithmetic->format = VIPS_FORMAT_NOTSET;
}

void
vips_arithmetic_set_format_table(VipsArithmeticClass *class,
	const VipsBandFormat *format_table)
{
	g_assert(!class->format_table);

	class->format_table = format_table;
}

/* Called from iofuncs to init all operations in this dir. Use a plugin system
 * instead?
 */
void
vips_arithmetic_operation_init(void)
{
	extern GType vips_add_get_type(void);
	extern GType vips_sum_get_type(void);
	extern GType vips_subtract_get_type(void);
	extern GType vips_multiply_get_type(void);
	extern GType vips_divide_get_type(void);
	extern GType vips_invert_get_type(void);
	extern GType vips_avg_get_type(void);
	extern GType vips_min_get_type(void);
	extern GType vips_max_get_type(void);
	extern GType vips_deviate_get_type(void);
	extern GType vips_linear_get_type(void);
	extern GType vips_math_get_type(void);
	extern GType vips_abs_get_type(void);
	extern GType vips_sign_get_type(void);
	extern GType vips_stats_get_type(void);
	extern GType vips_hist_find_get_type(void);
	extern GType vips_hist_find_ndim_get_type(void);
	extern GType vips_hist_find_indexed_get_type(void);
	extern GType vips_hough_line_get_type(void);
	extern GType vips_hough_circle_get_type(void);
	extern GType vips_project_get_type(void);
	extern GType vips_profile_get_type(void);
	extern GType vips_measure_get_type(void);
	extern GType vips_getpoint_get_type(void);
	extern GType vips_round_get_type(void);
	extern GType vips_relational_get_type(void);
	extern GType vips_relational_const_get_type(void);
	extern GType vips_remainder_get_type(void);
	extern GType vips_remainder_const_get_type(void);
	extern GType vips_boolean_get_type(void);
	extern GType vips_boolean_const_get_type(void);
	extern GType vips_math2_get_type(void);
	extern GType vips_math2_const_get_type(void);
	extern GType vips_complex_get_type(void);
	extern GType vips_complex2_get_type(void);
	extern GType vips_complexget_get_type(void);
	extern GType vips_complexform_get_type(void);
	extern GType vips_find_trim_get_type(void);

	vips_add_get_type();
	vips_sum_get_type();
	vips_subtract_get_type();
	vips_multiply_get_type();
	vips_divide_get_type();
	vips_invert_get_type();
	vips_avg_get_type();
	vips_min_get_type();
	vips_max_get_type();
	vips_deviate_get_type();
	vips_linear_get_type();
	vips_math_get_type();
	vips_abs_get_type();
	vips_sign_get_type();
	vips_stats_get_type();
	vips_hist_find_get_type();
	vips_hist_find_ndim_get_type();
	vips_hist_find_indexed_get_type();
	vips_hough_line_get_type();
	vips_hough_circle_get_type();
	vips_project_get_type();
	vips_profile_get_type();
	vips_measure_get_type();
	vips_getpoint_get_type();
	vips_round_get_type();
	vips_relational_get_type();
	vips_relational_const_get_type();
	vips_remainder_get_type();
	vips_remainder_const_get_type();
	vips_boolean_get_type();
	vips_boolean_const_get_type();
	vips_math2_get_type();
	vips_math2_const_get_type();
	vips_complex_get_type();
	vips_complex2_get_type();
	vips_complexget_get_type();
	vips_complexform_get_type();
	vips_find_trim_get_type();
}
