/* base class for all colour operations
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
#include <math.h>

#include <vips/vips.h>
#include <vips/internal.h>

#include "pcolour.h"

/* Areas under curves for Dxx. 2 degree observer.
 */

/**
 * VIPS_D93_X0:
 *
 * Areas under curves for D93, 2 degree observer.
 */

/**
 * VIPS_D75_X0:
 *
 * Areas under curves for D75, 2 degree observer.
 */

/**
 * VIPS_D65_X0:
 *
 * Areas under curves for D65, 2 degree observer.
 */

/**
 * VIPS_D55_X0:
 *
 * Areas under curves for D55, 2 degree observer.
 */

/**
 * VIPS_D50_X0:
 *
 * Areas under curves for D50, 2 degree observer.
 */

/**
 * VIPS_A_X0:
 *
 * Areas under curves for illuminant A (2856K), 2 degree observer.
 */

/**
 * VIPS_B_X0:
 *
 * Areas under curves for illuminant B (4874K), 2 degree observer.
 */

/**
 * VIPS_C_X0:
 *
 * Areas under curves for illuminant C (6774K), 2 degree observer.
 */

/**
 * VIPS_E_X0:
 *
 * Areas under curves for equal energy illuminant E.
 */

/**
 * VIPS_D3250_X0:
 *
 * Areas under curves for black body at 3250K, 2 degree observer.
 */

G_DEFINE_ABSTRACT_TYPE(VipsColour, vips_colour, VIPS_TYPE_OPERATION);

/* Maximum number of input images -- why not?
 */
#define MAX_INPUT_IMAGES (64)

static int
vips_colour_gen(VipsRegion *out_region,
	void *seq, void *a, void *b, gboolean *stop)
{
	VipsRegion **ir = (VipsRegion **) seq;
	VipsColour *colour = VIPS_COLOUR(b);
	VipsColourClass *class = VIPS_COLOUR_GET_CLASS(colour);
	VipsRect *r = &out_region->valid;

	int i, y;
	VipsPel *p[MAX_INPUT_IMAGES], *q;

	/*
	printf("vips_colour_gen: %s, "
		   "left = %d, top = %d, width = %d, height = %d\n",
		VIPS_OBJECT_CLASS(class)->nickname,
		r->left, r->top, r->width, r->height);
	*/

	if (vips_reorder_prepare_many(out_region->im, ir, r))
		return -1;

	VIPS_GATE_START("vips_colour_gen: work");

	for (y = 0; y < r->height; y++) {
		for (i = 0; ir[i]; i++)
			p[i] = VIPS_REGION_ADDR(ir[i], r->left, r->top + y);
		p[i] = NULL;
		q = VIPS_REGION_ADDR(out_region, r->left, r->top + y);

		class->process_line(colour, q, p, r->width);
	}

	VIPS_GATE_STOP("vips_colour_gen: work");

	VIPS_COUNT_PIXELS(out_region, VIPS_OBJECT_GET_CLASS(colour)->nickname);

	return 0;
}

static int
vips_colour_build(VipsObject *object)
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS(object);
	VipsColour *colour = VIPS_COLOUR(object);

	VipsImage **in;
	VipsImage **extra_bands;
	VipsImage *out;

#ifdef DEBUG
	printf("vips_colour_build: ");
	vips_object_print_name(object);
	printf("\n");
#endif /*DEBUG*/

	if (VIPS_OBJECT_CLASS(vips_colour_parent_class)->build(object))
		return -1;

	if (colour->n > MAX_INPUT_IMAGES) {
		vips_error(class->nickname, "%s", _("too many input images"));
		return -1;
	}
	for (int i = 0; i < colour->n; i++)
		if (vips_image_pio_input(colour->in[i]))
			return -1;

	/* colour->in[] must be NULL-terminated, we can use it as an arg to
	 * vips_start_many().
	 */
	g_assert(!colour->in[colour->n]);

	in = colour->in;
	extra_bands = (VipsImage **)
		vips_object_local_array(object, colour->n);

	/* If there are more than @input_bands bands, we detach and reattach
	 * after processing.
	 */
	if (colour->input_bands > 0) {
		VipsImage **new_in = (VipsImage **)
			vips_object_local_array(object, colour->n);

		for (int i = 0; i < colour->n; i++) {
			if (vips_check_bands_atleast(class->nickname,
					in[i], colour->input_bands))
				return -1;

			if (in[i]->Bands > colour->input_bands) {
				if (vips_extract_band(in[i], &new_in[i], 0,
						"n", colour->input_bands,
						NULL))
					return -1;
			}
			else {
				new_in[i] = in[i];
				g_object_ref(new_in[i]);
			}

			if (in[i]->Bands > colour->input_bands)
				if (vips_extract_band(in[i], &extra_bands[i],
						colour->input_bands,
						"n", in[i]->Bands - colour->input_bands,
						NULL))
					return -1;
		}

		in = new_in;
	}

	out = vips_image_new();
	if (vips_image_pipeline_array(out,
			VIPS_DEMAND_STYLE_THINSTRIP, in)) {
		g_object_unref(out);
		return -1;
	}
	out->Coding = colour->coding;
	out->Type = colour->interpretation;
	out->BandFmt = colour->format;
	out->Bands = colour->bands;

	if (colour->profile_filename &&
		vips__profile_set(out, colour->profile_filename))
		return -1;

	if (vips_image_generate(out,
			vips_start_many, vips_colour_gen, vips_stop_many,
			in, colour)) {
		VIPS_UNREF(out);
		return -1;
	}

	/* Reattach higher bands, if necessary. If we have more than one input
	 * image, just use the first extra bands.
	 */
	for (int i = 0; i < colour->n; i++)
		if (extra_bands[i]) {
			VipsImage **t = (VipsImage **) vips_object_local_array(object, 3);

			double max_alpha_before =
				vips_interpretation_max_alpha(extra_bands[i]->Type);
			double max_alpha_after =
				vips_interpretation_max_alpha(out->Type);

			VipsImage *alpha;

			alpha = extra_bands[i];

			/* Rescale, if the alpha scale has changed.
			 */
			if (max_alpha_before != max_alpha_after) {
				if (vips_linear1(alpha, &t[0],
					max_alpha_after / max_alpha_before, 0.0, NULL)) {
					VIPS_UNREF(out);
					return -1;
				}
				alpha = t[0];
			}

			if (vips_cast(alpha, &t[1], out->BandFmt, NULL)) {
				VIPS_UNREF(out);
				return -1;
			}
			alpha = t[1];

			if (vips_bandjoin2(out, alpha, &t[2], NULL)) {
				VIPS_UNREF(out);
				return -1;
			}
			g_object_unref(out);
			out = t[2];
			t[2] = NULL;

			break;
		}

	g_object_set(colour, "out", out, NULL);

	return 0;
}

static void
vips_colour_class_init(VipsColourClass *class)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS(class);
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS(class);
	VipsOperationClass *operation_class = VIPS_OPERATION_CLASS(class);

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "colour";
	vobject_class->description = _("color operations");
	vobject_class->build = vips_colour_build;

	operation_class->flags = VIPS_OPERATION_SEQUENTIAL;

	VIPS_ARG_IMAGE(class, "out", 100,
		_("Output"),
		_("Output image"),
		VIPS_ARGUMENT_REQUIRED_OUTPUT,
		G_STRUCT_OFFSET(VipsColour, out));
}

static void
vips_colour_init(VipsColour *colour)
{
	colour->coding = VIPS_CODING_NONE;
	colour->interpretation = VIPS_INTERPRETATION_sRGB;
	colour->format = VIPS_FORMAT_UCHAR;
	colour->bands = 3;
	colour->input_bands = -1;
}

G_DEFINE_ABSTRACT_TYPE(VipsColourTransform, vips_colour_transform,
	VIPS_TYPE_COLOUR);

static int
vips_colour_transform_build(VipsObject *object)
{
	VipsColour *colour = VIPS_COLOUR(object);
	VipsColourTransform *transform = VIPS_COLOUR_TRANSFORM(object);
	VipsImage **t = (VipsImage **) vips_object_local_array(object, 1);

	/* We only process float.
	 */
	if (transform->in &&
		transform->in->BandFmt != VIPS_FORMAT_FLOAT) {
		if (vips_cast_float(transform->in, &t[0], NULL))
			return -1;
	}
	else {
		t[0] = transform->in;
		g_object_ref(t[0]);
	}

	/* We always do 3 bands -> 3 bands.
	 */
	colour->input_bands = 3;

	colour->n = 1;
	colour->in = t;

	if (VIPS_OBJECT_CLASS(vips_colour_transform_parent_class)->build(object))
		return -1;

	return 0;
}

static void
vips_colour_transform_class_init(VipsColourTransformClass *class)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS(class);
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS(class);

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "space";
	vobject_class->description = _("color space transformations");
	vobject_class->build = vips_colour_transform_build;

	VIPS_ARG_IMAGE(class, "in", 1,
		_("Input"),
		_("Input image"),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET(VipsColourTransform, in));
}

static void
vips_colour_transform_init(VipsColourTransform *space)
{
	VipsColour *colour = (VipsColour *) space;

	/* What we write. interpretation should be overwritten in subclass
	 * builds.
	 */
	colour->coding = VIPS_CODING_NONE;
	colour->interpretation = VIPS_INTERPRETATION_LAB;
	colour->format = VIPS_FORMAT_FLOAT;
	colour->bands = 3;
}

G_DEFINE_ABSTRACT_TYPE(VipsColourCode, vips_colour_code, VIPS_TYPE_COLOUR);

static int
vips_colour_code_build(VipsObject *object)
{
	VipsColour *colour = VIPS_COLOUR(object);
	VipsColourCode *code = VIPS_COLOUR_CODE(object);
	VipsColourCodeClass *class = VIPS_COLOUR_CODE_GET_CLASS(object);
	VipsImage **t = (VipsImage **) vips_object_local_array(object, 6);

	VipsImage *in;

	in = code->in;

	/* We want labq, rad etc. all decoded (unlike colour_build).
	 */
	if (in &&
		code->input_coding == VIPS_CODING_NONE &&
		in->Coding != code->input_coding) {
		if (vips_image_decode(in, &t[0]))
			return -1;
		in = t[0];
	}

	if (in &&
		vips_check_coding(VIPS_OBJECT_CLASS(class)->nickname,
			in, code->input_coding))
		return -1;

	if (in &&
		code->input_coding == VIPS_CODING_NONE &&
		code->input_format != VIPS_FORMAT_NOTSET &&
		in->BandFmt != code->input_format) {
		if (vips_cast(in, &t[3], code->input_format, NULL))
			return -1;
		in = t[3];
	}

	if (in &&
		code->input_coding == VIPS_CODING_NONE &&
		code->input_interpretation != VIPS_INTERPRETATION_ERROR &&
		in->Type != code->input_interpretation) {
		if (vips_colourspace(in, &t[4],
				code->input_interpretation, NULL))
			return -1;
		in = t[4];
	}

	colour->n = 1;
	colour->in = VIPS_ARRAY(object, 2, VipsImage *);
	colour->in[0] = in;
	colour->in[1] = NULL;

	if (VIPS_OBJECT_CLASS(vips_colour_code_parent_class)->build(object))
		return -1;

	return 0;
}

static void
vips_colour_code_class_init(VipsColourCodeClass *class)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS(class);
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS(class);

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "code";
	vobject_class->description = _("change color coding");
	vobject_class->build = vips_colour_code_build;

	VIPS_ARG_IMAGE(class, "in", 1,
		_("Input"),
		_("Input image"),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET(VipsColourCode, in));
}

static void
vips_colour_code_init(VipsColourCode *code)
{
	code->input_coding = VIPS_CODING_NONE;
	code->input_interpretation = VIPS_INTERPRETATION_ERROR;
	code->input_format = VIPS_FORMAT_NOTSET;
}

G_DEFINE_ABSTRACT_TYPE(VipsColourDifference, vips_colour_difference,
	VIPS_TYPE_COLOUR);

static int
vips_colour_difference_build(VipsObject *object)
{
	VipsColour *colour = VIPS_COLOUR(object);
	VipsColourDifference *difference = VIPS_COLOUR_DIFFERENCE(object);

	VipsImage **t;
	VipsImage *left;
	VipsImage *right;

	t = (VipsImage **) vips_object_local_array(object, 12);

	left = difference->left;
	right = difference->right;

	if (left) {
		if (vips_image_decode(left, &t[0]))
			return -1;
		left = t[0];
	}

	if (right) {
		if (vips_image_decode(right, &t[1]))
			return -1;
		right = t[1];
	}

	/* Detach and reattach any extra bands.
	 */
	colour->input_bands = 3;

	if (left &&
		left->Type != difference->interpretation) {
		if (vips_colourspace(left, &t[6],
				difference->interpretation, NULL))
			return -1;
		left = t[6];
	}

	if (right &&
		right->Type != difference->interpretation) {
		if (vips_colourspace(right, &t[7],
				difference->interpretation, NULL))
			return -1;
		right = t[7];
	}

	/* We only process float.
	 */
	if (left &&
		left->BandFmt != VIPS_FORMAT_FLOAT) {
		if (vips_cast_float(left, &t[8], NULL))
			return -1;
		left = t[8];
	}

	if (right &&
		right->BandFmt != VIPS_FORMAT_FLOAT) {
		if (vips_cast_float(right, &t[9], NULL))
			return -1;
		right = t[9];
	}

	if (vips__sizealike(left, right, &t[10], &t[11]))
		return -1;
	left = t[10];
	right = t[11];

	colour->n = 2;
	colour->in = VIPS_ARRAY(object, 3, VipsImage *);
	colour->in[0] = left;
	colour->in[1] = right;
	colour->in[2] = NULL;

	if (VIPS_OBJECT_CLASS(vips_colour_difference_parent_class)->build(object))
		return -1;

	return 0;
}

static void
vips_colour_difference_class_init(VipsColourDifferenceClass *class)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS(class);
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS(class);

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "difference";
	vobject_class->description = _("calculate color difference");
	vobject_class->build = vips_colour_difference_build;

	VIPS_ARG_IMAGE(class, "left", 1,
		_("Left"),
		_("Left-hand input image"),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET(VipsColourDifference, left));

	VIPS_ARG_IMAGE(class, "right", 2,
		_("Right"),
		_("Right-hand input image"),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET(VipsColourDifference, right));
}

static void
vips_colour_difference_init(VipsColourDifference *difference)
{
	VipsColour *colour = VIPS_COLOUR(difference);

	colour->coding = VIPS_CODING_NONE;
	colour->interpretation = VIPS_INTERPRETATION_B_W;
	colour->format = VIPS_FORMAT_FLOAT;
	colour->bands = 1;
}

/* Called from iofuncs to init all operations in this dir. Use a plugin system
 * instead?
 */
void
vips_colour_operation_init(void)
{
	extern GType vips_colourspace_get_type(void);
	extern GType vips_Lab2XYZ_get_type(void);
	extern GType vips_XYZ2Lab_get_type(void);
	extern GType vips_Lab2LCh_get_type(void);
	extern GType vips_LCh2Lab_get_type(void);
	extern GType vips_LCh2CMC_get_type(void);
	extern GType vips_CMC2LCh_get_type(void);
	extern GType vips_Yxy2XYZ_get_type(void);
	extern GType vips_XYZ2Yxy_get_type(void);
	extern GType vips_LabQ2Lab_get_type(void);
	extern GType vips_Lab2LabQ_get_type(void);
	extern GType vips_LabQ2LabS_get_type(void);
	extern GType vips_LabS2LabQ_get_type(void);
	extern GType vips_LabS2Lab_get_type(void);
	extern GType vips_Lab2LabS_get_type(void);
	extern GType vips_rad2float_get_type(void);
	extern GType vips_float2rad_get_type(void);
	extern GType vips_LabQ2sRGB_get_type(void);
	extern GType vips_XYZ2sRGB_get_type(void);
	extern GType vips_sRGB2scRGB_get_type(void);
	extern GType vips_sRGB2HSV_get_type(void);
	extern GType vips_HSV2sRGB_get_type(void);
	extern GType vips_scRGB2XYZ_get_type(void);
	extern GType vips_scRGB2BW_get_type(void);
	extern GType vips_XYZ2scRGB_get_type(void);
	extern GType vips_scRGB2sRGB_get_type(void);
	extern GType vips_CMYK2XYZ_get_type(void);
	extern GType vips_XYZ2CMYK_get_type(void);
	extern GType vips_profile_load_get_type(void);
#ifdef HAVE_LCMS2
	extern GType vips_icc_import_get_type(void);
	extern GType vips_icc_export_get_type(void);
	extern GType vips_icc_transform_get_type(void);
#endif
	extern GType vips_dE76_get_type(void);
	extern GType vips_dE00_get_type(void);
	extern GType vips_dECMC_get_type(void);

	vips_colourspace_get_type();
	vips_Lab2XYZ_get_type();
	vips_XYZ2Lab_get_type();
	vips_Lab2LCh_get_type();
	vips_LCh2Lab_get_type();
	vips_LCh2CMC_get_type();
	vips_CMC2LCh_get_type();
	vips_XYZ2Yxy_get_type();
	vips_Yxy2XYZ_get_type();
	vips_LabQ2Lab_get_type();
	vips_Lab2LabQ_get_type();
	vips_LabQ2LabS_get_type();
	vips_LabS2LabQ_get_type();
	vips_LabS2Lab_get_type();
	vips_Lab2LabS_get_type();
	vips_rad2float_get_type();
	vips_float2rad_get_type();
	vips_LabQ2sRGB_get_type();
	vips_sRGB2scRGB_get_type();
	vips_scRGB2XYZ_get_type();
	vips_scRGB2BW_get_type();
	vips_sRGB2HSV_get_type();
	vips_HSV2sRGB_get_type();
	vips_XYZ2scRGB_get_type();
	vips_scRGB2sRGB_get_type();
	vips_CMYK2XYZ_get_type();
	vips_XYZ2CMYK_get_type();
	vips_profile_load_get_type();
#ifdef HAVE_LCMS2
	vips_icc_import_get_type();
	vips_icc_export_get_type();
	vips_icc_transform_get_type();
#endif
	vips_dE76_get_type();
	vips_dE00_get_type();
	vips_dECMC_get_type();
}
