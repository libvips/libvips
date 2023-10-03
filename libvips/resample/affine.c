/* affine transform with a supplied interpolator.
 *
 * Copyright N. Dessipris
 * Written on: 01/11/1991
 * Modified on: 12/3/92 JC
 *	- rounding error in interpolation routine fixed
 *	- test for scale=1, angle=0 case fixed
 *	- clipping of output removed: redundant
 *	- various little tidies
 *	- problems remain with scale>20, size<10
 *
 * Re-written on: 20/08/92, J.Ph Laurent
 *
 * 21/02/93, JC
 *	- speed-ups
 * 	- simplifications
 *	- im_similarity now calculates a window and calls this routine
 * 6/7/93 JC
 *	- rewritten for partials
 *	- ANSIfied
 *	- now rotates any non-complex type
 * 3/6/94 JC
 *	- C revised in bug search
 * 9/6/94 JC
 *	- im_prepare() was preparing too small an area! oops
 * 22/5/95 JC
 *	- added code to detect all-black output area case - helps lazy ip
 * 3/7/95 JC
 *	- IM_CODING_LABQ handling moved to here
 * 31/7/97 JC
 * 	- dx/dy sign reversed to be less confusing ... now follows comment at
 * 	  top ... ax - by + dx etc.
 *	- tiny speed up, replaced the *++ on interpolation with [z]
 *	- im_similarity() moved in here
 *	- args swapped: was whxy, now xywh
 *	- didn't agree with dispatch fns before :(
 * 3/3/98 JC
 *	- im_demand_hint() added
 * 20/12/99 JC
 *	- im_affine() made from im_similarity_area()
 *	- transform stuff cleaned up a bit
 * 14/4/01 JC
 *	- oops, invert_point() had a rounding problem
 * 23/2/02 JC
 *	- pre-calculate interpolation matrices
 *	- integer interpolation for int8/16 types, double for
 *	  int32/float/double
 *	- faster transformation
 * 15/8/02 JC
 *	- records Xoffset/Yoffset
 * 14/4/04
 *	- rounding, clipping and transforming revised, now pixel-perfect (or
 *	  better than gimp, anyway)
 * 22/6/05
 *	- all revised again, simpler and more reliable now
 * 30/3/06
 * 	- gah, still an occasional clipping problem
 * 12/7/06
 * 	- still more tweaking, gah again
 * 7/10/06
 * 	- set THINSTRIP for no-rotate affines
 * 20/10/08
 * 	- version with interpolate parameter, from im_affine()
 * 30/10/08
 * 	- allow complex image types
 * 4/11/08
 * 	- take an interpolator as a param
 * 	- replace im_affine with this, provide an im_affine() compat wrapper
 * 	- break transform stuff out to transform.c
 * 	- revise clipping / transform stuff, again
 * 	- now do corner rather than centre: this way the identity transform
 * 	  returns the input exactly
 * 12/8/10
 * 	- revise window_size / window_offset stuff again, see also
 * 	  interpolate.c
 * 2/2/11
 * 	- gtk-doc
 * 14/12/12
 * 	- redone as a class
 * 	- added input space translation
 * 22/1/14
 * 	- auto RAD decode
 * 1/8/14
 * 	- revise transform ... again
 * 	- see new stress test in nip2/test/extras
 * 7/11/17
 * 	- add "extend" param
 * 	- add "background" parameter
 * 	- better clipping means we have no jaggies on edges
 * 	- premultiply alpha
 * 18/5/20
 * 	- add "premultiplied" flag
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
#define DEBUG_VERBOSE
#define DEBUG
#define VIPS_DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <glib/gi18n-lib.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <limits.h>

#include <vips/vips.h>
#include <vips/debug.h>
#include <vips/internal.h>
#include <vips/transform.h>

#include "presample.h"

typedef struct _VipsAffine {
	VipsResample parent_instance;

	VipsArea *matrix;
	VipsInterpolate *interpolate;
	VipsArea *oarea;
	double odx;
	double ody;
	double idx;
	double idy;

	VipsTransformation trn;

	/* How to generate extra edge pixels.
	 */
	VipsExtend extend;

	/* Background colour.
	 */
	VipsArrayDouble *background;

	/* The [double] converted to the input image format.
	 */
	VipsPel *ink;

	/* True if the input is already premultiplied (and we don't need to).
	 */
	gboolean premultiplied;

} VipsAffine;

typedef VipsResampleClass VipsAffineClass;

G_DEFINE_TYPE(VipsAffine, vips_affine, VIPS_TYPE_RESAMPLE);

/* We have five (!!) coordinate systems. Working forward through them, these
 * are:
 *
 * 1. The original input image. iarea is defined on this image.
 *
 * 2. This is embedded in a larger image to provide borders for the
 * interpolator. window_offset and window_size control the embedding.
 * These are the coordinates we pass to VIPS_REGION_ADDR()/
 * vips_region_prepare() and the interpolator.
 *
 * The borders are sized by the interpolator's window_size property and offset
 * by the interpolator's window_offset property. For example,
 * for bilinear (window_size 2, window_offset 0) we add a single line
 * of extra pixels along the bottom and right (window_size - 1). For
 * bicubic (window_size 4, window_offset 1) we add a single line top and left
 * (window_offset), and two lines bottom and right (window_size - 1 -
 * window_offset).
 *
 * 3. We need point (0, 0) in (1) to be at (0, 0) for the transformation. So
 * shift everything up and left to make the displaced input image. This is the
 * space that the transformation maps from, and can have negative pixels
 * (up and left of the image, for interpolation). iarea works here too.
 *
 * 4. Output transform space. This is the where the transform maps to. Pixels
 * can be negative, since a rotated image can go up and left of the origin.
 *
 * 5. Output image space. This is the wh of the xywh passed to vips_affine()
 * below. These are the coordinates we pass to VIPS_REGION_ADDR() for the
 * output image, and that affinei_gen() is asked for.
 */

static int
vips_affine_gen(VipsRegion *out_region,
	void *seq, void *a, void *b, gboolean *stop)
{
	VipsRegion *ir = (VipsRegion *) seq;
	const VipsAffine *affine = (VipsAffine *) b;
	const VipsImage *in = (VipsImage *) a;
	const int window_size =
		vips_interpolate_get_window_size(affine->interpolate);
	const int window_offset =
		vips_interpolate_get_window_offset(affine->interpolate);
	const VipsInterpolateMethod interpolate =
		vips_interpolate_get_method(affine->interpolate);

	/* Area we generate in the output image.
	 */
	const VipsRect *r = &out_region->valid;
	const int le = r->left;
	const int ri = VIPS_RECT_RIGHT(r);
	const int to = r->top;
	const int bo = VIPS_RECT_BOTTOM(r);

	const VipsRect *iarea = &affine->trn.iarea;
	const VipsRect *oarea = &affine->trn.oarea;

	int ps = VIPS_IMAGE_SIZEOF_PEL(in);
	int x, y, z;

	VipsRect image, want, need, clipped;

#ifdef DEBUG_VERBOSE
	printf("vips_affine_gen: "
		   "generating left=%d, top=%d, width=%d, height=%d\n",
		r->left,
		r->top,
		r->width,
		r->height);
#endif /*DEBUG_VERBOSE*/

	/* We are generating this chunk of the transformed image. This takes
	 * us to space 4.
	 */
	want = *r;
	want.left += oarea->left;
	want.top += oarea->top;

	/* Find the area of the input image we need. This takes us to space 3.
	 */
	vips__transform_invert_rect(&affine->trn, &want, &need);

	/* That does round-to-nearest, because it has to stop rounding errors
	 * growing images unexpectedly. We need round-down, so we must
	 * add half a pixel along the left and top. But we are int :( so add 1
	 * pixel.
	 *
	 * Add an extra line along the right and bottom as well, for rounding.
	 */
	vips_rect_marginadjust(&need, 1);

	/* We need to fetch a larger area for the interpolator.
	 */
	need.left -= window_offset;
	need.top -= window_offset;
	need.width += window_size - 1;
	need.height += window_size - 1;

	/* Now go to space 2, the expanded input image. This is the one we
	 * read pixels from.
	 */
	need.left += window_offset;
	need.top += window_offset;

	/* Clip against the size of (2).
	 */
	image.left = 0;
	image.top = 0;
	image.width = in->Xsize;
	image.height = in->Ysize;
	vips_rect_intersectrect(&need, &image, &clipped);

#ifdef DEBUG_VERBOSE
	printf("vips_affine_gen: preparing left=%d, top=%d, width=%d, height=%d\n",
		clipped.left,
		clipped.top,
		clipped.width,
		clipped.height);
#endif /*DEBUG_VERBOSE*/

	if (vips_rect_isempty(&clipped)) {
		vips_region_paint_pel(out_region, r, affine->ink);
		return 0;
	}
	if (vips_region_prepare(ir, &clipped))
		return -1;

	VIPS_GATE_START("vips_affine_gen: work");

	/* Resample! x/y loop over pixels in the output image (5).
	 */
	for (y = to; y < bo; y++) {
		/* Input clipping rectangle. We offset this so we can clip in
		 * space 2.
		 */
		const int ile = iarea->left + window_offset;
		const int ito = iarea->top + window_offset;
		const int iri = ile + iarea->width;
		const int ibo = ito + iarea->height;

		/* Derivative of matrix.
		 */
		const double ddx = affine->trn.ia;
		const double ddy = affine->trn.ic;

		/* Continuous cods in transformed space.
		 */
		const double ox = le + oarea->left - affine->trn.odx;
		const double oy = y + oarea->top - affine->trn.ody;

		/* Continuous cods in input space.
		 */
		double ix, iy;

		VipsPel *q;

		/* To (3).
		 */
		ix = affine->trn.ia * ox + affine->trn.ib * oy;
		iy = affine->trn.ic * ox + affine->trn.id * oy;

		/* And the input offset in (3).
		 */
		ix -= affine->trn.idx;
		iy -= affine->trn.idy;

		/* Finally to 2.
		 */
		ix += window_offset;
		iy += window_offset;

		q = VIPS_REGION_ADDR(out_region, le, y);

		for (x = le; x < ri; x++) {
			int fx, fy;

			fx = VIPS_FLOOR(ix);
			fy = VIPS_FLOOR(iy);

			/* Clip against iarea.
			 */
			if (fx >= ile &&
				fx <= iri &&
				fy >= ito &&
				fy <= ibo) {
				/* Verify that we can read the whole stencil.
				 * With DEBUG on this will range-check.
				 */
				g_assert(VIPS_REGION_ADDR(ir,
					(int) ix - window_offset,
					(int) iy - window_offset));
				g_assert(VIPS_REGION_ADDR(ir,
					(int) ix - window_offset +
						window_size - 1,
					(int) iy - window_offset +
						window_size - 1));

				interpolate(affine->interpolate, q, ir, ix, iy);
			}
			else {
				/* Out of range: paint the background.
				 */
				for (z = 0; z < ps; z++)
					q[z] = affine->ink[z];
			}

			ix += ddx;
			iy += ddy;
			q += ps;
		}
	}

	VIPS_GATE_STOP("vips_affine_gen: work");

	VIPS_COUNT_PIXELS(out_region, "vips_affine_gen");

	return 0;
}

static int
vips_affine_build(VipsObject *object)
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS(object);
	VipsResample *resample = VIPS_RESAMPLE(object);
	VipsAffine *affine = (VipsAffine *) object;
	VipsImage **t = (VipsImage **) vips_object_local_array(object, 7);

	VipsImage *in;
	VipsDemandStyle hint;
	int window_size;
	int window_offset;
	double edge;

	/* TRUE if we've premultiplied and need to unpremultiply.
	 */
	gboolean have_premultiplied;
	VipsBandFormat unpremultiplied_format;

	if (VIPS_OBJECT_CLASS(vips_affine_parent_class)->build(object))
		return -1;

	if (vips_check_coding_known(class->nickname, resample->in))
		return -1;
	if (vips_check_vector_length(class->nickname,
			affine->matrix->n, 4))
		return -1;
	if (vips_object_argument_isset(object, "oarea") &&
		vips_check_vector_length(class->nickname,
			affine->oarea->n, 4))
		return -1;

	/* Can be set explicitly to NULL to mean default setting.
	 */
	if (!affine->interpolate)
		affine->interpolate = vips_interpolate_new("bilinear");

	in = resample->in;

	/* Set up transform.
	 */

	window_size = vips_interpolate_get_window_size(affine->interpolate);
	window_offset =
		vips_interpolate_get_window_offset(affine->interpolate);

	affine->trn.iarea.left = 0;
	affine->trn.iarea.top = 0;
	affine->trn.iarea.width = in->Xsize;
	affine->trn.iarea.height = in->Ysize;
	affine->trn.a = ((double *) affine->matrix->data)[0];
	affine->trn.b = ((double *) affine->matrix->data)[1];
	affine->trn.c = ((double *) affine->matrix->data)[2];
	affine->trn.d = ((double *) affine->matrix->data)[3];
	affine->trn.idx = 0;
	affine->trn.idy = 0;
	affine->trn.odx = 0;
	affine->trn.ody = 0;

	if (vips__transform_calc_inverse(&affine->trn))
		return -1;

	/* Set the default value for oarea.
	 */
	vips__transform_set_area(&affine->trn);

	if (vips_object_argument_isset(object, "oarea")) {
		affine->trn.oarea.left = ((int *) affine->oarea->data)[0];
		affine->trn.oarea.top = ((int *) affine->oarea->data)[1];
		affine->trn.oarea.width = ((int *) affine->oarea->data)[2];
		affine->trn.oarea.height = ((int *) affine->oarea->data)[3];
	}

	if (vips_object_argument_isset(object, "odx"))
		affine->trn.odx = affine->odx;
	if (vips_object_argument_isset(object, "ody"))
		affine->trn.ody = affine->ody;

	if (vips_object_argument_isset(object, "idx"))
		affine->trn.idx = affine->idx;
	if (vips_object_argument_isset(object, "idy"))
		affine->trn.idy = affine->idy;

#ifdef DEBUG
	printf("vips_affine_build: copy on identity transform disabled\n");
#else  /*!DEBUG*/
	if (vips__transform_isidentity(&affine->trn) &&
		affine->trn.oarea.left == 0 &&
		affine->trn.oarea.top == 0 &&
		affine->trn.oarea.width == in->Xsize &&
		affine->trn.oarea.height == in->Ysize)
		return vips_image_write(in, resample->out);
#endif /*!DEBUG*/

	/* Check for coordinate overflow ... we want to be able to hold the
	 * output space inside INT_MAX / TRANSFORM_SCALE.
	 */
	edge = (int) (INT_MAX / VIPS_TRANSFORM_SCALE);
	if (affine->trn.oarea.left < -edge ||
		affine->trn.oarea.top < -edge ||
		VIPS_RECT_RIGHT(&affine->trn.oarea) > edge ||
		VIPS_RECT_BOTTOM(&affine->trn.oarea) > edge) {
		vips_error(class->nickname,
			"%s", _("output coordinates out of range"));
		return -1;
	}

	if (vips_image_decode(in, &t[0]))
		return -1;
	in = t[0];

	/* Add new pixels around the input so we can interpolate at the edges.
	 *
	 * We add the interpolate stencil, plus one extra pixel on all the
	 * edges. This means when we clip in generate (above) we can be sure
	 * we clip outside the real pixels and don't get jaggies on edges.
	 */
	if (vips_embed(in, &t[2],
			window_offset + 1, window_offset + 1,
			in->Xsize + window_size - 1 + 2,
			in->Ysize + window_size - 1 + 2,
			"extend", affine->extend,
			"background", affine->background,
			NULL))
		return -1;
	in = t[2];

	/* We've added a one-pixel border to the input: displace the transform
	 * to compensate.
	 */
	affine->trn.idx -= 1;
	affine->trn.idy -= 1;

	/* If there's an alpha and we've not premultiplied, we have to
	 * premultiply before resampling. See
	 * https://github.com/libvips/libvips/issues/291
	 */
	have_premultiplied = FALSE;
	if (vips_image_hasalpha(in) &&
		!affine->premultiplied) {
		if (vips_premultiply(in, &t[3], NULL))
			return -1;
		have_premultiplied = TRUE;

		/* vips_premultiply() makes a float image. When we
		 * vips_unpremultiply() below, we need to cast back to the
		 * pre-premultiply format.
		 */
		unpremultiplied_format = in->BandFmt;
		in = t[3];
	}

	/* Convert the background to the image's format.
	 */
	if (!(affine->ink = vips__vector_to_ink(class->nickname,
			  in,
			  VIPS_AREA(affine->background)->data, NULL,
			  VIPS_AREA(affine->background)->n)))
		return -1;

	/* Normally SMALLTILE ... except if this is strictly a size
	 * up/down affine.
	 */
	if (affine->trn.b == 0.0 &&
		affine->trn.c == 0.0)
		hint = VIPS_DEMAND_STYLE_FATSTRIP;
	else
		hint = VIPS_DEMAND_STYLE_SMALLTILE;

	t[4] = vips_image_new();
	if (vips_image_pipelinev(t[4], hint, in, NULL))
		return -1;

	t[4]->Xsize = affine->trn.oarea.width;
	t[4]->Ysize = affine->trn.oarea.height;

#ifdef DEBUG
	printf("vips_affine_build: transform: ");
	vips__transform_print(&affine->trn);
	printf(" window_offset = %d, window_size = %d\n",
		window_offset, window_size);
	printf(" input image width = %d, height = %d\n",
		in->Xsize, in->Ysize);
	printf(" output image width = %d, height = %d\n",
		t[4]->Xsize, t[4]->Ysize);
#endif /*DEBUG*/

	/* Generate!
	 */
	if (vips_image_generate(t[4],
			vips_start_one, vips_affine_gen, vips_stop_one,
			in, affine))
		return -1;

	/* Finally: can now set Xoffset/Yoffset.
	 */
	t[4]->Xoffset = affine->trn.odx - affine->trn.oarea.left;
	t[4]->Yoffset = affine->trn.ody - affine->trn.oarea.top;

	in = t[4];

	if (have_premultiplied) {
		if (vips_unpremultiply(in, &t[5], NULL) ||
			vips_cast(t[5], &t[6], unpremultiplied_format, NULL))
			return -1;
		in = t[6];
	}

	if (vips_image_write(in, resample->out))
		return -1;

	return 0;
}

static void
vips_affine_class_init(VipsAffineClass *class)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS(class);
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS(class);

	VIPS_DEBUG_MSG("vips_affine_class_init\n");

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "affine";
	vobject_class->description = _("affine transform of an image");
	vobject_class->build = vips_affine_build;

	VIPS_ARG_BOXED(class, "matrix", 110,
		_("Matrix"),
		_("Transformation matrix"),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET(VipsAffine, matrix),
		VIPS_TYPE_ARRAY_DOUBLE);

	VIPS_ARG_INTERPOLATE(class, "interpolate", 2,
		_("Interpolate"),
		_("Interpolate pixels with this"),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET(VipsAffine, interpolate));

	VIPS_ARG_BOXED(class, "oarea", 111,
		_("Output rect"),
		_("Area of output to generate"),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET(VipsAffine, oarea),
		VIPS_TYPE_ARRAY_INT);

	VIPS_ARG_DOUBLE(class, "odx", 112,
		_("Output offset"),
		_("Horizontal output displacement"),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET(VipsAffine, odx),
		-10000000, 10000000, 0);

	VIPS_ARG_DOUBLE(class, "ody", 113,
		_("Output offset"),
		_("Vertical output displacement"),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET(VipsAffine, ody),
		-10000000, 10000000, 0);

	VIPS_ARG_DOUBLE(class, "idx", 114,
		_("Input offset"),
		_("Horizontal input displacement"),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET(VipsAffine, idx),
		-10000000, 10000000, 0);

	VIPS_ARG_DOUBLE(class, "idy", 115,
		_("Input offset"),
		_("Vertical input displacement"),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET(VipsAffine, idy),
		-10000000, 10000000, 0);

	VIPS_ARG_ENUM(class, "extend", 117,
		_("Extend"),
		_("How to generate the extra pixels"),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET(VipsAffine, extend),
		VIPS_TYPE_EXTEND, VIPS_EXTEND_BACKGROUND);

	VIPS_ARG_BOXED(class, "background", 116,
		_("Background"),
		_("Background value"),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET(VipsAffine, background),
		VIPS_TYPE_ARRAY_DOUBLE);

	VIPS_ARG_BOOL(class, "premultiplied", 117,
		_("Premultiplied"),
		_("Images have premultiplied alpha"),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET(VipsAffine, premultiplied),
		FALSE);
}

static void
vips_affine_init(VipsAffine *affine)
{
	affine->extend = VIPS_EXTEND_BACKGROUND;
	affine->background = vips_array_double_newv(1, 0.0);
}

/**
 * vips_affine: (method)
 * @in: input image
 * @out: (out): output image
 * @a: transformation matrix coefficient
 * @b: transformation matrix coefficient
 * @c: transformation matrix coefficient
 * @d: transformation matrix coefficient
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @interpolate: #VipsInterpolate, interpolate pixels with this
 * * @oarea: #VipsArrayInt, output rectangle
 * * @idx: %gdouble, input horizontal offset
 * * @idy: %gdouble, input vertical offset
 * * @odx: %gdouble, output horizontal offset
 * * @ody: %gdouble, output vertical offset
 * * @extend: #VipsExtend how to generate new pixels
 * * @background: #VipsArrayDouble colour for new pixels
 * * @premultiplied: %gboolean, images are already premultiplied
 *
 * This operator performs an affine transform on an image using @interpolate.
 *
 * The transform is:
 *
 * |[
 *   X = @a * (x + @idx) + @b * (y + @idy) + @odx
 *   Y = @c * (x + @idx) + @d * (y + @idy) + @doy
 *
 *   where:
 *     x and y are the coordinates in input image.
 *     X and Y are the coordinates in output image.
 *     (0,0) is the upper left corner.
 * ]|
 *
 * The section of the output space defined by @oarea is written to
 * @out. @oarea is a four-element int array of left, top, width, height.
 * By default @oarea is just large enough to cover the whole of the
 * transformed input image.
 *
 * By default, new pixels are filled with @background. This defaults to
 * zero (black). You can set other extend types with @extend. #VIPS_EXTEND_COPY
 * is better for image upsizing.
 *
 * @interpolate defaults to bilinear.
 *
 * @idx, @idy, @odx, @ody default to zero.
 *
 * Image are normally treated as unpremultiplied, so this operation can be used
 * directly on PNG images. If your images have been through vips_premultiply(),
 * set @premultiplied.
 *
 * This operation does not change xres or yres. The image resolution needs to
 * be updated by the application.
 *
 * See also: vips_shrink(), vips_resize(), #VipsInterpolate.
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_affine(VipsImage *in, VipsImage **out,
	double a, double b, double c, double d, ...)
{
	va_list ap;
	VipsArea *matrix;
	int result;

	matrix = VIPS_AREA(vips_array_double_newv(4, a, b, c, d));

	va_start(ap, d);
	result = vips_call_split("affine", ap, in, out, matrix);
	va_end(ap);

	vips_area_unref(matrix);

	return result;
}
