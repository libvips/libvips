/* vertical shrink with a box filter
 *
 * Copyright: 1990, N. Dessipris.
 *
 * Authors: Nicos Dessipris and Kirk Martinez
 * Written on: 29/04/1991
 * Modified on: 2/11/92, 22/2/93 Kirk Martinez - Xres Yres & cleanup
 incredibly inefficient for box filters as LUTs are used instead of +
 Needs converting to a smoother filter: eg Gaussian!  KM
 * 15/7/93 JC
 *	- rewritten for partial v2
 *	- ANSIfied
 *	- now shrinks any non-complex type
 *	- no longer cloned from im_convsub()
 *	- could be much better! see km comments above
 * 3/8/93 JC
 *	- rounding bug fixed
 * 11/1/94 JC
 *	- problems with .000001 and round up/down ignored! Try shrink 3738
 *	  pixel image by 9.345000000001
 * 7/10/94 JC
 *	- IM_NEW and IM_ARRAY added
 *	- more typedef
 * 3/7/95 JC
 *	- IM_CODING_LABQ handling added here
 * 20/12/08
 * 	- fall back to im_copy() for 1/1 shrink
 * 2/2/11
 * 	- gtk-doc
 * 10/2/12
 * 	- shrink in chunks to reduce peak memuse for large shrinks
 * 	- simpler
 * 12/6/12
 * 	- redone as a class
 * 	- warn about non-int shrinks
 * 	- some tuning .. tried an int coordinate path, not worthwhile
 * 16/11/12
 * 	- don't change xres/yres, see comment below
 * 8/4/13
 * 	- oops demand_hint was incorrect, thanks Jan
 * 6/6/13
 * 	- don't chunk horizontally, fixes seq problems with large shrink
 * 	  factors
 * 15/8/16
 * 	- rename yshrink -> vshrink for greater consistency
 * 7/3/17
 * 	- add a seq line cache
 * 6/8/19
 * 	- use a double sum buffer for int32 types
 * 22/4/22 kleisauke
 * 	- add @ceil option
 * 12/8/23 jcupitt
 *	- improve chunking for small shrinks
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
#include <vips/vector.h>
#include <vips/debug.h>
#include <vips/internal.h>

#include "presample.h"

typedef struct _VipsShrinkv {
	VipsResample parent_instance;

	int vshrink;   /* Shrink factor */
	gboolean ceil; /* Round operation */

} VipsShrinkv;

typedef VipsResampleClass VipsShrinkvClass;

G_DEFINE_TYPE(VipsShrinkv, vips_shrinkv, VIPS_TYPE_RESAMPLE);

/* Fixed-point arithmetic path for uchar images.
 */
#define UCHAR_SHRINK(BANDS) \
	{ \
		unsigned char *restrict p = (unsigned char *) in; \
		unsigned char *restrict q = (unsigned char *) out; \
\
		for (x = 0; x < width; x++) { \
			for (b = 0; b < BANDS; b++) { \
				int sum = amend; \
				unsigned char *restrict ptr = p + b; \
				unsigned char *restrict end = ptr + (shrink->vshrink * ls); \
				for (; ptr < end; ptr += ls) \
					sum += *ptr; \
				q[b] = (sum * multiplier) >> 24; \
			} \
			p += BANDS; \
			q += BANDS; \
		} \
	}

/* Integer shrink.
 */
#define ISHRINK(ACC_TYPE, TYPE, BANDS) \
	{ \
		TYPE *restrict p = (TYPE *) in; \
		TYPE *restrict q = (TYPE *) out; \
\
		for (x = 0; x < width; x++) { \
			for (b = 0; b < BANDS; b++) { \
				ACC_TYPE sum = amend; \
				TYPE *restrict ptr = p + b; \
				TYPE *restrict end = ptr + (shrink->vshrink * ls); \
				for (; ptr < end; ptr += ls) \
					sum += *ptr; \
				q[b] = sum / shrink->vshrink; \
			} \
			p += BANDS; \
			q += BANDS; \
		} \
	}

/* Float shrink.
 */
#define FSHRINK(TYPE) \
	{ \
		TYPE *restrict p = (TYPE *) in; \
		TYPE *restrict q = (TYPE *) out; \
\
		for (x = 0; x < width; x++) { \
			for (b = 0; b < bands; b++) { \
				double sum = 0.0; \
				TYPE *restrict ptr = p + b; \
				TYPE *restrict end = ptr + (shrink->vshrink * ls); \
				for (; ptr < end; ptr += ls) \
					sum += *ptr; \
				q[b] = sum / shrink->vshrink; \
			} \
			p += bands; \
			q += bands; \
		} \
	}

/* Generate an area of @out_region. @ir is large enough.
 */
static void
vips_shrinkv_gen2(VipsShrinkv *shrink, VipsRegion *out_region, VipsRegion *ir,
	int left, int top, int width)
{
	VipsResample *resample = VIPS_RESAMPLE(shrink);
	const int bands = resample->in->Bands *
		(vips_band_format_iscomplex(resample->in->BandFmt) ? 2 : 1);
	const int ls = VIPS_REGION_LSKIP(ir) /
		VIPS_IMAGE_SIZEOF_ELEMENT(resample->in);
	VipsPel *out = VIPS_REGION_ADDR(out_region, left, top);
	VipsPel *in = VIPS_REGION_ADDR(ir, left, top * shrink->vshrink);

	int amend = shrink->vshrink / 2;

	int x, b;

	switch (resample->in->BandFmt) {
	case VIPS_FORMAT_UCHAR: {
		unsigned int multiplier = (1LL << 32) / ((1 << 8) * shrink->vshrink);

		/* Generate a special path for 1, 3 and 4 band uchar data. The
		 * compiler will be able to vectorise these.
		 *
		 * Vectorisation doesn't help much for 16, 32-bit or float
		 * data, don't bother with them.
		 */
		switch (bands) {
		case 1:
			UCHAR_SHRINK(1);
			break;
		case 3:
			UCHAR_SHRINK(3);
			break;
		case 4:
			UCHAR_SHRINK(4);
			break;
		default:
			UCHAR_SHRINK(bands);
			break;
		}
		break;
	}
	case VIPS_FORMAT_CHAR:
		ISHRINK(int, char, bands);
		break;
	case VIPS_FORMAT_USHORT:
		ISHRINK(int, unsigned short, bands);
		break;
	case VIPS_FORMAT_SHORT:
		ISHRINK(int, short, bands);
		break;
	case VIPS_FORMAT_UINT:
		ISHRINK(gint64, unsigned int, bands);
		break;
	case VIPS_FORMAT_INT:
		ISHRINK(gint64, int, bands);
		break;
	case VIPS_FORMAT_FLOAT:
		FSHRINK(float);
		break;
	case VIPS_FORMAT_DOUBLE:
		FSHRINK(double);
		break;
	case VIPS_FORMAT_COMPLEX:
		FSHRINK(float);
		break;
	case VIPS_FORMAT_DPCOMPLEX:
		FSHRINK(double);
		break;

	default:
		g_assert_not_reached();
	}
}

static int
vips_shrinkv_gen(VipsRegion *out_region,
	void *seq, void *a, void *b, gboolean *stop)
{
	VipsShrinkv *shrink = (VipsShrinkv *) b;
	VipsRegion *ir = (VipsRegion *) seq;
	VipsRect *r = &out_region->valid;

	/* How do we chunk up the output image? We don't want to prepare the
	 * whole of the input region corresponding to *r since it could be huge.
	 *
	 * We also don't want to fetch a line at a time, since that can make
	 * upstream coordinate changes very expensive.
	 *
	 * Instead, aim for a minimum of tile_height on the input image.
	 */
	int input_target = VIPS_MAX(shrink->vshrink, r->height);
	int dy = input_target / shrink->vshrink;

	int y, y1;

#ifdef DEBUG
	printf("vips_shrinkv_gen: generating %d x %d at %d x %d\n",
		r->width, r->height, r->left, r->top);
#endif /*DEBUG*/

	for (y = 0; y < r->height; y += dy) {
		int chunk_height = VIPS_MIN(dy, r->height - y);

		VipsRect s;

		s.left = r->left;
		s.top = (r->top + y) * shrink->vshrink;
		s.width = r->width;
		s.height = chunk_height * shrink->vshrink;
#ifdef DEBUG
		printf("vips_shrinkv_gen: requesting %d lines from %d\n",
			s.height, s.top);
#endif /*DEBUG*/
		if (vips_region_prepare(ir, &s))
			return -1;

		VIPS_GATE_START("vips_shrinkv_gen: work");

		for (y1 = 0; y1 < chunk_height; y1++)
			vips_shrinkv_gen2(shrink, out_region, ir,
				r->left, r->top + y + y1, r->width);

		VIPS_GATE_STOP("vips_shrinkv_gen: work");
	}

	VIPS_COUNT_PIXELS(out_region, "vips_shrinkv_gen");

	return 0;
}

#ifdef HAVE_HWY
static int
vips_shrinkv_uchar_vector_gen(VipsRegion *out_region,
	void *seq, void *a, void *b, gboolean *stop)
{
	VipsImage *in = (VipsImage *) a;
	VipsShrinkv *shrink = (VipsShrinkv *) b;
	VipsRegion *ir = (VipsRegion *) seq;
	VipsRect *r = &out_region->valid;
	const int bands = in->Bands;
	int ne = r->width * bands;

	/* How do we chunk up the output image? We don't want to prepare the
	 * whole of the input region corresponding to *r since it could be huge.
	 *
	 * We also don't want to fetch a line at a time, since that can make
	 * upstream coordinate changes very expensive.
	 *
	 * Instead, aim for a minimum of tile_height on the input image.
	 */
	int input_target = VIPS_MAX(shrink->vshrink, r->height);
	int dy = input_target / shrink->vshrink;

	int y, y1;

#ifdef DEBUG
	printf("vips_shrinkv_uchar_vector_gen: generating %d x %d at %d x %d\n",
		r->width, r->height, r->left, r->top);
#endif /*DEBUG*/

	for (y = 0; y < r->height; y += dy) {
		int chunk_height = VIPS_MIN(dy, r->height - y);

		VipsRect s;

		s.left = r->left;
		s.top = (r->top + y) * shrink->vshrink;
		s.width = r->width;
		s.height = chunk_height * shrink->vshrink;
#ifdef DEBUG
		printf("vips_shrinkv_uchar_vector_gen: requesting %d lines from %d\n",
			s.height, s.top);
#endif /*DEBUG*/
		if (vips_region_prepare(ir, &s))
			return -1;

		VIPS_GATE_START("vips_shrinkv_uchar_vector_gen: work");

		const int lskip = VIPS_REGION_LSKIP(ir);

		// each output line
		for (y1 = 0; y1 < chunk_height; y1++) {
			// top of this line in the output
			int top = r->top + y + y1;

			VipsPel *q = VIPS_REGION_ADDR(out_region, r->left, top);
			VipsPel *p = VIPS_REGION_ADDR(ir, r->left, top * shrink->vshrink);

			vips_shrinkv_uchar_hwy(q, p, ne, shrink->vshrink, lskip);
		}

		VIPS_GATE_STOP("vips_shrinkv_uchar_vector_gen: work");
	}

	VIPS_COUNT_PIXELS(out_region, "vips_shrinkv_uchar_vector_gen");

	return 0;
}
#endif /*HAVE_HWY*/

static int
vips_shrinkv_build(VipsObject *object)
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS(object);
	VipsResample *resample = VIPS_RESAMPLE(object);
	VipsShrinkv *shrink = (VipsShrinkv *) object;
	VipsImage **t = (VipsImage **) vips_object_local_array(object, 4);

	VipsImage *in;
	VipsGenerateFn generate;

	if (VIPS_OBJECT_CLASS(vips_shrinkv_parent_class)->build(object))
		return -1;

	in = resample->in;

	if (shrink->vshrink < 1) {
		vips_error(class->nickname,
			"%s", _("shrink factors should be >= 1"));
		return -1;
	}

	if (shrink->vshrink == 1)
		return vips_image_write(in, resample->out);

	/* Make the height a multiple of the shrink factor so we don't need to
	 * average half pixels.
	 */
	if (vips_embed(in, &t[1],
			0, 0,
			in->Xsize, VIPS_ROUND_UP(in->Ysize, shrink->vshrink),
			"extend", VIPS_EXTEND_COPY,
			NULL))
		return -1;
	in = t[1];

	/* For uchar input, try to make a vector path.
	 */
#ifdef HAVE_HWY
	if (in->BandFmt == VIPS_FORMAT_UCHAR &&
		vips_vector_isenabled()) {
		generate = vips_shrinkv_uchar_vector_gen;
		g_info("shrinkv: using vector path");
	}
	else
#endif /*HAVE_HWY*/
		/* Default to the C path.
		 */
		generate = vips_shrinkv_gen;

	/* SMALLTILE or we'll need huge input areas for our output. In seq
	 * mode, the linecache above will keep us sequential.
	 */
	t[2] = vips_image_new();
	if (vips_image_pipelinev(t[2],
			VIPS_DEMAND_STYLE_SMALLTILE, in, NULL))
		return -1;

	/* Size output.
	 *
	 * Don't change xres/yres, leave that to the application layer. For
	 * example, vipsthumbnail knows the true shrink factor (including the
	 * fractional part), we just see the integer part here.
	 */
	t[2]->Ysize = shrink->ceil
		? ceil((double) resample->in->Ysize / shrink->vshrink)
		: VIPS_ROUND_UINT((double) resample->in->Ysize / shrink->vshrink);
	if (t[2]->Ysize <= 0) {
		vips_error(class->nickname,
			"%s", _("image has shrunk to nothing"));
		return -1;
	}

#ifdef DEBUG
	printf("vips_shrinkv_build: vshrink = %d\n", shrink->vshrink);
	printf("vips_shrinkv_build: shrinking %d x %d image to %d x %d\n",
		in->Xsize, in->Ysize,
		t[2]->Xsize, t[2]->Ysize);
#endif /*DEBUG*/

	if (vips_image_generate(t[2],
			vips_start_one, generate, vips_stop_one,
			in, shrink))
		return -1;

	in = t[2];

	/* Large vshrinks will throw off sequential mode. Suppose thread1 is
	 * generating tile (0, 0), but stalls. thread2 generates tile
	 * (0, 1), 128 lines further down the output. After it has done,
	 * thread1 tries to generate (0, 0), but by then the pixels it needs
	 * have gone from the input image line cache if the vshrink is large.
	 *
	 * To fix this, put another seq on the output of vshrink. Now we'll
	 * always have the previous XX lines of the shrunk image, and we won't
	 * fetch out of order.
	 */
	if (vips_image_is_sequential(in)) {
		g_info("shrinkv sequential line cache");

		if (vips_sequential(in, &t[3],
				"tile_height", 10,
				NULL))
			return -1;
		in = t[3];
	}

	if (vips_image_write(in, resample->out))
		return -1;

	return 0;
}

static void
vips_shrinkv_class_init(VipsShrinkvClass *class)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS(class);
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS(class);
	VipsOperationClass *operation_class = VIPS_OPERATION_CLASS(class);

	VIPS_DEBUG_MSG("vips_shrinkv_class_init\n");

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "shrinkv";
	vobject_class->description = _("shrink an image vertically");
	vobject_class->build = vips_shrinkv_build;

	operation_class->flags = VIPS_OPERATION_SEQUENTIAL;

	VIPS_ARG_INT(class, "vshrink", 9,
		_("Vshrink"),
		_("Vertical shrink factor"),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET(VipsShrinkv, vshrink),
		1, 1000000, 1);

	VIPS_ARG_BOOL(class, "ceil", 10,
		_("Ceil"),
		_("Round-up output dimensions"),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET(VipsShrinkv, ceil),
		FALSE);

	/* The old name .. now use h and v everywhere.
	 */
	VIPS_ARG_INT(class, "yshrink", 8,
		_("Yshrink"),
		_("Vertical shrink factor"),
		VIPS_ARGUMENT_REQUIRED_INPUT | VIPS_ARGUMENT_DEPRECATED,
		G_STRUCT_OFFSET(VipsShrinkv, vshrink),
		1, 1000000, 1);
}

static void
vips_shrinkv_init(VipsShrinkv *shrink)
{
}

/**
 * vips_shrinkv: (method)
 * @in: input image
 * @out: (out): output image
 * @vshrink: vertical shrink
 * @...: `NULL`-terminated list of optional named arguments
 *
 * Shrink @in vertically by an integer factor.
 *
 * Each pixel in the output is
 * the average of the corresponding column of @vshrink pixels in the input.
 *
 * This is a very low-level operation: see [method@Image.resize] for a more
 * convenient way to resize images.
 *
 * This operation does not change xres or yres. The image resolution needs to
 * be updated by the application.
 *
 * ::: tip "Optional arguments"
 *     * @ceil: `gboolean`, round-up output dimensions
 *
 * ::: seealso
 *     [method@Image.shrinkh], [method@Image.shrink], [method@Image.resize],
 *     [method@Image.affine].
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_shrinkv(VipsImage *in, VipsImage **out, int vshrink, ...)
{
	va_list ap;
	int result;

	va_start(ap, vshrink);
	result = vips_call_split("shrinkv", ap, in, out, vshrink);
	va_end(ap);

	return result;
}
