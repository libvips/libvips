/* join an array of images together
 *
 * 11/12/15
 * 	- from join.c
 * 6/9/21
 * 	- minmise inputs once we've used them
 * 29/12/22
 *	- much faster with large arrays
 * 29/1/24
 *	- render and don't forward pixels for complete subregions
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
#define VIPS_DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <glib/gi18n-lib.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <vips/vips.h>
#include <vips/internal.h>
#include <vips/debug.h>

#include "pconversion.h"

typedef struct _VipsArrayjoin {
	VipsConversion parent_instance;

	/* Params.
	 */
	VipsArrayImage *in;
	int across;
	int shim;
	VipsArrayDouble *background;
	VipsAlign halign;
	VipsAlign valign;
	int hspacing;
	int vspacing;

	int down;
	VipsRect *rects;
	gboolean *minimised;

} VipsArrayjoin;

typedef VipsConversionClass VipsArrayjoinClass;

G_DEFINE_TYPE(VipsArrayjoin, vips_arrayjoin, VIPS_TYPE_CONVERSION);

static int
vips_arrayjoin_gen(VipsRegion *out_region,
	void *seq, void *a, void *b, gboolean *stop)
{
	VipsImage **in = (VipsImage **) a;
	VipsArrayjoin *join = (VipsArrayjoin *) b;
	VipsConversion *conversion = VIPS_CONVERSION(join);
	VipsRect *r = &out_region->valid;
	int n;

	/* Find the left/top/width/height of the cells this region touches.
	 */
	int cell_width = join->hspacing + join->shim;
	int cell_height = join->vspacing + join->shim;
	int left = r->left / cell_width;
	int top = r->top / cell_height;
	int width = (VIPS_ROUND_UP(VIPS_RECT_RIGHT(r), cell_width) -
					VIPS_ROUND_DOWN(r->left, cell_width)) /
		cell_width;
	int height = (VIPS_ROUND_UP(VIPS_RECT_BOTTOM(r), cell_height) -
					 VIPS_ROUND_DOWN(r->top, cell_height)) /
		cell_height;

	int i;
	VipsRegion *reg;

	/* Size of image array.
	 */
	vips_array_image_get(join->in, &n);

	/* Does this rect fit completely within one of our inputs? We can just
	 * forward the request.
	 */
	if (width == 1 && height == 1) {
		VipsRect need;

		i = VIPS_MIN(n - 1, left + top * join->across);

		/* The part of in[i] we need.
		 */
		need = out_region->valid;
		need.left -= join->rects[i].left;
		need.top -= join->rects[i].top;

		/* And render into out_region. We can't just forward a pointer since
		 * we are about to unref reg.
		 */
		reg = vips_region_new(in[i]);
		if (vips_region_prepare_to(reg, out_region, &need, r->left, r->top)) {
			g_object_unref(reg);
			return -1;
		}
		g_object_unref(reg);
	}
	else {
		/* Output requires more than one input. Paste all touching
		 * inputs into the output.
		 */
		int x, y;

		for (y = 0; y < height; y++)
			for (x = 0; x < width; x++) {
				i = VIPS_MIN(n - 1, x + left + (y + top) * join->across);

				reg = vips_region_new(in[i]);

				if (vips__insert_paste_region(out_region, reg,
						&join->rects[i])) {
					g_object_unref(reg);
					return -1;
				}

				g_object_unref(reg);
			}
	}

	/* In sequential mode, we can minimise an input once our generate point
	 * is well past the end of it. This can save a lot of memory and file
	 * descriptors on large image arrays.
	 *
	 * minimise_all is quite expensive, so only trigger once for each input.
	 *
	 * We don't lock for minimised[], but it's harmless.
	 */
	if (vips_image_is_sequential(conversion->out))
		for (i = 0; i < n; i++) {
			int bottom_edge = VIPS_RECT_BOTTOM(&join->rects[i]);

			if (!join->minimised[i] &&
				r->top > bottom_edge + 1024) {
				join->minimised[i] = TRUE;
				vips_image_minimise_all(in[i]);
			}
		}

	return 0;
}

static int
vips_arrayjoin_build(VipsObject *object)
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS(object);
	VipsConversion *conversion = VIPS_CONVERSION(object);
	VipsArrayjoin *join = (VipsArrayjoin *) object;

	VipsImage **in;
	int n;

	VipsImage **format;
	VipsImage **band;
	VipsImage **size;

	int hspacing;
	int vspacing;
	int output_width;
	int output_height;
	int i;

	if (VIPS_OBJECT_CLASS(vips_arrayjoin_parent_class)->build(object))
		return -1;

	in = vips_array_image_get(join->in, &n);
	/* Array length zero means error.
	 */
	if (n == 0)
		return -1;

	for (i = 0; i < n; i++)
		if (vips_image_pio_input(in[i]) ||
			vips_check_coding_known(class->nickname, in[i]))
			return -1;

	/* Move all input images to a common format and number of bands.
	 */
	format = (VipsImage **) vips_object_local_array(object, n);
	if (vips__formatalike_vec(in, format, n))
		return -1;
	in = format;

	/* We have to include the number of bands in @background in our
	 * calculation.
	 */
	band = (VipsImage **) vips_object_local_array(object, n);
	if (vips__bandalike_vec(class->nickname,
			in, band, n, VIPS_AREA(join->background)->n))
		return -1;
	in = band;

	/* Now sizealike: search for the largest image.
	 */
	hspacing = in[0]->Xsize;
	vspacing = in[0]->Ysize;
	for (i = 1; i < n; i++) {
		if (in[i]->Xsize > hspacing)
			hspacing = in[i]->Xsize;
		if (in[i]->Ysize > vspacing)
			vspacing = in[i]->Ysize;
	}

	if (!vips_object_argument_isset(object, "hspacing"))
		join->hspacing = hspacing; // FIXME: Invalidates operation cache
	if (!vips_object_argument_isset(object, "vspacing"))
		join->vspacing = vspacing; // FIXME: Invalidates operation cache

	hspacing = join->hspacing;
	vspacing = join->vspacing;

	if (!vips_object_argument_isset(object, "across"))
		join->across = n; // FIXME: Invalidates operation cache

	/* How many images down the grid?
	 */
	join->down = VIPS_ROUND_UP(n, join->across) / join->across;

	/* The output size.
	 */
	output_width = hspacing * join->across +
		join->shim * (join->across - 1);
	output_height = vspacing * join->down +
		join->shim * (join->down - 1);

	/* Make a rect for the position of each input.
	 */
	join->rects = VIPS_ARRAY(join, n, VipsRect);
	for (i = 0; i < n; i++) {
		int x = i % join->across;
		int y = i / join->across;

		join->rects[i].left = x * (hspacing + join->shim);
		join->rects[i].top = y * (vspacing + join->shim);
		join->rects[i].width = hspacing;
		join->rects[i].height = vspacing;

		/* In the centre of the array, we make width / height larger
		 * by shim.
		 */
		if (x != join->across - 1)
			join->rects[i].width += join->shim;
		if (y != join->down - 1)
			join->rects[i].height += join->shim;

		/* The right edge of the final image is stretched to the right
		 * to fill the whole row.
		 */
		if (i == n - 1)
			join->rects[i].width =
				output_width - join->rects[i].left;
	}

	/* A thing to track which inputs we've signalled minimise on.
	 */
	join->minimised = VIPS_ARRAY(join, n, gboolean);
	for (i = 0; i < n; i++)
		join->minimised[i] = FALSE;

	/* Each image must be cropped and aligned within an @hspacing by
	 * @vspacing box.
	 */
	size = (VipsImage **) vips_object_local_array(object, n);
	for (i = 0; i < n; i++) {
		int left, top;
		int width, height;

		/* Compiler warnings.
		 */
		left = 0;
		top = 0;

		switch (join->halign) {
		case VIPS_ALIGN_LOW:
			left = 0;
			break;

		case VIPS_ALIGN_CENTRE:
			left = (hspacing - in[i]->Xsize) / 2;
			break;

		case VIPS_ALIGN_HIGH:
			left = hspacing - in[i]->Xsize;
			break;

		default:
			g_assert_not_reached();
			break;
		}

		switch (join->valign) {
		case VIPS_ALIGN_LOW:
			top = 0;
			break;

		case VIPS_ALIGN_CENTRE:
			top = (vspacing - in[i]->Ysize) / 2;
			break;

		case VIPS_ALIGN_HIGH:
			top = vspacing - in[i]->Ysize;
			break;

		default:
			g_assert_not_reached();
			break;
		}

		width = join->rects[i].width;
		height = join->rects[i].height;

		if (vips_embed(in[i], &size[i], left, top, width, height,
				"extend", VIPS_EXTEND_BACKGROUND,
				"background", join->background,
				NULL))
			return -1;
	}

	if (vips_image_pipeline_array(conversion->out,
			VIPS_DEMAND_STYLE_THINSTRIP, size))
		return -1;

	conversion->out->Xsize = output_width;
	conversion->out->Ysize = output_height;

	/* Don't use start_many -- the set of input images can be huge (many
	 * 10s of 1000s) and we don't want to have 20,000 regions active. It's
	 * much quicker to make them on demand.
	 */
	if (vips_image_generate(conversion->out,
			NULL, vips_arrayjoin_gen, NULL, size, join))
		return -1;

	return 0;
}

static void
vips_arrayjoin_class_init(VipsArrayjoinClass *class)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS(class);
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS(class);
	VipsOperationClass *operation_class = VIPS_OPERATION_CLASS(class);

	VIPS_DEBUG_MSG("vips_arrayjoin_class_init\n");

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "arrayjoin";
	vobject_class->description = _("join an array of images");
	vobject_class->build = vips_arrayjoin_build;

	operation_class->flags = VIPS_OPERATION_SEQUENTIAL;

	VIPS_ARG_BOXED(class, "in", -1,
		_("Input"),
		_("Array of input images"),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET(VipsArrayjoin, in),
		VIPS_TYPE_ARRAY_IMAGE);

	VIPS_ARG_INT(class, "across", 4,
		_("Across"),
		_("Number of images across grid"),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET(VipsArrayjoin, across),
		1, 1000000, 1);

	VIPS_ARG_INT(class, "shim", 5,
		_("Shim"),
		_("Pixels between images"),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET(VipsArrayjoin, shim),
		0, 1000000, 0);

	VIPS_ARG_BOXED(class, "background", 6,
		_("Background"),
		_("Colour for new pixels"),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET(VipsArrayjoin, background),
		VIPS_TYPE_ARRAY_DOUBLE);

	VIPS_ARG_ENUM(class, "halign", 7,
		_("Horizontal align"),
		_("Align on the left, centre or right"),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET(VipsArrayjoin, halign),
		VIPS_TYPE_ALIGN, VIPS_ALIGN_LOW);

	VIPS_ARG_ENUM(class, "valign", 8,
		_("Vertical align"),
		_("Align on the top, centre or bottom"),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET(VipsArrayjoin, valign),
		VIPS_TYPE_ALIGN, VIPS_ALIGN_LOW);

	VIPS_ARG_INT(class, "hspacing", 9,
		_("Horizontal spacing"),
		_("Horizontal spacing between images"),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET(VipsArrayjoin, hspacing),
		1, 1000000, 1);

	VIPS_ARG_INT(class, "vspacing", 10,
		_("Vertical spacing"),
		_("Vertical spacing between images"),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET(VipsArrayjoin, vspacing),
		1, 1000000, 1);
}

static void
vips_arrayjoin_init(VipsArrayjoin *join)
{
	/* Init our instance fields.
	 */
	join->background = vips_array_double_newv(1, 0.0);
}

static int
vips_arrayjoinv(VipsImage **in, VipsImage **out, int n, va_list ap)
{
	VipsArrayImage *array;
	int result;

	array = vips_array_image_new(in, n);
	result = vips_call_split("arrayjoin", ap, array, out);
	vips_area_unref(VIPS_AREA(array));

	return result;
}

/**
 * vips_arrayjoin:
 * @in: (array length=n) (transfer none): array of input images
 * @out: (out): output image
 * @n: number of input images
 * @...: `NULL`-terminated list of optional named arguments
 *
 * Lay out the images in @in in a grid. The grid is @across images across and
 * however high is necessary to use up all of @in. Images are set down
 * left-to-right and top-to-bottom. @across defaults to @n.
 *
 * Each input image is placed with a box of size @hspacing by @vspacing
 * pixels and cropped. These default to the largest width and largest height
 * of the input images.
 *
 * Space between images is filled with @background. This defaults to 0
 * (black).
 *
 * Images are positioned within their @hspacing by @vspacing box at low,
 * centre or high coordinate values, controlled by @halign and @valign. These
 * default to left-top.
 *
 * Boxes are joined and separated by @shim pixels. This defaults to 0.
 *
 * If the number of bands in the input images differs, all but one of the
 * images must have one band. In this case, an n-band image is formed from the
 * one-band image by joining n copies of the one-band image together, and then
 * the n-band images are operated upon.
 *
 * The input images are cast up to the smallest common type (see table
 * Smallest common format in
 * [arithmetic](libvips-arithmetic.html)).
 *
 * [method@Image.colourspace] can be useful for moving the images to a common
 * colourspace for compositing.
 *
 * ::: tip "Optional arguments"
 *     * @across: `gint`, number of images per row
 *     * @shim: `gint`, space between images, in pixels
 *     * @background: [struct@ArrayDouble], background ink colour
 *     * @halign: [enum@Align], low, centre or high alignment
 *     * @valign: [enum@Align], low, centre or high alignment
 *     * @hspacing: `gint`, horizontal distance between images
 *     * @vspacing: `gint`, vertical distance between images
 *
 * ::: seealso
 *     [method@Image.join], [method@Image.insert], [method@Image.colourspace].
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_arrayjoin(VipsImage **in, VipsImage **out, int n, ...)
{
	va_list ap;
	int result;

	va_start(ap, n);
	result = vips_arrayjoinv(in, out, n, ap);
	va_end(ap);

	return result;
}
