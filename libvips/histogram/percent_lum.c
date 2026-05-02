/* find the value at a given percentile of an image's BT.709 luminance
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <glib/gi18n-lib.h>

#include <stdio.h>
#include <string.h>

#include <vips/vips.h>

/* 1024 bins is enough to be +/- a few nits of the true value.
 */
#define PERCENT_LUM_BINS 1024

typedef struct _VipsPercentLum {
	VipsOperation parent_instance;

	VipsImage *in;
	double percent;
	double max;
	double threshold;

} VipsPercentLum;

typedef VipsOperationClass VipsPercentLumClass;

G_DEFINE_TYPE(VipsPercentLum, vips_percent_lum, VIPS_TYPE_OPERATION);

typedef struct _PercentLumAccum {
	guint64 bins[PERCENT_LUM_BINS];
	guint64 count;
	float bin_scale;
} PercentLumAccum;

static void *
vips_percent_lum_start(VipsImage *image, void *a, void *b)
{
	return g_new0(PercentLumAccum, 1);
}

static int
vips_percent_lum_scan(VipsRegion *region, void *seq,
	void *a, void *b, gboolean *stop)
{
	PercentLumAccum *accum = (PercentLumAccum *) seq;
	PercentLumAccum *master = (PercentLumAccum *) a;
	VipsRect *r = &region->valid;
	const int bands = region->im->Bands;
	const float scale = master->bin_scale;

	for (int y = 0; y < r->height; y++) {
		float *p = (float *)
			VIPS_REGION_ADDR(region, r->left, r->top + y);

		for (int x = 0; x < r->width; x++) {
			float Y = 0.2126f * p[0] + 0.7152f * p[1] + 0.0722f * p[2];
			int bin = (int) (Y * scale);
			bin = VIPS_CLIP(0, bin, PERCENT_LUM_BINS - 1);
			accum->bins[bin]++;
			p += bands;
		}

		accum->count += r->width;
	}

	return 0;
}

static int
vips_percent_lum_stop(void *seq, void *a, void *b)
{
	PercentLumAccum *thread = (PercentLumAccum *) seq;
	PercentLumAccum *total = (PercentLumAccum *) a;

	for (int i = 0; i < PERCENT_LUM_BINS; i++)
		total->bins[i] += thread->bins[i];
	total->count += thread->count;

	g_free(thread);
	return 0;
}

static int
vips_percent_lum_build(VipsObject *object)
{
	VipsPercentLum *pl = (VipsPercentLum *) object;
	PercentLumAccum accum = { { 0 }, 0, 0.0f };

	if (VIPS_OBJECT_CLASS(vips_percent_lum_parent_class)->build(object))
		return -1;

	if (vips_check_uncoded(object->nickname, pl->in) ||
		vips_check_format(object->nickname, pl->in, VIPS_FORMAT_FLOAT) ||
		vips_check_bands_atleast(object->nickname, pl->in, 3))
		return -1;

	if (vips_image_pio_input(pl->in))
		return -1;

	accum.bin_scale = (float) (PERCENT_LUM_BINS / pl->max);

	if (vips_sink(pl->in,
			vips_percent_lum_start,
			vips_percent_lum_scan,
			vips_percent_lum_stop,
			&accum, NULL))
		return -1;

	if (accum.count == 0) {
		g_object_set(object, "threshold", 0.0, NULL);
		return 0;
	}

	guint64 target = (guint64) (accum.count * (pl->percent / 100.0));
	guint64 cumul = 0;
	int bin;
	for (bin = 0; bin < PERCENT_LUM_BINS; bin++) {
		cumul += accum.bins[bin];
		if (cumul >= target)
			break;
	}

	double threshold = (bin + 0.5) * (pl->max / PERCENT_LUM_BINS);

	g_object_set(object, "threshold", threshold, NULL);

	return 0;
}

static void
vips_percent_lum_class_init(VipsPercentLumClass *class)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS(class);
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "percent_lum";
	object_class->description =
		_("find threshold for percent of pixels by BT.709 luminance");
	object_class->build = vips_percent_lum_build;

	VIPS_ARG_IMAGE(class, "in", 1,
		_("Input"),
		_("Input linear-light RGB float image"),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET(VipsPercentLum, in));

	VIPS_ARG_DOUBLE(class, "percent", 2,
		_("Percent"),
		_("Percentile (0-100) of luminance to return"),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET(VipsPercentLum, percent),
		0.0, 100.0, 99.0);

	VIPS_ARG_DOUBLE(class, "threshold", 3,
		_("Threshold"),
		_("Luminance value at the requested percentile in input unit"),
		VIPS_ARGUMENT_REQUIRED_OUTPUT,
		G_STRUCT_OFFSET(VipsPercentLum, threshold),
		-1e9, 1e9, 0.0);

	VIPS_ARG_DOUBLE(class, "max", 4,
		_("Max"),
		_("Histogram upper bound in input unit; values above clamp to the top bin"),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET(VipsPercentLum, max),
		1e-9, 1e9, 125.0);
}

static void
vips_percent_lum_init(VipsPercentLum *pl)
{
	pl->percent = 99.0;
	pl->max = 125.0;
}

/**
 * vips_percent_lum: (method)
 * @in: input linear-light RGB float image
 * @percent: percentile (0-100) of luminance to return
 * @threshold: (out): luminance value at the percentile, in input unit
 * @...: `NULL`-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @max: histogram upper bound in input unit (default 125.0)
 *
 * Computes BT.709 luminance over @in, builds a luminance histogram,
 * and returns the value at the requested percentile in @threshold.
 *
 * The histogram is in the same unit as the input and covers `[0, max]`.
 * For example, multiply by 80 to get nits for an scRGB (1.0 = 80 nits) input.
 *
 * The input must be a 3-band (or more) float image. Extra bands beyond
 * the first three are ignored.
 *
 * ::: seealso
 *     [method@Image.percent].
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_percent_lum(VipsImage *in, double percent, double *threshold, ...)
{
	va_list ap;
	int result;

	va_start(ap, threshold);
	result = vips_call_split("percent_lum", ap, in, percent, threshold);
	va_end(ap);

	return result;
}
