/* Built-in color quantizer: Wu's optimal + Floyd-Steinberg dithering.
 *
 * Provides baseline palette quantization when libimagequant/quantizr
 * are not available.
 *
 * Pipeline: Wu partition → nearest-color map → F-S dithering
 *
 * References:
 *   Xiaolin Wu, "Efficient Statistical Computations for Optimal Color
 *   Quantization", Graphics Gems II, 1991.
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

#include <vips/vips.h>

#include <string.h>

#include "quantise.h"

/* Only compile when no external quantizer is available.
 */
#ifndef HAVE_QUANTIZATION

/* Maximum palette size.
 */
#define MAX_COLORS 256

typedef struct {
	int r, g, b, a;
} PaletteEntry;

/* ---- Wu's optimal quantizer (5-bit RGB + 4-bit alpha) ----
 *
 * 4D RGBA histogram with 5-bit RGB and 4-bit alpha resolution.
 *
 * Histogram: 33^3 * 17 = 610,593 entries, ~14 MB.
 * Box map: 32^3 * 16 = 524,288 entries, 512 KB.
 */
#define HIST_RS 33  /* RGB bins + prefix-sum boundary */
#define HIST_AS 17  /* alpha bins + prefix-sum boundary */

#define HIST_SR (HIST_RS * HIST_RS * HIST_AS)
#define HIST_SG (HIST_RS * HIST_AS)
#define HIST_SB HIST_AS
#define HIST_TOTAL (HIST_RS * HIST_RS * HIST_RS * HIST_AS)
#define CACHE_SIZE (32 * 32 * 32 * 16)

#define IND(r, g, b, a) \
	((r) * HIST_SR + (g) * HIST_SG + (b) * HIST_SB + (a))

/* Box map index: 5-bit R, 5-bit G, 5-bit B, 4-bit A = 19 bits.
 */
#define BM(r, g, b, a) \
	(((r) << 14) | ((g) << 9) | ((b) << 4) | (a))

typedef struct {
	int r0, r1, g0, g1, b0, b1, a0, a1;
} WuBox;

typedef struct {
	gint64 *data;
	gint64 *wt, *mr, *mg, *mb, *ma;
} WuHist;

static WuHist *
wu_hist_new(void)
{
	WuHist *h = g_new(WuHist, 1);

	h->data = g_new0(gint64, 5 * HIST_TOTAL);
	h->wt = h->data;
	h->mr = h->data + HIST_TOTAL;
	h->mg = h->data + 2 * HIST_TOTAL;
	h->mb = h->data + 3 * HIST_TOTAL;
	h->ma = h->data + 4 * HIST_TOTAL;

	return h;
}

static void
wu_hist_free(WuHist *h)
{
	g_free(h->data);
	g_free(h);
}

static void
wu_build_histogram(WuHist *h, const VipsPel *pixels,
	int width, int height, int stride)
{
	int x, y;

	for (y = 0; y < height; y++) {
		const VipsPel *p = pixels + (gint64) y * stride;

		for (x = 0; x < width; x++) {
			int ir = (p[0] >> 3) + 1;
			int ig = (p[1] >> 3) + 1;
			int ib = (p[2] >> 3) + 1;
			int ia = (p[3] >> 4) + 1;
			int idx = IND(ir, ig, ib, ia);

			h->wt[idx]++;
			h->mr[idx] += p[0];
			h->mg[idx] += p[1];
			h->mb[idx] += p[2];
			h->ma[idx] += p[3];

			p += 4;
		}
	}
}

static void
wu_cumulate_moments(WuHist *h)
{
	gint64 *arrays[5] = { h->wt, h->mr, h->mg, h->mb, h->ma };
	int n, r, g, b, a;

	for (n = 0; n < 5; n++) {
		gint64 *m = arrays[n];

		/* Sum along A.
		 */
		for (r = 1; r < HIST_RS; r++)
			for (g = 1; g < HIST_RS; g++)
				for (b = 1; b < HIST_RS; b++)
					for (a = 1; a < HIST_AS; a++)
						m[IND(r, g, b, a)] +=
							m[IND(r, g, b, a - 1)];

		/* Sum along B.
		 */
		for (r = 1; r < HIST_RS; r++)
			for (g = 1; g < HIST_RS; g++)
				for (b = 1; b < HIST_RS; b++)
					for (a = 0; a < HIST_AS; a++)
						m[IND(r, g, b, a)] +=
							m[IND(r, g, b - 1, a)];

		/* Sum along G.
		 */
		for (r = 1; r < HIST_RS; r++)
			for (g = 1; g < HIST_RS; g++)
				for (b = 0; b < HIST_RS; b++)
					for (a = 0; a < HIST_AS; a++)
						m[IND(r, g, b, a)] +=
							m[IND(r, g - 1, b, a)];

		/* Sum along R.
		 */
		for (r = 1; r < HIST_RS; r++)
			for (g = 0; g < HIST_RS; g++)
				for (b = 0; b < HIST_RS; b++)
					for (a = 0; a < HIST_AS; a++)
						m[IND(r, g, b, a)] +=
							m[IND(r - 1, g, b, a)];
	}
}

/* 4D inclusion-exclusion: 16 terms.
 */
static gint64
vol(const gint64 *m, const WuBox *b)
{
	return m[IND(b->r1, b->g1, b->b1, b->a1)]
		- m[IND(b->r0, b->g1, b->b1, b->a1)]
		- m[IND(b->r1, b->g0, b->b1, b->a1)]
		- m[IND(b->r1, b->g1, b->b0, b->a1)]
		- m[IND(b->r1, b->g1, b->b1, b->a0)]
		+ m[IND(b->r0, b->g0, b->b1, b->a1)]
		+ m[IND(b->r0, b->g1, b->b0, b->a1)]
		+ m[IND(b->r0, b->g1, b->b1, b->a0)]
		+ m[IND(b->r1, b->g0, b->b0, b->a1)]
		+ m[IND(b->r1, b->g0, b->b1, b->a0)]
		+ m[IND(b->r1, b->g1, b->b0, b->a0)]
		- m[IND(b->r0, b->g0, b->b0, b->a1)]
		- m[IND(b->r0, b->g0, b->b1, b->a0)]
		- m[IND(b->r0, b->g1, b->b0, b->a0)]
		- m[IND(b->r1, b->g0, b->b0, b->a0)]
		+ m[IND(b->r0, b->g0, b->b0, b->a0)];
}

static double
wu_priority(const WuHist *h, const WuBox *b)
{
	gint64 w = vol(h->wt, b);
	double dr, dg, db, da;

	if (w <= 0)
		return 0.0;

	dr = b->r1 - b->r0;
	dg = b->g1 - b->g0;
	db = b->b1 - b->b0;
	da = b->a1 - b->a0;

	return (double) w * (dr * dr + dg * dg + db * db + da * da);
}

/* Partial prefix sums along each axis (8 terms each).
 */
static gint64
partial_r(const gint64 *m, const WuBox *b, int d)
{
	return m[IND(d, b->g1, b->b1, b->a1)]
		- m[IND(d, b->g0, b->b1, b->a1)]
		- m[IND(d, b->g1, b->b0, b->a1)]
		- m[IND(d, b->g1, b->b1, b->a0)]
		+ m[IND(d, b->g0, b->b0, b->a1)]
		+ m[IND(d, b->g0, b->b1, b->a0)]
		+ m[IND(d, b->g1, b->b0, b->a0)]
		- m[IND(d, b->g0, b->b0, b->a0)];
}

static gint64
partial_g(const gint64 *m, const WuBox *b, int d)
{
	return m[IND(b->r1, d, b->b1, b->a1)]
		- m[IND(b->r0, d, b->b1, b->a1)]
		- m[IND(b->r1, d, b->b0, b->a1)]
		- m[IND(b->r1, d, b->b1, b->a0)]
		+ m[IND(b->r0, d, b->b0, b->a1)]
		+ m[IND(b->r0, d, b->b1, b->a0)]
		+ m[IND(b->r1, d, b->b0, b->a0)]
		- m[IND(b->r0, d, b->b0, b->a0)];
}

static gint64
partial_b(const gint64 *m, const WuBox *b, int d)
{
	return m[IND(b->r1, b->g1, d, b->a1)]
		- m[IND(b->r0, b->g1, d, b->a1)]
		- m[IND(b->r1, b->g0, d, b->a1)]
		- m[IND(b->r1, b->g1, d, b->a0)]
		+ m[IND(b->r0, b->g0, d, b->a1)]
		+ m[IND(b->r0, b->g1, d, b->a0)]
		+ m[IND(b->r1, b->g0, d, b->a0)]
		- m[IND(b->r0, b->g0, d, b->a0)];
}

static gint64
partial_a(const gint64 *m, const WuBox *b, int d)
{
	return m[IND(b->r1, b->g1, b->b1, d)]
		- m[IND(b->r0, b->g1, b->b1, d)]
		- m[IND(b->r1, b->g0, b->b1, d)]
		- m[IND(b->r1, b->g1, b->b0, d)]
		+ m[IND(b->r0, b->g0, b->b1, d)]
		+ m[IND(b->r0, b->g1, b->b0, d)]
		+ m[IND(b->r1, b->g0, b->b0, d)]
		- m[IND(b->r0, b->g0, b->b0, d)];
}

typedef gint64 (*wu_partial_fn)(const gint64 *m,
	const WuBox *b, int d);

static int
wu_maximize_axis(const WuHist *h, const WuBox *b,
	int lo, int hi,
	wu_partial_fn partial_fn,
	double *max_gain)
{
	gint64 whole_w = vol(h->wt, b);
	gint64 whole_r = vol(h->mr, b);
	gint64 whole_g = vol(h->mg, b);
	gint64 whole_bv = vol(h->mb, b);
	gint64 whole_a = vol(h->ma, b);

	gint64 base_w = partial_fn(h->wt, b, lo);
	gint64 base_r = partial_fn(h->mr, b, lo);
	gint64 base_g = partial_fn(h->mg, b, lo);
	gint64 base_bv = partial_fn(h->mb, b, lo);
	gint64 base_a = partial_fn(h->ma, b, lo);

	int best = -1;
	int d;

	*max_gain = 0.0;

	for (d = lo; d < hi; d++) {
		gint64 half_w = partial_fn(h->wt, b, d) - base_w;
		gint64 half_r, half_g, half_bv, half_a;
		gint64 other_w, other_r, other_g, other_bv, other_a;
		double gain;

		if (half_w <= 0)
			continue;

		other_w = whole_w - half_w;
		if (other_w <= 0)
			continue;

		half_r = partial_fn(h->mr, b, d) - base_r;
		half_g = partial_fn(h->mg, b, d) - base_g;
		half_bv = partial_fn(h->mb, b, d) - base_bv;
		half_a = partial_fn(h->ma, b, d) - base_a;

		gain = ((double) half_r * half_r +
				(double) half_g * half_g +
				(double) half_bv * half_bv +
				(double) half_a * half_a) /
			(double) half_w;

		other_r = whole_r - half_r;
		other_g = whole_g - half_g;
		other_bv = whole_bv - half_bv;
		other_a = whole_a - half_a;

		gain += ((double) other_r * other_r +
				(double) other_g * other_g +
				(double) other_bv * other_bv +
				(double) other_a * other_a) /
			(double) other_w;

		if (gain > *max_gain) {
			*max_gain = gain;
			best = d;
		}
	}

	return best;
}

static gboolean
wu_cut(const WuHist *h, WuBox *b1, WuBox *b2)
{
	double gain_r, gain_g, gain_b, gain_a;
	int cut_r, cut_g, cut_b, cut_a;

	cut_r = wu_maximize_axis(h, b1, b1->r0, b1->r1,
		partial_r, &gain_r);
	cut_g = wu_maximize_axis(h, b1, b1->g0, b1->g1,
		partial_g, &gain_g);
	cut_b = wu_maximize_axis(h, b1, b1->b0, b1->b1,
		partial_b, &gain_b);
	cut_a = wu_maximize_axis(h, b1, b1->a0, b1->a1,
		partial_a, &gain_a);

	if (cut_r < 0 && cut_g < 0 && cut_b < 0 && cut_a < 0)
		return FALSE;

	*b2 = *b1;

	if (gain_r >= gain_g && gain_r >= gain_b && gain_r >= gain_a) {
		if (cut_r < 0)
			return FALSE;
		b2->r0 = cut_r;
		b1->r1 = cut_r;
	}
	else if (gain_g >= gain_r && gain_g >= gain_b &&
		gain_g >= gain_a) {
		if (cut_g < 0)
			return FALSE;
		b2->g0 = cut_g;
		b1->g1 = cut_g;
	}
	else if (gain_b >= gain_r && gain_b >= gain_g &&
		gain_b >= gain_a) {
		if (cut_b < 0)
			return FALSE;
		b2->b0 = cut_b;
		b1->b1 = cut_b;
	}
	else {
		if (cut_a < 0)
			return FALSE;
		b2->a0 = cut_a;
		b1->a1 = cut_a;
	}

	return TRUE;
}

static int
wu_partition(const WuHist *h, WuBox *boxes, int n_colors)
{
	double *priorities;
	int n_boxes = 1;
	int i;

	boxes[0].r0 = boxes[0].g0 = boxes[0].b0 = boxes[0].a0 = 0;
	boxes[0].r1 = boxes[0].g1 = boxes[0].b1 = HIST_RS - 1;
	boxes[0].a1 = HIST_AS - 1;

	priorities = g_new(double, n_colors);
	priorities[0] = wu_priority(h, &boxes[0]);

	while (n_boxes < n_colors) {
		int best = -1;
		double best_pri = 0.0;
		WuBox new_box;

		for (i = 0; i < n_boxes; i++) {
			if (priorities[i] > best_pri) {
				best_pri = priorities[i];
				best = i;
			}
		}

		if (best < 0 || best_pri <= 0.0)
			break;

		if (!wu_cut(h, &boxes[best], &new_box)) {
			priorities[best] = 0.0;
			continue;
		}

		boxes[n_boxes] = new_box;
		priorities[best] = wu_priority(h, &boxes[best]);
		priorities[n_boxes] = wu_priority(h, &new_box);
		n_boxes++;
	}

	g_free(priorities);

	return n_boxes;
}

static void
wu_box_color(const WuHist *h, const WuBox *b, PaletteEntry *out)
{
	gint64 w = vol(h->wt, b);

	if (w <= 0) {
		out->r = out->g = out->b = 0;
		out->a = 255;
		return;
	}

	out->r = (int) ((vol(h->mr, b) + w / 2) / w);
	out->g = (int) ((vol(h->mg, b) + w / 2) / w);
	out->b = (int) ((vol(h->mb, b) + w / 2) / w);
	out->a = (int) ((vol(h->ma, b) + w / 2) / w);

	out->r = VIPS_CLIP(0, out->r, 255);
	out->g = VIPS_CLIP(0, out->g, 255);
	out->b = VIPS_CLIP(0, out->b, 255);
	out->a = VIPS_CLIP(0, out->a, 255);
}

/* Build a lookup map: for each quantized (r,g,b,a) cell, find the
 * nearest palette entry by Euclidean distance in RGBA space.
 */
static void
build_nearest_map(const PaletteEntry *palette, int n_colors,
	VipsPel *map)
{
	int r, g, b, a, i;

	for (r = 0; r < 32; r++) {
		int rv = r * 8 + 4;

		for (g = 0; g < 32; g++) {
			int gv = g * 8 + 4;

			for (b = 0; b < 32; b++) {
				int bv = b * 8 + 4;

				for (a = 0; a < 16; a++) {
					int av = a * 16 + 8;
					int best = 0;
					int best_dist = INT_MAX;

					for (i = 0; i < n_colors; i++) {
						int dr = rv - palette[i].r;
						int dg = gv - palette[i].g;
						int db = bv - palette[i].b;
						int da = av - palette[i].a;
						int dist = dr * dr +
							dg * dg +
							db * db +
							da * da;

						if (dist < best_dist) {
							best_dist = dist;
							best = i;
						}
					}

					map[BM(r, g, b, a)] =
						(VipsPel) best;
				}
			}
		}
	}
}


static void
remap_centroid(const VipsPel *pixels, VipsPel *index_out,
	int width, int height, int stride,
	const VipsPel *nearest_map)
{
	int x, y;

	for (y = 0; y < height; y++) {
		const VipsPel *p = pixels + (gint64) y * stride;
		VipsPel *q = index_out + (gint64) y * width;

		for (x = 0; x < width; x++) {
			q[x] = nearest_map[BM(
				p[0] >> 3, p[1] >> 3,
				p[2] >> 3, p[3] >> 4)];
			p += 4;
		}
	}
}


/* Floyd-Steinberg error diffusion dithering with serpentine scanning.
 *
 * Each pixel's quantization error is distributed to 4 neighbors:
 *   right: 7/16, below-left: 3/16, below: 5/16, below-right: 1/16
 * Serpentine (alternating L-R / R-L) scanning reduces directional
 * artifacts. Uses the box_map for fast palette lookup.
 */
static void
remap_dither(const VipsPel *pixels, VipsPel *index_out,
	int width, int height, int stride,
	const VipsPel *nearest_map,
	const PaletteEntry *palette, double dither_strength)
{
	/* Error buffers: current and next row, 4 channels per pixel.
	 * +2 width for boundary padding (one pixel each side).
	 * int16 is sufficient: max accumulated error is 255*16 = 4080.
	 */
	gint16 *err_cur, *err_next, *tmp;
	int row_len = (width + 2) * 4;
	int x, y;

	err_cur = g_new0(gint16, row_len);
	err_next = g_new0(gint16, row_len);

	/* Scale dither_strength to fixed-point: 1.0 -> 16 (full F-S).
	 */
	int ds = (int) (dither_strength * 16.0 + 0.5);
	if (ds < 1)
		ds = 1;
	if (ds > 16)
		ds = 16;

	/* Fast path flag: when ds==16, error/16 is just a shift.
	 */
	gboolean full_strength = (ds == 16);

	for (y = 0; y < height; y++) {
		const VipsPel *p = pixels + (gint64) y * stride;
		VipsPel *q = index_out + (gint64) y * width;

		/* Swap error rows and clear the new next row.
		 */
		tmp = err_cur;
		err_cur = err_next;
		err_next = tmp;
		memset(err_next, 0, row_len * sizeof(gint16));

		/* Serpentine: alternate direction each row.
		 */
		gboolean forward = (y & 1) == 0;
		int x_start = forward ? 0 : width - 1;
		int x_end = forward ? width : -1;
		int x_step = forward ? 1 : -1;

		for (x = x_start; x != x_end; x += x_step) {
			/* px is the error buffer index (+1 for left pad).
			 */
			int px = (x + 1) * 4;

			/* Skip fully transparent pixels: assign via
			 * nearest_map directly, no error to propagate.
			 */
			if (p[x * 4 + 3] == 0) {
				q[x] = nearest_map[BM(
					p[x * 4] >> 3,
					p[x * 4 + 1] >> 3,
					p[x * 4 + 2] >> 3, 0)];
				continue;
			}

			/* Add accumulated error (stored * 16) to pixel.
			 * Fast path for dither=1.0: shift instead of
			 * multiply+divide.
			 */
			int r, g, b, a;

			if (full_strength) {
				r = p[x * 4 + 0] +
					(err_cur[px + 0] + 8) / 16;
				g = p[x * 4 + 1] +
					(err_cur[px + 1] + 8) / 16;
				b = p[x * 4 + 2] +
					(err_cur[px + 2] + 8) / 16;
				a = p[x * 4 + 3] +
					(err_cur[px + 3] + 8) / 16;
			}
			else {
				r = p[x * 4 + 0] +
					(err_cur[px + 0] * ds + 128) / 256;
				g = p[x * 4 + 1] +
					(err_cur[px + 1] * ds + 128) / 256;
				b = p[x * 4 + 2] +
					(err_cur[px + 2] * ds + 128) / 256;
				a = p[x * 4 + 3] +
					(err_cur[px + 3] * ds + 128) / 256;
			}

			int idx, er, eg, eb, ea;
			int right;

			r = VIPS_CLIP(0, r, 255);
			g = VIPS_CLIP(0, g, 255);
			b = VIPS_CLIP(0, b, 255);
			a = VIPS_CLIP(0, a, 255);

			/* Find palette entry via nearest_map.
			 */
			idx = nearest_map[BM(r >> 3, g >> 3,
				b >> 3, a >> 4)];
			q[x] = (VipsPel) idx;

			/* Quantization error.
			 * Scale RGB error by source alpha: low-alpha
			 * pixels contribute little visually, so their
			 * RGB error should not propagate at full
			 * strength (prevents bright-pixel artifacts at
			 * transparency edges).
			 */
			int src_a = p[x * 4 + 3];

			er = (r - palette[idx].r) * src_a / 255;
			eg = (g - palette[idx].g) * src_a / 255;
			eb = (b - palette[idx].b) * src_a / 255;
			ea = a - palette[idx].a;

			/* Distribute error to neighbors.
			 * Direction-aware for serpentine scanning.
			 */
			right = x_step * 4;

			/* Right (or left if reverse): 7/16.
			 */
			err_cur[px + right + 0] += er * 7;
			err_cur[px + right + 1] += eg * 7;
			err_cur[px + right + 2] += eb * 7;
			err_cur[px + right + 3] += ea * 7;

			/* Below-opposite: 3/16.
			 */
			err_next[px - right + 0] += er * 3;
			err_next[px - right + 1] += eg * 3;
			err_next[px - right + 2] += eb * 3;
			err_next[px - right + 3] += ea * 3;

			/* Below: 5/16.
			 */
			err_next[px + 0] += er * 5;
			err_next[px + 1] += eg * 5;
			err_next[px + 2] += eb * 5;
			err_next[px + 3] += ea * 5;

			/* Below-same: 1/16.
			 */
			err_next[px + right + 0] += er;
			err_next[px + right + 1] += eg;
			err_next[px + right + 2] += eb;
			err_next[px + right + 3] += ea;
		}
	}

	g_free(err_next);
	g_free(err_cur);
}

static int
wu_quantise_image(VipsImage *in,
	VipsImage **index_out, VipsImage **palette_out,
	int colours, double dither)
{
	WuHist *hist;
	WuBox *boxes;
	PaletteEntry *palette;
	VipsPel *nearest_map;
	VipsImage *index;
	VipsImage *palette_img;
	VipsPel *p;
	int n_colors;
	int stride;
	int i;

	if (colours < 2)
		colours = 2;
	if (colours > MAX_COLORS)
		colours = MAX_COLORS;

	stride = VIPS_IMAGE_SIZEOF_LINE(in);

	/* Build 4D RGBA histogram.
	 */
	hist = wu_hist_new();
	wu_build_histogram(hist,
		VIPS_IMAGE_ADDR(in, 0, 0),
		in->Xsize, in->Ysize, stride);
	wu_cumulate_moments(hist);

	/* Partition.
	 */
	boxes = g_new(WuBox, colours);
	n_colors = wu_partition(hist, boxes, colours);

	/* Extract initial palette from Wu box centroids.
	 */
	palette = g_new(PaletteEntry, n_colors);
	for (i = 0; i < n_colors; i++)
		wu_box_color(hist, &boxes[i], &palette[i]);

	wu_hist_free(hist);
	g_free(boxes);

	/* Build nearest-color lookup map: for each quantized cell,
	 * find the palette entry with minimum Euclidean distance.
	 */
	nearest_map = g_new(VipsPel, CACHE_SIZE);
	build_nearest_map(palette, n_colors, nearest_map);

	/* Create index image.
	 */
	index = vips_image_new_memory();
	vips_image_init_fields(index,
		in->Xsize, in->Ysize, 1, VIPS_FORMAT_UCHAR,
		VIPS_CODING_NONE, VIPS_INTERPRETATION_B_W, 1.0, 1.0);

	if (vips_image_write_prepare(index)) {
		VIPS_UNREF(index);
		g_free(palette);
		g_free(nearest_map);
		return -1;
	}

	/* Remap pixels.
	 */
	if (dither > 0.0)
		remap_dither(
			VIPS_IMAGE_ADDR(in, 0, 0),
			VIPS_IMAGE_ADDR(index, 0, 0),
			in->Xsize, in->Ysize, stride,
			nearest_map, palette, dither);
	else
		remap_centroid(
			VIPS_IMAGE_ADDR(in, 0, 0),
			VIPS_IMAGE_ADDR(index, 0, 0),
			in->Xsize, in->Ysize, stride,
			nearest_map);

	g_free(nearest_map);

	/* Build palette image.
	 */
	palette_img = vips_image_new_memory();
	vips_image_init_fields(palette_img, n_colors, 1, 4,
		VIPS_FORMAT_UCHAR, VIPS_CODING_NONE,
		VIPS_INTERPRETATION_sRGB, 1.0, 1.0);

	if (vips_image_write_prepare(palette_img)) {
		VIPS_UNREF(index);
		VIPS_UNREF(palette_img);
		g_free(palette);
		return -1;
	}

	p = VIPS_IMAGE_ADDR(palette_img, 0, 0);
	for (i = 0; i < n_colors; i++) {
		p[0] = palette[i].r;
		p[1] = palette[i].g;
		p[2] = palette[i].b;
		p[3] = palette[i].a;
		p += 4;
	}

	g_free(palette);

	*index_out = index;
	*palette_out = palette_img;

	return 0;
}

/* ---- Public entry point ---- */

int
vips__builtin_quantise_image(VipsImage *in,
	VipsImage **index_out, VipsImage **palette_out,
	int colours, double dither)
{
	return wu_quantise_image(in, index_out, palette_out,
		colours, dither);
}

#endif /*!HAVE_QUANTIZATION*/
