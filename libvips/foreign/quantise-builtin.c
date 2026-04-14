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

/* Maximum palette size.
 */
#define MAX_COLORS 256

/* Pack RGBA bytes into a guint32 key for hash lookup.
 * Cast to guint32 before shifting to avoid signed-int overflow UB
 * when a >= 128.
 */
#define PACK_RGBA(r, g, b, a) \
	((guint32)(r) | ((guint32)(g) << 8) | \
	 ((guint32)(b) << 16) | ((guint32)(a) << 24))

/* Internal palette entry: all channels in 10-bit perceptual
 * space (perceptual_fwd output, 0..PERCEPTUAL_RANGE).
 */
typedef struct {
	int r, g, b, a;
} PaletteEntry;

/* Perceptual tuning for Wu's quantizer.
 *
 * Gamma LUT: maps sRGB byte values to a space where variance-based
 * splitting better matches human vision. sRGB already provides
 * ~perceptual uniformity; the exponent 1.25 ≈ 0.57/0.4545 slightly
 * pulls back its shadow expansion, matching libimagequant's internal
 * gamma (empirically tuned by kornelski/pngquant).
 * Alpha is left linear — transparency is not perceptual.
 *
 * Channel weights: applied to squared-difference distance in
 * splitting priority, gain, and nearest-colour map. Green dominates
 * (human vision most sensitive), red above blue (cone population),
 * alpha moderate.
 */
#define W_R 4
#define W_G 9
#define W_B 3
#define W_A 5

#define PERCEPTUAL_GAMMA 1.25
#define PERCEPTUAL_RANGE 1023
#define KMEANS_PASSES 9
#define DITHER_ERROR_THRESHOLD 38
#define DITHER_MAX_SHIFT 41

/* 10-bit perceptual space: 256 sRGB inputs → 1024 perceptual outputs.
 * Zero collisions (all 256 inputs produce distinct outputs), giving
 * 4× finer centroids, distances, and dither error computation than
 * 8-bit. Inverse maps 1024 perceptual values back to 8-bit sRGB.
 */
static int perceptual_fwd[256];
static VipsPel perceptual_inv[PERCEPTUAL_RANGE + 1];

static void *
perceptual_lut_build(void *client)
{
	int i;

	for (i = 0; i < 256; i++)
		perceptual_fwd[i] =
			(int) (pow(i / 255.0, PERCEPTUAL_GAMMA) *
			PERCEPTUAL_RANGE + 0.5);

	for (i = 0; i <= PERCEPTUAL_RANGE; i++)
		perceptual_inv[i] =
			(VipsPel) (pow((double) i / PERCEPTUAL_RANGE,
			1.0 / PERCEPTUAL_GAMMA) * 255.0 + 0.5);

	return NULL;
}

static GOnce perceptual_lut_once = G_ONCE_INIT;

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

/* Dither remap grid: 6-bit RGB + 5-bit alpha.
 * 16x denser than the coarse nearest map, 8 MB.
 * Keeps the hot remap path to a single table lookup per pixel.
 */
#define DITHER_MAP_RS 64
#define DITHER_MAP_AS 32
#define DITHER_MAP_SIZE \
	(DITHER_MAP_RS * DITHER_MAP_RS * DITHER_MAP_RS * DITHER_MAP_AS)

#define IND(r, g, b, a) \
	((r) * HIST_SR + (g) * HIST_SG + (b) * HIST_SB + (a))

/* Box map index: 5-bit R, 5-bit G, 5-bit B, 4-bit A = 19 bits.
 */
#define BM(r, g, b, a) \
	(((r) << 14) | ((g) << 9) | ((b) << 4) | (a))

#define DBM(r, g, b, a) \
	(((r) << 17) | ((g) << 11) | ((b) << 5) | (a))

typedef struct {
	int r0, r1, g0, g1, b0, b1, a0, a1;
} WuBox;

/* Compact representation of a non-empty histogram cell for k-means.
 * Built during histogram construction, avoids copying the full 24 MB
 * histogram and eliminates iteration over empty cells.
 */
typedef struct {
	int bm;			/* BM() index for nearest_map lookup */
	gint64 wt;		/* pixel count */
	gint64 mr, mg, mb, ma;	/* perceptual RGB + linear alpha sums */
} HistCell;

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

	return (double) w * (W_R * dr * dr + W_G * dg * dg +
		W_B * db * db + W_A * da * da);
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

		gain = (W_R * (double) half_r * half_r +
				W_G * (double) half_g * half_g +
				W_B * (double) half_bv * half_bv +
				W_A * (double) half_a * half_a) /
			(double) half_w;

		other_r = whole_r - half_r;
		other_g = whole_g - half_g;
		other_bv = whole_bv - half_bv;
		other_a = whole_a - half_a;

		gain += (W_R * (double) other_r * other_r +
				W_G * (double) other_g * other_g +
				W_B * (double) other_bv * other_bv +
				W_A * (double) other_a * other_a) /
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
		out->a = PERCEPTUAL_RANGE;
		return;
	}

	/* Centroids stored in perceptual space directly.
	 */
	out->r = VIPS_CLIP(0,
		(int) ((vol(h->mr, b) + w / 2) / w), PERCEPTUAL_RANGE);
	out->g = VIPS_CLIP(0,
		(int) ((vol(h->mg, b) + w / 2) / w), PERCEPTUAL_RANGE);
	out->b = VIPS_CLIP(0,
		(int) ((vol(h->mb, b) + w / 2) / w), PERCEPTUAL_RANGE);

	out->a = VIPS_CLIP(0,
		(int) ((vol(h->ma, b) + w / 2) / w), PERCEPTUAL_RANGE);
}

/* Palette entry with perceptual values, sorted by green for
 * sort-means acceleration in build_nearest_map.
 */
typedef struct {
	int pg;		/* perceptual green (sort key) */
	int pr;		/* perceptual red */
	int pb;		/* perceptual blue */
	int alpha;		/* perceptual alpha */
	int idx;		/* original palette index */
} SortedEntry;

static int
sorted_entry_cmp(const void *a, const void *b)
{
	return ((const SortedEntry *) a)->pg -
		((const SortedEntry *) b)->pg;
}

static inline int
cell_palette_dist(int rv, int gv, int bv, int av,
	const PaletteEntry *pe);

static void
build_sorted_palette(const PaletteEntry *palette, int n_colors,
	SortedEntry sorted[MAX_COLORS])
{
	int i;

	for (i = 0; i < n_colors; i++) {
		sorted[i].pg = palette[i].g;
		sorted[i].pr = palette[i].r;
		sorted[i].pb = palette[i].b;
		sorted[i].alpha = palette[i].a;
		sorted[i].idx = i;
	}
	qsort(sorted, n_colors, sizeof(SortedEntry), sorted_entry_cmp);
}

/* Try a single sorted palette entry against a query cell.
 * Returns TRUE if the entry was within green pruning distance
 * (caller should keep expanding), FALSE to stop that direction.
 */
static inline gboolean
try_candidate(const SortedEntry *entry,
	int rv, int gv, int bv, int av,
	int *best_dist, int *best)
{
	int dg = gv - entry->pg;
	int d = W_G * dg * dg;

	if (d >= *best_dist)
		return FALSE;

	int da = av - entry->alpha;
	d += W_A * da * da;
	if (d < *best_dist) {
		int dr = rv - entry->pr;
		d += W_R * dr * dr;
		if (d < *best_dist) {
			int db = bv - entry->pb;
			d += W_B * db * db;
			if (d < *best_dist) {
				*best_dist = d;
				*best = entry->idx;
			}
		}
	}

	return TRUE;
}

/* Build nearest-color lookup map using sort-means: palette entries are
 * sorted by perceptual green (highest-weighted channel). For each cell,
 * binary-search to the closest green value, then expand outward. Stop
 * expanding a direction when the green-only distance exceeds the best
 * full distance found so far. Typically visits ~10 entries instead of
 * all 256.
 */
static void
build_nearest_map(const PaletteEntry *palette, int n_colors,
	VipsPel *map)
{
	int r, g, b, a;
	SortedEntry sorted[MAX_COLORS];

	build_sorted_palette(palette, n_colors, sorted);

	for (r = 0; r < 32; r++) {
		int rv = perceptual_fwd[r * 8 + 4];

		for (g = 0; g < 32; g++) {
			int gv = perceptual_fwd[g * 8 + 4];

			/* Binary search for the closest green value.
			 */
			int lo = 0, hi = n_colors;

			while (lo < hi) {
				int mid = (lo + hi) / 2;
				if (sorted[mid].pg < gv)
					lo = mid + 1;
				else
					hi = mid;
			}

			for (b = 0; b < 32; b++) {
				int bv = perceptual_fwd[b * 8 + 4];

				for (a = 0; a < 16; a++) {
					int av = perceptual_fwd[a * 16 + 8];
					int best = 0;
					int best_dist = INT_MAX;
					int left = lo - 1;
					int right = lo;

					while (left >= 0 || right < n_colors) {
						if (right < n_colors) {
							if (!try_candidate(
								&sorted[right],
								rv, gv, bv, av,
								&best_dist,
								&best))
								right = n_colors;
							else
								right++;
						}

						if (left >= 0) {
							if (!try_candidate(
								&sorted[left],
								rv, gv, bv, av,
								&best_dist,
								&best))
								left = -1;
							else
								left--;
						}
					}

					map[BM(r, g, b, a)] =
						(VipsPel) best;
				}
			}
		}
	}
}

/* Build a denser remap grid for the dither path. This replaces the
 * per-pixel adjacent-bin refinement with a single precomputed lookup.
 */
static void
build_dither_map(const PaletteEntry *palette, const VipsPel *coarse_map,
	VipsPel *map)
{
	int r, g, b, a;

	for (r = 0; r < 32; r++)
		for (g = 0; g < 32; g++)
				for (b = 0; b < 32; b++)
					for (a = 0; a < 16; a++) {
						VipsPel candidates[9];
						int bm = BM(r, g, b, a);
						VipsPel idx = coarse_map[bm];
						int n_candidates = 1;
						gboolean boundary = FALSE;
						int sr, sg, sb, sa;

						candidates[0] = idx;

#define ADD_CANDIDATE_IF_DIFFERENT(cand) \
	do { \
		VipsPel value = (cand); \
		if (value != idx) { \
			int j; \
			boundary = TRUE; \
			for (j = 1; j < n_candidates; j++) \
				if (candidates[j] == value) \
					break; \
			if (j == n_candidates) \
				candidates[n_candidates++] = value; \
		} \
	} while (0)

						if (r > 0)
							ADD_CANDIDATE_IF_DIFFERENT(
								coarse_map[BM(
									r - 1, g, b, a)]);
						if (r < 31)
							ADD_CANDIDATE_IF_DIFFERENT(
								coarse_map[BM(
									r + 1, g, b, a)]);
						if (g > 0)
							ADD_CANDIDATE_IF_DIFFERENT(
								coarse_map[BM(
									r, g - 1, b, a)]);
						if (g < 31)
							ADD_CANDIDATE_IF_DIFFERENT(
								coarse_map[BM(
									r, g + 1, b, a)]);
						if (b > 0)
							ADD_CANDIDATE_IF_DIFFERENT(
								coarse_map[BM(
									r, g, b - 1, a)]);
						if (b < 31)
							ADD_CANDIDATE_IF_DIFFERENT(
								coarse_map[BM(
									r, g, b + 1, a)]);
						if (a > 0)
							ADD_CANDIDATE_IF_DIFFERENT(
								coarse_map[BM(
									r, g, b, a - 1)]);
						if (a < 15)
							ADD_CANDIDATE_IF_DIFFERENT(
								coarse_map[BM(
									r, g, b, a + 1)]);

#undef ADD_CANDIDATE_IF_DIFFERENT

						if (!boundary) {
							for (sr = 0; sr < 2; sr++)
								for (sg = 0; sg < 2; sg++)
									for (sb = 0; sb < 2; sb++)
										for (sa = 0; sa < 2; sa++)
											map[DBM(
												r * 2 + sr,
												g * 2 + sg,
												b * 2 + sb,
												a * 2 + sa)] = idx;
							continue;
						}

						for (sr = 0; sr < 2; sr++) {
							int rv = perceptual_fwd[
								r * 8 + (sr ? 6 : 2)];

							for (sg = 0; sg < 2; sg++) {
								int gv = perceptual_fwd[
									g * 8 + (sg ? 6 : 2)];

								for (sb = 0; sb < 2; sb++) {
									int bv = perceptual_fwd[
										b * 8 + (sb ? 6 : 2)];

									for (sa = 0; sa < 2; sa++) {
										int av = perceptual_fwd[
											a * 16 + (sa ? 12 : 4)];
										int best = idx;
										int best_dist =
											cell_palette_dist(
											rv, gv, bv, av,
											&palette[idx]);
										int i;

										for (i = 1;
											i < n_candidates;
											i++) {
											int d =
											cell_palette_dist(
												rv, gv, bv,
												av,
												&palette[
												candidates[
												i]]);
											if (d < best_dist) {
												best_dist = d;
												best = candidates[i];
											}
										}

										map[DBM(
											r * 2 + sr,
											g * 2 + sg,
											b * 2 + sb,
											a * 2 + sa)] =
											(VipsPel) best;
									}
								}
							}
						}
					}
}

/* Compute weighted perceptual distance² between a cell and a palette entry.
 */
static inline int
cell_palette_dist(int rv, int gv, int bv, int av,
	const PaletteEntry *pe)
{
	int dr = rv - pe->r;
	int dg = gv - pe->g;
	int db = bv - pe->b;
	int da = av - pe->a;

	return W_R * dr * dr + W_G * dg * dg +
		W_B * db * db + W_A * da * da;
}

/* K-means palette refinement with selective nearest-map rebuild.
 *
 * Uses the raw (pre-cumulated) histogram for exact moment sums.
 * After each pass, tracks which centers moved; cells assigned to
 * stationary centers are skipped in the nearest-map rebuild.
 * With integer sRGB palettes, centers either stay put or jump
 * by at least one unit, so this simple check skips 80-90% of
 * cells in later passes — matching the practical benefit of full
 * Hamerly bounds without the overhead.
 *
 * max_passes: number of k-means iterations to run.
 * Returns the total number of centroid changes across all passes.
 */
static int
kmeans_hamerly(const HistCell *cells, int n_cells,
	PaletteEntry *palette, int n_colors,
	VipsPel *nearest_map, gboolean has_transparent,
	int max_passes)
{
	gint64 sum_r[MAX_COLORS], sum_g[MAX_COLORS];
	gint64 sum_b[MAX_COLORS], sum_a[MAX_COLORS];
	gint64 count[MAX_COLORS];
	/* Per-center squared movement distance after each pass.
	 */
	int center_delta[MAX_COLORS];
	int first_color;
	int total_changed;
	int pass, i;

	first_color = has_transparent ? 1 : 0;
	total_changed = 0;

	/* Seed center_delta so pass 0 checks all cells
	 * without a separate full nearest_map build.
	 * Must cover MAX_COLORS since nearest_map is
	 * uninitialized and old_idx can be any byte value.
	 */
	for (i = 0; i < MAX_COLORS; i++)
		center_delta[i] = 1;

	for (pass = 0; pass < max_passes; pass++) {
		int changed;
		int max_delta;

		{
			/* Check convergence (pass 0 always proceeds
			 * due to the seeded center_delta).
			 */
			max_delta = 0;
			for (i = first_color; i < n_colors; i++)
				if (center_delta[i] > max_delta)
					max_delta = center_delta[i];

			if (max_delta == 0)
				break;

			/* Build sort-means index for the palette.
			 */
			SortedEntry sorted[MAX_COLORS];
			build_sorted_palette(palette, n_colors,
				sorted);

			/* Only recheck cells that exist in the image
			 * and whose assigned center moved. Full 524K
			 * rebuild deferred to after k-means converges.
			 */
			for (i = 0; i < n_cells; i++) {
				int bm = cells[i].bm;
				int old_idx = nearest_map[bm];
				int rv, gv, bv, av;
				int best, best_dist;
				int lo, hi, left, right;

				if (center_delta[old_idx] == 0)
					continue;

				rv = perceptual_fwd[((bm >> 14) & 0x1f) * 8 + 4];
				gv = perceptual_fwd[((bm >> 9) & 0x1f) * 8 + 4];
				bv = perceptual_fwd[((bm >> 4) & 0x1f) * 8 + 4];
				av = perceptual_fwd[(bm & 0x0f) * 16 + 8];

				best = old_idx;
				best_dist = cell_palette_dist(
					rv, gv, bv, av,
					&palette[old_idx]);

				/* Binary search for sort-means.
				 */
				lo = 0;
				hi = n_colors;
				while (lo < hi) {
					int mid = (lo + hi) / 2;
					if (sorted[mid].pg < gv)
						lo = mid + 1;
					else
						hi = mid;
				}

				left = lo - 1;
				right = lo;
				while (left >= 0 || right < n_colors) {
					if (right < n_colors) {
						if (!try_candidate(
							&sorted[right],
							rv, gv, bv, av,
							&best_dist, &best))
							right = n_colors;
						else
							right++;
					}
					if (left >= 0) {
						if (!try_candidate(
							&sorted[left],
							rv, gv, bv, av,
							&best_dist, &best))
							left = -1;
						else
							left--;
					}
				}

				nearest_map[bm] = (VipsPel) best;
			}
		}

		/* Accumulate moments from compact cell list.
		 */
		memset(sum_r, 0, sizeof(sum_r));
		memset(sum_g, 0, sizeof(sum_g));
		memset(sum_b, 0, sizeof(sum_b));
		memset(sum_a, 0, sizeof(sum_a));
		memset(count, 0, sizeof(count));

		for (i = 0; i < n_cells; i++) {
			int idx = nearest_map[cells[i].bm];

			sum_r[idx] += cells[i].mr;
			sum_g[idx] += cells[i].mg;
			sum_b[idx] += cells[i].mb;
			sum_a[idx] += cells[i].ma;
			count[idx] += cells[i].wt;
		}

		/* Recompute centroids, track movements.
		 */
		changed = 0;
		for (i = first_color; i < n_colors; i++) {
			center_delta[i] = 0;

			if (count[i] > 0) {
				int nr = VIPS_CLIP(0,
					(int) ((sum_r[i] + count[i] / 2) / count[i]),
					PERCEPTUAL_RANGE);
				int ng = VIPS_CLIP(0,
					(int) ((sum_g[i] + count[i] / 2) / count[i]),
					PERCEPTUAL_RANGE);
				int nb = VIPS_CLIP(0,
					(int) ((sum_b[i] + count[i] / 2) / count[i]),
					PERCEPTUAL_RANGE);
				int na = VIPS_CLIP(0,
					(int) ((sum_a[i] + count[i] / 2) / count[i]),
					PERCEPTUAL_RANGE);

				if (nr != palette[i].r || ng != palette[i].g ||
					nb != palette[i].b || na != palette[i].a) {
					int dr = nr - palette[i].r;
					int dg = ng - palette[i].g;
					int db = nb - palette[i].b;
					int da = na - palette[i].a;
					center_delta[i] = W_R * dr * dr +
						W_G * dg * dg +
						W_B * db * db +
						W_A * da * da;

					palette[i].r = nr;
					palette[i].g = ng;
					palette[i].b = nb;
					palette[i].a = na;
					changed++;
				}
			}
		}

		total_changed += changed;

		if (changed == 0)
			break;
	}

	return total_changed;
}

/* No-dither remap for a single row: nearest-map lookup only.
 * q may be NULL to skip output.
 */
static inline void
remap_row_nearest(const VipsPel *p, VipsPel *q, int width,
	const VipsPel *nearest_map, gboolean has_transparent)
{
	int x;

	if (!q)
		return;

	for (x = 0; x < width; x++) {
		if (has_transparent && p[3] == 0)
			q[x] = 0;
		else
			q[x] = nearest_map[BM(
				p[0] >> 3, p[1] >> 3,
				p[2] >> 3, p[3] >> 4)];
		p += 4;
	}
}

/* Floyd-Steinberg dither for a single row. Shared by the streaming
 * callback (wu_remap_stream_cb) and the parallel strip thread
 * (wu_dither_strip_fn). q may be NULL to run dithering without
 * writing output.
 */
static inline void
dither_row(const VipsPel *p, VipsPel *q, int width,
	gint16 *err_cur, gint16 *err_next,
	int ds, gboolean full_strength,
	const PaletteEntry *palette, const VipsPel *nearest_map,
	gboolean has_transparent, int row_y)
{
	gboolean forward = (row_y & 1) == 0;
	int x_start = forward ? 0 : width - 1;
	int x_end = forward ? width : -1;
	int x_step = forward ? 1 : -1;
	int carry_r = 0, carry_g = 0;
	int carry_b = 0, carry_a = 0;
	int x;

	for (x = x_start; x != x_end; x += x_step) {
		int px = (x + 1) * 4;

		if (has_transparent && p[x * 4 + 3] == 0) {
			if (q) q[x] = 0;
			carry_r = carry_g = 0;
			carry_b = carry_a = 0;
			continue;
		}

		int pr, pg, pb, a_val;

		/* Clamp inherited error to prevent edge
		 * contamination: large accumulated error at a
		 * pixel means the neighbors were dithering a
		 * different color (edge crossing). Clamping the
		 * error rather than the result preserves the
		 * feedback loop's self-correction ability.
		 */
		int ie_r = VIPS_CLIP(-DITHER_MAX_SHIFT * 16,
			err_cur[px + 0] + carry_r,
			DITHER_MAX_SHIFT * 16);
		int ie_g = VIPS_CLIP(-DITHER_MAX_SHIFT * 16,
			err_cur[px + 1] + carry_g,
			DITHER_MAX_SHIFT * 16);
		int ie_b = VIPS_CLIP(-DITHER_MAX_SHIFT * 16,
			err_cur[px + 2] + carry_b,
			DITHER_MAX_SHIFT * 16);
		int ie_a = VIPS_CLIP(-DITHER_MAX_SHIFT * 16,
			err_cur[px + 3] + carry_a,
			DITHER_MAX_SHIFT * 16);

		if (full_strength) {
			pr = perceptual_fwd[p[x * 4 + 0]] +
				(ie_r + 8) / 16;
			pg = perceptual_fwd[p[x * 4 + 1]] +
				(ie_g + 8) / 16;
			pb = perceptual_fwd[p[x * 4 + 2]] +
				(ie_b + 8) / 16;
			a_val = perceptual_fwd[p[x * 4 + 3]] +
				(ie_a + 8) / 16;
		}
		else {
			pr = perceptual_fwd[p[x * 4 + 0]] +
				(ie_r * ds + 128) / 256;
			pg = perceptual_fwd[p[x * 4 + 1]] +
				(ie_g * ds + 128) / 256;
			pb = perceptual_fwd[p[x * 4 + 2]] +
				(ie_b * ds + 128) / 256;
			a_val = perceptual_fwd[p[x * 4 + 3]] +
				(ie_a * ds + 128) / 256;
		}

		int r, g, b, idx, er, eg, eb, ea;
		int right, src_a, err_mag;

		pr = VIPS_CLIP(0, pr, PERCEPTUAL_RANGE);
		pg = VIPS_CLIP(0, pg, PERCEPTUAL_RANGE);
		pb = VIPS_CLIP(0, pb, PERCEPTUAL_RANGE);
		a_val = VIPS_CLIP(0, a_val, PERCEPTUAL_RANGE);

		r = perceptual_inv[pr];
		g = perceptual_inv[pg];
		b = perceptual_inv[pb];

		idx = nearest_map[DBM(
			r >> 2, g >> 2,
			b >> 2,
			perceptual_inv[a_val] >> 3)];

		if (q) q[x] = (VipsPel) idx;

		src_a = p[x * 4 + 3];
		er = ((pr - palette[idx].r) * src_a) >> 8;
		eg = ((pg - palette[idx].g) * src_a) >> 8;
		eb = ((pb - palette[idx].b) * src_a) >> 8;
		ea = a_val - palette[idx].a;

		/* Dampen large errors to prevent cascading
		 * overshoot (dark/bright dot artifacts).
		 * RGB L1 norm with 3/4 scaling via shift.
		 */
		err_mag = VIPS_ABS(er) + VIPS_ABS(eg) +
			VIPS_ABS(eb);
		if (err_mag > DITHER_ERROR_THRESHOLD) {
			er = er - (er >> 2);
			eg = eg - (eg >> 2);
			eb = eb - (eb >> 2);
			ea = ea - (ea >> 2);
		}

		carry_r = er * 7;
		carry_g = eg * 7;
		carry_b = eb * 7;
		carry_a = ea * 7;

		right = x_step * 4;

		err_next[px - right + 0] += er * 3;
		err_next[px - right + 1] += eg * 3;
		err_next[px - right + 2] += eb * 3;
		err_next[px - right + 3] += ea * 3;

		err_next[px + 0] += er * 5;
		err_next[px + 1] += eg * 5;
		err_next[px + 2] += eb * 5;
		err_next[px + 3] += ea * 5;

		err_next[px + right + 0] += er;
		err_next[px + right + 1] += eg;
		err_next[px + right + 2] += eb;
		err_next[px + right + 3] += ea;
	}
}

/* ---- Streaming API via vips_sink_disc ---- */

/* State for streaming histogram build.
 */
typedef struct {
	WuHist *hist;
	HistCell *cells;
	int n_cells;
	int cells_alloc;
	gboolean has_transparent;
	gboolean collect_cells;

	/* Few-colours detection: track exact unique RGBA values.
	 * Abandoned (set NULL) once count exceeds max_colors.
	 */
	GHashTable *exact;
	int n_exact;
	int max_colors;
} WuHistStreamState;

/* Exact remap callback for few-colours fast path.
 * Uses hash lookup instead of binned nearest_map.
 */
typedef struct {
	VipsImage *index;
	GHashTable *exact;
	gboolean has_transparent;
} WuExactRemapState;

static int
wu_exact_remap_cb(VipsRegion *region, VipsRect *area, void *a)
{
	WuExactRemapState *state = (WuExactRemapState *) a;
	int lsk = VIPS_REGION_LSKIP(region);
	int y;

	VipsPel *line = VIPS_REGION_ADDR(region, area->left, area->top);

	for (y = 0; y < area->height; y++) {
		const VipsPel *p = line;
		VipsPel *q = VIPS_IMAGE_ADDR(state->index, 0,
			area->top + y);
		int x;

		for (x = 0; x < area->width; x++) {
			if (state->has_transparent && p[3] == 0)
				q[x] = 0;
			else {
				guint32 rgba = PACK_RGBA(
					p[0], p[1], p[2], p[3]);

				q[x] = (VipsPel) GPOINTER_TO_INT(
					g_hash_table_lookup(state->exact,
						GUINT_TO_POINTER(rgba)));
			}

			p += 4;
		}

		line += lsk;
	}

	return 0;
}

/* State for streaming F-S remap.
 */
typedef struct {
	VipsImage *index;
	const VipsPel *nearest_map;
	const PaletteEntry *palette;
	gboolean has_transparent;

	gint16 *err_cur;
	gint16 *err_next;
	int ds;
	int row_count;	/* tracks global y for serpentine */
} WuRemapStreamState;

static int
wu_remap_stream_cb(VipsRegion *region, VipsRect *area, void *a)
{
	WuRemapStreamState *state = (WuRemapStreamState *) a;
	int lsk = VIPS_REGION_LSKIP(region);
	int width = area->width;
	gboolean full_strength = (state->ds == 16);
	int y;

	VipsPel *line = VIPS_REGION_ADDR(region, area->left, area->top);

	for (y = 0; y < area->height; y++) {
		const VipsPel *p = line;
		VipsPel *q = VIPS_IMAGE_ADDR(state->index, 0,
			area->top + y);
		gint16 *tmp;

		if (!state->err_cur && !state->err_next) {
			remap_row_nearest(p, q, width,
				state->nearest_map,
				state->has_transparent);
		}
		else {
			/* Swap error rows.
			 */
			tmp = state->err_cur;
			state->err_cur = state->err_next;
			state->err_next = tmp;
			memset(state->err_next, 0,
				(width + 2) * 4 * sizeof(gint16));

			dither_row(p, q, width,
				state->err_cur, state->err_next,
				state->ds, full_strength,
				state->palette, state->nearest_map,
				state->has_transparent,
				state->row_count);
		}

		state->row_count++;
		line += lsk;
	}

	return 0;
}

/* Stream-based exact remap for the few-colours fast path.
 */
int
vips__builtin_exact_remap_stream(VipsImage *in, VipsImage *index,
	GHashTable *exact_map, gboolean has_transparent)
{
	WuExactRemapState state;
	int result;

	state.index = index;
	state.exact = exact_map;
	state.has_transparent = has_transparent;

	result = vips_sink_disc(in, wu_exact_remap_cb, &state);

	return result;
}

/* Sparse per-thread histogram: GHashTable mapping BM bin index
 * to HistCell. Replaces the full 24 MB dense WuHist per thread
 * with ~2K-50K cells depending on image complexity. Less cache
 * pressure than dense arrays at high thread counts.
 */
typedef struct {
	GHashTable *ht;
	int n_cells;
} SparseHist;

static SparseHist *
sparse_hist_new(void)
{
	SparseHist *sh = g_new(SparseHist, 1);

	sh->ht = g_hash_table_new_full(g_direct_hash, g_direct_equal,
		NULL, g_free);
	sh->n_cells = 0;

	return sh;
}

static void
sparse_hist_free(SparseHist *sh)
{
	g_hash_table_destroy(sh->ht);
	g_free(sh);
}

/* Accumulate a region into a sparse per-thread histogram,
 * detecting transparency and tracking exact unique colours.
 */
static inline void
sparse_hist_accumulate(const VipsPel *line, int width, int height,
	int lsk, SparseHist *sh, gboolean *has_transparent,
	GHashTable **exact, int *n_exact, int max_colors)
{
	int y;

	for (y = 0; y < height; y++) {
		const VipsPel *p = line;
		int x;

		for (x = 0; x < width; x++) {
			if (p[3] == 0) {
				*has_transparent = TRUE;
				p += 4;
				continue;
			}

			int bm = BM(p[0] >> 3, p[1] >> 3,
				p[2] >> 3, p[3] >> 4);
			gpointer key = GINT_TO_POINTER(bm);
			HistCell *cell = g_hash_table_lookup(
				sh->ht, key);

			if (!cell) {
				cell = g_new0(HistCell, 1);
				cell->bm = bm;
				g_hash_table_insert(sh->ht,
					key, cell);
				sh->n_cells++;
			}
			cell->wt++;
			cell->mr += perceptual_fwd[p[0]];
			cell->mg += perceptual_fwd[p[1]];
			cell->mb += perceptual_fwd[p[2]];
			cell->ma += perceptual_fwd[p[3]];

			if (*exact) {
				guint32 rgba = PACK_RGBA(
					p[0], p[1], p[2], p[3]);
				guint old_size =
					g_hash_table_size(*exact);

				g_hash_table_add(*exact,
					GUINT_TO_POINTER(rgba));

				if (g_hash_table_size(*exact) >
					old_size &&
					++*n_exact > max_colors) {
					g_hash_table_destroy(*exact);
					*exact = NULL;
				}
			}

			p += 4;
		}

		line += lsk;
	}
}

/* Merge one sparse histogram cell into the main dense histogram.
 */
static void
sparse_hist_merge_cb(gpointer key, gpointer value, gpointer user_data)
{
	HistCell *cell = (HistCell *) value;
	WuHist *h = (WuHist *) user_data;
	int bm = cell->bm;
	int ir = (bm >> 14) + 1;
	int ig = ((bm >> 9) & 0x1f) + 1;
	int ib = ((bm >> 4) & 0x1f) + 1;
	int ia = (bm & 0x0f) + 1;
	int idx = IND(ir, ig, ib, ia);

	h->wt[idx] += cell->wt;
	h->mr[idx] += cell->mr;
	h->mg[idx] += cell->mg;
	h->mb[idx] += cell->mb;
	h->ma[idx] += cell->ma;
}

/* Merge sparse per-thread histogram into main dense histogram.
 */
static void
sparse_hist_merge(const SparseHist *sh, WuHist *main)
{
	g_hash_table_foreach(sh->ht, sparse_hist_merge_cb, main);
}

/* Per-thread accumulator for threaded histogram build via vips_sink.
 */
typedef struct {
	WuHistStreamState *main;
	SparseHist *hist;
	gboolean has_transparent;
	GHashTable *exact;
	int n_exact;
} WuHistThread;

static void *
wu_hist_start(VipsImage *im, void *a, void *b)
{
	WuHistStreamState *main = (WuHistStreamState *) a;
	WuHistThread *thr = g_new(WuHistThread, 1);

	thr->main = main;
	thr->hist = sparse_hist_new();
	thr->has_transparent = FALSE;
	thr->exact = (main->exact)
		? g_hash_table_new(g_direct_hash, g_direct_equal)
		: NULL;
	thr->n_exact = 0;

	return thr;
}

static int
wu_hist_scan(VipsRegion *region, void *seq,
	void *a, void *b, gboolean *stop)
{
	WuHistThread *thr = (WuHistThread *) seq;
	VipsRect *area = &region->valid;

	sparse_hist_accumulate(
		VIPS_REGION_ADDR(region, area->left, area->top),
		area->width, area->height,
		VIPS_REGION_LSKIP(region),
		thr->hist, &thr->has_transparent,
		&thr->exact, &thr->n_exact, thr->main->max_colors);

	return 0;
}

static int
wu_hist_stop(void *seq, void *a, void *b)
{
	WuHistThread *thr = (WuHistThread *) seq;
	WuHistStreamState *main = thr->main;

	sparse_hist_merge(thr->hist, main->hist);

	if (thr->has_transparent)
		main->has_transparent = TRUE;

	if (main->exact && thr->exact) {
		GHashTableIter iter;
		gpointer key;

		g_hash_table_iter_init(&iter, thr->exact);
		while (g_hash_table_iter_next(&iter, &key, NULL)) {
			guint old_size = g_hash_table_size(main->exact);

			g_hash_table_add(main->exact, key);
			if (g_hash_table_size(main->exact) > old_size)
				main->n_exact++;
		}

		if (main->n_exact > main->max_colors) {
			g_hash_table_destroy(main->exact);
			main->exact = NULL;
		}
	}
	else if (main->exact && !thr->exact) {
		g_hash_table_destroy(main->exact);
		main->exact = NULL;
	}

	if (thr->exact)
		g_hash_table_destroy(thr->exact);

	sparse_hist_free(thr->hist);
	g_free(thr);

	return 0;
}

/* Stream-based palette generation: builds histogram (threaded for
 * large images), then runs Wu partition + k-means refinement.
 * Returns 0 on success, -1 on error.
 */
int
vips__builtin_quantise_stream(VipsImage *in,
	int max_colors, int effort,
	VipsQuantisePalette *palette_out,
	GHashTable **exact_map_out)
{
	WuHistStreamState state;
	WuHist *hist;
	WuBox *boxes;
	PaletteEntry *entries;
	gboolean has_transparent;
	int n_colors;
	int visible_colours;
	int i;

	*exact_map_out = NULL;

	if (max_colors < 1)
		max_colors = 1;
	if (max_colors > MAX_COLORS)
		max_colors = MAX_COLORS;

	VIPS_ONCE(&perceptual_lut_once, perceptual_lut_build, NULL);

	/* Pass 1: threaded histogram build via vips_sink. Each thread
	 * accumulates into a sparse GHashTable, merged into the main
	 * dense histogram at the end.
	 */
	state.hist = wu_hist_new();
	state.cells = NULL;
	state.n_cells = 0;
	state.cells_alloc = 0;
	state.has_transparent = FALSE;
	state.collect_cells = (KMEANS_PASSES > 0);
	state.exact = g_hash_table_new(g_direct_hash, g_direct_equal);
	state.n_exact = 0;
	state.max_colors = max_colors;

	if (vips_sink(in, wu_hist_start, wu_hist_scan,
			wu_hist_stop, &state, NULL)) {
		wu_hist_free(state.hist);
		g_free(state.cells);
		if (state.exact)
			g_hash_table_destroy(state.exact);
		return -1;
	}

	/* Collect occupied cells from the merged histogram
	 * (can't do per-thread because cells must be unique).
	 */
	if (state.collect_cells) {
		int r, g, b, a;

		for (r = 1; r < HIST_RS; r++)
		for (g = 1; g < HIST_RS; g++)
		for (b = 1; b < HIST_RS; b++)
		for (a = 1; a < HIST_AS; a++) {
			int idx = IND(r, g, b, a);

			if (state.hist->wt[idx] == 0)
				continue;

			if (state.n_cells >= state.cells_alloc) {
				state.cells_alloc =
					state.cells_alloc == 0
					? 4096
					: state.cells_alloc * 2;
				state.cells = g_renew(HistCell,
					state.cells,
					state.cells_alloc);
			}

			state.cells[state.n_cells].bm =
				BM(r - 1, g - 1, b - 1, a - 1);
			state.n_cells++;
		}
	}

	hist = state.hist;
	has_transparent = state.has_transparent;

	/* For max_colors==1 we can't afford to burn a slot on transparent:
	 * fold the transparent semantic into the single output entry. A
	 * fully-transparent image still collapses to (0,0,0,0).
	 */
	gboolean want_transparent_slot = has_transparent && max_colors > 1;

	/* Few-colours fast path: use exact sRGB values as palette.
	 * Store internally in perceptual space (via perceptual_fwd)
	 * so the palette is consistent with wu_box_color's output.
	 * The final output converts back to sRGB via perceptual_inv.
	 */
	if (state.exact) {
		GHashTableIter iter;
		gpointer key;
		int first = want_transparent_slot ? 1 : 0;

		n_colors = state.n_exact + first;

		/* max_colors==1 + fully-transparent image: emit a single
		 * (0,0,0,0) entry instead of the empty palette that the
		 * normal code path would produce.
		 */
		if (max_colors == 1 && has_transparent && n_colors == 0)
			n_colors = 1;

		entries = g_new(PaletteEntry, n_colors);

		if (want_transparent_slot ||
			(max_colors == 1 && has_transparent && state.n_exact == 0))
			entries[0] = (PaletteEntry) { 0, 0, 0, 0 };

		/* Build palette (sRGB) and RGBA→index map. */
		i = first;
		g_hash_table_iter_init(&iter, state.exact);
		while (g_hash_table_iter_next(&iter, &key, NULL)) {
			guint32 rgba = GPOINTER_TO_UINT(key);

			entries[i].r = rgba & 0xff;
			entries[i].g = (rgba >> 8) & 0xff;
			entries[i].b = (rgba >> 16) & 0xff;
			entries[i].a = (rgba >> 24) & 0xff;
			i++;
		}

		/* Replace hash set with RGBA→palette index map.
		 */
		g_hash_table_remove_all(state.exact);
		for (i = first; i < n_colors; i++) {
			guint32 rgba = PACK_RGBA(entries[i].r,
				entries[i].g, entries[i].b,
				entries[i].a);
			g_hash_table_insert(state.exact,
				GUINT_TO_POINTER(rgba),
				GINT_TO_POINTER(i));
		}
		if (want_transparent_slot)
			g_hash_table_insert(state.exact,
				GUINT_TO_POINTER(0),
				GINT_TO_POINTER(0));

		wu_hist_free(hist);
		g_free(state.cells);

		/* Fill output palette (sRGB).
		 */
		palette_out->count = n_colors;
		for (i = 0; i < n_colors; i++) {
			palette_out->entries[i].r = entries[i].r;
			palette_out->entries[i].g = entries[i].g;
			palette_out->entries[i].b = entries[i].b;
			palette_out->entries[i].a = entries[i].a;
		}

		g_free(entries);

		/* Return the hash map for exact remap.
		 * Caller must free with g_hash_table_destroy.
		 */
		*exact_map_out = state.exact;

		return 0;
	}

	/* Normal path: Wu partition + k-means.
	 */
	if (state.collect_cells) {
		for (i = 0; i < state.n_cells; i++) {
			int r = (state.cells[i].bm >> 14) + 1;
			int g = ((state.cells[i].bm >> 9) & 0x1f) + 1;
			int b = ((state.cells[i].bm >> 4) & 0x1f) + 1;
			int a = (state.cells[i].bm & 0x0f) + 1;
			int idx = IND(r, g, b, a);

			state.cells[i].wt = hist->wt[idx];
			state.cells[i].mr = hist->mr[idx];
			state.cells[i].mg = hist->mg[idx];
			state.cells[i].mb = hist->mb[idx];
			state.cells[i].ma = hist->ma[idx];
		}
	}

	wu_cumulate_moments(hist);

	visible_colours = want_transparent_slot
		? VIPS_MAX(max_colors - 1, 1)
		: max_colors;

	boxes = g_new(WuBox, visible_colours);
	n_colors = wu_partition(hist, boxes, visible_colours);

	entries = g_new(PaletteEntry, n_colors + (want_transparent_slot ? 1 : 0));
	if (want_transparent_slot)
		entries[0] = (PaletteEntry) { 0, 0, 0, 0 };
	for (i = 0; i < n_colors; i++)
		wu_box_color(hist, &boxes[i],
			&entries[i + (want_transparent_slot ? 1 : 0)]);

	/* max_colors==1 + fully-transparent: wu_box_color's empty-box fallback
	 * is (0, 0, 0, PERCEPTUAL_RANGE) which inverts to opaque black. Force
	 * (0,0,0,0) so the single entry matches the transparent semantic.
	 */
	if (max_colors == 1 && has_transparent && n_colors == 1 &&
		vol(hist->wt, &boxes[0]) == 0)
		entries[0] = (PaletteEntry) { 0, 0, 0, 0 };

	if (want_transparent_slot)
		n_colors++;

	/* K-means refinement. Skip for n_colors==1: Wu's single box already
	 * produced the exact perceptual mean, and kmeans_hamerly would loop
	 * uselessly assigning every cell to the only centroid.
	 */
	if (KMEANS_PASSES > 0 && n_colors > 1) {
		VipsPel *nearest_map = g_new(VipsPel, CACHE_SIZE);

		kmeans_hamerly(state.cells, state.n_cells,
			entries, n_colors,
			nearest_map, has_transparent,
			KMEANS_PASSES);
		g_free(nearest_map);
	}

	g_free(state.cells);
	wu_hist_free(hist);
	g_free(boxes);

	/* Fill palette — convert perceptual back to sRGB.
	 */
	palette_out->count = n_colors;
	for (i = 0; i < n_colors; i++) {
		palette_out->entries[i].r = perceptual_inv[entries[i].r];
		palette_out->entries[i].g = perceptual_inv[entries[i].g];
		palette_out->entries[i].b = perceptual_inv[entries[i].b];
		palette_out->entries[i].a = perceptual_inv[entries[i].a];
	}

	g_free(entries);

	return 0;
}

/* Per-thread strip dither state.
 */
typedef struct {
	VipsImage *in;
	VipsImage *index;
	const VipsPel *nearest_map;
	const PaletteEntry *palette;
	gboolean has_transparent;
	int ds;
	int strip_start;	/* first output row (inclusive) */
	int strip_end;		/* last output row (exclusive) */
	int width;
	int error;		/* thread sets to -1 on failure */
} WuDitherStrip;

static gpointer
wu_dither_strip_fn(gpointer data)
{
	WuDitherStrip *strip = (WuDitherStrip *) data;
	int width = strip->width;
	int row_len = (width + 2) * 4;
	gint16 *err_cur = g_new0(gint16, row_len);
	gint16 *err_next = g_new0(gint16, row_len);
	gboolean full_strength = (strip->ds == 16);
	VipsRegion *region = vips_region_new(strip->in);
	int y;

	for (y = strip->strip_start; y < strip->strip_end; y++) {
		VipsRect rect = { 0, y, width, 1 };
		const VipsPel *p;
		VipsPel *q;
		gint16 *tmp;

		if (vips_region_prepare(region, &rect)) {
			strip->error = -1;
			break;
		}

		p = VIPS_REGION_ADDR(region, 0, y);
		q = VIPS_IMAGE_ADDR(strip->index, 0, y);

		/* Swap error rows.
		 */
		tmp = err_cur;
		err_cur = err_next;
		err_next = tmp;
		memset(err_next, 0, row_len * sizeof(gint16));

		dither_row(p, q, width,
			err_cur, err_next,
			strip->ds, full_strength,
			strip->palette, strip->nearest_map,
			strip->has_transparent, y);
	}

	g_object_unref(region);
	g_free(err_cur);
	g_free(err_next);

	return NULL;
}

/* Parallel F-S remap: splits the image into horizontal strips,
 * each processed by a separate thread. Falls back to
 * single-threaded vips_sink_disc for no-dither or small images.
 */
int
vips__builtin_remap_stream(VipsImage *in, VipsImage *index,
	const VipsQuantisePalette *palette,
	float dither_level)
{
	PaletteEntry *pal;
	VipsPel *nearest_map;
	VipsPel *coarse_map;
	gboolean has_transparent;
	int i;
	int n_threads;
	int ds;

	VIPS_ONCE(&perceptual_lut_once, perceptual_lut_build, NULL);

	pal = g_new(PaletteEntry, palette->count);
	has_transparent = FALSE;
	for (i = 0; i < (int) palette->count; i++) {
		pal[i].r = perceptual_fwd[palette->entries[i].r];
		pal[i].g = perceptual_fwd[palette->entries[i].g];
		pal[i].b = perceptual_fwd[palette->entries[i].b];
		pal[i].a = perceptual_fwd[palette->entries[i].a];
		if (palette->entries[i].a == 0)
			has_transparent = TRUE;
	}

	ds = 0;
	if (dither_level > 0.0) {
		ds = (int) (dither_level * 16.0 + 0.5);
		if (ds < 1) ds = 1;
		if (ds > 16) ds = 16;
	}

	if (ds > 0) {
		coarse_map = g_new(VipsPel, CACHE_SIZE);
		build_nearest_map(pal, palette->count, coarse_map);

		nearest_map = g_new(VipsPel, DITHER_MAP_SIZE);
		build_dither_map(pal, coarse_map, nearest_map);
		g_free(coarse_map);
	}
	else {
		nearest_map = g_new(VipsPel, CACHE_SIZE);
		build_nearest_map(pal, palette->count, nearest_map);
	}

	n_threads = vips_concurrency_get();

	/* Use parallel strips when dithering and the image is
	 * tall enough for each strip to have meaningful work.
	 */
	if (ds > 0 && n_threads > 1 &&
		in->Ysize >= n_threads * 2) {
		WuDitherStrip *strips;
		GThread **threads;
		int rows_per_strip;
		int error = 0;

		rows_per_strip = in->Ysize / n_threads;
		strips = g_new(WuDitherStrip, n_threads);
		threads = g_new(GThread *, n_threads);

		for (i = 0; i < n_threads; i++) {
			strips[i].in = in;
			strips[i].index = index;
			strips[i].nearest_map = nearest_map;
			strips[i].palette = pal;
			strips[i].has_transparent = has_transparent;
			strips[i].ds = ds;
			strips[i].width = in->Xsize;
			strips[i].error = 0;

			strips[i].strip_start = i * rows_per_strip;
			strips[i].strip_end = (i == n_threads - 1)
				? in->Ysize
				: (i + 1) * rows_per_strip;
		}

		for (i = 0; i < n_threads; i++)
			threads[i] = g_thread_new("dither",
				wu_dither_strip_fn, &strips[i]);

		for (i = 0; i < n_threads; i++) {
			g_thread_join(threads[i]);
			if (strips[i].error)
				error = -1;
		}

		g_free(threads);
		g_free(strips);
		g_free(nearest_map);
		g_free(pal);

		return error;
	}
	else {
		/* Single-threaded fallback: no dither, small image,
		 * or single-threaded mode.
		 */
		WuRemapStreamState state;
		int row_len = (in->Xsize + 2) * 4;
		int result;

		state.index = index;
		state.nearest_map = nearest_map;
		state.palette = pal;
		state.has_transparent = has_transparent;
		state.row_count = 0;

		if (ds > 0) {
			state.ds = ds;
			state.err_cur = g_new0(gint16, row_len);
			state.err_next = g_new0(gint16, row_len);
		}
		else {
			state.ds = 0;
			state.err_cur = NULL;
			state.err_next = NULL;
		}

		result = vips_sink_disc(in,
			wu_remap_stream_cb, &state);

		g_free(state.err_cur);
		g_free(state.err_next);
		g_free(nearest_map);
		g_free(pal);

		return result;
	}
}

/* ---- Low-level API for VipsQuantise wrappers ---- */

/* Build a Wu palette from raw RGBA pixel data.
 * Wraps raw pointer in a VipsImage and delegates to the
 * streaming path, which handles threaded histogram build,
 * few-colours detection, and k-means refinement.
 * Returns 0 on success, -1 on error.
 */
int
vips__builtin_quantise(const unsigned char *pixels,
	int width, int height, int max_colors, int effort,
	VipsQuantisePalette *palette_out)
{
	VipsImage *in;
	GHashTable *exact_map;
	int result;

	in = vips_image_new_from_memory((void *) pixels,
		(size_t) 4 * width * height,
		width, height, 4, VIPS_FORMAT_UCHAR);
	if (!in)
		return -1;

	result = vips__builtin_quantise_stream(in, max_colors, effort,
		palette_out, &exact_map);

	if (exact_map)
		g_hash_table_destroy(exact_map);

	g_object_unref(in);

	return result;
}

/* Remap raw RGBA pixels to palette indices.
 * Wraps raw pointers in VipsImages and delegates to the
 * streaming path, which handles both single-threaded and
 * parallel dithering.
 * Returns 0 on success, -1 on error.
 */
int
vips__builtin_remap(const unsigned char *pixels,
	int width, int height,
	const VipsQuantisePalette *palette,
	float dither_level,
	void *index_out)
{
	VipsImage *in;
	VipsImage *index;
	int result;

	/* Wrap the raw RGBA buffer as a VipsImage (no copy).
	 */
	in = vips_image_new_from_memory((void *) pixels,
		(size_t) 4 * width * height,
		width, height, 4, VIPS_FORMAT_UCHAR);
	if (!in)
		return -1;

	/* Wrap the output buffer as a 1-band VipsImage (no copy).
	 */
	index = vips_image_new_from_memory(index_out,
		(size_t) width * height,
		width, height, 1, VIPS_FORMAT_UCHAR);
	if (!index) {
		g_object_unref(in);
		return -1;
	}

	result = vips__builtin_remap_stream(in, index,
		palette, dither_level);

	g_object_unref(index);
	g_object_unref(in);

	return result;
}
