/* im_maxpos_avg.c
 *
 * Copyright: 2006, The Nottingham Trent University
 * Copyright: 2006, Tom Vajzovic
 *
 * Author: Tom Vajzovic
 *
 * Written on: 2006-09-25
 * 15/10/07 JC
 * 	- changed spelling of occurrences
 * 	- check for !occurrences before using val
 * 	- renamed avg as sum, a bit clearer
 * 2/9/09
 * 	- gtkdoc comment
 * 8/9/08
 * 	- rewrite from im_maxpos()
 * 	- now handles many bands, complex, faster
 * 27/7/14
 * 	- fix a race ... did not merge states if max was equal
 * 26/3/15
 * 	- avoid NaN, thanks Paul
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

/* A position and maximum.
 */
typedef struct _Maxposavg {
	int xpos;
	int ypos;
	double max;

	/* occurences == 0 means we found no points, or we are uninitialised.
	 */
	int occurences;
} Maxposavg;

/* New sequence value.
 */
static void *
maxposavg_start(IMAGE *in, void *a, void *b)
{
	Maxposavg *global_maxposavg = (Maxposavg *) b;
	Maxposavg *maxposavg;

	if (!(maxposavg = IM_NEW(NULL, Maxposavg)))
		return NULL;
	*maxposavg = *global_maxposavg;

	return (void *) maxposavg;
}

/* Merge the sequence value back into the per-call state.
 */
static int
maxposavg_stop(void *seq, void *a, void *b)
{
	Maxposavg *global_maxposavg = (Maxposavg *) b;
	Maxposavg *maxposavg = (Maxposavg *) seq;

	/* Merge.
	 */
	if (maxposavg->occurences == 0) {
	}
	else if (maxposavg->max > global_maxposavg->max)
		*global_maxposavg = *maxposavg;
	else if (maxposavg->max == global_maxposavg->max) {
		global_maxposavg->xpos += maxposavg->xpos;
		global_maxposavg->ypos += maxposavg->ypos;
		global_maxposavg->occurences += maxposavg->occurences;
	}

	im_free(seq);

	return 0;
}

/* int loop.
 */
#define ILOOP(TYPE) \
	{ \
		TYPE *p = (TYPE *) in; \
		TYPE m; \
\
		m = max; \
\
		for (x = 0; x < sz; x++) { \
			TYPE v = p[x]; \
\
			if (occurences == 0 || v > m) { \
				m = v; \
				xpos = r->left + x / reg->im->Bands; \
				ypos = r->top + y; \
				occurences = 1; \
			} \
			else if (v == m) { \
				xpos += r->left + x / reg->im->Bands; \
				ypos += r->top + y; \
				occurences += 1; \
			} \
		} \
\
		max = m; \
	}

/* float/double loop ... avoid NaN.
 */
#define FLOOP(TYPE) \
	{ \
		TYPE *p = (TYPE *) in; \
		TYPE m; \
\
		m = max; \
\
		for (x = 0; x < sz; x++) { \
			TYPE v = p[x]; \
\
			if (isnan(v)) { \
			} \
			else if (occurences == 0 || v > m) { \
				m = v; \
				xpos = r->left + x / reg->im->Bands; \
				ypos = r->top + y; \
				occurences = 1; \
			} \
			else if (v == m) { \
				xpos += r->left + x / reg->im->Bands; \
				ypos += r->top + y; \
				occurences += 1; \
			} \
		} \
\
		max = m; \
	}

/* complex/dpcomplex loop ... avoid NaN.
 */
#define CLOOP(TYPE) \
	{ \
		TYPE *p = (TYPE *) in; \
\
		for (x = 0; x < sz; x++) { \
			double mod, re, im; \
\
			re = p[0]; \
			im = p[1]; \
			p += 2; \
			mod = re * re + im * im; \
\
			if (isnan(mod)) { \
			} \
			else if (occurences == 0 || mod > max) { \
				max = mod; \
				xpos = r->left + x / reg->im->Bands; \
				ypos = r->top + y; \
				occurences = 1; \
			} \
			else if (mod == max) { \
				xpos += r->left + x / reg->im->Bands; \
				ypos += r->top + y; \
				occurences += 1; \
			} \
		} \
	}

/* Loop over region, adding to seq.
 */
static int
maxposavg_scan(REGION *reg, void *seq, void *a, void *b, gboolean *stop)
{
	const Rect *r = &reg->valid;
	const int sz = IM_REGION_N_ELEMENTS(reg);
	Maxposavg *maxposavg = (Maxposavg *) seq;

	int x, y;
	double max;
	int xpos, ypos, occurences;

	xpos = maxposavg->xpos;
	ypos = maxposavg->ypos;
	max = maxposavg->max;
	occurences = maxposavg->occurences;

	for (y = 0; y < r->height; y++) {
		VipsPel *in = VIPS_REGION_ADDR(reg, r->left, r->top + y);

		switch (reg->im->BandFmt) {
		case IM_BANDFMT_UCHAR:
			ILOOP(unsigned char);
			break;
		case IM_BANDFMT_CHAR:
			ILOOP(signed char);
			break;
		case IM_BANDFMT_USHORT:
			ILOOP(unsigned short);
			break;
		case IM_BANDFMT_SHORT:
			ILOOP(signed short);
			break;
		case IM_BANDFMT_UINT:
			ILOOP(unsigned int);
			break;
		case IM_BANDFMT_INT:
			ILOOP(signed int);
			break;
		case IM_BANDFMT_FLOAT:
			FLOOP(float);
			break;
		case IM_BANDFMT_DOUBLE:
			FLOOP(double);
			break;
		case IM_BANDFMT_COMPLEX:
			CLOOP(float);
			break;
		case IM_BANDFMT_DPCOMPLEX:
			CLOOP(double);
			break;

		default:
			g_assert(0);
		}
	}

	maxposavg->xpos = xpos;
	maxposavg->ypos = ypos;
	maxposavg->max = max;
	maxposavg->occurences = occurences;

	return 0;
}

/**
 * im_maxpos_avg:
 * @im: image to scan
 * @xpos: returned X position
 * @ypos: returned Y position
 * @out: returned value
 *
 * Function to find the maximum of an image.  Returns coords and value at
 * double precision.  In the event of a draw, returns average of all
 * drawing coords.
 *
 * See also: im_maxpos(), im_min(), im_stats().
 *
 * Returns: 0 on success, -1 on error
 */
int
im_maxpos_avg(IMAGE *in, double *xpos, double *ypos, double *out)
{
	Maxposavg *global_maxposavg;

	if (im_pincheck(in) ||
		im_check_uncoded("im_maxpos_avg", in))
		return -1;

	if (!(global_maxposavg = IM_NEW(in, Maxposavg)))
		return -1;
	global_maxposavg->occurences = 0;

	if (vips_sink(in, maxposavg_start, maxposavg_scan, maxposavg_stop,
			in, global_maxposavg))
		return -1;

	if (global_maxposavg->occurences == 0) {
		*xpos = nan("");
		*ypos = nan("");
		*out = nan("");
	}
	else {
		/* Back to modulus.
		 */
		if (vips_band_format_iscomplex(in->BandFmt))
			global_maxposavg->max = sqrt(global_maxposavg->max);

		if (xpos)
			*xpos = (double) global_maxposavg->xpos /
				global_maxposavg->occurences;
		if (ypos)
			*ypos = (double) global_maxposavg->ypos /
				global_maxposavg->occurences;
		if (out)
			*out = global_maxposavg->max;
	}

	return 0;
}
