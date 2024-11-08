/* Read FITS files with cfitsio
 *
 * 26/10/10
 *	- from matlab.c
 * 27/10/10
 * 	- oops, forgot to init status in close
 * 30/11/10
 * 	- set RGB16/GREY16 if appropriate
 * 	- allow up to 10 dimensions as long as they are empty
 * 27/1/11
 * 	- lazy read
 * 31/1/11
 * 	- read in planes and combine with im_bandjoin()
 * 	- read whole tiles with fits_read_subset() when we can
 * 17/3/11
 * 	- renames, updates etc. ready for adding fits write
 * 	- fits write!
 * 21/3/11
 * 	- read/write metadata as whole records to avoid changing things
 * 	- cast input to a supported format
 * 	- bandsplit for write
 * 13/12/11
 * 	- redo as a set of fns ready for wrapping in a new-style class
 * 23/6/13
 * 	- fix ushort save with values >32k, thanks weaverwb
 * 4/1/17
 * 	- load to equivalent data type, not raw image data type ... improves
 * 	  support for BSCALE / BZERO settings
 * 17/1/17
 * 	- invalidate operation on read error
 * 26/1/17 aferrero2707
 * 	- use fits_open_diskfile(), not fits_open_file() ... we don't want the
 *	  extended filename syntax
 * 15/4/17
 * 	- skip HDUs with zero dimensions, thanks benepo
 * 27/10/22
 *      - band interleave ourselves on read
 *      - don't duplicate metadata
 * 6/1/23 ewelot
 *	- save mono images as NAXIS=2
 * 18/1/23 ewelot
 *	- dedupe header fields
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

#ifdef HAVE_CFITSIO

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vips/vips.h>
#include <vips/internal.h>
#include <vips/debug.h>

#include <fitsio.h>

#include "pforeign.h"

/* vips only supports 3 dimensions, but we allow up to MAX_DIMENSIONS as long
 * as the higher dimensions are all empty. If you change this value, change
 * fits2vips_get_header() as well.
 */
#define MAX_DIMENSIONS (10)

/* What we track during a cfitsio-file read or write.
 */
typedef struct {
	char *filename;
	VipsImage *image;

	fitsfile *fptr;
	int datatype;
	int naxis;
	long long int naxes[MAX_DIMENSIONS];

	GMutex lock; /* Lock fits_*() calls with this */

	/* One line of pels ready for scatter/gather.
	 */
	VipsPel *line;

	/* All the lines or part lines we've written so we can dedupe
	 * metadata.
	 */
	GSList *dedupe;

} VipsFits;

const char *vips__fits_suffs[] = { ".fits", ".fit", ".fts", NULL };

static void
vips_fits_error(int status)
{
	char buf[80];

	fits_get_errstatus(status, buf);
	vips_error("fits", "%s", buf);
}

/* Shut down. Can be called many times.
 */
static void
vips_fits_close(VipsFits *fits)
{
	VIPS_FREE(fits->filename);
	if (fits->line)
		g_mutex_clear(&fits->lock);
	VIPS_FREEF(vips_slist_free_all, fits->dedupe);

	if (fits->fptr) {
		int status;

		status = 0;

		if (fits_close_file(fits->fptr, &status))
			vips_fits_error(status);

		fits->fptr = NULL;
	}

	VIPS_FREE(fits->line);
}

static void
vips_fits_close_cb(VipsImage *image, VipsFits *fits)
{
	vips_fits_close(fits);
}

static VipsFits *
vips_fits_new_read(const char *filename, VipsImage *out)
{
	VipsFits *fits;
	int status;

	if (!(fits = VIPS_NEW(out, VipsFits)))
		return NULL;

	fits->filename = vips_strdup(NULL, filename);
	fits->image = out;
	fits->fptr = NULL;
	g_mutex_init(&fits->lock);
	fits->line = NULL;
	g_signal_connect(out, "close",
		G_CALLBACK(vips_fits_close_cb), fits);

	status = 0;
	if (fits_open_diskfile(&fits->fptr, filename, READONLY, &status)) {
		vips_error("fits", _("unable to open \"%s\""), filename);
		vips_fits_error(status);
		return NULL;
	}

	return fits;
}

/* fits image types -> VIPS band formats. VIPS doesn't have 64-bit int, so no
 * entry for LONGLONG_IMG (64).
 */
static int fits2vips_formats[][3] = {
	{ BYTE_IMG, VIPS_FORMAT_UCHAR, TBYTE },
	{ SHORT_IMG, VIPS_FORMAT_SHORT, TSHORT },
	{ USHORT_IMG, VIPS_FORMAT_USHORT, TUSHORT },
	{ LONG_IMG, VIPS_FORMAT_INT, TINT },
	{ ULONG_IMG, VIPS_FORMAT_UINT, TUINT },
	{ FLOAT_IMG, VIPS_FORMAT_FLOAT, TFLOAT },
	{ DOUBLE_IMG, VIPS_FORMAT_DOUBLE, TDOUBLE }
};

static int
vips_fits_get_header(VipsFits *fits, VipsImage *out)
{
	int status;
	int bitpix;

	int width, height, bands;
	VipsBandFormat format;
	VipsInterpretation interpretation;
	int keysexist;
	int i;

	status = 0;

	/* Some FITS images have the first HDU for extra metadata ... skip
	 * forward until we find a header unit we can load as an image.
	 */
	for (;;) {
		if (fits_get_img_paramll(fits->fptr,
				10, &bitpix, &fits->naxis, fits->naxes, &status)) {
			vips_fits_error(status);
			return -1;
		}

		if (fits->naxis > 0)
			break;

		if (fits_movrel_hdu(fits->fptr, 1, NULL, &status)) {
			vips_fits_error(status);
			vips_error("fits",
				"%s", _("no HDU found with naxes > 0"));
			return -1;
		}
	}

	/* cfitsio does automatic conversion from the format stored in
	 * the file to the equivalent type after scale/offset. We need
	 * to allocate a vips image of the equivalent type, not the original
	 * type.
	 */
	if (fits_get_img_equivtype(fits->fptr, &bitpix, &status)) {
		vips_fits_error(status);
		return -1;
	}

#ifdef VIPS_DEBUG
	VIPS_DEBUG_MSG("naxis = %d\n", fits->naxis);
	for (i = 0; i < fits->naxis; i++)
		VIPS_DEBUG_MSG("%d) %lld\n", i, fits->naxes[i]);
	VIPS_DEBUG_MSG("fits2vips: bitpix = %d\n", bitpix);
#endif /*VIPS_DEBUG*/

	height = 1;
	bands = 1;
	switch (fits->naxis) {
	/* If you add more dimensions here, adjust data read below. See also
	 * the definition of MAX_DIMENSIONS above.
	 */
	case 10:
	case 9:
	case 8:
	case 7:
	case 6:
	case 5:
	case 4:
		for (i = fits->naxis; i > 3; i--)
			if (fits->naxes[i - 1] != 1) {
				vips_error("fits",
					"%s", _("dimensions above 3 must be size 1"));
				return -1;
			}

	case 3:
		bands = fits->naxes[2];

	case 2:
		height = fits->naxes[1];

	case 1:
		width = fits->naxes[0];
		break;

	default:
		vips_error("fits", _("bad number of axis %d"), fits->naxis);
		return -1;
	}

	/* Get image format. This is the equivalent format, or the format
	 * stored in the file.
	 */
	for (i = 0; i < VIPS_NUMBER(fits2vips_formats); i++)
		if (fits2vips_formats[i][0] == bitpix)
			break;
	if (i == VIPS_NUMBER(fits2vips_formats)) {
		vips_error("fits", _("unsupported bitpix %d\n"),
			bitpix);
		return -1;
	}
	format = fits2vips_formats[i][1];
	fits->datatype = fits2vips_formats[i][2];

	if (bands == 1) {
		if (format == VIPS_FORMAT_USHORT)
			interpretation = VIPS_INTERPRETATION_GREY16;
		else
			interpretation = VIPS_INTERPRETATION_B_W;
	}
	else if (bands == 3) {
		if (format == VIPS_FORMAT_USHORT)
			interpretation = VIPS_INTERPRETATION_RGB16;
		else
			interpretation = VIPS_INTERPRETATION_sRGB;
	}
	else
		interpretation = VIPS_INTERPRETATION_MULTIBAND;

	vips_image_init_fields(out,
		width, height, bands,
		format,
		VIPS_CODING_NONE, interpretation, 1.0, 1.0);

	/* We read in lines, so SMALLTILE ends up being too small.
	 */
	if (vips_image_pipelinev(out, VIPS_DEMAND_STYLE_FATSTRIP, NULL))
		return -1;

	/* We need to be able to hold one scanline of one band for
	 * scatter/gather.
	 */
	if (!(fits->line = VIPS_ARRAY(NULL,
			  VIPS_IMAGE_SIZEOF_ELEMENT(out) * out->Xsize, VipsPel)))
		return -1;

	/* Read all keys into meta.
	 */
	if (fits_get_hdrspace(fits->fptr, &keysexist, NULL, &status)) {
		vips_fits_error(status);
		return -1;
	}

	for (i = 0; i < keysexist; i++) {
		char record[81];
		char vipsname[100];

		if (fits_read_record(fits->fptr, i + 1, record, &status)) {
			vips_fits_error(status);
			return -1;
		}

		VIPS_DEBUG_MSG("fits2vips: setting meta on vips image:\n");
		VIPS_DEBUG_MSG(" record == \"%s\"\n", record);

		/* FITS lets keys repeat. For example, HISTORY appears many
		 * times, each time with a fresh line of history attached. We
		 * have to include the key index in the vips name we assign.
		 */

		g_snprintf(vipsname, 100, "fits-%d", i);
		vips_image_set_string(out, vipsname, record);
	}

	return 0;
}

int
vips__fits_read_header(const char *filename, VipsImage *out)
{
	VipsFits *fits;

	VIPS_DEBUG_MSG("fits2vips_header: reading \"%s\"\n", filename);

	if (!(fits = vips_fits_new_read(filename, out)))
		return -1;

	if (vips_fits_get_header(fits, out)) {
		vips_fits_close(fits);
		return -1;
	}

	vips_fits_close(fits);

	return 0;
}

static int
vips_fits_read_subset(VipsFits *fits,
	long *fpixel, long *lpixel, long *inc, VipsPel *q)
{
	int status;

	/* We must zero this or fits_read_subset() fails.
	 */
	status = 0;

	/* Break on ffgsv() for this call.
	 */
	if (fits_read_subset(fits->fptr, fits->datatype,
			fpixel, lpixel, inc,
			NULL, q, NULL, &status)) {
		vips_fits_error(status);
		vips_foreign_load_invalidate(fits->image);

		return -1;
	}

	return 0;
}

#define SCATTER(TYPE) \
	{ \
		TYPE *tp = (TYPE *) p; \
		TYPE *tq = ((TYPE *) q) + band; \
\
		for (int x = 0; x < width; x++) { \
			*tq = tp[x]; \
			tq += bands; \
		} \
	}

static void
vips_fits_scatter(VipsFits *fits, VipsPel *q, VipsPel *p, int width, int band)
{
	int bands = fits->image->Bands;

	switch (fits->image->BandFmt) {
	case VIPS_FORMAT_UCHAR:
	case VIPS_FORMAT_CHAR:
		SCATTER(guchar);
		break;

	case VIPS_FORMAT_SHORT:
	case VIPS_FORMAT_USHORT:
		SCATTER(gushort);
		break;

	case VIPS_FORMAT_INT:
	case VIPS_FORMAT_UINT:
	case VIPS_FORMAT_FLOAT:
		SCATTER(guint);
		break;

	case VIPS_FORMAT_DOUBLE:
		SCATTER(double);
		break;

	default:
		g_assert_not_reached();
	}
}

static int
vips_fits_generate(VipsRegion *out,
	void *seq, void *a, void *b, gboolean *stop)
{
	VipsFits *fits = (VipsFits *) a;
	VipsRect *r = &out->valid;

	VIPS_DEBUG_MSG("fits2vips_generate: "
				   "generating left = %d, top = %d, width = %d, height = %d\n",
		r->left, r->top, r->width, r->height);

	vips__worker_lock(&fits->lock);

	for (int w = 0; w < out->im->Bands; w++) {
		for (int y = r->top; y < VIPS_RECT_BOTTOM(r); y++) {
			long fpixel[MAX_DIMENSIONS];
			long lpixel[MAX_DIMENSIONS];
			long inc[MAX_DIMENSIONS];

			for (int z = 0; z < MAX_DIMENSIONS; z++)
				fpixel[z] = 1;
			fpixel[0] = r->left + 1;
			fpixel[1] = y + 1;
			fpixel[2] = w + 1;

			for (int z = 0; z < MAX_DIMENSIONS; z++)
				lpixel[z] = 1;
			lpixel[0] = VIPS_RECT_RIGHT(r);
			lpixel[1] = y + 1;
			lpixel[2] = w + 1;

			for (int z = 0; z < MAX_DIMENSIONS; z++)
				inc[z] = 1;

			/* We're inside a lock, so it's OK to write to ->line.
			 */
			if (vips_fits_read_subset(fits,
					fpixel, lpixel, inc, fits->line)) {
				g_mutex_unlock(&fits->lock);
				return -1;
			}

			vips_fits_scatter(fits,
				VIPS_REGION_ADDR(out, r->left, y), fits->line,
				r->width, w);
		}
	}

	g_mutex_unlock(&fits->lock);

	return 0;
}

int
vips__fits_read(const char *filename, VipsImage *out)
{
	VipsFits *fits;

	if (!(fits = vips_fits_new_read(filename, out)))
		return -1;
	if (vips_fits_get_header(fits, out) ||
		vips_image_generate(out,
			NULL, vips_fits_generate, NULL, fits, NULL)) {
		vips_fits_close(fits);
		return -1;
	}

	return 0;
}

int
vips__fits_isfits(const char *filename)
{
	fitsfile *fptr;
	int status;

	VIPS_DEBUG_MSG("isfits: testing \"%s\"\n", filename);

	status = 0;

	if (fits_open_diskfile(&fptr, filename, READONLY, &status)) {
		VIPS_DEBUG_MSG("isfits: error reading \"%s\"\n", filename);
#ifdef VIPS_DEBUG
		vips_fits_error(status);
		VIPS_DEBUG_MSG("isfits: %s\n", vips_error_buffer());
#endif /*VIPS_DEBUG*/

		return 0;
	}
	fits_close_file(fptr, &status);

	return 1;
}

static VipsFits *
vips_fits_new_write(VipsImage *in, const char *filename)
{
	VipsFits *fits;
	int status;

	status = 0;

	if (!(fits = VIPS_NEW(in, VipsFits)))
		return NULL;
	fits->filename = vips_strdup(VIPS_OBJECT(in), filename);
	fits->image = in;
	fits->fptr = NULL;
	g_mutex_init(&fits->lock);
	fits->line = NULL;
	g_signal_connect(in, "close",
		G_CALLBACK(vips_fits_close_cb), fits);

	if (!(fits->filename = vips_strdup(NULL, filename)))
		return NULL;

	/* We need to be able to hold one scanline of one band.
	 */
	if (!(fits->line = VIPS_ARRAY(NULL,
			  VIPS_IMAGE_SIZEOF_ELEMENT(in) * in->Xsize, VipsPel)))
		return NULL;

	/* fits_create_file() will fail if there's a file of that name, unless
	 * we put a "!" in front of the filename. This breaks conventions with
	 * the rest of vips, so just unlink explicitly.
	 */
	g_unlink(filename);

	if (fits_create_file(&fits->fptr, filename, &status)) {
		vips_error("fits",
			_("unable to write to \"%s\""), filename);
		vips_fits_error(status);
		return NULL;
	}

	return fits;
}

/* Header fields which cfitsio 4.1 writes for us start like this. It'll use
 * BZERO and BSCALE for 16- and 32-bit signed data.
 */
const char *vips_fits_basic[] = {
	"SIMPLE ",
	"BITPIX ",
	"NAXIS ",
	"NAXIS1 ",
	"NAXIS2 ",
	"NAXIS3 ",
	"EXTEND ",
	"BZERO ",
	"BSCALE ",
	"COMMENT   FITS (Flexible Image Transport System) format",
	"COMMENT   and Astrophysics', volume 376, page 359; bibcode:",
	// may be present in a multi HDU file, but not allowed in a single HDU
	// file
	"XTENSION",
	"PCOUNT ",
	"GCOUNT ",
};

/* Header fields which can be duplicated start like this.
 */
const char *vips_fits_duplicate[] = {
	"        ",
	"COMMENT ",
	"HISTORY ",
	"CONTINUE",
};

/* Write a line of header text. Lines can be eg.:
 *
 *	"EXTEND  =                    T / FITS dataset may contain extensions"
 *	"COMMENT   FITS (Flexible Image Transport System) format is defined
 *	""
 *
 * - always left justified
 * - keyword is always 8 characters, right padded with spaces
 * - "= ", if present, is cols 9 and 10
 * - lines are variable length, can be zero length for blank lines
 */
static int
vips_fits_write_record(VipsFits *fits, const char *line)
{
	char keyword[9];
	int i;
	GSList *p;
	int status;

	VIPS_DEBUG_MSG("vips_fits_write_record: %s\n", line);

	/* cfitsio writes lines like these for us, don't write them again.
	 */
	for (i = 0; i < VIPS_NUMBER(vips_fits_basic); i++)
		if (vips_isprefix(vips_fits_basic[i], line))
			return 0;

	/* Dedupe on the keyword, with some exceptions (see below).
	 */
	g_strlcpy(keyword, line, 9);
	for (p = fits->dedupe; p; p = p->next) {
		const char *written = (const char *) p->data;

		if (strcmp(keyword, written) == 0)
			return 0;
	}

	status = 0;
	if (fits_write_record(fits->fptr, line, &status)) {
		vips_fits_error(status);
		return -1;
	}

	/* Add this keyword to the dedupe list if it's not on the allowed
	 * dupe table, or a blank line.
	 */
	if (strcmp(line, "") != 0) {
		for (i = 0; i < VIPS_NUMBER(vips_fits_duplicate); i++)
			if (vips_isprefix(vips_fits_duplicate[i], keyword))
				break;

		if (i == VIPS_NUMBER(vips_fits_duplicate))
			fits->dedupe = g_slist_prepend(fits->dedupe,
				g_strdup(keyword));
	}

	return 0;
}

static void *
vips_fits_write_meta(VipsImage *image,
	const char *field, GValue *value, void *a)
{
	VipsFits *fits = (VipsFits *) a;

	const char *value_str;

	/* We want fields which start "fits-".
	 */
	if (!vips_isprefix("fits-", field))
		return NULL;

	/* The value should be a refstring, since we wrote it in fits2vips
	 * above ^^.
	 */
	value_str = vips_value_get_ref_string(value, NULL);

	if (vips_fits_write_record(fits, value_str))
		return a;

	return NULL;
}

static int
vips_fits_set_header(VipsFits *fits, VipsImage *in)
{
	int status;
	int bitpix;
	int i;

	status = 0;

	fits->naxis = in->Bands == 1 ? 2 : 3;
	fits->naxes[0] = in->Xsize;
	fits->naxes[1] = in->Ysize;
	fits->naxes[2] = in->Bands;

	for (i = 0; i < VIPS_NUMBER(fits2vips_formats); i++)
		if (fits2vips_formats[i][1] == in->BandFmt)
			break;
	if (i == VIPS_NUMBER(fits2vips_formats)) {
		vips_error("fits",
			_("unsupported BandFmt %d\n"), in->BandFmt);
		return -1;
	}
	bitpix = fits2vips_formats[i][0];
	fits->datatype = fits2vips_formats[i][2];

#ifdef VIPS_DEBUG
	VIPS_DEBUG_MSG("naxis = %d\n", fits->naxis);
	for (i = 0; i < fits->naxis; i++)
		VIPS_DEBUG_MSG("%d) %lld\n", i, fits->naxes[i]);
	VIPS_DEBUG_MSG("bitpix = %d\n", bitpix);
#endif /*VIPS_DEBUG*/

	if (fits_create_imgll(fits->fptr, bitpix, fits->naxis,
			fits->naxes, &status)) {
		vips_fits_error(status);
		return -1;
	}

	if (vips_image_map(in,
			(VipsImageMapFn) vips_fits_write_meta, fits))
		return -1;

	return 0;
}

static int
vips_fits_write(VipsRegion *region, VipsRect *area, void *a)
{
	VipsFits *fits = (VipsFits *) a;
	VipsImage *image = fits->image;
	int es = VIPS_IMAGE_SIZEOF_ELEMENT(image);
	int ps = VIPS_IMAGE_SIZEOF_PEL(image);

	int status;
	int y, b, x, k;

	status = 0;

	VIPS_DEBUG_MSG("vips_fits_write: "
				   "writing left = %d, top = %d, width = %d, height = %d\n",
		area->left, area->top, area->width, area->height);

	/* We need to write a band at a time. We can't bandsplit in vips,
	 * since vips_sink_disc() can't loop over many images at once, sadly.
	 */

	for (y = 0; y < area->height; y++) {
		VipsPel *p = VIPS_REGION_ADDR(region,
			area->left, area->top + y);

		for (b = 0; b < image->Bands; b++) {
			VipsPel *p1, *q;
			long fpixel[3];

			p1 = p + b * es;
			q = fits->line;

			for (x = 0; x < area->width; x++) {
				for (k = 0; k < es; k++)
					q[k] = p1[k];

				q += es;
				p1 += ps;
			}

			fpixel[0] = area->left + 1;
			fpixel[1] = area->top + y + 1;
			fpixel[2] = b + 1;

			/* No need to lock, write functions are single-threaded.
			 */

			if (fits_write_pix(fits->fptr, fits->datatype,
					fpixel, area->width, fits->line,
					&status)) {
				vips_fits_error(status);
				return -1;
			}
		}
	}

	return 0;
}

int
vips__fits_write(VipsImage *in, const char *filename)
{
	VipsFits *fits;

	VIPS_DEBUG_MSG("vips2fits: writing \"%s\"\n", filename);

	if (!(fits = vips_fits_new_write(in, filename)))
		return -1;

	if (vips_fits_set_header(fits, fits->image) ||
		vips_sink_disc(fits->image, vips_fits_write, fits)) {
		vips_fits_close(fits);
		return -1;
	}
	vips_fits_close(fits);

	return 0;
}

#endif /*HAVE_CFITSIO*/
