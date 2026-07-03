/* horizontal and vertical projection
 *
 * 20/4/06
 *	- from im_histgr()
 * 25/3/10
 * 	- gtkdoc
 * 	- small celanups
 * 11/9/13
 * 	- redo as a class, from vips_hist_find()
 * 3/7/26
 *	- add @combine
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <glib/gi18n-lib.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vips/vips.h>

#include "statistic.h"

struct _Project;

typedef struct {
	/* Horizontal array: combination of all columns.
	 */
	void *columns;

	/* Vertical array: conbination of all rows.
	 */
	void *rows;

	/* TRUE for hist has been initialised.
	 */
	int init;
} Histogram;

typedef struct _VipsProject {
	VipsStatistic parent_instance;

	/* Main image histogram. Subhists accumulate to this.
	 */
	Histogram *hist;

	/* Write sums here.
	 */
	VipsImage *columns;
	VipsImage *rows;

	/* Combine bins with this.
	 */
	VipsCombine combine;

} VipsProject;

typedef VipsStatisticClass VipsProjectClass;

G_DEFINE_TYPE(VipsProject, vips_project, VIPS_TYPE_STATISTIC);

/* Save a bit of typing.
 */
#define UI VIPS_FORMAT_UINT
#define I VIPS_FORMAT_INT
#define D VIPS_FORMAT_DOUBLE
#define N VIPS_FORMAT_NOTSET

static const VipsBandFormat vips_project_format_table[10] = {
	/* Band format:  UC  C  US  S  UI  I  F  X  D  DX */
	/* Promotion: */ UI, I, UI, I, UI, I, D, N, D, N
};

static Histogram *
histogram_new(VipsProject *project)
{
	VipsStatistic *statistic = VIPS_STATISTIC(project);
	VipsImage *in = statistic->ready;
	VipsBandFormat outfmt = vips_project_format_table[in->BandFmt];
	size_t psize = vips_format_sizeof(outfmt) * in->Bands;

	Histogram *hist;

	if (!(hist = VIPS_NEW(project, Histogram)))
		return NULL;
	hist->columns = VIPS_ARRAY(project, psize * in->Xsize, guchar);
	hist->rows = VIPS_ARRAY(project, psize * in->Ysize, guchar);
	if (!hist->columns ||
		!hist->rows)
		return NULL;

	memset(hist->columns, 0, psize * in->Xsize);
	memset(hist->rows, 0, psize * in->Ysize);

	return hist;
}

static int
vips_project_build(VipsObject *object)
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS(object);
	VipsStatistic *statistic = VIPS_STATISTIC(object);
	VipsProject *project = (VipsProject *) object;

	int y;

	if (statistic->in &&
		vips_check_noncomplex(class->nickname, statistic->in))
		return -1;

	g_object_set(object,
		"columns", vips_image_new(),
		"rows", vips_image_new(),
		NULL);

	/* main hist made on first thread start.
	 */

	if (VIPS_OBJECT_CLASS(vips_project_parent_class)->build(object))
		return -1;

	/* Make the output image.
	 */
	if (vips_image_pipelinev(project->columns,
			VIPS_DEMAND_STYLE_ANY, statistic->ready, NULL) ||
		vips_image_pipelinev(project->rows,
			VIPS_DEMAND_STYLE_ANY, statistic->ready, NULL))
		return -1;
	project->columns->Ysize = 1;
	project->columns->BandFmt =
		vips_project_format_table[statistic->ready->BandFmt];
	project->columns->Type = VIPS_INTERPRETATION_HISTOGRAM;
	project->rows->Xsize = 1;
	project->rows->BandFmt =
		vips_project_format_table[statistic->ready->BandFmt];
	project->rows->Type = VIPS_INTERPRETATION_HISTOGRAM;

	if (vips_image_write_line(project->columns, 0,
			(VipsPel *) project->hist->columns))
		return -1;
	for (y = 0; y < project->rows->Ysize; y++)
		if (vips_image_write_line(project->rows, y,
				(VipsPel *) project->hist->rows +
					y * VIPS_IMAGE_SIZEOF_PEL(project->rows)))
			return -1;

	return 0;
}

/* Build a sub-hist, based on the main hist.
 */
static void *
vips_project_start(VipsStatistic *statistic)
{
	VipsProject *project = (VipsProject *) statistic;

	/* Make the main hist, if necessary.
	 */
	if (!project->hist)
		project->hist = histogram_new(project);

	return (void *) histogram_new(project);
}

/* Combine B with A according to mode.
 */
#define COMBINE(MODE, A, B) \
	G_STMT_START \
	{ \
		switch (MODE) { \
		case VIPS_COMBINE_MAX: \
			(A) = VIPS_MAX(A, B); \
			break; \
\
		case VIPS_COMBINE_SUM: \
			(A) += (B); \
			break; \
\
		case VIPS_COMBINE_MIN: \
			(A) = VIPS_MIN(A, B); \
			break; \
\
		default: \
			g_assert_not_reached(); \
		} \
	} \
	G_STMT_END

/* Combine a line of pixels into a hist,
 */
#define COMBINE_PIXELS(OUT, IN) \
	G_STMT_START \
	{ \
		OUT *rows = ((OUT *) hist->rows) + y * nb; \
		OUT *columns; \
		IN *p; \
\
		columns = ((OUT *) hist->columns) + x * nb; \
		p = (IN *) in; \
		for (int i = 0; i < n; i++) { \
			if (hist->init) \
				for (int j = 0; j < nb; j++) { \
					COMBINE(project->combine, columns[j], p[j]); \
					COMBINE(project->combine, rows[j], p[j]); \
				} \
			else { \
				for (int j = 0; j < nb; j++) { \
					columns[j] = p[j]; \
					rows[j] = p[j]; \
				} \
				hist->init = TRUE; \
			} \
\
			p += nb; \
			columns += nb; \
		} \
	} \
	G_STMT_END

/* Add a region to a project.
 */
static int
vips_project_scan(VipsStatistic *statistic, void *seq,
	int x, int y, void *in, int n)
{
	VipsProject *project = (VipsProject *) statistic;
	int nb = statistic->ready->Bands;
	Histogram *hist = (Histogram *) seq;

	switch (statistic->ready->BandFmt) {
	case VIPS_FORMAT_UCHAR:
		COMBINE_PIXELS(guint, guchar);
		break;

	case VIPS_FORMAT_CHAR:
		COMBINE_PIXELS(int, char);
		break;

	case VIPS_FORMAT_USHORT:
		COMBINE_PIXELS(guint, gushort);
		break;

	case VIPS_FORMAT_SHORT:
		COMBINE_PIXELS(int, short);
		break;

	case VIPS_FORMAT_UINT:
		COMBINE_PIXELS(guint, guint);
		break;

	case VIPS_FORMAT_INT:
		COMBINE_PIXELS(int, int);
		break;

	case VIPS_FORMAT_FLOAT:
		COMBINE_PIXELS(double, float);
		break;

	case VIPS_FORMAT_DOUBLE:
		COMBINE_PIXELS(double, double);
		break;

	default:
		g_assert_not_reached();
	}

	return 0;
}

#define COMBINE_BUFFER(TYPE, Q, P, N) \
	G_STMT_START \
	{ \
		TYPE *p = (TYPE *) (P); \
		TYPE *q = (TYPE *) (Q); \
		int n = (N); \
\
		if (hist->init) \
			for (int i = 0; i < n; i++) \
				COMBINE(project->combine, q[i], p[i]); \
		else \
			for (int i = 0; i < n; i++) \
				q[i] = p[i]; \
	} \
	G_STMT_END

/* Join a sub-project onto the main project.
 */
static int
vips_project_stop(VipsStatistic *statistic, void *seq)
{
	VipsProject *project = (VipsProject *) statistic;
	Histogram *hist = project->hist;
	Histogram *sub_hist = (Histogram *) seq;
	VipsImage *in = statistic->ready;
	VipsBandFormat outfmt = vips_project_format_table[in->BandFmt];
	int hsz = in->Xsize * in->Bands;
	int vsz = in->Ysize * in->Bands;

	// I think this is always true
	g_assert(sub_hist->init);

	/* Add on sub-data.
	 */
	switch (outfmt) {
	case VIPS_FORMAT_UINT:
		COMBINE_BUFFER(guint, hist->columns, sub_hist->columns, hsz);
		COMBINE_BUFFER(guint, hist->rows, sub_hist->rows, vsz);
		break;

	case VIPS_FORMAT_INT:
		COMBINE_BUFFER(int, hist->columns, sub_hist->columns, hsz);
		COMBINE_BUFFER(int, hist->rows, sub_hist->rows, vsz);
		break;

	case VIPS_FORMAT_DOUBLE:
		COMBINE_BUFFER(double, hist->columns, sub_hist->columns, hsz);
		COMBINE_BUFFER(double, hist->rows, sub_hist->rows, vsz);
		break;

	default:
		g_assert_not_reached();
	}

	/* Blank out sub-project to make sure we can't add it again.
	 */
	sub_hist->columns = NULL;
	sub_hist->rows = NULL;

	hist->init = TRUE;

	return 0;
}

static void
vips_project_class_init(VipsProjectClass *class)
{
	GObjectClass *gobject_class = (GObjectClass *) class;
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsStatisticClass *sclass = VIPS_STATISTIC_CLASS(class);

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "project";
	object_class->description = _("find image projections");
	object_class->build = vips_project_build;

	sclass->start = vips_project_start;
	sclass->scan = vips_project_scan;
	sclass->stop = vips_project_stop;

	VIPS_ARG_IMAGE(class, "columns", 100,
		_("Columns"),
		_("Sums of columns"),
		VIPS_ARGUMENT_REQUIRED_OUTPUT,
		G_STRUCT_OFFSET(VipsProject, columns));

	VIPS_ARG_IMAGE(class, "rows", 101,
		_("Rows"),
		_("Sums of rows"),
		VIPS_ARGUMENT_REQUIRED_OUTPUT,
		G_STRUCT_OFFSET(VipsProject, rows));

	VIPS_ARG_ENUM(class, "combine", 102,
		_("Combine"),
		_("Combine values with this"),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET(VipsProject, combine),
		VIPS_TYPE_COMBINE, VIPS_COMBINE_SUM);
}

static void
vips_project_init(VipsProject *project)
{
	project->combine = VIPS_COMBINE_SUM;
}

/**
 * vips_project: (method)
 * @in: input image
 * @columns: (out): sums of columns
 * @rows: (out): sums of rows
 * @...: `NULL`-terminated list of optional named arguments
 *
 * Find the horizontal and vertical projections of an image, ie. the sum
 * of every row of pixels, and the sum of every column of pixels. The output
 * format is uint, int or double, depending on the input format.
 *
 * Normally, pixels are summed, but you can use @combine to set other combine
 * modes.
 *
 * Non-complex images only.
 *
 * ::: tip "Optional arguments"
 *     * @combine: [enum@Combine], combine bins like this
 *
 * ::: seealso
 *     [method@Image.hist_find], [method@Image.profile].
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_project(VipsImage *in, VipsImage **columns, VipsImage **rows, ...)
{
	va_list ap;
	int result;

	va_start(ap, rows);
	result = vips_call_split("project", ap, in, columns, rows);
	va_end(ap);

	return result;
}
