/* horizontal and vertical projection
 *
 * 20/4/06
 *	- from im_histgr()
 * 25/3/10
 * 	- gtkdoc
 * 	- small celanups
 * 11/9/13
 * 	- redo as a class, from vips_hist_find()
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
#include <vips/intl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vips/vips.h>

#include "statistic.h"

struct _Project;

typedef struct {
	/* Horizontal array: sums of all columns.
	 */
	void *column_sums;

	/* Vertical array: sums of all rows.
	 */
	void *row_sums;
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

} VipsProject;

typedef VipsStatisticClass VipsProjectClass;

G_DEFINE_TYPE( VipsProject, vips_project, VIPS_TYPE_STATISTIC );

/* Save a bit of typing.
 */
#define UI VIPS_FORMAT_UINT
#define I VIPS_FORMAT_INT
#define D VIPS_FORMAT_DOUBLE
#define N VIPS_FORMAT_NOTSET

static const VipsBandFormat vips_project_format_table[10] = {
/* UC   C  US   S  UI   I   F   X   D  DX */
   UI,  I, UI,  I, UI,  I,  D,  N,  D, N
};

static Histogram *
histogram_new( VipsProject *project )
{
	VipsStatistic *statistic = VIPS_STATISTIC( project ); 
	VipsImage *in = statistic->ready; 
	VipsBandFormat outfmt = vips_project_format_table[in->BandFmt];
	int psize = vips_format_sizeof( outfmt ) * in->Bands; 

	Histogram *hist;

	if( !(hist = VIPS_NEW( project, Histogram )) )
		return( NULL );
	hist->column_sums = VIPS_ARRAY( project, psize * in->Xsize, guchar );
	hist->row_sums = VIPS_ARRAY( project, psize * in->Ysize, guchar );
	if( !hist->column_sums || 
		!hist->row_sums )
		return( NULL );

	memset( hist->column_sums, 0, psize * in->Xsize );
	memset( hist->row_sums, 0, psize * in->Ysize );

	return( hist );
}

static int
vips_project_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsStatistic *statistic = VIPS_STATISTIC( object ); 
	VipsProject *project = (VipsProject *) object;

	int y;

	if( statistic->in &&
		vips_check_noncomplex( class->nickname, statistic->in ) )
		return( -1 ); 

	g_object_set( object, 
		"columns", vips_image_new(),
		"rows", vips_image_new(),
		NULL );

	/* main hist made on first thread start.
	 */

	if( VIPS_OBJECT_CLASS( vips_project_parent_class )->build( object ) )
		return( -1 );

	/* Make the output image.
	 */
	if( vips_image_pipelinev( project->columns, 
			VIPS_DEMAND_STYLE_ANY, statistic->ready, NULL ) || 
		vips_image_pipelinev( project->rows, 
			VIPS_DEMAND_STYLE_ANY, statistic->ready, NULL ) ) 
		return( -1 );
	project->columns->Ysize = 1;
	project->columns->BandFmt = 
		vips_project_format_table[statistic->ready->BandFmt];
	project->columns->Type = VIPS_INTERPRETATION_HISTOGRAM;
	project->rows->Xsize = 1;
	project->rows->BandFmt = 
		vips_project_format_table[statistic->ready->BandFmt];
	project->rows->Type = VIPS_INTERPRETATION_HISTOGRAM;

	if( vips_image_write_line( project->columns, 0, 
		(VipsPel *) project->hist->column_sums ) )
		return( -1 );
	for( y = 0; y < project->rows->Ysize; y++ )
		if( vips_image_write_line( project->rows, y, 
			(VipsPel *) project->hist->row_sums + 
				y * VIPS_IMAGE_SIZEOF_PEL( project->rows ) ) )
			return( -1 );

	return( 0 );
}

/* Build a sub-hist, based on the main hist.
 */
static void *
vips_project_start( VipsStatistic *statistic )
{
	VipsProject *project = (VipsProject *) statistic;

	/* Make the main hist, if necessary.
	 */
	if( !project->hist ) 
		project->hist = histogram_new( project );  

	return( (void *) histogram_new( project ) );  
}

/* Add a line of pixels.
 */
#define ADD_PIXELS( OUT, IN ) { \
	OUT *row_sums = ((OUT *) hist->row_sums) + y * nb; \
	OUT *column_sums; \
	IN *p; \
	\
	column_sums = ((OUT *) hist->column_sums) + x * nb; \
	p = (IN *) in; \
	for( i = 0; i < n; i++ ) { \
		for( j = 0; j < nb; j++ ) { \
			column_sums[j] += p[j]; \
			row_sums[j] += p[j]; \
		} \
		\
		p += nb; \
		column_sums += nb; \
	} \
}

/* Add a region to a project.
 */
static int
vips_project_scan( VipsStatistic *statistic, void *seq, 
	int x, int y, void *in, int n )
{
	int nb = statistic->ready->Bands;
	Histogram *hist = (Histogram *) seq;
	int i, j;

	switch( statistic->ready->BandFmt ) {
	case VIPS_FORMAT_UCHAR:
		ADD_PIXELS( guint, guchar );
		break;

	case VIPS_FORMAT_CHAR:
		ADD_PIXELS( int, char );
		break;

	case VIPS_FORMAT_USHORT:
		ADD_PIXELS( guint, gushort );
		break;

	case VIPS_FORMAT_SHORT:
		ADD_PIXELS( int, short );
		break;

	case VIPS_FORMAT_UINT:
		ADD_PIXELS( guint, guint );
		break;

	case VIPS_FORMAT_INT:
		ADD_PIXELS( int, int );
		break;

	case VIPS_FORMAT_FLOAT:
		ADD_PIXELS( double, float );
		break;

	case VIPS_FORMAT_DOUBLE:
		ADD_PIXELS( double, double );
		break;

	default:
		g_assert_not_reached();
	}

	return( 0 );
}

#define ADD_BUFFER( TYPE, Q, P, N ) { \
	TYPE *p = (TYPE *) (P); \
	TYPE *q = (TYPE *) (Q); \
	int n = (N); \
	int i; \
	\
	for( i = 0; i < n; i++ ) \
		q[i] += p[i]; \
}

/* Join a sub-project onto the main project.
 */
static int
vips_project_stop( VipsStatistic *statistic, void *seq )
{
	VipsProject *project = (VipsProject *) statistic;
	Histogram *hist = project->hist; 
	Histogram *sub_hist = (Histogram *) seq;
	VipsImage *in = statistic->ready;
	VipsBandFormat outfmt = vips_project_format_table[in->BandFmt];
	int hsz = in->Xsize * in->Bands;
	int vsz = in->Ysize * in->Bands;

	/* Add on sub-data.
	 */
	switch( outfmt ) {
	case VIPS_FORMAT_UINT:
		ADD_BUFFER( guint, 
			hist->column_sums, sub_hist->column_sums, hsz );
		ADD_BUFFER( guint, hist->row_sums, sub_hist->row_sums, vsz );
		break;

	case VIPS_FORMAT_INT:
		ADD_BUFFER( int, 
			hist->column_sums, sub_hist->column_sums, hsz );
		ADD_BUFFER( int, hist->row_sums, sub_hist->row_sums, vsz );
		break;

	case VIPS_FORMAT_DOUBLE:
		ADD_BUFFER( double, 
			hist->column_sums, sub_hist->column_sums, hsz );
		ADD_BUFFER( double, hist->row_sums, sub_hist->row_sums, vsz );
		break;

	default:
		g_assert_not_reached();
	}

	/* Blank out sub-project to make sure we can't add it again.
	 */
	sub_hist->column_sums = NULL; 
	sub_hist->row_sums = NULL; 

	return( 0 );
}

static void
vips_project_class_init( VipsProjectClass *class )
{
	GObjectClass *gobject_class = (GObjectClass *) class;
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsStatisticClass *sclass = VIPS_STATISTIC_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "project";
	object_class->description = _( "find image projections" );
	object_class->build = vips_project_build;

	sclass->start = vips_project_start;
	sclass->scan = vips_project_scan;
	sclass->stop = vips_project_stop;

	VIPS_ARG_IMAGE( class, "columns", 100, 
		_( "Columns" ), 
		_( "Sums of columns" ),
		VIPS_ARGUMENT_REQUIRED_OUTPUT, 
		G_STRUCT_OFFSET( VipsProject, columns ) );

	VIPS_ARG_IMAGE( class, "rows", 101, 
		_( "Rows" ), 
		_( "Sums of rows" ),
		VIPS_ARGUMENT_REQUIRED_OUTPUT, 
		G_STRUCT_OFFSET( VipsProject, rows ) );

}

static void
vips_project_init( VipsProject *project )
{
}

/**
 * vips_project:
 * @in: input image
 * @columns: sums of columns
 * @rows: sums of rows
 * @...: %NULL-terminated list of optional named arguments
 *
 * Find the horizontal and vertical projections of an image, ie. the sum
 * of every row of pixels, and the sum of every column of pixels. The output
 * format is uint, int or double, depending on the input format.
 *
 * Non-complex images only.
 *
 * See also: vips_hist_find(), vips_profile().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_project( VipsImage *in, VipsImage **columns, VipsImage **rows, ... )
{
	va_list ap;
	int result;

	va_start( ap, rows );
	result = vips_call_split( "project", ap, in, columns, rows );
	va_end( ap );

	return( result );
}

