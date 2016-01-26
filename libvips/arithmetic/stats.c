/* stats.c ... many image stats in a single pass
 *
(C) Kirk Martinez 1993
23/4/93 J.Cupitt
	- adapted to partial images
	- special struct abandoned; now returns DOUBLEMASK.
1/7/93 JC
	- adapted for partial v2
	- ANSIfied
27/7/93 JC
	- init of mask changed to use actual values, not IM_MAXDOUBLE and
	  (-IM_MAXDOUBLE). These caused problems when assigned to floats.
	  funny business with offset==42, yuk!
31/8/93 JC
	- forgot to init global max/min properly! sorry.
21/6/95 JC
	- still did not init max and min correctly --- now fixed for good

 * 13/1/05
 *	- use 64 bit arithmetic 
 * 1/9/09
 *	- argh nope min/max was broken again for >1CPU in short pipelines on 
 *  	  some architectures
 * 7/9/09
 * 	- rework based on new im__wrapscan() / im_max() ideas for a proper fix
 * 	- gtkdoc comment
 * 7/11/11
 * 	- redone as a class
 * 	- track maxpos / minpos too
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
#include <vips/intl.h>

#include <stdio.h>
#include <stdlib.h>
#include <math.h>

#include <vips/vips.h>
#include <vips/internal.h>

#include "statistic.h"

typedef struct _VipsStats {
	VipsStatistic parent_instance;

	VipsImage *out;

	gboolean set;		/* FALSE means no value yet */
} VipsStats;

typedef VipsStatisticClass VipsStatsClass;

G_DEFINE_TYPE( VipsStats, vips_stats, VIPS_TYPE_STATISTIC );

/* Names for our columns.
 */
enum {
	COL_MIN = 0,
	COL_MAX = 1,
	COL_SUM = 2,
	COL_SUM2 = 3,
	COL_AVG = 4,
	COL_SD = 5,
	COL_XMIN = 6,
	COL_YMIN = 7,
	COL_XMAX = 8,
	COL_YMAX = 9,
	COL_LAST = 10
};

static int
vips_stats_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsStatistic *statistic = VIPS_STATISTIC( object ); 
	VipsStats *stats = (VipsStats *) object;

	gint64 vals, pels;
	double *row0, *row;
	int b, y, i;

	if( vips_object_argument_isset( object, "in" ) ) {
		int bands = vips_image_get_bands( statistic->in );

		if( vips_check_noncomplex( class->nickname, statistic->in ) )
			return( -1 );

		g_object_set( object, 
			"out", vips_image_new_matrix( COL_LAST, bands + 1 ),
			NULL );
	}

	if( VIPS_OBJECT_CLASS( vips_stats_parent_class )->build( object ) )
		return( -1 );

	pels = (gint64) vips_image_get_width( statistic->in ) * 
		vips_image_get_height( statistic->in );
	vals = pels * vips_image_get_bands( statistic->in );

	row0 = VIPS_MATRIX( stats->out, 0, 0 ); 
	row = VIPS_MATRIX( stats->out, 0, 1 ); 
	for( i = 0; i < COL_LAST; i++ )
		row0[i] = row[i];

	for( b = 1; b < vips_image_get_bands( statistic->in ); b++ ) {
		row = VIPS_MATRIX( stats->out, 0, b + 1 ); 

		if( row[COL_MIN] < row0[COL_MIN] ) {
			row0[COL_MIN] = row[COL_MIN];
			row0[COL_XMIN] = row[COL_XMIN];
			row0[COL_YMIN] = row[COL_YMIN];
		}

		if( row[COL_MAX] > row0[COL_MAX] ) {
			row0[COL_MAX] = row[COL_MAX];
			row0[COL_XMAX] = row[COL_XMAX];
			row0[COL_YMAX] = row[COL_YMAX];
		}

		row0[COL_SUM] += row[COL_SUM];
		row0[COL_SUM2] += row[COL_SUM2];
	}

	for( y = 1; y < vips_image_get_height( stats->out ); y++ ) {
		double *row = VIPS_MATRIX( stats->out, 0, y ); 

		row[COL_AVG] = row[COL_SUM] / pels;
		row[COL_SD] = sqrt( VIPS_FABS( row[COL_SUM2] - 
			(row[COL_SUM] * row[COL_SUM] / pels) ) / (pels - 1) );
	}

	row0[COL_AVG] = row0[COL_SUM] / vals;
	row0[COL_SD] = sqrt( VIPS_FABS( row0[COL_SUM2] - 
		(row0[COL_SUM] * row0[COL_SUM] / vals) ) / (vals - 1) );

	return( 0 );
}

/* Stop function. Add these little stats to the main set of stats.
 */
static int
vips_stats_stop( VipsStatistic *statistic, void *seq )
{
	int bands = vips_image_get_bands( statistic->in );
	VipsStats *global = (VipsStats *) statistic;
	VipsStats *local = (VipsStats *) seq;

	int b;

	if( local->set && !global->set ) {
		for( b = 0; b < bands; b++ ) {
			double *p = VIPS_MATRIX( local->out, 0, b + 1 );
			double *q = VIPS_MATRIX( global->out, 0, b + 1 );

			int i;

			for( i = 0; i < COL_LAST; i++ )
				q[i] = p[i];
		}

		global->set = TRUE;
	}
	else if( local->set && global->set ) {
		for( b = 0; b < bands; b++ ) {
			double *p = VIPS_MATRIX( local->out, 0, b + 1 );
			double *q = VIPS_MATRIX( global->out, 0, b + 1 );

			if( p[COL_MIN] < q[COL_MIN] ) {
				q[COL_MIN] = p[COL_MIN];
				q[COL_XMIN] = p[COL_XMIN];
				q[COL_YMIN] = p[COL_YMIN];
			}

			if( p[COL_MAX] > q[COL_MAX] ) {
				q[COL_MAX] = p[COL_MAX];
				q[COL_XMAX] = p[COL_XMAX];
				q[COL_YMAX] = p[COL_YMAX];
			}

			q[COL_SUM] += p[COL_SUM];
			q[COL_SUM2] += p[COL_SUM2];
		}
	}

	VIPS_FREEF( g_object_unref, local->out );
	VIPS_FREEF( g_free, seq );

	return( 0 );
}

/* Start function: make a dummy local stats for the private use of this thread. 
 */
static void *
vips_stats_start( VipsStatistic *statistic )
{
	int bands = vips_image_get_bands( statistic->in );

	VipsStats *stats;

	stats = g_new( VipsStats, 1 );
	if( !(stats->out = vips_image_new_matrix( COL_LAST, bands + 1 )) ) {
		g_free( stats );
		return( NULL );
	}
	stats->set = FALSE;

	return( (void *) stats );
}

/* We scan lines bands times to avoid repeating band loops.
 * Use temp variables of same type for min/max for faster comparisons.
 */
#define LOOP( TYPE ) { \
	for( b = 0; b < bands; b++ ) { \
		TYPE *p = ((TYPE *) in) + b; \
		double *q = VIPS_MATRIX( local->out, 0, b + 1 ); \
		TYPE small, big; \
		double sum, sum2; \
		int xmin, ymin; \
		int xmax, ymax; \
		\
		if( local->set ) { \
			small = q[COL_MIN]; \
			big = q[COL_MAX]; \
			sum = q[COL_SUM]; \
			sum2 = q[COL_SUM2]; \
			xmin = q[COL_XMIN]; \
			ymin = q[COL_YMIN]; \
			xmax = q[COL_XMAX]; \
			ymax = q[COL_YMAX]; \
		} \
		else { \
			small = p[0]; \
			big = p[0]; \
			sum = 0; \
			sum2 = 0; \
			xmin = x; \
			ymin = y; \
			xmax = x; \
			ymax = y; \
		} \
		\
		for( i = 0; i < n; i++ ) { \
			TYPE value = *p; \
			\
			sum += value; \
			sum2 += (double) value * (double) value; \
			if( value > big ) { \
				big = value; \
				xmax = x + i; \
				ymax = y; \
			} \
			else if( value < small ) { \
				small = value; \
				xmin = x + i; \
				ymin = y; \
			} \
			\
			p += bands; \
		} \
		\
		q[COL_MIN] = small; \
		q[COL_MAX] = big; \
		q[COL_SUM] = sum; \
		q[COL_SUM2] = sum2; \
		q[COL_XMIN] = xmin; \
		q[COL_YMIN] = ymin; \
		q[COL_XMAX] = xmax; \
		q[COL_YMAX] = ymax; \
	} \
	\
	local->set = TRUE; \
} 

/* As above, but for float/double types where we have to avoid NaN.
 */
#define LOOPF( TYPE ) { \
	for( b = 0; b < bands; b++ ) { \
		TYPE *p = ((TYPE *) in) + b; \
		double *q = VIPS_MATRIX( local->out, 0, b + 1 ); \
		TYPE small, big; \
		double sum, sum2; \
		int xmin, ymin; \
		int xmax, ymax; \
		\
		if( local->set ) { \
			small = q[COL_MIN]; \
			big = q[COL_MAX]; \
			sum = q[COL_SUM]; \
			sum2 = q[COL_SUM2]; \
			xmin = q[COL_XMIN]; \
			ymin = q[COL_YMIN]; \
			xmax = q[COL_XMAX]; \
			ymax = q[COL_YMAX]; \
		} \
		else { \
			small = p[0]; \
			big = p[0]; \
			sum = 0; \
			sum2 = 0; \
			xmin = x; \
			ymin = y; \
			xmax = x; \
			ymax = y; \
		} \
		\
		for( i = 0; i < n; i++ ) { \
			TYPE value = *p; \
			\
			sum += value; \
			sum2 += (double) value * (double) value; \
			if( value > big ) { \
				big = value; \
				xmax = x + i; \
				ymax = y; \
			} \
			else if( value < small ) { \
				small = value; \
				xmin = x + i; \
				ymin = y; \
			} \
			\
			p += bands; \
		} \
		\
		q[COL_MIN] = small; \
		q[COL_MAX] = big; \
		q[COL_SUM] = sum; \
		q[COL_SUM2] = sum2; \
		q[COL_XMIN] = xmin; \
		q[COL_YMIN] = ymin; \
		q[COL_XMAX] = xmax; \
		q[COL_YMAX] = ymax; \
	} \
	\
	local->set = TRUE; \
} 

/* Loop over region, accumulating a sum in *tmp.
 */
static int
vips_stats_scan( VipsStatistic *statistic, void *seq, 
	int x, int y, void *in, int n )
{
	const int bands = vips_image_get_bands( statistic->in );
	VipsStats *local = (VipsStats *) seq;

	int b, i;

	switch( vips_image_get_format( statistic->in ) ) {
	case VIPS_FORMAT_UCHAR:		LOOP( unsigned char ); break; 
	case VIPS_FORMAT_CHAR:		LOOP( signed char ); break; 
	case VIPS_FORMAT_USHORT:	LOOP( unsigned short ); break; 
	case VIPS_FORMAT_SHORT:		LOOP( signed short ); break; 
	case VIPS_FORMAT_UINT:		LOOP( unsigned int ); break;
	case VIPS_FORMAT_INT:		LOOP( signed int ); break; 
	case VIPS_FORMAT_FLOAT:		LOOP( float ); break; 
	case VIPS_FORMAT_DOUBLE:	LOOP( double ); break; 

	default: 
		g_assert_not_reached();
	}

	return( 0 );
}

static void
vips_stats_class_init( VipsStatsClass *class )
{
	GObjectClass *gobject_class = (GObjectClass *) class;
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsStatisticClass *sclass = VIPS_STATISTIC_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "stats";
	object_class->description = _( "find image average" );
	object_class->build = vips_stats_build;

	sclass->start = vips_stats_start;
	sclass->scan = vips_stats_scan;
	sclass->stop = vips_stats_stop;

	VIPS_ARG_IMAGE( class, "out", 100, 
		_( "Output" ), 
		_( "Output array of statistics" ),
		VIPS_ARGUMENT_REQUIRED_OUTPUT, 
		G_STRUCT_OFFSET( VipsStats, out ) );
}

static void
vips_stats_init( VipsStats *stats )
{
}

/**
 * vips_stats:
 * @in: image to scan
 * @out: image of statistics
 * @...: %NULL-terminated list of optional named arguments
 *
 * Find many image statistics in a single pass through the data. @out is a
 * one-band #VIPS_FORMAT_DOUBLE image of at least 10 columns by n + 1 
 * (where n is number of bands in image @in) 
 * rows. Columns are statistics, and are, in order: minimum, maximum, sum, 
 * sum of squares, mean, standard deviation, x coordinate of minimum, y
 * coordinate of minimum, x coordinate of maximum, y coordinate of maximum. 
 * Later versions of vips_stats() may add more columns.
 *
 * Row 0 has statistics for all 
 * bands together, row 1 has stats for band 1, and so on.
 *
 * See also: vips_avg(), vips_min().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_stats( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "stats", ap, in, out );
	va_end( ap );

	return( result );
}
