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
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

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
#include <math.h>

#include <vips/vips.h>
#include <vips/internal.h>

#include "statistic.h"

/**
 * VipsStats:
 * @in: image to scan
 * @out: image of statistics
 *
 * Find many image statistics in a single pass through the data. @out is a
 * one-band #VIPS_FORMAT_DOUBLE image of at least 10 columns by n + 1 
 * (where n is number of bands in image @in) 
 * rows. Columns are statistics, and are, in order: minimum, maximum, sum, 
 * sum of squares, mean, standard deviation, x coordinate of minimum, y
 * coordinate of minimum, x coordinate of maximum, y coordinate of maximum. 
 * Later versions of VipsStats may add more columns.
 *
 * Row 0 has statistics for all 
 * bands together, row 1 has stats for band 1, and so on.
 *
 * See also: #VipsAvg, #VipsMin, and friends.
 */

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

/* Address a double in our array image.
 */
#define ARY( im, x, y ) ((double *) VIPS_IMAGE_ADDR( im, x, y ))

static int
vips_stats_build( VipsObject *object )
{
	VipsStatistic *statistic = VIPS_STATISTIC( object ); 
	VipsStats *stats = (VipsStats *) object;

	gint64 vals, pels;
	double *row0;
	int b;

	if( statistic->in ) {
		int bands = vips_image_get_bands( statistic->in );

		if( vips_check_noncomplex( "VipsStats", statistic->in ) )
			return( -1 );

		g_object_set( object, 
			"out", vips_image_new_array( COL_LAST, bands + 1 ),
			NULL );
	}

	if( VIPS_OBJECT_CLASS( vips_stats_parent_class )->build( object ) )
		return( -1 );

	pels = (gint64) 
		vips_image_get_width( statistic->in ) * 
		vips_image_get_height( statistic->in );
	vals = pels * vips_image_get_bands( statistic->in );

	row0 = ARY( stats->out, 0, 0 ); 

	row0[COL_MIN] = *ARY( stats->out, 0, COL_MIN ); 
	row0[COL_MAX] = *ARY( stats->out, 0, COL_MAX ); 
	row0[COL_SUM] = 0;
	row0[COL_SUM2] = 0;

	for( b = 0; b < vips_image_get_bands( statistic->in ); b++ ) {
		double *row = ARY( stats->out, 0, b + 1 ); 

		row0[COL_MIN] = VIPS_MIN( row0[COL_MIN], row[COL_MIN] );
		row0[COL_MAX] = VIPS_MAX( row0[COL_MAX], row[COL_MAX] );
		row0[COL_SUM] += row[COL_SUM];
		row0[COL_SUM2] += row[COL_SUM2];

		row[COL_AVG] = row[COL_SUM] / pels;
		row[COL_SD] = sqrt( fabs( row[COL_SUM2] - 
			(row[COL_SUM] * row[COL_SUM] / pels) ) / (pels - 1) );
	}

	row0[COL_AVG] = row0[COL_SUM] / vals;
	row0[COL_SD] = sqrt( fabs( row0[COL_SUM2] - 
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
			double *p = ARY( local->out, 0, b + 1 );
			double *q = ARY( global->out, 0, b + 1 );

			q[COL_MIN] = p[COL_MIN];
			q[COL_MAX] = p[COL_MAX];
			q[COL_SUM] = p[COL_SUM];
			q[COL_SUM2] = p[COL_SUM2];
		}

		global->set = TRUE;
	}
	else if( local->set && global->set ) {
		for( b = 0; b < bands; b++ ) {
			double *p = ARY( local->out, 0, b + 1 );
			double *q = ARY( global->out, 0, b + 1 );

			q[COL_MIN] = VIPS_MIN( q[COL_MIN], p[COL_MIN] );
			q[COL_MAX] = VIPS_MAX( q[COL_MAX], p[COL_MAX] );
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
	if( !(stats->out = vips_image_new_array( COL_LAST, bands + 1 )) ) {
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
		double *q = ARY( local->out, 0, b + 1 ); \
		TYPE small, big; \
		double sum, sum2; \
		\
		if( local->set ) { \
			small = q[COL_MIN]; \
			big = q[COL_MAX]; \
			sum = q[COL_SUM]; \
			sum2 = q[COL_SUM2]; \
		} \
		else { \
			small = p[0]; \
			big = p[0]; \
			sum = 0; \
			sum2 = 0; \
		} \
		\
		for( i = 0; i < n; i++ ) { \
			TYPE value = *p; \
			\
			sum += value;\
			sum2 += (double) value * (double) value;\
			if( value > big ) \
				big = value; \
			else if( value < small ) \
				small = value;\
			\
			p += bands; \
		} \
		\
		q[COL_MIN] = small; \
		q[COL_MAX] = big; \
		q[COL_SUM] = sum; \
		q[COL_SUM2] = sum2; \
		local->set = TRUE; \
	} \
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
		g_assert( 0 );
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
