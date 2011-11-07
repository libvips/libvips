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
 * one-band #VIPS_FORMAT_DOUBLE image 
 * of 6 columns by n + 1 (where n is number of bands in image @in) 
 * rows. Columns are statistics, and are, in order: minimum, maximum, sum, 
 * sum of squares, mean, standard deviation. Row 0 has statistics for all 
 * bands together, row 1 has stats for band 1, and so on.
 *
 * See also: #VipsAvg, #VipsMin, and friends.
 *
 * Returns: 0 on success, -1 on error
 */

typedef struct _VipsStats {
	VipsStatistic parent_instance;

	VipsImage *out;

	or build out and use that as an array?

	double **stats;
} VipsStats;

typedef VipsStatisticClass VipsStatsClass;

G_DEFINE_TYPE( VipsStats, vips_stats, VIPS_TYPE_STATISTIC );

static int
vips_stats_build( VipsObject *object )
{
	VipsStatistic *statistic = VIPS_STATISTIC( object ); 
	VipsStats *stats = (VipsStats *) object;

	gint64 vals;
	double average;

	if( VIPS_OBJECT_CLASS( vips_stats_parent_class )->build( object ) )
		return( -1 );

	/* Calculate average. For complex, we accumulate re*re +
	 * im*im, so we need to sqrt.
	 */
	vals = (gint64) 
		vips_image_get_width( statistic->in ) * 
		vips_image_get_height( statistic->in ) * 
		vips_image_get_bands( statistic->in );
	average = stats->sum / vals;
	if( vips_bandfmt_iscomplex( vips_image_get_format( statistic->in ) ) )
		average = sqrt( average );
	g_object_set( object, "out", average, NULL );

	return( 0 );
}

/* Start function: allocate space for a double in which we can accumulate the
 * sum for this thread.
 */
static void *
vips_stats_start( VipsStatistic *statistic )
{
	return( (void *) g_new0( double, 1 ) );
}

/* Stop function. Add this little sum to the main sum.
 */
static int
vips_stats_stop( VipsStatistic *statistic, void *seq )
{
	VipsStats *stats = (VipsStats *) statistic;
	double *sum = (double *) seq;

	stats->sum += *sum;

	g_free( seq );

	return( 0 );
}

/* Sum pels in this section.
 */
#define LOOP( TYPE ) { \
	TYPE *p = (TYPE *) in; \
	\
	for( i = 0; i < sz; i++ ) \
		m += p[i]; \
}

#define CLOOP( TYPE ) { \
	TYPE *p = (TYPE *) in; \
	\
	for( i = 0; i < sz; i++ ) { \
		double mod; \
		\
		mod = p[0] * p[0] + p[1] * p[1]; \
		p += 2; \
		\
		m += mod; \
	} \
} 

/* Loop over region, accumulating a sum in *tmp.
 */
static int
vips_stats_scan( VipsStatistic *statistic, void *seq, 
	int x, int y, void *in, int n )
{
	const int sz = n * vips_image_get_bands( statistic->in );

	double *sum = (double *) seq;

	int i;
	double m;

	m = *sum;

	/* Now generate code for all types. 
	 */
	switch( vips_image_get_format( statistic->in ) ) {
	case VIPS_FORMAT_UCHAR:		LOOP( unsigned char ); break; 
	case VIPS_FORMAT_CHAR:		LOOP( signed char ); break; 
	case VIPS_FORMAT_USHORT:	LOOP( unsigned short ); break; 
	case VIPS_FORMAT_SHORT:		LOOP( signed short ); break; 
	case VIPS_FORMAT_UINT:		LOOP( unsigned int ); break;
	case VIPS_FORMAT_INT:		LOOP( signed int ); break; 
	case VIPS_FORMAT_FLOAT:		LOOP( float ); break; 
	case VIPS_FORMAT_DOUBLE:	LOOP( double ); break; 
	case VIPS_FORMAT_COMPLEX:	CLOOP( float ); break; 
	case VIPS_FORMAT_DPCOMPLEX:	CLOOP( double ); break; 

	default: 
		g_assert( 0 );
	}

	*sum = m;

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
		_( "Output image" ),
		VIPS_ARGUMENT_REQUIRED_OUTPUT, 
		G_STRUCT_OFFSET( VipsStats, out ) );
}

static void
vips_stats_init( VipsStats *stats )
{
}

int
vips_stats( VipsImage *in, double *out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "stats", ap, in, out );
	va_end( ap );

	return( result );
}
