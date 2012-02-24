/* avg ... average value of image
 *
 * Copyright: 1990, J. Cupitt
 *
 * Author: J. Cupitt
 * Written on: 02/08/1990
 * Modified on: 
 * 5/5/93 JC
 *	- now does partial images
 *	- less likely to overflow
 * 1/7/93 JC
 *	- adapted for partial v2
 *	- ANSI C
 * 21/2/95 JC
 *	- modernised again
 * 11/5/95 JC
 * 	- oops! return( NULL ) in im_avg(), instead of return( -1 )
 * 20/6/95 JC
 *	- now returns double
 * 13/1/05
 *	- use 64 bit arithmetic 
 * 8/12/06
 * 	- add liboil support
 * 18/8/09
 * 	- gtkdoc, minor reformatting
 * 7/9/09
 * 	- rewrite for im__wrapiter()
 * 	- add complex case (needed for im_max())
 * 8/9/09
 * 	- wrapscan stuff moved here
 * 31/7/10
 * 	- remove liboil
 * 24/8/11
 * 	- rewrite as a class
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

typedef struct _VipsAvg {
	VipsStatistic parent_instance;

	double sum;
	double out;
} VipsAvg;

typedef VipsStatisticClass VipsAvgClass;

G_DEFINE_TYPE( VipsAvg, vips_avg, VIPS_TYPE_STATISTIC );

static int
vips_avg_build( VipsObject *object )
{
	VipsStatistic *statistic = VIPS_STATISTIC( object ); 
	VipsAvg *avg = (VipsAvg *) object;

	gint64 vals;
	double average;

	if( VIPS_OBJECT_CLASS( vips_avg_parent_class )->build( object ) )
		return( -1 );

	/* Calculate average. For complex, we accumulate re*re +
	 * im*im, so we need to sqrt.
	 */
	vals = (gint64) 
		vips_image_get_width( statistic->in ) * 
		vips_image_get_height( statistic->in ) * 
		vips_image_get_bands( statistic->in );
	average = avg->sum / vals;
	if( vips_bandfmt_iscomplex( vips_image_get_format( statistic->in ) ) )
		average = sqrt( average );
	g_object_set( object, "out", average, NULL );

	return( 0 );
}

/* Start function: allocate space for a double in which we can accumulate the
 * sum for this thread.
 */
static void *
vips_avg_start( VipsStatistic *statistic )
{
	return( (void *) g_new0( double, 1 ) );
}

/* Stop function. Add this little sum to the main sum.
 */
static int
vips_avg_stop( VipsStatistic *statistic, void *seq )
{
	VipsAvg *avg = (VipsAvg *) statistic;
	double *sum = (double *) seq;

	avg->sum += *sum;

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
vips_avg_scan( VipsStatistic *statistic, void *seq, 
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
vips_avg_class_init( VipsAvgClass *class )
{
	GObjectClass *gobject_class = (GObjectClass *) class;
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsStatisticClass *sclass = VIPS_STATISTIC_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "avg";
	object_class->description = _( "find image average" );
	object_class->build = vips_avg_build;

	sclass->start = vips_avg_start;
	sclass->scan = vips_avg_scan;
	sclass->stop = vips_avg_stop;

	VIPS_ARG_DOUBLE( class, "out", 2, 
		_( "Output" ), 
		_( "Output value" ),
		VIPS_ARGUMENT_REQUIRED_OUTPUT,
		G_STRUCT_OFFSET( VipsAvg, out ),
		-INFINITY, INFINITY, 0.0 );
}

static void
vips_avg_init( VipsAvg *avg )
{
}


/**
 * vips_avg:
 * @in: input #VipsImage
 * @out: output pixel average
 * @...: %NULL-terminated list of optional named arguments
 *
 * This operation finds the average value in an image. It operates on all 
 * bands of the input image: use vips_stats() if you need to calculate an 
 * average for each band. For complex images, return the average modulus.
 *
 * See also: vips_stats(), vips_bandmean(), vips_deviate(), vips_rank()
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_avg( VipsImage *in, double *out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "avg", ap, in, out );
	va_end( ap );

	return( result );
}
