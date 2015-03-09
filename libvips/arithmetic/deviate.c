/* VipsDeviate
 *
 * Copyright: 1990, J. Cupitt
 *
 * Author: J. Cupitt
 * Written on: 02/08/1990
 * Modified on: 
 * 5/5/93 JC
 *	- now does partial images
 *	- less likely to overflow
 *	- adapted from im_deviate
 * 1/7/93 JC
 *	- adapted for partial v2
 *	- ANSIfied
 * 21/2/95 JC
 *	- modernised again
 * 11/5/95 JC
 * 	- oops! return( NULL ) in im_deviate(), instead of return( -1 )
 * 20/6/95 JC
 *	- now returns double, not float
 * 13/1/05
 *	- use 64 bit arithmetic 
 * 8/12/06
 * 	- add liboil support
 * 2/9/09
 * 	- gtk-doc comment
 * 	- minor reformatting
 * 4/9/09
 * 	- use im__wrapscan()
 * 31/7/10
 * 	- remove liboil
 * 6/11/11
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
#include <math.h>

#include <vips/vips.h>
#include <vips/internal.h>

#include "statistic.h"

typedef struct _VipsDeviate {
	VipsStatistic parent_instance;

	double sum;
	double sum2;
	double out;
} VipsDeviate;

typedef VipsStatisticClass VipsDeviateClass;

G_DEFINE_TYPE( VipsDeviate, vips_deviate, VIPS_TYPE_STATISTIC );

static int
vips_deviate_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsStatistic *statistic = VIPS_STATISTIC( object ); 
	VipsDeviate *deviate = (VipsDeviate *) object;

	gint64 vals;
	double s, s2;

	if( statistic->in &&
		vips_check_noncomplex( class->nickname, statistic->in ) )
		return( -1 );

	if( VIPS_OBJECT_CLASS( vips_deviate_parent_class )->build( object ) )
		return( -1 );

	/*
	  
		NOTE: NR suggests a two-pass algorithm to minimise roundoff. 
		But that's too expensive for us :-( so do it the old one-pass 
		way.

	 */

	/* Calculate and return deviation. Add a fabs to stop sqrt(<=0).
	 */
	vals = (gint64) 
		vips_image_get_width( statistic->in ) * 
		vips_image_get_height( statistic->in ) * 
		vips_image_get_bands( statistic->in );
	s = deviate->sum;
	s2 = deviate->sum2;

	g_object_set( object, 
		"out", sqrt( fabs( s2 - (s * s / vals) ) / (vals - 1) ),
		NULL );

	return( 0 );
}

/* Start function: allocate space for an array in which we can accumulate the
 * sum and sum of squares for this thread.
 */
static void *
vips_deviate_start( VipsStatistic *statistic )
{
	return( (void *) g_new0( double, 2 ) );
}

/* Stop function. Add this little sum to the main sum.
 */
static int
vips_deviate_stop( VipsStatistic *statistic, void *seq )
{
	VipsDeviate *deviate = (VipsDeviate *) statistic;
	double *ss2 = (double *) seq;

	deviate->sum += ss2[0];
	deviate->sum2 += ss2[1];

	g_free( ss2 );

	return( 0 );
}

#define LOOP( TYPE ) { \
	TYPE *p = (TYPE *) in; \
	\
	for( x = 0; x < sz; x++ ) { \
		TYPE v = p[x]; \
		\
		sum += v; \
		sum2 += (double) v * (double) v; \
	} \
}

static int
vips_deviate_scan( VipsStatistic *statistic, void *seq, 
	int x, int y, void *in, int n )
{
	const int sz = n * vips_image_get_bands( statistic->in );

	double *ss2 = (double *) seq;

	double sum;
	double sum2;

	sum = ss2[0];
	sum2 = ss2[1];

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

	default: 
		g_assert( 0 );
	}

	ss2[0] = sum;
	ss2[1] = sum2;

	return( 0 );
}

static void
vips_deviate_class_init( VipsDeviateClass *class )
{
	GObjectClass *gobject_class = (GObjectClass *) class;
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsStatisticClass *sclass = VIPS_STATISTIC_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "deviate";
	object_class->description = _( "find image standard deviation" );
	object_class->build = vips_deviate_build;

	sclass->start = vips_deviate_start;
	sclass->scan = vips_deviate_scan;
	sclass->stop = vips_deviate_stop;

	VIPS_ARG_DOUBLE( class, "out", 2, 
		_( "Output" ), 
		_( "Output value" ),
		VIPS_ARGUMENT_REQUIRED_OUTPUT,
		G_STRUCT_OFFSET( VipsDeviate, out ),
		-INFINITY, INFINITY, 0.0 );
}

static void
vips_deviate_init( VipsDeviate *deviate )
{
}

/**
 * vips_deviate:
 * @in: input #VipsImage
 * @out: output pixel standard deviation
 * @...: %NULL-terminated list of optional named arguments
 *
 * This operation finds the standard deviation of all pixels in @in. It 
 * operates on all bands of the input image: use vips_stats() if you need 
 * to calculate an average for each band. 
 *
 * Non-complex images only.
 *
 * See also: vips_avg(), vips_stats()..
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_deviate( VipsImage *in, double *out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "deviate", ap, in, out );
	va_end( ap );

	return( result );
}
