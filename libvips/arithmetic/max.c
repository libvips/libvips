/* find image maximum
 *
 * Copyright: 1990, J. Cupitt
 *
 * Author: J. Cupitt
 * Written on: 02/05/1990
 * Modified on : 18/03/1991, N. Dessipris
 * 	23/11/92:  J.Cupitt - correct result for more than 1 band now.
 * 23/7/93 JC
 *	- im_incheck() call added
 * 20/6/95 JC
 *	- now returns double for value, like im_max()
 * 4/9/09
 * 	- gtkdoc comment
 * 8/9/09
 * 	- rewrite based on im_max() to get partial
 * 	- move im_max() in here as a convenience function
 * 6/11/11
 * 	- rewrite as a class
 * 	- abandon scan if we find maximum possible value
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

/*
#define DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <limits.h>

#include <vips/vips.h>
#include <vips/internal.h>

#include "statistic.h"

/**
 * VipsMax:
 * @in: input #VipsImage
 * @out: output pixel maximum
 *
 * This operation finds the maximum value in an image. 
 *
 * If the image contains several maximum values, only the first one found is
 * returned.
 *
 * It operates on all 
 * bands of the input image: use im_stats() if you need to find an 
 * maximum for each band. For complex images, find the maximum modulus.
 *
 * See also: #VipsAvg, #VipsMin, im_stats(), im_bandmean(), im_deviate(), im_rank()
 */

typedef struct _VipsMax {
	VipsStatistic parent_instance;

	gboolean set;		/* FALSE means no value yet */

	/* The current maximum. When scanning complex images, we keep the
	 * square of the modulus here and do a single sqrt() right at the end.
	 */
	double max;

	/* And its position.
	 */
	int x, y;
} VipsMax;

typedef VipsStatisticClass VipsMaxClass;

G_DEFINE_TYPE( VipsMax, vips_max, VIPS_TYPE_STATISTIC );

static int
vips_max_build( VipsObject *object )
{
	VipsStatistic *statistic = VIPS_STATISTIC( object ); 
	VipsMax *max = (VipsMax *) object;

	double m;

	if( VIPS_OBJECT_CLASS( vips_max_parent_class )->build( object ) )
		return( -1 );

	/* For speed we accumulate max^2 for complex.
	 */
	m = max->max;
	if( vips_bandfmt_iscomplex( vips_image_get_format( statistic->in ) ) )
		m = sqrt( m );

	/* We have to set the props via g_object_set() to stop vips
	 * complaining they are unset.
	 */
	g_object_set( max, 
		"out", m,
		"x", max->x,
		"y", max->y,
		NULL );

	return( 0 );
}

/* New sequence value. Make a private VipsMax for this thread.
 */
static void *
vips_max_start( VipsStatistic *statistic )
{
	VipsMax *global = (VipsMax *) statistic;
	VipsMax *max;

	max = g_new( VipsMax, 1 );
	*max = *global;

	return( (void *) max );
}

/* Merge the sequence value back into the per-call state.
 */
static int
vips_max_stop( VipsStatistic *statistic, void *seq )
{
	VipsMax *global = (VipsMax *) statistic;
	VipsMax *max = (VipsMax *) seq;

	if( !global->set ||
		max->max < global->max ) {
		global->max = max->max;
		global->x = max->x;
		global->y = max->y;
		global->set = TRUE;
	}

	g_free( max );

	return( 0 );
}

/* real max with no limits.
 */
#define LOOP( TYPE ) { \
	TYPE *p = (TYPE *) in; \
	TYPE m; \
	\
	if( max->set ) \
		m = max->max; \
	else \
		m = p[0]; \
	\
	for( i = 0; i < sz; i++ ) { \
		if( p[i] > m ) { \
			m = p[i]; \
			max->x = x + i / bands; \
			max->y = y; \
		} \
	} \
	\
	max->max = m; \
	max->set = TRUE; \
} 

/* real max with an upper bound.
 */
#define LOOPL( TYPE, UPPER ) { \
	TYPE *p = (TYPE *) in; \
	TYPE m; \
	\
	if( max->set ) \
		m = max->max; \
	else \
		m = p[0]; \
	\
	for( i = 0; i < sz; i++ ) { \
		if( p[i] > m ) { \
			m = p[i]; \
			max->x = x + i / bands; \
			max->y = y; \
			if( m >= UPPER ) { \
				statistic->stop = TRUE; \
				break; \
			} \
		} \
	} \
	\
	max->max = m; \
	max->set = TRUE; \
} 

#define CLOOP( TYPE ) { \
	TYPE *p = (TYPE *) in; \
	double m; \
	\
	if( max->set ) \
		m = max->max; \
	else \
		m = p[0] * p[0] + p[1] * p[1]; \
	\
	for( i = 0; i < sz; i++ ) { \
		double mod; \
		\
		mod = p[0] * p[0] + p[1] * p[1]; \
		p += 2; \
		\
		if( mod > m ) { \
			m = mod; \
			max->x = x + i / bands; \
			max->y = y; \
		} \
	} \
	\
	max->max = m; \
	max->set = TRUE; \
} 

/* Loop over region, adding to seq.
 */
static int
vips_max_scan( VipsStatistic *statistic, void *seq, 
	int x, int y, void *in, int n )
{
	VipsMax *max = (VipsMax *) seq;
	const int bands = vips_image_get_bands( statistic->in );
	const int sz = n * bands;

	int i;

	switch( vips_image_get_format( statistic->in ) ) {
	case IM_BANDFMT_UCHAR:		LOOPL( unsigned char, 0 ); break; 
	case IM_BANDFMT_CHAR:		LOOPL( signed char, SCHAR_MAX ); break; 
	case IM_BANDFMT_USHORT:		LOOPL( unsigned short, 0 ); break; 
	case IM_BANDFMT_SHORT:		LOOPL( signed short, SHRT_MAX ); break; 
	case IM_BANDFMT_UINT:		LOOPL( unsigned int, 0 ); break;
	case IM_BANDFMT_INT:		LOOPL( signed int, INT_MAX ); break; 

	case IM_BANDFMT_FLOAT:		LOOP( float ); break; 
	case IM_BANDFMT_DOUBLE:		LOOP( double ); break; 

	case IM_BANDFMT_COMPLEX:	CLOOP( float ); break; 
	case IM_BANDFMT_DPCOMPLEX:	CLOOP( double ); break; 

	default:  
		g_assert( 0 );
	}

	return( 0 );
}

static void
vips_max_class_init( VipsMaxClass *class )
{
	GObjectClass *gobject_class = (GObjectClass *) class;
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsStatisticClass *sclass = VIPS_STATISTIC_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "max";
	object_class->description = _( "find image maximum" );
	object_class->build = vips_max_build;

	sclass->start = vips_max_start;
	sclass->scan = vips_max_scan;
	sclass->stop = vips_max_stop;

	VIPS_ARG_DOUBLE( class, "out", 1, 
		_( "Output" ), 
		_( "Output value" ),
		VIPS_ARGUMENT_REQUIRED_OUTPUT,
		G_STRUCT_OFFSET( VipsMax, max ),
		-G_MAXDOUBLE, G_MAXDOUBLE, 0.0 );

	VIPS_ARG_INT( class, "x", 2, 
		_( "x" ), 
		_( "Horizontal position of maximum" ),
		VIPS_ARGUMENT_OPTIONAL_OUTPUT,
		G_STRUCT_OFFSET( VipsMax, x ),
		0, 1000000, 0 );

	VIPS_ARG_INT( class, "y", 2, 
		_( "y" ), 
		_( "Vertical position of maximum" ),
		VIPS_ARGUMENT_OPTIONAL_OUTPUT,
		G_STRUCT_OFFSET( VipsMax, y ),
		0, 1000000, 0 );
}

static void
vips_max_init( VipsMax *max )
{
}

int
vips_max( VipsImage *in, double *out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "max", ap, in, out );
	va_end( ap );

	return( result );
}
