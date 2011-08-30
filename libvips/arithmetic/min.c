/* find image minimum
 *
 * Copyright: 1990, J. Cupitt
 *
 * Author: J. Cupitt
 * Written on: 02/05/1990
 * Modified on : 18/03/1991, N. Dessipris
 * 23/11/92 JC
 *	- correct result for more than 1 band now.
 * 23/7/93 JC
 *	- im_incheck() added
 * 20/6/95 JC
 *	- now returns double for value, like im_max()
 * 4/9/09
 * 	- gtkdoc comment
 * 8/9/09
 * 	- rewrite, from im_maxpos()
 * 30/8/11
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

#include <vips/vips.h>
#include <vips/internal.h>

#include "statistic.h"

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/**
 * VipsMin:
 * @in: input #VipsImage
 * @out: output pixel minimum
 *
 * This operation finds the minimum value in an image. 
 *
 * If the image contains several minimum values, only the first one found is
 * returned.
 *
 * It operates on all 
 * bands of the input image: use im_stats() if you need to find an 
 * minimum for each band. For complex images, return the minimum modulus.
 *
 * See also: #VipsAvg, im_stats(), im_bandmean(), im_deviate(), im_rank()
 */

/* Properties.
 */
enum {
	PROP_OUTPUT = 1,
	PROP_X,			/* Position of minimum */
	PROP_Y,
	PROP_LAST
}; 

typedef struct _VipsMin {
	VipsStatistic parent_instance;

	gboolean set;		/* FALSE means no value yet */

	/* The current miniumum. When scanning complex images, we keep the
	 * square of the modulus here and do a single sqrt() right at the end.
	 */
	double min;

	/* And its position.
	 */
	int x, y;
} VipsMin;

typedef VipsStatisticClass VipsMinClass;

G_DEFINE_TYPE( VipsMin, vips_min, VIPS_TYPE_STATISTIC );

static int
vips_min_build( VipsObject *object )
{
	VipsStatistic *statistic = VIPS_STATISTIC( object ); 
	VipsImage *input = statistic->input; 
	VipsMin *min = (VipsMin *) object;

	double m;

	if( VIPS_OBJECT_CLASS( vips_min_parent_class )->build( object ) )
		return( -1 );

	/* For speed we accumulate min^2 for complex.
	 */
	m = min->min;
	if( vips_bandfmt_iscomplex( vips_image_get_format( input ) ) )
		m = sqrt( m );

	/* We have to set the props via g_object_set() to stop vips
	 * complaining they are unset.
	 */
	g_object_set( min, 
		"out", m,
		"x", min->x,
		"y", min->y,
		NULL );

	return( 0 );
}

/* New sequence value. Make a private VipsMin for this thread.
 */
static void *
vips_min_start( VipsStatistic *statistic )
{
	VipsMin *global = (VipsMin *) statistic;
	VipsMin *min;

	if( !(min = VIPS_NEW( NULL, VipsMin )) ) 
		return( NULL );
	*min = *global;

	return( (void *) min );
}

/* Merge the sequence value back into the per-call state.
 */
static int
vips_min_stop( VipsStatistic *statistic, void *seq )
{
	VipsMin *global = (VipsMin *) statistic;
	VipsMin *min = (VipsMin *) seq;

	if( !global->set ||
		min->min < global->min ) {
		global->min = min->min;
		global->x = min->x;
		global->y = min->y;
		global->set = TRUE;
	}

	vips_free( min );

	return( 0 );
}

#define LOOP( TYPE ) { \
	TYPE *p = (TYPE *) in; \
	TYPE m; \
	\
	if( min->set ) \
		m = min->min; \
	else \
		m = p[0]; \
	\
	for( i = 0; i < sz; i++ ) { \
		if( p[i] < m ) { \
			m = p[i]; \
			min->x = x + i / bands; \
			min->y = y; \
		} \
	} \
	\
	min->min = m; \
	min->set = TRUE; \
} 

#define CLOOP( TYPE ) { \
	TYPE *p = (TYPE *) in; \
	double m; \
	\
	if( min->set ) \
		m = min->min; \
	else \
		m = p[0] * p[0] + p[1] * p[1]; \
	\
	for( i = 0; i < sz; i++ ) { \
		double mod; \
		\
		mod = p[0] * p[0] + p[1] * p[1]; \
		p += 2; \
		\
		if( mod < m ) { \
			m = mod; \
			min->x = x + i / bands; \
			min->y = y; \
		} \
	} \
	\
	min->min = m; \
	min->set = TRUE; \
} 

/* Loop over region, adding to seq.
 */
static int
vips_min_scan( VipsStatistic *statistic, void *seq, 
	int x, int y, void *in, int n )
{
	VipsMin *min = (VipsMin *) seq;
	const VipsImage *input = statistic->input;
	const int bands = vips_image_get_bands( input );
	const int sz = n * bands;

	int i;

	switch( vips_image_get_format( input ) ) {
	case IM_BANDFMT_UCHAR:		LOOP( unsigned char ); break; 
	case IM_BANDFMT_CHAR:		LOOP( signed char ); break; 
	case IM_BANDFMT_USHORT:		LOOP( unsigned short ); break; 
	case IM_BANDFMT_SHORT:		LOOP( signed short ); break; 
	case IM_BANDFMT_UINT:		LOOP( unsigned int ); break;
	case IM_BANDFMT_INT:		LOOP( signed int ); break; 
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
vips_min_class_init( VipsMinClass *class )
{
	GObjectClass *gobject_class = (GObjectClass *) class;
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsStatisticClass *sclass = VIPS_STATISTIC_CLASS( class );

	GParamSpec *pspec;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "min";
	object_class->description = _( "find image minimum" );
	object_class->build = vips_min_build;

	sclass->start = vips_min_start;
	sclass->scan = vips_min_scan;
	sclass->stop = vips_min_stop;

	pspec = g_param_spec_double( "out", "Output", 
		_( "Output value" ),
		-G_MAXDOUBLE,
		G_MAXDOUBLE,
		0.0,
		G_PARAM_READWRITE );
	g_object_class_install_property( gobject_class, 
		PROP_OUTPUT, pspec );
	vips_object_class_install_argument( object_class, pspec,
		VIPS_ARGUMENT_REQUIRED_OUTPUT | VIPS_ARGUMENT_APPEND, 
		G_STRUCT_OFFSET( VipsMin, min ) );

	pspec = g_param_spec_int( "x", "x",
		_( "Horizontal position of minimum" ),
		0, 1000000, 0,
		G_PARAM_READWRITE );
	g_object_class_install_property( gobject_class, 
		PROP_X, pspec );
	vips_object_class_install_argument( object_class, pspec,
		VIPS_ARGUMENT_OPTIONAL_OUTPUT,
		G_STRUCT_OFFSET( VipsMin, x ) );

	pspec = g_param_spec_int( "y", "y",
		_( "Vertical position of minimum" ),
		0, 1000000, 0,
		G_PARAM_READWRITE );
	g_object_class_install_property( gobject_class, 
		PROP_Y, pspec );
	vips_object_class_install_argument( object_class, pspec,
		VIPS_ARGUMENT_OPTIONAL_OUTPUT,
		G_STRUCT_OFFSET( VipsMin, y ) );
}

static void
vips_min_init( VipsMin *min )
{
}

int
vips_min( VipsImage *in, double *out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "min", ap, in, out );
	va_end( ap );

	return( result );
}
