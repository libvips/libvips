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
 * 24/2/12
 * 	- avoid NaN in float/double/complex images
 * 	- allow +/- INFINITY as a result
 * 4/12/12
 * 	- track and return top n values
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

/* Track max values and position here. We need one of these for each thread,
 * and one for the main value.
 *
 * We will generally only be tracking a small (<10?) number of values, so
 * simple arrays will be fastest.
 */
typedef struct _VipsValues {
	struct _VipsMax *max;

	/* The max number of values we track.
	 */
	int size;

	/* How many values we have in the arrays.
	 */
	int n;

	/* Position and values. We track mod**2 for complex and do a sqrt() at
	 * the end. The three arrays are sorted by values, smallest first.
	 */
	double *value;
	int *x_pos;
	int *y_pos;
} VipsValues;

typedef struct _VipsMax {
	VipsStatistic parent_instance;

	/* Max number of values we track.
	 */
	int size;

	/* The single max. Can be unset if, for example, the whole image is
	 * NaN.
	 */
	double max;
	int x;
	int y;

	/* And the postions and values we found as VipsArrays for returning to
	 * our caller.
	 */
	VipsArrayDouble *max_array;
	VipsArrayInt *x_array;
	VipsArrayInt *y_array;

	/* Global state here.
	 */
	VipsValues values;
} VipsMax;

static void
vips_values_init( VipsValues *values, VipsMax *max )
{
	values->max = max;

	values->size = max->size;
	values->n = 0;
	values->value = VIPS_ARRAY( max, values->size, double );
	values->x_pos = VIPS_ARRAY( max, values->size, int );
	values->y_pos = VIPS_ARRAY( max, values->size, int );
}

/* Add a value. Do nothing if the value is too small.
 */
static void
vips_values_add( VipsValues *values, double v, int x, int y )
{
	int i, j;

	/* Find insertion point.
	 */
	for( i = 0; i < values->n; i++ )
		if( values->value[i] > v ) 
			break;

	/* Array full? 
	 */
	if( values->n == values->size ) {
		if( i > 0 ) {
			/* We need to move stuff to the left to make space,
			 * shunting the smallest out.
			 */
			for( j = 0; j < i - 1; j++ ) {
				values->value[j] = values->value[j + 1];
				values->x_pos[j] = values->x_pos[j + 1];
				values->y_pos[j] = values->y_pos[j + 1];
			}
			values->value[i - 1] = v;
			values->x_pos[i - 1] = x;
			values->y_pos[i - 1] = y;
		}
	}
	else {
		/* Not full, move stuff to the right into empty space.
		 */
		for( j = values->n; j > i; j-- ) {
			values->value[j] = values->value[j - 1];
			values->x_pos[j] = values->x_pos[j - 1];
			values->y_pos[j] = values->y_pos[j - 1];
		}
		values->value[i] = v;
		values->x_pos[i] = x;
		values->y_pos[i] = y;
		values->n += 1;
	}
}

typedef VipsStatisticClass VipsMaxClass;

G_DEFINE_TYPE( VipsMax, vips_max, VIPS_TYPE_STATISTIC );

static int
vips_max_build( VipsObject *object )
{
	VipsStatistic *statistic = VIPS_STATISTIC( object ); 
	VipsMax *max = (VipsMax *) object;
	VipsValues *values = &max->values;
	int i;

	vips_values_init( values, max );

	if( VIPS_OBJECT_CLASS( vips_max_parent_class )->build( object ) )
		return( -1 );

	/* For speed we accumulate max ** 2 for complex.
	 */
	if( vips_bandfmt_iscomplex( vips_image_get_format( statistic->in ) ) ) 
		for( i = 0; i < values->n; i++ ) 
			values->value[i] = sqrt( values->value[i] );

	/* Don't set if there's no value (eg. if every pixel is NaN). This
	 * will trigger an error later.
	 */
	if( values->n > 0 ) {
		VipsArrayDouble *out_array;
		VipsArrayInt *x_array;
		VipsArrayInt *y_array;

		out_array = vips_array_double_new( values->value, values->n );
		x_array = vips_array_int_new( values->x_pos, values->n );
		y_array = vips_array_int_new( values->y_pos, values->n );

		/* We have to set the props via g_object_set() to stop vips
		 * complaining they are unset.
		 */
		g_object_set( max, 
			"out", values->value[values->n - 1],
			"x", values->x_pos[values->n - 1],
			"y", values->y_pos[values->n - 1],
			"out_array", out_array,
			"x_array", x_array,
			"y_array", y_array,
			NULL );

		vips_area_unref( (VipsArea *) out_array );
		vips_area_unref( (VipsArea *) x_array );
		vips_area_unref( (VipsArea *) y_array );
	}

#ifdef DEBUG
	printf( "vips_max_build: %d values found\n", values->n );
	for( i = 0; i < values->n; i++ )
		printf( "%d) %g\t%d\t%d\n", 
			i, 
			values->value[i], 
			values->x_pos[i], values->y_pos[i] ); 
#endif /*DEBUG*/

	return( 0 );
}

/* New sequence value. Make a private VipsValues for this thread.
 */
static void *
vips_max_start( VipsStatistic *statistic )
{
	VipsValues *values;

	values = g_new( VipsValues, 1 );
	vips_values_init( values, (VipsMax *) statistic ); 

	return( (void *) values );
}

/* Merge the sequence value back into the per-call state.
 */
static int
vips_max_stop( VipsStatistic *statistic, void *seq )
{
	VipsMax *max = (VipsMax *) statistic;
	VipsValues *values = (VipsValues *) seq;

	int i;

	for( i = 0; i < values->n; i++ )
		vips_values_add( &max->values, 
			values->value[i], values->x_pos[i], values->y_pos[i] );

	g_free( values );

	return( 0 );
}

/* Real max with an upper bound. 
 *
 * Add values to the buffer if they are greater than the buffer minimum. If
 * the buffer isn't full, there is no minimum.
 *
 * Avoid a double test by splitting the loop into two phases: before and after
 * the buffer fills.
 *
 * Stop if our array fills with maxval.
 */
#define LOOPU( TYPE, UPPER ) { \
	TYPE *p = (TYPE *) in; \
	TYPE m; \
	\
	for( i = 0; i < sz && values->n < values->size; i++ ) \
		vips_values_add( values, p[i], x + i / bands, y ); \
	m = values->value[0]; \
	\
	for( ; i < sz; i++ ) { \
		if( p[i] > m ) { \
			vips_values_add( values, p[i], x + i / bands, y ); \
			m = values->value[0]; \
			\
			if( m >= UPPER ) { \
				statistic->stop = TRUE; \
				break; \
			} \
		} \
	} \
} 

/* float/double max ... no limits, and we have to avoid NaN.
 *
 * NaN compares false to every float value, so if we were to take the first
 * point in this buffer as our start max (as we do above) and it was NaN, we'd
 * never replace it with a true value.
 */
#define LOOPF( TYPE ) { \
	TYPE *p = (TYPE *) in; \
	TYPE m; \
	\
	for( i = 0; i < sz && values->n < values->size; i++ ) \
		if( !isnan( p[i] ) ) \
			vips_values_add( values, p[i], x + i / bands, y ); \
	m = values->value[0]; \
	\
	for( ; i < sz; i++ ) \
		if( p[i] > m ) { \
			vips_values_add( values, p[i], x + i / bands, y ); \
			m = values->value[0]; \
		} \
} 

/* As LOOPF, but complex. Track max(mod ** 2) to avoid sqrt().
 */
#define LOOPC( TYPE ) { \
	TYPE *p = (TYPE *) in; \
	TYPE m; \
	\
	for( i = 0; i < sz && values->n < values->size; i++ ) { \
		TYPE mod2 = p[0] * p[0] + p[1] * p[1]; \
		\
		if( !isnan( mod2 ) ) \
			vips_values_add( values, p[i], x + i / bands, y ); \
		\
		p += 2; \
	} \
	m = values->value[0]; \
	\
	for( ; i < sz; i++ ) { \
		TYPE mod2 = p[0] * p[0] + p[1] * p[1]; \
		\
		if( mod2 > m ) { \
			vips_values_add( values, mod2, x + i / bands, y ); \
			m = values->value[0]; \
		} \
		\
		p += 2; \
	} \
} 

/* Loop over region, adding to seq.
 */
static int
vips_max_scan( VipsStatistic *statistic, void *seq, 
	int x, int y, void *in, int n )
{
	VipsValues *values = (VipsValues *) seq;
	const int bands = vips_image_get_bands( statistic->in );
	const int sz = n * bands;

	int i;

	switch( vips_image_get_format( statistic->in ) ) {
	case VIPS_FORMAT_UCHAR:		
		LOOPU( unsigned char, UCHAR_MAX ); break; 
	case VIPS_FORMAT_CHAR:	
		LOOPU( signed char, SCHAR_MAX ); break; 
	case VIPS_FORMAT_USHORT:	
		LOOPU( unsigned short, USHRT_MAX ); break; 
	case VIPS_FORMAT_SHORT:	
		LOOPU( signed short, SHRT_MAX ); break; 
	case VIPS_FORMAT_UINT:	
		LOOPU( unsigned int, UINT_MAX ); break;
	case VIPS_FORMAT_INT:	
		LOOPU( signed int, INT_MAX ); break; 

	case VIPS_FORMAT_FLOAT:	
		LOOPF( float ); break; 
	case VIPS_FORMAT_DOUBLE:	
		LOOPF( double ); break; 

	case VIPS_FORMAT_COMPLEX:
		LOOPC( float ); break; 
	case VIPS_FORMAT_DPCOMPLEX:
		LOOPC( double ); break; 

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
		-INFINITY, INFINITY, 0.0 );

	VIPS_ARG_INT( class, "x", 2, 
		_( "x" ), 
		_( "Horizontal position of maximum" ),
		VIPS_ARGUMENT_OPTIONAL_OUTPUT,
		G_STRUCT_OFFSET( VipsMax, x ),
		0, 1000000, 0 );

	VIPS_ARG_INT( class, "y", 3, 
		_( "y" ), 
		_( "Vertical position of maximum" ),
		VIPS_ARGUMENT_OPTIONAL_OUTPUT,
		G_STRUCT_OFFSET( VipsMax, y ),
		0, 1000000, 0 );

	VIPS_ARG_INT( class, "size", 4, 
		_( "Size" ), 
		_( "Number of maximum values to find" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsMax, size ),
		0, 1000000, 10 );

	VIPS_ARG_BOXED( class, "out_array", 6, 
		_( "Output array" ), 
		_( "Array of output values" ),
		VIPS_ARGUMENT_OPTIONAL_OUTPUT,
		G_STRUCT_OFFSET( VipsMax, max_array ),
		VIPS_TYPE_ARRAY_DOUBLE );

	VIPS_ARG_BOXED( class, "x_array", 7, 
		_( "x array" ), 
		_( "Array of horizontal positions" ),
		VIPS_ARGUMENT_OPTIONAL_OUTPUT,
		G_STRUCT_OFFSET( VipsMax, x_array ),
		VIPS_TYPE_ARRAY_INT );

	VIPS_ARG_BOXED( class, "y_array", 8, 
		_( "y array" ), 
		_( "Array of vertical positions" ),
		VIPS_ARGUMENT_OPTIONAL_OUTPUT,
		G_STRUCT_OFFSET( VipsMax, y_array ),
		VIPS_TYPE_ARRAY_INT );
}

static void
vips_max_init( VipsMax *max )
{
	max->size = 1;
}

/**
 * vips_max:
 * @in: input #VipsImage
 * @out: output pixel maximum
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * @x: horizontal position of maximum
 * @y: vertical position of maximum
 * @size: number of maxima to find
 * @out_array: return array of maximum values
 * @x_array: corresponding horizontal positions
 * @y_array: corresponding vertical positions
 *
 * This operation finds the maximum value in an image. 
 *
 * If the image contains several maximum values, only the first @size 
 * found are returned.
 *
 * It operates on all 
 * bands of the input image: use vips_stats() if you need to find an 
 * maximum for each band. 
 *
 * For complex images, this operation finds the maximum modulus.
 *
 * You can read out the position of the maximum with @x and @y. You can read
 * out arrays of the values and positions of the top @size maxima with
 * @out_array, @x_array and @y_array.
 *
 * See also: vips_min(), vips_stats().
 *
 * Returns: 0 on success, -1 on error
 */
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
