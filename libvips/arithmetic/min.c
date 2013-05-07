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
 *	- now returns double for value, like im_min()
 * 4/9/09
 * 	- gtkdoc comment
 * 8/9/09
 * 	- rewrite, from im_minpos()
 * 30/8/11
 * 	- rewrite as a class
 * 5/9/11
 * 	- abandon scan if we find minimum possible value
 * 24/2/12
 * 	- avoid NaN in float/double/complex images
 * 	- allow +/- INFINITY as a result
 * 4/12/12
 * 	- from min.c
 * 	- track and return bottom n values
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

/* Track min values and position here. We need one of these for each thread,
 * and one for the main value.
 *
 * We will generally only be tracking a small (<10?) number of values, so
 * simple arrays will be fastest.
 */
typedef struct _VipsValues {
	struct _VipsMin *min;

	/* The min number of values we track.
	 */
	int size;

	/* How many values we have in the arrays.
	 */
	int n;

	/* Position and values. We track mod**2 for complex and do a sqrt() at
	 * the end. The three arrays are sorted by @value, largest first.
	 */
	double *value;
	int *x_pos;
	int *y_pos;
} VipsValues;

typedef struct _VipsMin {
	VipsStatistic parent_instance;

	/* Number of values we track.
	 */
	int size;

	/* The single min. Can be unset if, for example, the whole image is
	 * NaN.
	 */
	double min;
	int x;
	int y;

	/* And the positions and values we found as VipsArrays for returning 
	 * to our caller.
	 */
	VipsArrayDouble *min_array;
	VipsArrayInt *x_array;
	VipsArrayInt *y_array;

	/* Global state here.
	 */
	VipsValues values;
} VipsMin;

static void
vips_values_init( VipsValues *values, VipsMin *min )
{
	values->min = min;

	values->size = min->size;
	values->n = 0;
	values->value = VIPS_ARRAY( min, values->size, double );
	values->x_pos = VIPS_ARRAY( min, values->size, int );
	values->y_pos = VIPS_ARRAY( min, values->size, int );
}

/* Add a value. Do nothing if the value is too large.
 */
static void
vips_values_add( VipsValues *values, double v, int x, int y )
{
	int i, j;

	/* Find insertion point.
	 */
	for( i = 0; i < values->n; i++ )
		if( v >= values->value[i] ) 
			break;

	/* Array full? 
	 */
	if( values->n == values->size ) {
		if( i > 0 ) {
			/* We need to move stuff to the left to make space,
			 * shunting the largest out.
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

typedef VipsStatisticClass VipsMinClass;

G_DEFINE_TYPE( VipsMin, vips_min, VIPS_TYPE_STATISTIC );

static int
vips_min_build( VipsObject *object )
{
	VipsStatistic *statistic = VIPS_STATISTIC( object ); 
	VipsMin *min = (VipsMin *) object;
	VipsValues *values = &min->values;

	vips_values_init( values, min );

	if( VIPS_OBJECT_CLASS( vips_min_parent_class )->build( object ) )
		return( -1 );

	/* For speed we accumulate min ** 2 for complex.
	 */
	if( vips_bandfmt_iscomplex( vips_image_get_format( statistic->in ) ) ) {
		int i;

		for( i = 0; i < values->n; i++ ) 
			values->value[i] = sqrt( values->value[i] );
	}

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
		g_object_set( min, 
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
{	
	int i;

	printf( "vips_min_build: %d values found\n", values->n );
	for( i = 0; i < values->n; i++ )
		printf( "%d) %g\t%d\t%d\n", 
			i, 
			values->value[i], 
			values->x_pos[i], values->y_pos[i] ); 
}
#endif /*DEBUG*/

	return( 0 );
}

/* New sequence value. Make a private VipsValues for this thread.
 */
static void *
vips_min_start( VipsStatistic *statistic )
{
	VipsValues *values;

	values = g_new( VipsValues, 1 );
	vips_values_init( values, (VipsMin *) statistic ); 

	return( (void *) values );
}

/* Merge the sequence value back into the per-call state.
 */
static int
vips_min_stop( VipsStatistic *statistic, void *seq )
{
	VipsMin *min = (VipsMin *) statistic;
	VipsValues *values = (VipsValues *) seq;

	int i;

	for( i = 0; i < values->n; i++ )
		vips_values_add( &min->values, 
			values->value[i], values->x_pos[i], values->y_pos[i] );

	g_free( values );

	return( 0 );
}

/* Real min with a lower bound. 
 *
 * Add values to the buffer if they are less than the buffer maximum. If
 * the buffer isn't full, there is no maximum.
 *
 * Avoid a double test by splitting the loop into two phases: before and after
 * the buffer fills.
 *
 * Stop if our array fills with minval.
 */
#define LOOPU( TYPE, LOWER ) { \
	TYPE *p = (TYPE *) in; \
	TYPE m; \
	\
	for( i = 0; i < sz && values->n < values->size; i++ ) \
		vips_values_add( values, p[i], x + i / bands, y ); \
	m = values->value[0]; \
	\
	for( ; i < sz; i++ ) { \
		if( p[i] < m ) { \
			vips_values_add( values, p[i], x + i / bands, y ); \
			m = values->value[0]; \
			\
			if( m <= LOWER ) { \
				statistic->stop = TRUE; \
				break; \
			} \
		} \
	} \
} 

/* float/double min ... no limits, and we have to avoid NaN.
 *
 * NaN compares false to every float value, so we don't need to test for NaN
 * in the second loop. 
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
		if( p[i] < m ) { \
			vips_values_add( values, p[i], x + i / bands, y ); \
			m = values->value[0]; \
		} \
} 

/* As LOOPF, but complex. Track min(mod ** 2) to avoid sqrt().
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
		if( mod2 < m ) { \
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
vips_min_scan( VipsStatistic *statistic, void *seq, 
	int x, int y, void *in, int n )
{
	VipsValues *values = (VipsValues *) seq;
	const int bands = vips_image_get_bands( statistic->in );
	const int sz = n * bands;

	int i;

	switch( vips_image_get_format( statistic->in ) ) {
	case VIPS_FORMAT_UCHAR:		
		LOOPU( unsigned char, 0 ); break; 
	case VIPS_FORMAT_CHAR:	
		LOOPU( signed char, SCHAR_MIN ); break; 
	case VIPS_FORMAT_USHORT:	
		LOOPU( unsigned short, 0 ); break; 
	case VIPS_FORMAT_SHORT:	
		LOOPU( signed short, SHRT_MIN ); break; 
	case VIPS_FORMAT_UINT:	
		LOOPU( unsigned int, 0 ); break;
	case VIPS_FORMAT_INT:	
		LOOPU( signed int, INT_MIN ); break; 

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
vips_min_class_init( VipsMinClass *class )
{
	GObjectClass *gobject_class = (GObjectClass *) class;
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsStatisticClass *sclass = VIPS_STATISTIC_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "min";
	object_class->description = _( "find image minimum" );
	object_class->build = vips_min_build;

	sclass->start = vips_min_start;
	sclass->scan = vips_min_scan;
	sclass->stop = vips_min_stop;

	VIPS_ARG_DOUBLE( class, "out", 1, 
		_( "Output" ), 
		_( "Output value" ),
		VIPS_ARGUMENT_REQUIRED_OUTPUT,
		G_STRUCT_OFFSET( VipsMin, min ),
		-INFINITY, INFINITY, 0.0 );

	VIPS_ARG_INT( class, "x", 2, 
		_( "x" ), 
		_( "Horizontal position of minimum" ),
		VIPS_ARGUMENT_OPTIONAL_OUTPUT,
		G_STRUCT_OFFSET( VipsMin, x ),
		0, 1000000, 0 );

	VIPS_ARG_INT( class, "y", 3, 
		_( "y" ), 
		_( "Vertical position of minimum" ),
		VIPS_ARGUMENT_OPTIONAL_OUTPUT,
		G_STRUCT_OFFSET( VipsMin, y ),
		0, 1000000, 0 );

	VIPS_ARG_INT( class, "size", 4, 
		_( "Size" ), 
		_( "Number of minimum values to find" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsMin, size ),
		0, 1000000, 10 );

	VIPS_ARG_BOXED( class, "out_array", 6, 
		_( "Output array" ), 
		_( "Array of output values" ),
		VIPS_ARGUMENT_OPTIONAL_OUTPUT,
		G_STRUCT_OFFSET( VipsMin, min_array ),
		VIPS_TYPE_ARRAY_DOUBLE );

	VIPS_ARG_BOXED( class, "x_array", 7, 
		_( "x array" ), 
		_( "Array of horizontal positions" ),
		VIPS_ARGUMENT_OPTIONAL_OUTPUT,
		G_STRUCT_OFFSET( VipsMin, x_array ),
		VIPS_TYPE_ARRAY_INT );

	VIPS_ARG_BOXED( class, "y_array", 8, 
		_( "y array" ), 
		_( "Array of vertical positions" ),
		VIPS_ARGUMENT_OPTIONAL_OUTPUT,
		G_STRUCT_OFFSET( VipsMin, y_array ),
		VIPS_TYPE_ARRAY_INT );
}

static void
vips_min_init( VipsMin *min )
{
	min->size = 1;
}

/**
 * vips_min:
 * @in: input #VipsImage
 * @out: output pixel minimum
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * @x: horizontal position of minimum
 * @y: vertical position of minimum
 * @size: number of minima to find
 * @out_array: return array of minimum values
 * @x_array: corresponding horizontal positions
 * @y_array: corresponding vertical positions
 *
 * This operation finds the minimum value in an image. 
 *
 * If the image contains several minimum values, only the first @size 
 * found are returned.
 *
 * It operates on all 
 * bands of the input image: use vips_stats() if you need to find an 
 * minimum for each band. 
 *
 * For complex images, this operation finds the minimum modulus.
 *
 * You can read out the position of the minimum with @x and @y. You can read
 * out arrays of the values and positions of the top @size minima with
 * @out_array, @x_array and @y_array.
 *
 * See also: vips_min(), vips_stats().
 *
 * Returns: 0 on success, -1 on error
 */
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
