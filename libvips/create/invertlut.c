/* invert a lut
 *
 * Written on: 5/6/01
 * Modified on : 
 *
 * 7/7/03 JC
 * 	- generate image rather than doublemask (arrg)
 * 23/3/10
 * 	- gtkdoc
 * 23/5/13
 * 	- fix 1 high input matrices
 * 	- fix file output
 * 4/9/13
 * 	- convert to a class
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

#include "pcreate.h"

/*
#define DEBUG
 */

/* Our state.
 */
typedef struct _VipsInvertlut {
	VipsCreate parent_instance;

	/* Input image.
	 */
	VipsImage *in;	

	/* .. and cast to a matrix.
	 */
	VipsImage *mat;

	int size;		/* Number of output elements to generate */

	double **data;		/* Rows of unpacked matrix */
	double *buf;		/* Output buffer */
} VipsInvertlut;

typedef VipsCreateClass VipsInvertlutClass;

G_DEFINE_TYPE( VipsInvertlut, vips_invertlut, VIPS_TYPE_CREATE );

static void
vips_invertlut_dispose( GObject *gobject )
{
	VipsInvertlut *lut = (VipsInvertlut *) gobject;

	VIPS_FREE( lut->data );
	VIPS_FREE( lut->buf );
	VIPS_UNREF( lut->mat );

	G_OBJECT_CLASS( vips_invertlut_parent_class )->dispose( gobject );
}

/* Use this to sort our input rows by the first column.
 */
static int
compare( const void *a, const void *b )
{
	double **r1 = (double **) a;
	double **r2 = (double **) b;

	double diff = r1[0][0] - r2[0][0];

	if( diff > 0 )
		return( 1 );
	else if( diff == 0 )
		return( 0 );
	else 
		return( -1 );
}

static int
vips_invertlut_build_init( VipsInvertlut *lut )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( lut );

	int x, y;

	if( !lut->mat ||
		lut->mat->Xsize < 2 || 
		lut->mat->Ysize < 1 ) {
		vips_error( class->nickname, "%s", _( "bad input matrix" ) );
		return( -1 );
	}
	if( lut->size < 1 || 
		lut->size > 65536 ) {
		vips_error( class->nickname, "%s", _( "bad size" ) );
		return( -1 );
	}

	if( !(lut->buf = 
		VIPS_ARRAY( NULL, lut->size * (lut->mat->Xsize - 1), double )) )
		return( -1 );

	if( !(lut->data = VIPS_ARRAY( NULL, lut->mat->Ysize, double * )) )
		return( -1 );
	for( y = 0; y < lut->mat->Ysize; y++ ) 
		lut->data[y] = VIPS_MATRIX( lut->mat, 0, y );

	/* Sanity check for data range.
	 */
	for( y = 0; y < lut->mat->Ysize; y++ ) 
		for( x = 0; x < lut->mat->Xsize; x++ ) 
			if( lut->data[y][x] > 1.0 || 
				lut->data[y][x] < 0.0 ) {
				vips_error( class->nickname,
					_( "element (%d, %d) is %g, "
						"outside range [0,1]" ),
					x, y, lut->data[y][x] );
				return( -1 );
			}

	/* Sort by 1st column in input.
	 */
	qsort( lut->data, lut->mat->Ysize, sizeof( double * ), compare );

#ifdef DEBUG
	printf( "Input table, sorted by 1st column\n" );
	for( y = 0; y < lut->mat->Ysize; y++ ) {
		printf( "%.4d ", y );

		for( x = 0; x < lut->mat->Xsize; x++ )
			printf( "%.9f ", lut->data[y][x] );

		printf( "\n" );
	}
#endif /*DEBUG*/

	return( 0 );
}

static int
vips_invertlut_build_create( VipsInvertlut *lut )
{
	int bands = lut->mat->Xsize - 1;
	int height = lut->mat->Ysize;

	int b;

	/* Do each output channel separately.
	 */
	for( b = 0; b < bands; b++ ) {
		/* The first and last lut positions we know real values for.
		 */
		int first = lut->data[0][b + 1] * (lut->size - 1);
		int last = lut->data[height - 1][b + 1] * (lut->size - 1);

		int k;

		/* Extrapolate bottom and top segments to (0,0) and (1,1).
		 */
		for( k = 0; k < first; k++ ) {
			/* Have this inside the loop to avoid /0 errors if
			 * first == 0.
			 */
			double fac = lut->data[0][0] / first;

			lut->buf[b + k * bands] = k * fac;
		}

		for( k = last; k < lut->size; k++ ) {
			/* Inside the loop to avoid /0 errors for last ==
			 * (size - 1).
			 */
			double fac = (1 - lut->data[height - 1][0]) / 
				((lut->size - 1) - last);

			lut->buf[b + k * bands] = 
				lut->data[height - 1][0] + (k - last) * fac;
		}

		/* Interpolate the data sections.
		 */
		for( k = first; k < last; k++ ) {
			/* Where we're at in the [0,1] range.
			 */
			double ki = (double) k / (lut->size - 1);

			double irange, orange;
			int j;

			/* Search for the lowest real value < ki. There may
			 * not be one: if not, just use 0. Tiny error.
			 */
			for( j = height - 1; j >= 0; j-- )
				if( lut->data[j][b + 1] < ki )
					break;
			if( j == -1 )
				j = 0;

			/* Interpolate k as being between row data[j] and row
			 * data[j + 1].
			 */
			irange = lut->data[j + 1][b + 1] - lut->data[j][b + 1];
			orange = lut->data[j + 1][0] - lut->data[j][0];

			lut->buf[b + k * bands] = lut->data[j][0] +
				orange * ((ki - lut->data[j][b + 1]) / irange);
		}
	}

	return( 0 );
}

static int
vips_invertlut_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsCreate *create = VIPS_CREATE( object );
	VipsInvertlut *lut = (VipsInvertlut *) object;

	if( VIPS_OBJECT_CLASS( vips_invertlut_parent_class )->build( object ) )
		return( -1 );

	if( vips_check_matrix( class->nickname, lut->in, &lut->mat ) )
		return( -1 ); 

	if( vips_invertlut_build_init( lut ) ||
		vips_invertlut_build_create( lut ) )
		return( -1 ); 

        vips_image_init_fields( create->out,
                lut->size, 1, lut->mat->Xsize - 1, 
		VIPS_FORMAT_DOUBLE, VIPS_CODING_NONE, 
		VIPS_INTERPRETATION_HISTOGRAM, 1.0, 1.0 );
        if( vips_image_write_line( create->out, 0, (VipsPel *) lut->buf ) ) 
		return( -1 );

	return( 0 );
}

static void
vips_invertlut_class_init( VipsInvertlutClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	gobject_class->dispose = vips_invertlut_dispose;
	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "invertlut";
	vobject_class->description = _( "build an inverted look-up table" );
	vobject_class->build = vips_invertlut_build;

	VIPS_ARG_IMAGE( class, "in", 0, 
		_( "Input" ), 
		_( "Matrix of XY coordinates" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsInvertlut, in ) ); 

	VIPS_ARG_INT( class, "size", 5, 
		_( "Size" ), 
		_( "LUT size to generate" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsInvertlut, size ),
		1, 1000000, 256 );

}

static void
vips_invertlut_init( VipsInvertlut *lut )
{
	lut->size = 256; 
}

/**
 * vips_invertlut:
 * @in: input mask
 * @out: output LUT
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @size: generate this much
 *
 * Given a mask of target values and real values, generate a LUT which
 * will map reals to targets. Handy for linearising images from
 * measurements of a colour chart. All values in [0,1]. Piecewise linear
 * interpolation, extrapolate head and tail to 0 and 1.
 * 
 * Eg. input like this:
 * 
 *   <tgroup cols='4' align='left' colsep='1' rowsep='1'>
 *     <tbody>
 *       <row>
 *         <entry>4</entry>
 *         <entry>3</entry>
 *       </row>
 *       <row>
 *         <entry>0.1</entry>
 *         <entry>0.2</entry>
 *         <entry>0.3</entry>
 *         <entry>0.1</entry>
 *       </row>
 *       <row>
 *         <entry>0.2</entry>
 *         <entry>0.4</entry>
 *         <entry>0.4</entry>
 *         <entry>0.2</entry>
 *       </row>
 *       <row>
 *         <entry>0.7</entry>
 *         <entry>0.5</entry>
 *         <entry>0.6</entry>
 *         <entry>0.3</entry>
 *       </row>
 *     </tbody>
 *   </tgroup>
 *
 * Means a patch with 10% reflectance produces an image with 20% in
 * channel 1, 30% in channel 2, and 10% in channel 3, and so on.
 * 
 * Inputs don't need to be sorted (we do that). Generate any precision
 * LUT, default to 256 elements.
 *
 * It won't work too well for non-monotonic camera responses 
 * (we should fix this). Interpolation is simple piecewise linear; we ought to 
 * do something better really.
 *
 * See also: vips_buildlut().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_invertlut( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "invertlut", ap, in, out );
	va_end( ap );

	return( result );
}
