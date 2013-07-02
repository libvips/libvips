/* Build a LUT from a set of x/y points. 
 *
 * Written on: 26/9/06
 * 	- from im_invertlut()
 * 9/10/06
 * 	- don't output x values
 * 18/3/09
 * 	- saner limit and rounding behaviour
 * 30/3/09
 * 	- argh, fixed again
 * 22/6/09
 *	- more fixes for tables that don't start at zero (thanks Jack)
 * 23/3/10
 * 	- gtkdoc
 * 2/7/13
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

/* Our state.
 */
typedef struct _VipsBuildlut {
	VipsCreate parent_instance;

	VipsImage *input;	/* Input matrix */

	int xlow;		/* Index 0 in output is this x */
	int lut_size;		/* Number of output elements to generate */
	double **data;		/* Rows of unpacked matrix */
	double *buf;		/* Ouput buffer */
} VipsBuildlut;

typedef VipsCreateClass VipsBuildlutClass;

G_DEFINE_TYPE( VipsBuildlut, vips_buildlut, VIPS_TYPE_CREATE );

static void
vips_buildlut_dispose( GObject *gobject )
{
	VipsBuildlut *lut = (VipsBuildlut *) gobject;

	if( lut->data ) {
		int i;

		for( i = 0; i < lut->input->Ysize; i++ ) 
			VIPS_FREE( lut->data[i] );
	}

	VIPS_FREE( lut->data );
	VIPS_FREE( lut->buf );

	G_OBJECT_CLASS( vips_buildlut_parent_class )->dispose( gobject );
}

/* Use this to sort our input rows by the first column.
 */
static int
vips_buildlut_compare( const void *a, const void *b )
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
vips_buildlut_build_init( VipsBuildlut *lut )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( lut );
	VipsCreate *create = VIPS_CREATE( lut );

	int x, y, i;
	int xlow, xhigh;

	/* Need xlow and xhigh to get the size of the LUT we build.
	 */
	xlow = xhigh = input->coeff[0];
	for( y = 0; y < input->ysize; y++ ) {
		double v = input->coeff[y * input->xsize];

		if( floor( v ) != v ) {
			im_error( "im_buildlut", 
				"%s", _( "x value not an int" ) );
			return( -1 );
		}

		if( v < xlow )
			xlow = v;
		if( v > xhigh )
			xhigh = v;
	}
	state->xlow = xlow;
	state->lut_size = xhigh - xlow + 1;

	if( state->lut_size < 1 ) {
		im_error( "im_buildlut", "%s", _( "x range too small" ) );
		return( -1 );
	}

	if( !(state->data = IM_ARRAY( NULL, input->ysize, double * )) )
		return( -1 );
	for( y = 0; y < input->ysize; y++ ) 
		state->data[y] = NULL;
	for( y = 0; y < input->ysize; y++ ) 
		if( !(state->data[y] = IM_ARRAY( NULL, input->xsize, double )) )
			return( -1 );

	for( i = 0, y = 0; y < input->ysize; y++ ) 
		for( x = 0; x < input->xsize; x++, i++ ) 
			state->data[y][x] = input->coeff[i];

	if( !(state->buf = IM_ARRAY( NULL, 
		state->lut_size * (input->xsize - 1), double )) )
		return( -1 );

	/* Sort by 1st column in input.
	 */
	qsort( state->data, input->ysize, sizeof( double * ), compare );

#ifdef DEBUG
	printf( "Input table, sorted by 1st column\n" );
	for( y = 0; y < input->ysize; y++ ) {
		printf( "%.4d ", y );

		for( x = 0; x < input->xsize; x++ )
			printf( "%.9f ", state->data[y][x] );

		printf( "\n" );
	}
#endif /*DEBUG*/

	return( 0 );
}

/* Fill our state.
 */
static int
vips_buildlut_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsCreate *create = VIPS_CREATE( object );
	VipsBuildlut *lut = (VipsBuildlut *) object;

	if( VIPS_OBJECT_CLASS( vips_buildlut_parent_class )->build( object ) )
		return( -1 );

	if( vips_buildlut_build_init( lut ) )
		return( -1 ); 

	return( 0 );
}

static void
vips_buildlut_class_init( VipsTextClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	gobject_class->dispose = vips_buildlut_dispose;
	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "buildlut";
	vobject_class->description = _( "build a look-up table" );
	vobject_class->build = vips_buildlut_build;

	VIPS_ARG_IMAGE( class, "in", 4, 
		_( "Input" ), 
		_( "Matrix of XY coordinates" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsImage, input ),
		NULL ); 

}

static int
buildlut( State *state )
{
	const int xlow = state->xlow;
	const DOUBLEMASK *input = state->input;
	const int ysize = input->ysize;
	const int xsize = input->xsize;
	const int bands = xsize - 1;
	const int xlast = state->data[ysize - 1][0];

	int b, i, x;

	/* Do each output channel separately.
	 */
	for( b = 0; b < bands; b++ ) {
		for( i = 0; i < ysize - 1; i++ ) {
			const int x1 = state->data[i][0];
			const int x2 = state->data[i + 1][0];
			const int dx = x2 - x1;
			const double y1 = state->data[i][b + 1];
			const double y2 = state->data[i + 1][b + 1];
			const double dy = y2 - y1;

			for( x = 0; x < dx; x++ ) 
				state->buf[b + (x + x1 - xlow) * bands] = 
					y1 + x * dy / dx;
		}

		/* We are inclusive: pop the final value in by hand.
		 */
		state->buf[b + (xlast - xlow) * bands] =
			state->data[ysize - 1][b + 1];
	}

	return( 0 );
}

/**
 * im_buildlut:
 * @input: input mask
 * @output: output image
 *
 * This operation builds a lookup table from a set of points. Intermediate
 * values are generated by piecewise linear interpolation. 
 *
 * For example, consider this 2 x 2 matrix of (x, y) coordinates:
 *
 *   <tgroup cols='2' align='left' colsep='1' rowsep='1'>
 *     <tbody>
 *       <row>
 *         <entry>0</entry>
 *         <entry>0</entry>
 *       </row>
 *       <row>
 *         <entry>255</entry>
 *         <entry>100</entry>
 *       </row>
 *     </tbody>
 *   </tgroup>
 * 
 * We then generate:
 *
 *   <tgroup cols='2' align='left' colsep='1' rowsep='1'>
 *     <thead>
 *       <row>
 *         <entry>Index</entry>
 *         <entry>Value</entry>
 *       </row>
 *     </thead>
 *     <tbody>
 *       <row>
 *         <entry>0</entry>
 *         <entry>0</entry>
 *       </row>
 *       <row>
 *         <entry>1</entry>
 *         <entry>0.4</entry>
 *       </row>
 *       <row>
 *         <entry>...</entry>
 *         <entry>etc. by linear interpolation</entry>
 *       </row>
 *       <row>
 *         <entry>255</entry>
 *         <entry>100</entry>
 *       </row>
 *     </tbody>
 *   </tgroup>
 *
 * This is then written as the output image, with the left column giving the
 * index in the image to place the value.
 * 
 * The (x, y) points don't need to be sorted: we do that. You can have 
 * several Ys, each becomes a band in the output LUT. You don't need to
 * start at zero, any integer will do, including negatives.
 *
 * See also: im_identity(), im_invertlut().
 *
 * Returns: 0 on success, -1 on error
 */
int
im_buildlut( DOUBLEMASK *input, IMAGE *output )
{
	State state;

	if( !input || input->xsize < 2 || input->ysize < 1 ) {
		im_error( "im_buildlut", "%s", _( "bad input matrix size" ) );
		return( -1 );
	}

	if( build_state( &state, input ) ||
		buildlut( &state ) ) {
		free_state( &state );
                return( -1 );
	}

        im_initdesc( output,
                state.lut_size, 1, input->xsize - 1, 
		IM_BBITS_DOUBLE, IM_BANDFMT_DOUBLE,
                IM_CODING_NONE, IM_TYPE_HISTOGRAM, 1.0, 1.0, 0, 0 );
        if( im_setupout( output ) ||
		im_writeline( 0, output, (VipsPel *) state.buf ) ) {
		free_state( &state );
		return( -1 );
	}

	free_state( &state );

	return( 0 );
}
