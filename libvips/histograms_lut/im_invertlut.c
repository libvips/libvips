/* invert a lut
 *
 * Written on: 5/6/01
 * Modified on : 
 *
 * 7/7/03 JC
 * 	- generate image rather than doublemask (arrg)
 * 23/3/10
 * 	- gtkdoc
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

/*
#define DEBUG
 */

/* Our state.
 */
typedef struct {
	DOUBLEMASK *input;	/* Input mask */
	IMAGE *output;		/* Output lut */
	int lut_size;		/* Number of output elements to generate */

	double **data;		/* Rows of unpacked matrix */
} State;

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

/* Free our state.
 */
static void
free_state( State *state )
{
	if( state->data ) {
		int i;

		for( i = 0; i < state->input->ysize; i++ )
			if( state->data[i] ) {
				im_free( state->data[i] );
				state->data[i] = NULL;
			}

		im_free( state->data );
		state->data = NULL;
	}
}

/* Fill our state.
 */
static int
build_state( State *state, DOUBLEMASK *input, IMAGE *output, int lut_size )
{
	int x, y, i;

	state->input = input;
	state->output = output;
	state->lut_size = lut_size;
	state->data = NULL;

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

	/* Sanity check for data range.
	 */
	for( y = 0; y < input->ysize; y++ ) 
		for( x = 0; x < input->xsize; x++ ) 
			if( state->data[y][x] > 1.0 || 
				state->data[y][x] < 0.0 ) {
				im_error( "im_invertlut", "%s", 
					_( "element out of range [0,1]" ) );
				return( -1 );
			}

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

static int
invertlut( State *state )
{
	DOUBLEMASK *input = state->input;
	int ysize = input->ysize;
	int xsize = input->xsize;
	IMAGE *output = state->output;
	double *odata = (double *) output->data;
	int bands = xsize - 1;

	double **data = state->data;
	int lut_size = state->lut_size;

	int i;

	/* Do each output channel separately.
	 */
	for( i = 0; i < bands; i++ ) {
		/* The first and last lut positions we know real values for.
		 */
		int first = data[0][i + 1] * (lut_size - 1);
		int last = data[ysize - 1][i + 1] * (lut_size - 1);

		int k;
		double fac;

		/* Extrapolate bottom and top segments to (0,0) and (1,1).
		 */
		fac = data[0][0] / first;
		for( k = 0; k < first; k++ )
			odata[i + k * bands] = k * fac;

		fac = (1 - data[ysize - 1][0]) / ((lut_size - 1) - last);
		for( k = last + 1; k < lut_size; k++ )
			odata[i + k * bands] = 
				data[ysize - 1][0] + (k - last) * fac;

		/* Interpolate the data setions.
		 */
		for( k = first; k <= last; k++ ) {
			/* Where we're at in the [0,1] range.
			 */
			double ki = (double) k / (lut_size - 1);

			double irange, orange;
			int j;

			/* Search for the lowest real value < ki. There may
			 * not be one: if not, just use 0. Tiny error.
			 */
			for( j = ysize - 1; j >= 0; j-- )
				if( data[j][i + 1] < ki )
					break;
			if( j == -1 )
				j = 0;

			/* Interpolate k as being between row data[j] and row
			 * data[j + 1].
			 */
			irange = data[j + 1][i + 1] - data[j][i + 1];
			orange = data[j + 1][0] - data[j][0];

			odata[i + k * bands] = data[j][0] +
				orange * ((ki - data[j][i + 1]) / irange);
		}
	}

	return( 0 );
}

/**
 * im_invertlut:
 * @input: input mask
 * @output: output LUT
 * @lut_size: generate this much
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
 * LUT, typically you might ask for 256 elements.
 *
 * It won't work too well for non-monotonic camera responses 
 * (we should fix this). Interpolation is simple piecewise linear; we ought to 
 * do something better really.
 *
 * See also: im_buildlut(), im_invertlut()
 *
 * Returns: 0 on success, -1 on error
 */
int
im_invertlut( DOUBLEMASK *input, IMAGE *output, int lut_size )
{
	State state;

	if( !input || 
		input->xsize < 2 || 
		input->ysize < 1 ) {
		im_error( "im_invertlut", "%s", _( "bad input matrix" ) );
		return( -1 );
	}
	if( lut_size < 1 || 
		lut_size > 65536 ) {
		im_error( "im_invertlut", "%s", _( "bad lut_size" ) );
		return( -1 );
	}

        im_initdesc( output,
                lut_size, 1, input->xsize - 1, 
		IM_BBITS_DOUBLE, IM_BANDFMT_DOUBLE,
                IM_CODING_NONE, IM_TYPE_HISTOGRAM, 1.0, 1.0, 0, 0 );
        if( im_setupout( output ) )
                return( -1 );

	if( build_state( &state, input, output, lut_size ) ||
		invertlut( &state ) ) {
		free_state( &state );
		return( -1 );
	}
	free_state( &state );

	return( 0 );
}
