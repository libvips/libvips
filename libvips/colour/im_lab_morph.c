/* Morph a lab image.
 *
 * 8/3/01
 * 	- added
 * 2/11/09
 * 	- cleanups
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
#include <string.h>
#include <assert.h>
#include <stdlib.h>

#include <vips/vips.h>
#include <vips/internal.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

typedef struct {
	IMAGE *in, *out;

	double L_scale, L_offset;

	double a_offset[101], b_offset[101];
	double a_scale, b_scale;
} Params;

static int
morph_init( Params *parm, 
	IMAGE *in, IMAGE *out,
	double L_scale, double L_offset, 
	DOUBLEMASK *mask, double a_scale, double b_scale )
{
	int i, j;

	parm->in = in;
	parm->out = out;
	parm->L_scale = L_scale;
	parm->L_offset = L_offset;
	parm->a_scale = a_scale;
	parm->b_scale = b_scale;

	if( mask->xsize != 3 || mask->ysize < 1 || mask->ysize > 100 ) {
		im_error( "im_lab_morph", "%s", 
			_( "bad greyscale mask size" ) );
		return( -1 );
	}
	for( i = 0; i < mask->ysize; i++ ) {
		double L = mask->coeff[i*3];
		double a = mask->coeff[i*3 + 1];
		double b = mask->coeff[i*3 + 2];

		if( L < 0 || L > 100 || a < -120 || a > 120 || 
			b < -120 || b > 120 ) {
			im_error( "im_lab_morph", 
				_( "bad greyscale mask value, row %d" ), i );
			return( -1 );
		}
	}

	/* Generate a/b offsets.
	 */
	for( i = 0; i <= 100; i++ ) {
		double L_low = 0;
		double a_low = 0;
		double b_low = 0;

		double L_high = 100;
		double a_high = 0;
		double b_high = 0;

		/* Search for greyscale L just below i. Don't assume sorted by
		 * L*.
		 */
		for( j = 0; j < mask->ysize; j++ ) {
			double L = mask->coeff[j*3];
			double a = mask->coeff[j*3 + 1];
			double b = mask->coeff[j*3 + 2];

			if( L < i && L > L_low ) {
				L_low = L;
				a_low = a;
				b_low = b;
			}
		}

		/* Search for greyscale L just above i.
		 */
		for( j = mask->ysize - 1; j >= 0; j-- ) {
			double L = mask->coeff[j*3];
			double a = mask->coeff[j*3 + 1];
			double b = mask->coeff[j*3 + 2];

			if( L >= i && L < L_high ) {
				L_high = L;
				a_high = a;
				b_high = b;
			}
		}

		/* Interpolate.
		 */
		parm->a_offset[i] = a_low + 
			(a_high - a_low) * ((i - L_low) / (L_high - L_low));
		parm->b_offset[i] = b_low + 
			(b_high - b_low) * ((i - L_low) / (L_high - L_low));
	}

	return( 0 );
}

static void
morph_buffer( float *in, float *out, int width, Params *parm )
{
	int x;

	for( x = 0; x < width; x++ ) { 
		double L = in[0]; 
		double a = in[1]; 
		double b = in[2]; 
 		
		L = IM_CLIP( 0, L, 100 ); 
		a -= parm->a_offset[(int) L]; 
		b -= parm->b_offset[(int) L]; 
 		
		L = (L + parm->L_offset) * parm->L_scale; 
		L = IM_CLIP( 0, L, 100 ); 

		a *= parm->a_scale; 
		b *= parm->b_scale; 
 
		out[0] = L; 
		out[1] = a; 
		out[2] = b; 

		in += 3; 
		out += 3; 
	} 
}

/**
 * im_lab_morph:
 * @in: input image
 * @out: output image
 * @mask: cast correction table
 * @L_offset: L adjustment
 * @L_scale: L adjustment
 * @a_scale: a scale
 * @b_scale: b scale
 *
 * Morph an image in CIELAB colour space. Useful for certain types of gamut
 * mapping, or correction of greyscales on some printers.
 *
 * We perform three adjustments:
 * 	
 * <itemizedlist>
 *   <listitem>
 *     <para>
 *       <emphasis>cast</emphasis>
 *
 * Pass in @mask containing CIELAB readings for a neutral greyscale. For
 * example:
 *
 * <tgroup cols='3' align='left' colsep='1' rowsep='1'>
 *   <tbody>
 *     <row>
 *       <entry>3</entry>
 *       <entry>4</entry>
 *     </row>
 *     <row>
 *       <entry>14.23</entry>
 *       <entry>4.8</entry>
 *       <entry>-3.95</entry>
 *     </row>
 *     <row>
 *       <entry>18.74</entry>
 *       <entry>2.76</entry>
 *       <entry>-2.62</entry>
 *     </row>
 *     <row>
 *       <entry>23.46</entry>
 *       <entry>1.4</entry>
 *       <entry>-1.95</entry>
 *     </row>
 *     <row>
 *       <entry>27.53</entry>
 *       <entry>1.76</entry>
 *       <entry>-2.01</entry>
 *     </row>
 *   </tbody>
 * </tgroup>
 *
 * Interpolation from this makes cast corrector. The top and tail are
 * interpolated towards [0, 0, 0] and [100, 0, 0], intermediate values are 
 * interpolated along straight lines fitted between the specified points. 
 * Rows may be in any order (ie. they need not be sorted on L*).
 *
 * Each pixel is displaced in a/b by the amount specified for that L in the
 * table.
 *     </para>
 *   </listitem>
 *   <listitem>
 *     <para>
 *       <emphasis>L*</emphasis>
 *	
 * Pass in scale and offset for L. L' = (L + offset) * scale.
 *     </para>
 *   </listitem>
 *   <listitem>
 *     <para>
 *       <emphasis>saturation</emphasis>
 *
 * scale a and b by these amounts, eg. 1.5 increases saturation. 
 *     </para>
 *   </listitem>
 * </itemizedlist>
 *
 * Find the top two by generating and printing a greyscale. Find the bottom
 * by printing a Macbeth and looking at a/b spread
 *
 * Returns: 0 on success, -1 on error.
 */
int
im_lab_morph( IMAGE *in, IMAGE *out,
	DOUBLEMASK *mask, 
	double L_offset, double L_scale, 
	double a_scale, double b_scale )
{
	Params *parm;

        /* Recurse for coded images.
         */
	if( in->Coding == IM_CODING_LABQ ) {
		IMAGE *t[2];

		if( im_open_local_array( out, t, 2, "im_lab_morph", "p" ) ||
			im_LabQ2Lab( in, t[0] ) ||
			im_lab_morph( t[0], t[1], 
				mask, L_offset, L_scale, a_scale, b_scale ) ||
			im_Lab2LabQ( t[1], out ) )
			return( -1 );

		return( 0 );
	}

	if( !(parm = IM_NEW( out, Params )) ||
		morph_init( parm,
			in, out, L_scale, L_offset, mask, a_scale, b_scale ) ) 
		return( -1 );

	return( im__colour_unary( "im_lab_morph", in, out, IM_TYPE_LAB,
		(im_wrapone_fn) morph_buffer, parm, NULL ) );
}
