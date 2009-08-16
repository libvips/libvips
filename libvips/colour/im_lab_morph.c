/* Morph a lab image ... adjust:
 * 	
 * - cast 
 *	Pass in a MASK containing CIELAB readings for a neutral greyscale ...
 *	eg.
 *
 *		3 4
 *		14.23   4.8     -3.95
 *		18.74   2.76    -2.62
 *		23.46   1.4     -1.95
 *		27.53   1.76    -2.01
 *
 *	interpolation from this makes cast corrector ... interpolate top and
 *	tail towards [0,0,0] and [100,0,0] ... can be in any order (ie. need 
 *	not be sorted on L*)
 *
 * - L* 
 *	Pass in scale and offset for L* ... L*' = (L* + offset) * scale
 *
 * - saturation
 *	scale a and b by these amounts ... eg. 1.5 increases saturation ...
 *	useful for some gammut mapping
 *
 * Find the top two by generating and printing a greyscale ... find the bottom
 * by printing a Macbeth and looking at a/b spread
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
		im_errormsg( "im_lab_morph: bad greyscale mask size" );
		return( -1 );
	}
	for( i = 0; i < mask->ysize; i++ ) {
		double L = mask->coeff[i*3];
		double a = mask->coeff[i*3 + 1];
		double b = mask->coeff[i*3 + 2];

		if( L < 0 || L > 100 || a < -120 || a > 120 || 
			b < -120 || b > 120 ) {
			im_errormsg( "im_lab_morph: bad greyscale mask "
				"value, row %d", i );
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

#define loop( TYPE ) \
{ \
	TYPE *p = (TYPE *) in; \
	TYPE *q = (TYPE *) out; \
 	\
	for( x = 0; x < width; x++ ) { \
		double L = p[0]; \
		double a = p[1]; \
		double b = p[2]; \
 		\
		L = IM_CLIP( 0, L, 100 ); \
		a -= parm->a_offset[(int) L]; \
		b -= parm->b_offset[(int) L]; \
 		\
		L = (L + parm->L_offset) * parm->L_scale; \
		L = IM_CLIP( 0, L, 100 ); \
 		\
		a *= parm->a_scale; \
		b *= parm->b_scale; \
 		\
		q[0] = L; \
		q[1] = a; \
		q[2] = b; \
 		\
		p += 3; \
		q += 3; \
	} \
}

static void
morph_buffer( float *in, float *out, int width, Params *parm )
{
	int x;

	switch( parm->in->BandFmt ) {
	case IM_BANDFMT_FLOAT:	loop( float ); break;
	case IM_BANDFMT_DOUBLE:	loop( double ); break;
	default: assert( 0 );
	}
}

/* Morph an image.
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
		IMAGE *t1 = im_open_local( out, "im_lab_morph:1", "p" );
		IMAGE *t2 = im_open_local( out, "im_lab_morph:2", "p" );

		if( !t1 || !t2 ||
			im_LabQ2Lab( in, t1 ) ||
			im_lab_morph( t1, t2, 
				mask, L_offset, L_scale, a_scale, b_scale ) ||
			im_Lab2LabQ( t2, out ) )
			return( -1 );

		return( 0 );
	}

        if( in->Coding != IM_CODING_NONE ) {
		im_errormsg( "im_lab_morph: must be uncoded or IM_CODING_LABQ" ); 
		return( -1 );
	}
	if( in->BandFmt != IM_BANDFMT_FLOAT && in->BandFmt != IM_BANDFMT_DOUBLE ) {
		im_errormsg( "im_lab_morph: must be uncoded float or double" );
		return( -1 );
	}
	if( in->Bands != 3 ) {
		im_errormsg( "im_lab_morph: must be 3 bands" ); 
		return( -1 );
	}

	if( !(parm = IM_NEW( out, Params )) ||
		morph_init( parm,
			in, out, L_scale, L_offset, mask, a_scale, b_scale ) ) 
		return( -1 );

	if( im_cp_desc( out, in ) )
		return( -1 );
	out->Type = IM_TYPE_LAB;

	if( im_wrapone( in, out, 
		(im_wrapone_fn) morph_buffer, parm, NULL ) )
		return( -1 );

        return( 0 );
}
