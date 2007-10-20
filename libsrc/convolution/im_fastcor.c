/* @(#) Functions which calculates spatial correlation between two images.
 * @(#) by taking absolute differences pixel by pixel without calculating 
 * @(#) the correlation coefficient.
 * @(#) 
 * @(#) The function works as follows:
 * @(#) 
 * @(#) int im_fastcor( im, ref, out )
 * @(#) IMAGE *im, *ref, *out;
 * @(#) 
 * @(#) ref must be smaller than in.  The correlation is
 * @(#) calculated by overlaping im on the top left corner of ref
 * @(#) and moving it all over ref calculating the correlation coefficient
 * @(#) at each point.  The resultant coefficients are written as unsigned int
 * @(#) numbers in out which has the size of im.
 * @(#)
 * @(#) Returns 0 on sucess  and -1 on error.
 *
 * Copyright: 1990, N. Dessipris.
 *
 * Author: Nicos Dessipris
 * Written on: 02/05/1990
 * Modified on : 15/03/1991
 * 20/2/95 JC
 *	- ANSIfied
 *	- in1 and in2 swapped, to match order for im_spcor
 *	- memory leaks fixed
 * 21/2/95 JC
 * 	- partialed
 *	- speed-ups
 * 7/4/04 
 *	- now uses im_embed() with edge stretching on the output
 *	- sets Xoffset / Yoffset
 * 8/3/06 JC
 *	- use im_embed() with edge stretching on the input, not the output
 *	- calculate sum of squares of differences, rather than abs of
 *	  difference
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
#include <math.h>

#include <vips/vips.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* Fastcor generate function.
 */
static int
fastcor_gen( REGION *or, void *seq, void *a, void *b )
{
	REGION *ir = (REGION *) seq;
	IMAGE *ref = (IMAGE *) b;
	Rect irect;
	Rect *r = &or->valid;
	int le = r->left;
	int to = r->top;
	int bo = IM_RECT_BOTTOM(r);
	int ri = IM_RECT_RIGHT(r);

	int x, y, i, j;
	int lsk;

	/* What part of ir do we need?
	 */
	irect.left = or->valid.left;
	irect.top = or->valid.top;
	irect.width = or->valid.width + ref->Xsize - 1;
	irect.height = or->valid.height + ref->Ysize - 1;

	if( im_prepare( ir, &irect ) )
		return( -1 );
	lsk = IM_REGION_LSKIP( ir );

	/* Loop over or.
	 */
	for( y = to; y < bo; y++ ) {
		PEL *a = (PEL *) IM_REGION_ADDR( ir, le, y );
		unsigned int *q = (unsigned int *) IM_REGION_ADDR( or, le, y );

		for( x = le; x < ri; x++ ) {
			int sum = 0;
			PEL *b = (PEL *) ref->data;
			PEL *a1 = a;

			for( j = 0; j < ref->Ysize; j++ ) {
				PEL *a2 = a1;

				for( i = 0; i < ref->Xsize; i++ ) {
					int t = *b++ - *a2++;

					sum += t * t;
				}
				
				a1 += lsk;
			}

			*q++ = sum;
			a += 1;
		}
	}

	return( 0 );
}

/* Raw fastcor, with no borders.
 */
int 
im_fastcor_raw( IMAGE *in, IMAGE *ref, IMAGE *out )
{
	/* PIO between in and out; WIO from ref.
	 */
	if( im_piocheck( in, out ) || im_incheck( ref ) )
		return( -1 );

	/* Check sizes.
	 */
	if( in->Xsize < ref->Xsize || in->Ysize < ref->Ysize ) {
		im_errormsg( "im_fastcor: ref not smaller than in" );
		return( -1 );
	}

	/* Check types.
	 */
	if( in->Coding != IM_CODING_NONE || in->Bands != 1 ||
		in->BandFmt != IM_BANDFMT_UCHAR ||
		ref->Coding != IM_CODING_NONE || ref->Bands != 1 ||
		ref->BandFmt != IM_BANDFMT_UCHAR ) {
		im_errormsg( "im_fastcor_raw: input not uncoded 1 band uchar" );
		return( -1 );
	}

	/* Prepare the output image. 
	 */
	if( im_cp_descv( out, in, ref, NULL ) )
		return( -1 );
	out->Bbits = IM_BBITS_INT;
	out->BandFmt = IM_BANDFMT_UINT;
	out->Xsize = in->Xsize - ref->Xsize + 1;
	out->Ysize = in->Ysize - ref->Ysize + 1;

	/* Set demand hints. FATSTRIP is good for us, as THINSTRIP will cause
	 * too many recalculations on overlaps.
	 */
	if( im_demand_hint( out, IM_FATSTRIP, in, NULL ) )
		return( -1 );

	/* Write the correlation.
	 */
	if( im_generate( out,
		im_start_one, fastcor_gen, im_stop_one, in, ref ) )
		return( -1 );

	out->Xoffset = -ref->Xsize / 2;
	out->Yoffset = -ref->Ysize / 2;

	return( 0 );
}

/* The above, with a border to make out the same size as in.
 */
int 
im_fastcor( IMAGE *in, IMAGE *ref, IMAGE *out )
{
	IMAGE *t1 = im_open_local( out, "im_fastcor intermediate", "p" );

	if( !t1 ||
		im_embed( in, t1, 1, 
			ref->Xsize / 2, ref->Ysize / 2, 
			in->Xsize + ref->Xsize - 1, 
			in->Ysize + ref->Ysize - 1 ) ||
		im_fastcor_raw( t1, ref, out ) ) 
		return( -1 );

	out->Xoffset = 0;
	out->Yoffset = 0;

	return( 0 );
}
