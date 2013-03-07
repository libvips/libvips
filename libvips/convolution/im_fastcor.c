/* im_fastcor
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
 * 3/2/10
 * 	- gtkdoc
 * 	- cleanups
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
#include <math.h>

#include <vips/vips.h>

/* Fastcor generate function.
 */
static int
fastcor_gen( REGION *or, void *seq, void *a, void *b )
{
	REGION *ir = (REGION *) seq;
	IMAGE *ref = (IMAGE *) b;
	Rect irect;
	Rect *r = &or->valid;

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
	for( y = 0; y < r->height; y++ ) {
		unsigned int *q = (unsigned int *) 
			IM_REGION_ADDR( or, r->left, r->top + y );

		for( x = 0; x < r->width; x++ ) {
			VipsPel *b = ref->data;
			VipsPel *a = 
				IM_REGION_ADDR( ir, r->left + x, r->top + y );

			int sum;

			sum = 0;
			for( j = 0; j < ref->Ysize; j++ ) {
				for( i = 0; i < ref->Xsize; i++ ) {
					int t = b[i] - a[i];

					sum += t * t;
				}
				
				a += lsk;
				b += ref->Xsize;
			}

			q[x] = sum;
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
	if( im_piocheck( in, out ) || 
		im_incheck( ref ) )
		return( -1 );

	/* Check sizes.
	 */
	if( in->Xsize < ref->Xsize || in->Ysize < ref->Ysize ) {
		im_error( "im_fastcor", "%s", 
			_( "ref not smaller than or equal to in" ) );
		return( -1 );
	}

	/* Check types.
	 */
	if( im_check_uncoded( "im_fastcor", in ) ||
		im_check_mono( "im_fastcor", in ) || 
		im_check_format( "im_fastcor", in, IM_BANDFMT_UCHAR ) ||
		im_check_coding_same( "im_fastcor", in, ref ) ||
		im_check_bands_same( "im_fastcor", in, ref ) || 
		im_check_format_same( "im_fastcor", in, ref ) )
		return( -1 );

	/* Prepare the output image. 
	 */
	if( im_cp_descv( out, in, ref, NULL ) )
		return( -1 );
	out->BandFmt = IM_BANDFMT_UINT;
	out->Xsize = in->Xsize - ref->Xsize + 1;
	out->Ysize = in->Ysize - ref->Ysize + 1;

	/* FATSTRIP is good for us, as THINSTRIP will cause
	 * too many recalculations on overlaps.
	 */
	if( im_demand_hint( out, IM_FATSTRIP, in, NULL ) ||
		im_generate( out, 
			im_start_one, fastcor_gen, im_stop_one, in, ref ) )
		return( -1 );

	out->Xoffset = -ref->Xsize / 2;
	out->Yoffset = -ref->Ysize / 2;

	return( 0 );
}

/**
 * im_fastcor:
 * @in: input image
 * @ref: reference image
 * @out: output image
 *
 * Calculate a fast correlation surface.
 *
 * @ref is placed at every position in @in and the sum of squares of
 * differences calculated. One-band, 8-bit unsigned images only. The output
 * image is always %IM_BANDFMT_UINT. @ref must be smaller than or equal to 
 * @in. The output
 * image is the same size as the input.
 *
 * See also: im_spcor().
 *
 * Returns: 0 on success, -1 on error
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
