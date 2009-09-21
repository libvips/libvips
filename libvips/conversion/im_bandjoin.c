/* @(#) Function to perform a band-wise join of two images. If the two images
 * @(#) have n and m bands respectively, then the output image will have n+m
 * @(#) bands, with the first n coming from the first image and the last m
 * @(#) from the second. Works for any image type.
 * @(#)
 * @(#) Function im_bandjoin() assumes that the imin image
 * @(#) is either memory mapped or in the buffer pimin->data.
 * @(#)
 * @(#) int im_bandjoin(imin1, imin2, imout)
 * @(#) IMAGE *imin1, *imin2, *imout;
 * @(#)
 * @(#) All functions return 0 on success and -1 on error
 * @(#)
 *
 * Copyright: 1990, J. Cupitt
 *
 * Author: J. Cupitt
 * Written on: 12/02/1990
 * Modified on : 07/03/1991, by N. Dessipris, history removed
 * 27/10/93 JC
 *	- adapted for partials
 *	- Nicos formatting removed
 *	- ANSIfied
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

#include <vips/vips.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* Bandjoin generate function.
 */
static int
bandjoin_gen( REGION *or, void *seq, void *a, void *b )
{
	REGION **ir = (REGION **) seq;
	Rect *r = &or->valid;
	int le = r->left;
	int ri = IM_RECT_RIGHT(r);
	int to = r->top;
	int bo = IM_RECT_BOTTOM(r);
	int x, y, z;
	int i1s = IM_IMAGE_SIZEOF_PEL( ir[0]->im );
	int i2s = IM_IMAGE_SIZEOF_PEL( ir[1]->im );

	/* Ask for input we need.
	 */
	if( im_prepare( ir[0], r ) )
		return( -1 );
	if( im_prepare( ir[1], r ) ) 
		return( -1 );

	/* Perform join.
	 */
	for( y = to; y < bo; y++ ) {
		PEL *i1 = (PEL *) IM_REGION_ADDR( ir[0], le, y );
		PEL *i2 = (PEL *) IM_REGION_ADDR( ir[1], le, y );
		PEL *q = (PEL *) IM_REGION_ADDR( or, le, y );

		for( x = le; x < ri; x++ ) {
			/* Copy bytes from first file.  
			 */
			for( z = 0; z < i1s; z++ )
				*q++ = *i1++;

			/* Copy bytes from in2.  
			 */
			for( z = 0; z < i2s; z++ )
				*q++ = *i2++;
		}
	}

	return( 0 );
}

/* Join two images. out->Bands = in1->Bands + in2->Bands. in1 goes first in
 * the list.  
 */
int
im_bandjoin( IMAGE *in1, IMAGE *in2, IMAGE *out )
{
	IMAGE **in;

	/* Check our args. 
	 */
	if( im_piocheck( in1, out ) )
		return( -1 );
	if( im_piocheck( in2, out ) ) 
		return( -1 );
	if( in1->Xsize != in2->Xsize ||
		in1->Ysize != in2->Ysize ) {
		im_error( "im_bandjoin", "%s", _( "images not same size" ) );
		return( -1 );
	}
	if( in1->BandFmt != in2->BandFmt ) {
		im_error( "im_bandjoin", "%s", _( "images not same type" ) );
		return( -1 );
	}
	if( in1->Coding != IM_CODING_NONE || in2->Coding != IM_CODING_NONE ) {
		im_error( "im_bandjoin", "%s", _( "input coded" ) );
		return( -1 );
	}

	/* Set up the output header.
	 */
	if( im_cp_descv( out, in1, in2, NULL ) )
                return( -1 ); 
	out->Bands = in1->Bands + in2->Bands;

	/* Set demand hints.
	 */
	if( im_demand_hint( out, IM_THINSTRIP, in1, in2, NULL ) )
		 return( -1 );

	/* Make input array. 
	 */
	if( !(in = im_allocate_input_array( out, in1, in2, NULL )) )
		return( -1 );

	/* Make output image.
	 */
	if( im_generate( out, 
		im_start_many, bandjoin_gen, im_stop_many, in, NULL ) )
		return( -1 );

	return( 0 );
}
