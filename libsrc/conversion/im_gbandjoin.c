/* @(#) Function to perform a band-wise join of no images. 
 * @(#) Input images can have any number of bands; for instance if im[0] has j
 * @(#) bands, im[1] k, ...., im[no-1] l bands, output has j+k+...+l bands
 * @(#) respectively
 * @(#)
 * @(#) Function im_gbandjoin() assumes that the imin image
 * @(#) is either memory mapped or in buffer
 * @(#)
 * @(#) int im_gbandjoin( imarray, imout, no )
 * @(#) IMAGE *imarray[], *imout;
 * @(#) int no;
 * @(#)
 * @(#) All functions return 0 on success and -1 on error
 * @(#)
 *
 * Copyright: 1991, N. Dessipris, modification of im_bandjoin()
 *
 * Author: N. Dessipris
 * Written on: 17/04/1991
 * Modified on : 
 * 16/3/94 JC
 *	- rewritten for partials
 *	- now in ANSI C
 *	- now works for any number of input images, except zero
 * 7/10/94 JC
 *	- new IM_NEW()
 * 16/4/07
 * 	- fall back to im_copy() for 1 input image
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

/* Struct we carry stuff around in.
 */
typedef struct joins {
	int nim;		/* Number of input images */
	IMAGE **in;		/* Array of input images, NULL-terminated */
	int *is;		/* An int for SIZEOF_PEL() for each image */
} Join;

/* Make a Join struct.
 */
static Join *
make_join( IMAGE *out, IMAGE **in, int nim )
{
	Join *jn;
	int i;

	if( !(jn = IM_NEW( out, Join )) )
		return( NULL );
	jn->nim = nim;
	if( !(jn->in = IM_ARRAY( out, nim + 1, IMAGE * )) || 
		!(jn->is = IM_ARRAY( out, nim, int )) ) 
		return( NULL );

	/* Remember to NULL-terminate.
	 */
	for( i = 0; i < nim; i++ ) {
		jn->in[i] = in[i];
		jn->is[i] = IM_IMAGE_SIZEOF_PEL( in[i] );
	}
	jn->in[nim] = NULL;

	return( jn );
}

/* Perform join.  
 */
static int
join_bands( REGION *or, void *seq, void *a, void *b )
{
	REGION **ir = (REGION **) seq;
	Join *jn = (Join *) b;
	int x, y, z, i;
	Rect *r = &or->valid;
        int le = r->left;
        int ri = IM_RECT_RIGHT(r);
        int to = r->top;
        int bo = IM_RECT_BOTTOM(r);
	int ps = IM_IMAGE_SIZEOF_PEL( or->im );

	/* Prepare each input area.
	 */
	for( i = 0; i < jn->nim; i++ )
		if( im_prepare( ir[i], r ) )
			return( -1 );

	/* Loop over output!
	 */
	for( y = to; y < bo; y++ ) {
		PEL *qb = (PEL *) IM_REGION_ADDR( or, le, y );

		/* Loop for each input image.
		 */
		for( i = 0; i < jn->nim; i++ ) {
			PEL *p = (PEL *) IM_REGION_ADDR( ir[i], le, y );
			PEL *q = qb;
			int k = jn->is[i];

			/* Copy all PELs from this line of this input image 
			 * into the correct place in the output line.
			 */
			for( x = le; x < ri; x++ ) {
				PEL *qn = q;

				/* Copy one PEL.
				 */
				for( z = 0; z < k; z++ )
					*q++ = *p++;
				
				/* Skip to the point at which the next PEL
				 * from this input should go.
				 */
				q = qn + ps;
			}

			/* Move on to the line start for the next PEL.
			 */
			qb += k;
		}
	}

	return( 0 );
}

/* Band-wise join of a vector of image descriptors.
 */
int
im_gbandjoin( IMAGE **in, IMAGE *out, int nim )
{
	int i;
	Join *jn;

	/* Check it out!
	 */
	if( nim < 1 ) {
		im_error( "im_gbandjoin", "%s", _( "zero input images!" ) );
		return( -1 );
	}
	if( nim == 1 ) 
		return( im_copy( in[0], out ) );

	/* Check our args. 
	 */
	if( im_poutcheck( out ) )
		return( -1 );
	for( i = 0; i < nim; i++ ) {
		if( im_pincheck( in[i] ) )
			return( -1 );

		if( in[i]->Coding != IM_CODING_NONE )	{
			im_error( "im_gbandjoin", 
				"%s", _( "uncoded input only" ) );
			return( -1 );
		}

		if( in[0]->BandFmt != in[i]->BandFmt ) {
			im_error( "im_gbandjoin", 
				"%s", _( "input images differ in format" ) );
			return( -1 );
		}
		if( in[0]->Xsize != in[i]->Xsize ||
		    in[0]->Ysize != in[i]->Ysize ) {
			im_error( "im_gbandjoin", 
				"%s", _( "input images differ in size" ) );
			return( -1 );
		}
	}

	/* Build a data area.
	 */
	if( !(jn = make_join( out, in, nim )) )
		return( -1 );

	/* Prepare the output header.
	 */
	if( im_cp_desc_array( out, jn->in ) )
                return( -1 ); 
	out->Bands = 0;
	for( i = 0; i < nim; i++ )
		out->Bands += in[i]->Bands;

	/* Set demand hints.
	 */
	if( im_demand_hint_array( out, IM_THINSTRIP, jn->in ) )
		return( -1 );

	if( im_generate( out,
		im_start_many, join_bands, im_stop_many, jn->in, jn ) )
		return( -1 );
	
	return( 0 );
}
