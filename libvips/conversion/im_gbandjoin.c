/* im_gbandjoin -- bandwise join of a set of images
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
 * 17/1/09
 * 	- cleanups
 * 	- gtk-doc
 * 	- im_bandjoin() just calls this
 * 	- works for RAD coding too
 * 27/1/10
 * 	- formatalike inputs
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
join_new( IMAGE *out, IMAGE **in, int nim )
{
	Join *join;
	int i;

	if( !(join = IM_NEW( out, Join )) )
		return( NULL );
	join->nim = nim;
	if( !(join->in = IM_ARRAY( out, nim + 1, IMAGE * )) || 
		!(join->is = IM_ARRAY( out, nim, int )) ) 
		return( NULL );

	/* Cast inputs up to a common format.
	 */
	if( im_open_local_array( out, join->in, nim, "im_gbandjoin", "p" ) ||
		im__formatalike_vec( in, join->in, nim ) )
		return( -1 );

	for( i = 0; i < nim; i++ ) 
		join->is[i] = IM_IMAGE_SIZEOF_PEL( join->in[i] );

	/* Remember to NULL-terminate. We pass ->in[] to
	 * im_demand_hint_array() and friends later.
	 */
	join->in[nim] = NULL;

	return( join );
}

/* Perform join.  
 */
static int
join_bands( REGION *or, void *seq, void *a, void *b )
{
	REGION **ir = (REGION **) seq;
	Join *join = (Join *) b;
	Rect *r = &or->valid;
	const int ps = IM_IMAGE_SIZEOF_PEL( or->im );

	int x, y, z, i;

	for( i = 0; i < join->nim; i++ )
		if( im_prepare( ir[i], r ) )
			return( -1 );

	/* Loop over output!
	 */
	for( y = 0; y < r->height; y++ ) {
		PEL *qb;

		qb = (PEL *) IM_REGION_ADDR( or, r->left, r->top + y );

		/* Loop for each input image. Scattered write is faster than
		 * scattered read.
		 */
		for( i = 0; i < join->nim; i++ ) {
			int k = join->is[i];

			PEL *p;
			PEL *q;

			p = (PEL *) IM_REGION_ADDR( ir[i], 
				r->left, r->top + y );
			q = qb;

			for( x = 0; x < r->width; x++ ) {
				for( z = 0; z < k; z++ )
					q[z] = p[z];

				p += z;
				q += ps;
			}

			qb += k;
		}
	}

	return( 0 );
}

/**
 * im_gbandjoin:
 * @in: vector of input images
 * @out: output image
 * @nim: number of input images
 *
 * Join a set of images together, bandwise. 
 * If the images
 * have n and m bands, then the output image will have n + m
 * bands, with the first n coming from the first image and the last m
 * from the second. 
 *
 * The images must be the same size. 
 * The input images are cast up to the smallest common type (see table 
 * Smallest common format in 
 * <link linkend="VIPS-arithmetic">arithmetic</link>).
 *
 * See also: im_bandjoin(), im_insert().
 *
 * Returns: 0 on success, -1 on error
 */
int
im_gbandjoin( IMAGE **in, IMAGE *out, int nim )
{
	int i;
	Join *join;

	/* Check it out!
	 */
	if( nim < 1 ) {
		im_error( "im_gbandjoin", "%s", _( "zero input images!" ) );
		return( -1 );
	}
	else if( nim == 1 ) 
		return( im_copy( in[0], out ) );

	/* Check our args. 
	 */
	if( im_poutcheck( out ) ||
		im_check_known_coded( "im_gbandjoin", in[0] ) )
		return( -1 );
	for( i = 0; i < nim; i++ ) 
		if( im_pincheck( in[i] ) ||
			im_check_same_size( "im_gbandjoin", in[i], in[0] ) ||
			im_check_same_coding( "im_gbandjoin", in[i], in[0] ) )
			return( -1 );

	/* Build a data area.
	 */
	if( !(join = join_new( out, in, nim )) )
		return( -1 );

	/* Prepare the output header.
	 */
	if( im_cp_desc_array( out, join->in ) )
                return( -1 ); 
	out->Bands = 0;
	for( i = 0; i < nim; i++ )
		out->Bands += in[i]->Bands;
	if( im_demand_hint_array( out, IM_THINSTRIP, join->in ) )
		return( -1 );

	if( im_generate( out,
		im_start_many, join_bands, im_stop_many, join->in, join ) )
		return( -1 );
	
	return( 0 );
}

/**
 * im_bandjoin:
 * @in1: first input image
 * @in2: second input image
 * @out: output image
 *
 * Join two images bandwise. 
 * If the two images
 * have n and m bands respectively, then the output image will have n + m
 * bands, with the first n coming from the first image and the last m
 * from the second. 
 *
 * The images must be the same size. 
 * The two input images are cast up to the smallest common type (see table 
 * Smallest common format in 
 * <link linkend="VIPS-arithmetic">arithmetic</link>).
 *
 * See also: im_gbandjoin(), im_insert().
 *
 * Returns: 0 on success, -1 on error
 */
int
im_bandjoin( IMAGE *in1, IMAGE *in2, IMAGE *out )
{
	IMAGE *t[2];

	t[0] = in1;
	t[1] = in2;

	return( im_gbandjoin( t, out, 2 ) );
}
