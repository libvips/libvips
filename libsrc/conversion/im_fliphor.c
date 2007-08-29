/* @(#) Flips image left-right.
 * @(#) 
 * @(#) Usage:
 * @(#) 
 * @(#) int im_fliphor( IMAGE *in, IMAGE *out )
 * @(#) 
 * @(#) Returns 0 on sucess and -1 on error
 * @(#) 
 * Copyright: 1990, N. Dessipris
 * Written on: 28/10/91
 * Updated on:
 * 19/7/93 JC
 *	- now allows IM_CODING_LABQ too
 *	- yuk! needs rewriting
 * 21/12/94 JC
 *	- rewritten
 * 14/4/04 
 *	- sets Xoffset / Yoffset
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

#include <vips/vips.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* Flip a small area.
 */
static int
flip_gen( REGION *or, REGION *ir )
{	
	Rect *r = &or->valid;
	Rect in;
	char *p, *q;
	int x, y, z;

	int le = r->left;
	int ri = IM_RECT_RIGHT(r);
	int to = r->top;
	int bo = IM_RECT_BOTTOM(r);

	int ps = IM_IMAGE_SIZEOF_PEL( ir->im );	/* sizeof pel */

	int hgt = ir->im->Xsize - r->width;

	int lastx;

	/* Transform to input coordinates.
	 */
	in = *r;
	in.left = hgt - r->left;

	/* Find x of final pixel in input area.
	 */
	lastx = IM_RECT_RIGHT( &in ) - 1;

	/* Ask for input we need.
	 */
	if( im_prepare( ir, &in ) )
		return( -1 );

	/* Loop, copying and reversing lines.
	 */
	for( y = to; y < bo; y++ ) {
		p = IM_REGION_ADDR( ir, lastx, y );
		q = IM_REGION_ADDR( or, le, y );

		for( x = le; x < ri; x++ ) {
			/* Copy the pel.
			 */
			for( z = 0; z < ps; z++ )
				q[z] = p[z];

			/* Skip forwards in out, back in in.
			 */
			q += ps;
			p -= ps;
		}
	}

	return( 0 );
}

/* Copy image.
 */
int 
im_fliphor( IMAGE *in, IMAGE *out )
{	
	/* Check args.
	 */
        if( im_piocheck( in, out ) )
		return( -1 );
	if( in->Coding != IM_CODING_NONE && in->Coding != IM_CODING_LABQ ) {
		im_errormsg( "im_fliphor: in must be uncoded" );
		return( -1 );
	}

	/* Prepare output header.
	 */
	if( im_cp_desc( out, in ) )
		return( -1 );

	/* Set demand hints.
	 */
	if( im_demand_hint( out, IM_THINSTRIP, in, NULL ) )
		return( -1 );

	/* Generate!
	 */
	if( im_generate( out, im_start_one, flip_gen, im_stop_one, in, NULL ) )
		return( -1 );

	out->Xoffset = in->Xsize;
	out->Yoffset = 0;

	return( 0 );
}
