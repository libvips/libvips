/* @(#) rotates an image 180 degrees 
 * @(#) Usage:
 * @(#) im_rot180(in, out)
 * @(#) IMAGE *in, *out;
 * @(#) 
 * @(#) Returns 0 on sucess and -1 on error
 * @(#) 
 * Copyright: 1991, N. Dessipris
 * Written on: 28/10/91
 * Updated on: 2/4/92, J.Cupitt 
 * 	bugs in im_la90rot fixed, now works for any type.
 * 19/7/93 JC
 *	- IM_CODING_LABQ allowed now
 * 15/11/94 JC
 *	- name changed
 *	- memory leaks fixed
 * 8/2/95 JC
 *	- oops! memory allocation problem fixed
 * 18/5/95 JC
 * 	- IM_MAXLINES increased
 * 13/8/96 JC
 *	- rewritten for partials
 *	- adapted from im_rot90
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
#include <stdlib.h>
#include <string.h>

#include <vips/vips.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* Rotate a small piece.
 */
static int
rot180_gen( REGION *or, REGION *ir, IMAGE *in )
{
	/* Output area.
	 */
	Rect *r = &or->valid;
	int le = r->left;
	int ri = IM_RECT_RIGHT(r);
	int to = r->top;
	int bo = IM_RECT_BOTTOM(r);

	int x, y;

	/* Pixel geometry.
	 */
	int ps;

	/* Find the area of the input image we need.
	 */
	Rect need;

	need.left = in->Xsize - ri;
	need.top = in->Ysize - bo;
	need.width = r->width;
	need.height = r->height;
	if( im_prepare( ir, &need ) )
		return( -1 );

	/* Find PEL size and line skip for ir.
	 */
	ps = IM_IMAGE_SIZEOF_PEL( in );

	/* Rotate the bit we now have.
	 */
	for( y = to; y < bo; y++ ) {
		/* Start of this output line.
		 */
		PEL *q = (PEL *) IM_REGION_ADDR( or, le, y );

		/* Corresponding position in ir.
		 */
		PEL *p = (PEL *) IM_REGION_ADDR( ir, 
			need.left + need.width - 1, 
			need.top + need.height - (y - to) - 1 );

		/* Blap across!
		 */
		for( x = le; x < ri; x++ ) {
			memcpy( q, p, ps );
			q += ps;
			p -= ps;
		}
	}

	return( 0 );
}

int 
im_rot180( IMAGE *in, IMAGE *out )
{	
	/* Make output image.
	 */
	if( im_piocheck( in, out ) ) 
		return( -1 );
	if( in->Coding != IM_CODING_NONE && in->Coding != IM_CODING_LABQ ) {
		im_error( "im_rot180", _( "uncoded or IM_CODING_LABQ only" ) );
		return( -1 );
	}
	if( im_cp_desc( out, in ) ) 
		return( -1 );

	/* We are fastest with thinstrip.
	 */
	if( im_demand_hint( out, IM_THINSTRIP, in, NULL ) )
		return( -1 );

	/* Generate!
	 */
	if( im_generate( out, 
		im_start_one, rot180_gen, im_stop_one, in, NULL ) )
		return( -1 );

	out->Xoffset = in->Xsize;
	out->Yoffset = in->Ysize;

	return( 0 );
}

