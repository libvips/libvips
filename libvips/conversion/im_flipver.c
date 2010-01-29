/* im_flipver
 *
 * Copyright: 1990, N. Dessipris
 * Written on: 28/10/91
 * Updated on:
 * 21/12/94 JC
 *	- adapted from new im_fliphor().
 * 30/8/96 JC
 *	- ooops! IM_REGION_SIZEOF_LINE() not valid until im_prepare() has been 
 *	  called
 * 7/3/03 JC
 *	- ahem, memcpy() line size calc was wrong, occasional segvs
 * 14/4/04 
 *	- sets Xoffset / Yoffset
 * 24/3/09
 * 	- added IM_CODING_RAD support
 * 29/1/10
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

#include <vips/vips.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* Flip a small area.
 */
static int
flip_gen( REGION *or, void *seq, void *a, void *b )
{	
	REGION *ir = (REGION *) seq;
	Rect *r = &or->valid;
	Rect in;
	PEL *p, *q;
	int y;

	int le = r->left;
	int to = r->top;
	int bo = IM_RECT_BOTTOM( r );

	int ls;
	int psk, qsk;

	/* Transform to input coordinates.
	 */
	in = *r;
	in.top = ir->im->Ysize - bo;

	/* Ask for input we need.
	 */
	if( im_prepare( ir, &in ) )
		return( -1 );

	/* Loop, copying and reversing lines.
	 */
	p = (PEL *) IM_REGION_ADDR( ir, le, in.top + in.height - 1 );
	q = (PEL *) IM_REGION_ADDR( or, le, to );
	psk = IM_REGION_LSKIP( ir );
	qsk = IM_REGION_LSKIP( or );
	ls = IM_REGION_SIZEOF_LINE( or );

	for( y = to; y < bo; y++ ) {
		memcpy( q, p, ls );

		p -= psk;
		q += qsk;
	}

	return( 0 );
}

/**
 * im_flipver:
 * @in: input image
 * @out: output image
 *
 * Flips an image top-bottom.
 *
 * See also: im_fliphor(), im_rot90().
 *
 * Returns: 0 on success, -1 on error
 */
int 
im_flipver( IMAGE *in, IMAGE *out )
{	
        if( im_piocheck( in, out ) ||
		im_check_coding_known( "im_flipver", in ) ||
		im_cp_desc( out, in ) ||
		im_demand_hint( out, IM_THINSTRIP, in, NULL ) ||
		im_generate( out, 
			im_start_one, flip_gen, im_stop_one, in, NULL ) )
		return( -1 );

	out->Xoffset = 0;
	out->Yoffset = in->Ysize;

	return( 0 );
}
