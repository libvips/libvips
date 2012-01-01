/* im_zoom
 *
 * Author: N. Martinez 1991
 * 6/6/94 JC
 *	- rewritten to ANSI-C
 *	- now works for any type, including IM_CODING_LABQ
 * 7/10/94 JC
 *	- new IM_ARRAY() macro
 * 26/1/96 JC
 *	- separate x and y zoom factors
 * 21/8/96 JC
 *	- partial, yuk! this is so complicated ...
 * 30/8/96 JC
 *	- sets demand_hint
 * 10/2/00 JC
 *	- check for integer overflow in zoom facs ... was happening with ip's 
 * 	  zoom on large images
 * 3/8/02 JC
 *	- fall back to im_copy() for x & y factors == 1
 * 24/3/09
 * 	- added IM_CODING_RAD support
 * 1/2/10
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

/*
 * TODO:
 * Test for pixel size and use memcpy() on individual pixels once they reach
 * sizes of the order of tens of bytes. char-wise copy is quicker than 
 * memcpy() for smaller pixels.
 *
 * Also, I haven't tested it but int-wise copying may be faster still, as 
 * long as alignment permits it.
 *
 * tcv.  2006-09-01
 */

/* Turn on IM_REGION_ADDR() range checks.
#define DEBUG 1
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include <vips/vips.h>

/* Round N down to P boundary. 
 */
#define ROUND_DOWN(N,P) ((N) - ((N) % P)) 

/* Round N up to P boundary. 
 */
#define ROUND_UP(N,P) (ROUND_DOWN( (N) + (P) - 1, (P) ))

/* Our main parameter struct.
 */
typedef struct {
	int xfac;		/* Scale factors */
	int yfac;
} ZoomInfo;

/* Paint the part of the region containing only whole pels.
 */
static void
paint_whole( REGION *or, REGION *ir, ZoomInfo *zm,
	const int left, const int right, const int top, const int bottom )
{
	const int ps = IM_IMAGE_SIZEOF_PEL( ir->im );
	const int ls = IM_REGION_LSKIP( or );
	const int rs = ps * (right - left);

	/* Transform to ir coordinates.
	 */
	const int ileft = left / zm->xfac;
	const int iright = right / zm->xfac;
	const int itop = top / zm->yfac;
	const int ibottom = bottom / zm->yfac;

	int x, y, z, i;

	/* We know this!
	 */
	g_assert( right > left && bottom > top && 
		right % zm->xfac == 0 &&
		left % zm->xfac == 0 &&
		top % zm->yfac == 0 &&
		bottom % zm->yfac == 0 );

	/* Loop over input, as we know we are all whole.
	 */
	for( y = itop; y < ibottom; y++ ) {
		VipsPel *p = IM_REGION_ADDR( ir, ileft, y );
		VipsPel *q = IM_REGION_ADDR( or, left, y * zm->yfac );
		VipsPel *r;

		/* Expand the first line of pels.
		 */
		r = q;
		for( x = ileft; x < iright; x++ ) {
			/* Copy each pel xfac times.
			 */
			for( z = 0; z < zm->xfac; z++ ) {
				for( i = 0; i < ps; i++ )
					r[i] = p[i];

				r += ps;
			}

			p += ps;
		}

		/* Copy the expanded line yfac-1 times.
		 */
		r = q + ls;
		for( z = 1; z < zm->yfac; z++ ) {
			memcpy( r, q, rs );
			r += ls;
		}
	}
}

/* Paint the part of the region containing only part-pels.
 */
static void
paint_part( REGION *or, REGION *ir, const ZoomInfo *zm,
	const int left, const int right, const int top, const int bottom )
{
	const int ps = IM_IMAGE_SIZEOF_PEL( ir->im );
	const int ls = IM_REGION_LSKIP( or );
	const int rs = ps * (right - left);

	/* Start position in input.
	 */
	const int ix = left / zm->xfac;
	const int iy = top / zm->yfac;

	/* Pels down to yfac boundary, pels down to bottom. Do the smallest of
	 * these for first y loop.
	 */
	const int ptbound = (iy + 1) * zm->yfac - top;
	const int ptbot = bottom - top;

	int yt = IM_MIN( ptbound, ptbot );

	int x, y, z, i;

	/* Only know this.
	 */
	g_assert( right - left >= 0 && bottom - top >= 0 );

	/* Have to loop over output.
	 */
	for( y = top; y < bottom; ) {
		VipsPel *p = IM_REGION_ADDR( ir, ix, y / zm->yfac );
		VipsPel *q = IM_REGION_ADDR( or, left, y );
		VipsPel *r;

		/* Output pels until we jump the input pointer.
		 */
		int xt = (ix + 1) * zm->xfac - left;

		/* Loop for this output line.
		 */
		r = q;
		for( x = left; x < right; x++ ) {
			/* Copy 1 pel.
			 */
			for( i = 0; i < ps; i++ )
				r[i] = p[i];
			r += ps;

			/* Move input if on boundary.
			 */
			--xt;
			if( xt == 0 ) {
				xt = zm->xfac;
				p += ps;
			}
		}

		/* Repeat that output line until the bottom of this pixel
		 * boundary, or we hit bottom.
		 */
		r = q + ls;
		for( z = 1; z < yt; z++ ) {
			memcpy( r, q, rs );
			r += ls;
		}

		/* Move y on by the number of lines we wrote.
		 */
		y += yt;

		/* Reset yt for next iteration.
		 */
		yt = zm->yfac;
	}
}

/* Zoom a REGION.
 */
static int
zoom_gen( REGION *or, void *seq, void *a, void *b )
{
	REGION *ir = (REGION *) seq;
	ZoomInfo *zm = (ZoomInfo *) b;

	/* Output area we are building.
	 */
	const Rect *r = &or->valid;
	const int ri = IM_RECT_RIGHT( r );
	const int bo = IM_RECT_BOTTOM(r);

	Rect s;
	int left, right, top, bottom;
	int width, height;

	/* Area of input we need. We have to round out, as we may have
	 * part-pixels all around the edges.
	 */
	left = ROUND_DOWN( r->left, zm->xfac );
	right = ROUND_UP( ri, zm->xfac );
	top = ROUND_DOWN( r->top, zm->yfac );
	bottom = ROUND_UP( bo, zm->yfac );
	width = right - left;
	height = bottom - top;
	s.left = left / zm->xfac;
	s.top = top / zm->yfac;
	s.width = width / zm->xfac;
	s.height = height / zm->yfac;
	if( im_prepare( ir, &s ) )
		return( -1 );
	
	/* Find the part of the output (if any) which uses only whole pels.
	 */
	left = ROUND_UP( r->left, zm->xfac );
	right = ROUND_DOWN( ri, zm->xfac );
	top = ROUND_UP( r->top, zm->yfac );
	bottom = ROUND_DOWN( bo, zm->yfac );
	width = right - left;
	height = bottom - top;

	/* Stage 1: we just paint the whole pels in the centre of the region.
	 * As we know they are not clipped, we can do it quickly.
	 */
	if( width > 0 && height > 0 ) 
		paint_whole( or, ir, zm, left, right, top, bottom );

	/* Just fractional pixels left. Paint in the top, left, right and
	 * bottom parts.
	 */
	if( top - r->top > 0 ) 
		/* Some top pixels.
		 */
		paint_part( or, ir, zm, 
			r->left, ri, r->top, IM_MIN( top, bo ) );
	if( left - r->left > 0 && height > 0 )
		/* Left pixels.
		 */
		paint_part( or, ir, zm, 
			r->left, IM_MIN( left, ri ), top, bottom );
	if( ri - right > 0 && height > 0 )
		/* Right pixels.
		 */
		paint_part( or, ir, zm, 
			IM_MAX( right, r->left ), ri, top, bottom );
	if( bo - bottom > 0 && height >= 0 )
		/* Bottom pixels.
		 */
		paint_part( or, ir, zm, 
			r->left, ri, IM_MAX( bottom, r->top ), bo );

	return( 0 );
}

/**
 * im_zoom:
 * @in: input image
 * @out: output image
 * @xfac: horizontal scale factor
 * @yfac: vertical scale factor
 *
 * Zoom an image by repeating pixels. This is fast nearest-neighbour
 * zoom.
 *
 * See also: im_affinei(), im_subsample().
 * 
 * Returns: 0 on success, -1 on error.
 */
int
im_zoom( IMAGE *in, IMAGE *out, int xfac, int yfac )
{
	ZoomInfo *zm;

	/* Check arguments.
	 */
	if( xfac <= 0 || yfac <= 0 ) { 
		im_error( "im_zoom", "%s", _( "zoom factors should be >= 0" ) );
		return( -1 );
	}
	if( (double) in->Xsize * xfac > (double) INT_MAX / 2 || 
		(double) in->Ysize * yfac > (double) INT_MAX / 2 ) { 
		/* Make sure we won't get integer overflow.
 		 */
		im_error( "im_zoom", "%s", _( "zoom factors too large" ) );
		return( -1 );
	}
	if( xfac == 1 && yfac == 1 ) 
		return( im_copy( in, out ) );
	if( im_piocheck( in, out ) ||
		im_check_coding_known( "im_zoom", in ) )
		return( -1 );

	/* Make output.
	 */
	if( im_cp_desc( out, in ) )
		return( -1 );
	out->Xsize = in->Xsize * xfac;
	out->Ysize = in->Ysize * yfac;

	/* Save parameters.
	 */
	if( !(zm = IM_NEW( out, ZoomInfo )) )
		return( -1 );
	zm->xfac = xfac;
	zm->yfac = yfac;

	/* Set demand hints. THINSTRIP will prevent us from using
	 * paint_whole() much ... so go for FATSTRIP.
	 */
	if( im_demand_hint( out, IM_FATSTRIP, in, NULL ) )
		return( -1 );

	/* Generate!
	 */
	if( im_generate( out, 
		im_start_one, zoom_gen, im_stop_one, in, zm ) )
		return( -1 );

	return( 0 );
}
