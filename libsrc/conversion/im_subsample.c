/* @(#) Shrink any image by some integer xy factor. Sub-samples! Partial, and
 * @(#) quick as a result.
 * @(#)
 * @(#) int 
 * @(#) im_subsample( in, out, xshrink, yshrink )
 * @(#) IMAGE *in, *out;
 * @(#) int xshrink, yshrink;
 * @(#)
 * @(#) Returns either 0 (success) or -1 (fail)
 * @(#)
 *
 * 3/7/95 JC
 *	- adapted from im_shrink()
 * 3/8/02 JC
 *	- fall back to im_copy() for x/y factors == 1
 * 21/4/08
 * 	- don't fall back to pixel-wise shrinks for smalltile, it kills
 * 	  performance, just bring IM_MAX_WIDTH down instead
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

/* Maximum width of input we ask for.
 */
#define IM_MAX_WIDTH (100)

/* Our main parameter struct.
 */
typedef struct {
	int xshrink;		/* Subsample factors */
	int yshrink;
} SubsampleInfo;

/* Subsample a REGION. We fetch in IM_MAX_WIDTH pixel-wide strips, left-to-right
 * across the input.
 */
static int
line_shrink_gen( REGION *or, void *seq, void *a, void *b )
{
	REGION *ir = (REGION *) seq;
	IMAGE *in = (IMAGE *) a;
	SubsampleInfo *st = (SubsampleInfo *) b;
	Rect *r = &or->valid;

	int le = r->left;
	int ri = IM_RECT_RIGHT( r );
	int to = r->top;
	int bo = IM_RECT_BOTTOM(r);

	int ps = IM_IMAGE_SIZEOF_PEL( in );

	int owidth = IM_MAX_WIDTH / st->xshrink;

	Rect s;
	int x, y;
	int z, k;

	/* Loop down the region.
	 */
	for( y = to; y < bo; y++ ) {
		char *q = IM_REGION_ADDR( or, le, y );
		char *p;

		/* Loop across the region, in owidth sized pieces.
		 */
		for( x = le; x < ri; x += owidth ) {
			/* How many pixels do we make this time?
			 */
			int ow = IM_MIN( owidth, ri - x );

			/* Ask for this many from input ... can save a 
			 * little here!
			 */
			int iw = ow * st->xshrink - (st->xshrink - 1);

			/* Ask for input.
			 */
			s.left = x * st->xshrink;
			s.top = y * st->yshrink;
			s.width = iw;
			s.height = 1;
			if( im_prepare( ir, &s ) )
				return( -1 );

			/* Append new pels to output.
			 */
			p = IM_REGION_ADDR( ir, s.left, s.top );
			for( z = 0; z < ow; z++ ) {
				for( k = 0; k < ps; k++ )
					q[k] = p[k];

				q += ps;
				p += ps * st->xshrink;
			}
		}
	}

	return( 0 );
}

/* Fetch one pixel at a time ... good for very large shrinks.
 */
static int
point_shrink_gen( REGION *or, void *seq, void *a, void *b )
{
	REGION *ir = (REGION *) seq;
	IMAGE *in = (IMAGE *) a;
	SubsampleInfo *st = (SubsampleInfo *) b;
	Rect *r = &or->valid;

	int le = r->left;
	int ri = IM_RECT_RIGHT( r );
	int to = r->top;
	int bo = IM_RECT_BOTTOM(r);

	int ps = IM_IMAGE_SIZEOF_PEL( in );

	Rect s;
	int x, y;
	int k;

	/* Loop down the region.
	 */
	for( y = to; y < bo; y++ ) {
		char *q = IM_REGION_ADDR( or, le, y );
		char *p;

		/* Loop across the region, in owidth sized pieces.
		 */
		for( x = le; x < ri; x++ ) {
			/* Ask for input.
			 */
			s.left = x * st->xshrink;
			s.top = y * st->yshrink;
			s.width = 1;
			s.height = 1;
			if( im_prepare( ir, &s ) )
				return( -1 );

			/* Append new pels to output.
			 */
			p = IM_REGION_ADDR( ir, s.left, s.top );
			for( k = 0; k < ps; k++ )
				q[k] = p[k];
			q += ps;
		}
	}

	return( 0 );
}

int 
im_subsample( IMAGE *in, IMAGE *out, int xshrink, int yshrink )
{
	SubsampleInfo *st;

	/* Check parameters.
	 */
	if( xshrink < 1 || yshrink < 1 ) {
		im_error( "im_subsample", _( "factors should both be >= 1" ) );
		return( -1 );
	}
	if( xshrink == 1 && yshrink == 1 ) 
		return( im_copy( in, out ) );
	if( im_piocheck( in, out ) )
		return( -1 );

	/* Prepare output. Note: we round the output width down!
	 */
	if( im_cp_desc( out, in ) )
		return( -1 );
	out->Xsize = in->Xsize / xshrink;
	out->Ysize = in->Ysize / yshrink;
	out->Xres = in->Xres / xshrink;
	out->Yres = in->Yres / yshrink;
	if( out->Xsize <= 0 || out->Ysize <= 0 ) {
		im_error( "im_subsample", _( "image has shrunk to nothing" ) );
		return( -1 );
	}

	/* Build and attach state struct.
	 */
	if( !(st = IM_NEW( out, SubsampleInfo )) )
		return( -1 );
	st->xshrink = xshrink;
	st->yshrink = yshrink;

	/* Set demand hints. We want THINSTRIP, as we will be demanding a
	 * large area of input for each output line.
	 */
	if( im_demand_hint( out, IM_THINSTRIP, in, NULL ) )
		return( -1 );

	/* Generate! If this is a very large shrink, then it's
	 * probably faster to do it a pixel at a time. 
	 */
	if( xshrink > 10 ) {
		if( im_generate( out, 
			im_start_one, point_shrink_gen, im_stop_one, in, st ) )
			return( -1 );
	}
	else {
		if( im_generate( out, 
			im_start_one, line_shrink_gen, im_stop_one, in, st ) )
			return( -1 );
	}

	return( 0 );
}
