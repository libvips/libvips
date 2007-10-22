/* @(#) Performs local histogram equalisation on an image using a
 * @(#) window of size xw by yw
 * @(#) Works only on monochrome images
 * @(#)
 * @(#) int im_lhisteq(in, out, xwin, ywin)
 * @(#) IMAGE *in, *out;
 * @(#) int xwin, ywin;
 * @(#)
 * @(#) Returns 0 on sucess and -1 on error
 *
 * Copyright: 1991, N. Dessipris 
 *
 * Author: N. Dessipris
 * Written on: 24/10/1991
 * Modified on : 
 * 25/1/96 JC
 *	- rewritten, adapting im_spcor()
 *	- correct result, 2x faster, partial, simpler, better arg checking
 * 8/7/04
 *	- expand input rather than output with new im_embed() mode
 *	- _raw() output is one pixel larger
 *	- sets Xoffset/Yoffset
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

/* Hold global stuff here.
 */
typedef struct {
	int xwin, ywin;		/* Parameters */

	int npels; 		/* Pels in window */
} LhistInfo;

/* lhist generate function.
 */
static int
lhist_gen( REGION *or, void *seq, void *a, void *b )
{
	REGION *ir = (REGION *) seq;
	LhistInfo *inf = (LhistInfo *) inf;
	Rect irect;

	Rect *r = &or->valid;
	int le = r->left;
	int to = r->top;
	int bo = IM_RECT_BOTTOM(r);
	int ri = IM_RECT_RIGHT(r);

	int x, y, i, j;
	int lsk;

	int coff;		/* Offset to move to centre of window */

	/* What part of ir do we need?
	 */
	irect.left = or->valid.left;
	irect.top = or->valid.top;
	irect.width = or->valid.width + inf->xwin;
	irect.height = or->valid.height + inf->ywin;

	if( im_prepare( ir, &irect ) )
		return( -1 );
	lsk = IM_REGION_LSKIP( ir );
	coff = lsk * (inf->ywin/2) + inf->xwin/2;

	for( y = to; y < bo; y++ ) {
		/* Get input and output pointers for this line.
		 */
		PEL *p = (PEL *) IM_REGION_ADDR( ir, le, y );
		PEL *q = (PEL *) IM_REGION_ADDR( or, le, y );
		PEL *p1, *p2;
		int hist[ 256 ];

		/* Find histogram for start of this line.
		 */
		memset( hist, 0, 256 * sizeof(int) );
		for( p1 = p, j = 0; j < inf->ywin; j++, p1 += lsk )
			for( p2 = p1, i = 0; i < inf->xwin; i++, p2++ )
				hist[*p2]++;

		/* Loop for output pels.
		 */
		for( x = le; x < ri; x++, p++ ) {
			/* Sum histogram up to current pel.
			 */
			int target = p[coff];
			int sum = 0;

			for( sum = 0, i = 0; i < target; i++ )
				sum += hist[i];

			/* Transform.
			 */
			*q++ = sum * 256 / inf->npels;

			/* Adapt histogram - remove the pels from the left hand
			 * column, add in pels for a new right-hand column.
			 */
			for( p1 = p, j = 0; j < inf->ywin; j++, p1 += lsk ) {
				hist[p1[0]]--;
				hist[p1[inf->xwin]]++;
			}
		}
	}

	return( 0 );
}

int 
im_lhisteq_raw( IMAGE *in, IMAGE *out, int xwin, int ywin )
{
	LhistInfo *inf;

	if( im_piocheck( in, out ) )
		return( -1 );
	if( in->Bbits != IM_BBITS_BYTE || in->BandFmt != IM_BANDFMT_UCHAR || 
		in->Bands != 1 || in->Coding != IM_CODING_NONE ) { 
		im_errormsg( "im_lhisteq: one band uchar uncoded only" ); 
		return( -1 ); 
	}
	if( xwin > in->Xsize || ywin > in->Ysize ) {
		im_errormsg( "im_lhisteq: window too large" );
		return( -1 );
	}
	if( im_cp_desc( out, in ) ) 
		return( -1 );
	out->Xsize -= xwin - 1;
	out->Ysize -= ywin - 1;

	/* Save parameters.
	 */
	if( !(inf = IM_NEW( out, LhistInfo )) )
		return( -1 );
	inf->xwin = xwin;
	inf->ywin = ywin;
	inf->npels = xwin * ywin;

	/* Set demand hints. FATSTRIP is good for us, as THINSTRIP will cause
	 * too many recalculations on overlaps.
	 */
	if( im_demand_hint( out, IM_FATSTRIP, in, NULL ) )
		return( -1 );

	/* Write the hist.
	 */
	if( im_generate( out,
		im_start_one, lhist_gen, im_stop_one, in, inf ) )
		return( -1 );

	out->Xoffset = -xwin / 2;
	out->Yoffset = -xwin / 2;

	return( 0 );
}

/* The above, with a border to make out the same size as in.
 */
int 
im_lhisteq( IMAGE *in, IMAGE *out, int xwin, int ywin )
{
	IMAGE *t1 = im_open_local( out, "im_lhisteq:1", "p" );

	if( !t1 ||
		im_embed( in, t1, 1, 
			xwin / 2, ywin / 2, 
			in->Xsize + xwin - 1, in->Ysize + ywin - 1 ) ||
		im_lhisteq_raw( t1, out, xwin, ywin ) )
		return( -1 );

	out->Xoffset = 0;
	out->Yoffset = 0;

	return( 0 );
}
