/* local histogram equalisation
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
 * 23/6/08
 * 	- check for window too small as well
 * 25/3/10
 * 	- gtkdoc
 * 	- small cleanups
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
	LhistInfo *inf = (LhistInfo *) b;
	Rect *r = &or->valid;

	Rect irect;
	int x, y, i, j;
	int lsk;
	int centre;		/* Offset to move to centre of window */

	/* What part of ir do we need?
	 */
	irect.left = or->valid.left;
	irect.top = or->valid.top;
	irect.width = or->valid.width + inf->xwin;
	irect.height = or->valid.height + inf->ywin;
	if( im_prepare( ir, &irect ) )
		return( -1 );

	lsk = IM_REGION_LSKIP( ir );
	centre = lsk * (inf->ywin / 2) + inf->xwin / 2;

	for( y = 0; y < r->height; y++ ) {
		/* Get input and output pointers for this line.
		 */
		PEL *p = (PEL *) IM_REGION_ADDR( ir, r->left, r->top + y );
		PEL *q = (PEL *) IM_REGION_ADDR( or, r->left, r->top + y );

		PEL *p1;
		int hist[256];

		/* Find histogram for start of this line.
		 */
		memset( hist, 0, 256 * sizeof( int ) );
		p1 = p;
		for( j = 0; j < inf->ywin; j++ ) {
			for( i = 0; i < inf->xwin; i++ )
				hist[p1[i]] += 1;
			
			p1 += lsk;
		}

		/* Loop for output pels.
		 */
		for( x = 0; x < r->width; x++ ) {
			/* Sum histogram up to current pel.
			 */
			int target = p[centre];
			int sum;

			sum = 0;
			for( i = 0; i < target; i++ )
				sum += hist[i];

			/* Transform.
			 */
			q[x] = sum * 256 / inf->npels;

			/* Adapt histogram - remove the pels from the left hand
			 * column, add in pels for a new right-hand column.
			 */
			p1 = p;
			for( j = 0; j < inf->ywin; j++ ) {
				hist[p1[0]] -= 1;
				hist[p1[inf->xwin]] += 1;

				p1 += lsk;
			}

			p += 1;
		}
	}

	return( 0 );
}

int 
im_lhisteq_raw( IMAGE *in, IMAGE *out, int xwin, int ywin )
{
	LhistInfo *inf;

	if( im_check_mono( "im_lhisteq", in ) ||
		im_check_uncoded( "im_lhisteq", in ) ||
		im_check_format( "im_lhisteq", in, IM_BANDFMT_UCHAR ) ||
		im_piocheck( in, out ) )
		return( -1 );
	if( xwin > in->Xsize || 
		ywin > in->Ysize ) {
		im_error( "im_lhisteq", "%s", _( "window too large" ) );
		return( -1 );
	}
	if( xwin <= 0 || 
		ywin <= 0 ) {
		im_error( "im_lhisteq", "%s", _( "window too small" ) );
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

	if( im_generate( out,
		im_start_one, lhist_gen, im_stop_one, in, inf ) )
		return( -1 );

	out->Xoffset = -xwin / 2;
	out->Yoffset = -xwin / 2;

	return( 0 );
}

/**
 * im_lhisteq:
 * @in: input image
 * @out: output image
 * @xwin: width of region
 * @ywin: height of region
 *
 * Performs local histogram equalisation on @in using a
 * window of size @xwin by @ywin centered on the input pixel. Works only on 
 * monochrome images.
 *
 * The output image is the same size as the input image. The edge pixels are
 * created by copy edge pixels of the input image outwards.
 *
 * See also: im_stdif(), im_heq().
 *
 * Returns: 0 on success, -1 on error
 */
int 
im_lhisteq( IMAGE *in, IMAGE *out, int xwin, int ywin )
{
	IMAGE *t1;

	if( !(t1 = im_open_local( out, "im_lhisteq:1", "p" )) ||
		im_embed( in, t1, 1, 
			xwin / 2, ywin / 2, 
			in->Xsize + xwin - 1, in->Ysize + ywin - 1 ) ||
		im_lhisteq_raw( t1, out, xwin, ywin ) )
		return( -1 );

	out->Xoffset = 0;
	out->Yoffset = 0;

	return( 0 );
}
