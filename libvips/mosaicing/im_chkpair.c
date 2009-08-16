/* @(#)  Functions which improve the selection of two ttie points pairs in two
 * @(#) images, by estimating the correlation coefficient given in page 426 
 * @(#) 2nd edn of the book Digital Image processing Gonzalez and Wintz
 * @(#)  The function works as follows:
 * @(#)  It expects to receive nopoints pairs (coordinates) of points 
 * @(#) corresponding to ref and sec.
 * @(#)  The coordinates of the pairs are in arrays x1,y1 and x2,y2
 * @(#)  After that the program reads a region of 2*halfcorsize +1 pels centered
 * @(#) at point (x1, y1) and looks around
 * @(#) an area 2*halfareasize+1 centered at point (x2, y2).
 * @(#)  For each point in this 2*halfareasize+1,
 * @(#) the program reads the corresponding
 * @(#) image2 values in a region of 2*halfcorsize+1 pels centered at this point
 * @(#) and calculates the corresponding correlation coefficients.
 * @(#)  The result is stored in a the array 
 * @(#) corcoef[(2*halfareasize+1)(2*halfareasize+1)].  Within this window, the 
 * @(#) max correlation coefficient is estimated and its corresponding
 * @(#) (x, y) coordinates are returned in (x2, y2).
 * @(#)   The purpose of this function is to improve the selection of 
 * @(#) control points entered in (x1, y1)
 * @(#) Both input images should are either memory mapped or in a buffer.
 * @(#) The variable bandno should be between 1 and ref->Bands
 * @(#)  The program fills the dx[] and dy[] arrays before returning.
 * @(#)
 * @(#) int im__chkpair( ref, sec, bandno, points )
 * @(#) IMAGE *ref, *sec;
 * @(#) int bandno;
 * @(#) TIE_POINTS *points;
 * @(#) 
 * @(#) Returns 0 on sucess  and -1 on error.
 *
 * Copyright: 1990, N. Dessipris.
 *
 * Author: Nicos Dessipris
 * Written on: 02/05/1990
 * Modified on : 18/04/1991
 * 8/7/93 JC
 *	- allows IM_CODING_LABQ coding
 *	- now calls im_incheck()
 * 13/7/95 JC
 *	- rewritten
 *	- now uses im_spcor()
 * 13/8/96 JC
 *	- order of args changed to help C++ API
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
#include <math.h>

#include <vips/vips.h>

#include "mosaic.h"

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* Find position of sec within ref. Search around point xsec, ysec for the
 * best match for the area around xref, yref. Search an area of size
 * hsearchsize for an of size hwindowsize.
 *
 * Return a new value for xsec, ysec and the correlation at that point.
 * 
 * Also used by im_match_linear(), im_match_linear_search(), etc.
 */
int 
im_correl( IMAGE *ref, IMAGE *sec, 
	int xref, int yref, int xsec, int ysec,
	int hwindowsize, int hsearchsize,
	double *correlation, int *x, int *y )
{
	IMAGE *surface = im_open( "surface", "t" );
	IMAGE *t1, *t2, *t3, *t4;

	Rect refr, secr;
	Rect winr, srhr;
	Rect wincr, srhcr;

	if( !surface || 
		!(t1 = im_open_local( surface, "correlate:1", "p" )) ||
		!(t2 = im_open_local( surface, "correlate:1", "p" )) ||
		!(t3 = im_open_local( surface, "correlate:1", "p" )) ||
		!(t4 = im_open_local( surface, "correlate:1", "p" )) )
		return( -1 );
	
	/* Find position of window and search area, and clip against image
	 * size.
	 */
	refr.left = 0;
	refr.top = 0;
	refr.width = ref->Xsize;
	refr.height = ref->Ysize;
	winr.left = xref - hwindowsize;
	winr.top = yref - hwindowsize;
	winr.width = hwindowsize*2 + 1;
	winr.height = hwindowsize*2 + 1;
	im_rect_intersectrect( &refr, &winr, &wincr );

	secr.left = 0;
	secr.top = 0;
	secr.width = sec->Xsize;
	secr.height = sec->Ysize;
	srhr.left = xsec - hsearchsize;
	srhr.top = ysec - hsearchsize;
	srhr.width = hsearchsize*2 + 1;
	srhr.height = hsearchsize*2 + 1;
	im_rect_intersectrect( &secr, &srhr, &srhcr );

	/* Extract window and search area.
	 */
	if( im_extract_area( ref, t1, 
			wincr.left, wincr.top, wincr.width, wincr.height ) ||
		im_extract_area( sec, t2, 
			srhcr.left, srhcr.top, srhcr.width, srhcr.height ) ) {
		im_close( surface );
		return( -1 );
	}

	/* Make sure we have just one band. From im_*mosaic() we will, but
	 * from im_match_linear_search() etc. we may not.
	 */
	if( t1->Bands != 1 ) {
		if( im_extract_band( t1, t3, 0 ) ) {
			im_close( surface );
			return( -1 );
		}
		t1 = t3;
	}
	if( t2->Bands != 1 ) {
		if( im_extract_band( t2, t4, 0 ) ) {
			im_close( surface );
			return( -1 );
		}
		t2 = t4;
	}

	/* Search!
	 */
	if( im_spcor( t2, t1, surface ) ) {
		im_close( surface );
		return( -1 );
	}

	/* Find maximum of correlation surface.
	 */
	if( im_maxpos( surface, x, y, correlation ) ) {
		im_close( surface );
		return( -1 );
	}
	im_close( surface );

	/* Translate back to position within sec.
	 */
	*x += srhcr.left;
	*y += srhcr.top;

	return( 0 );
}

int 
im__chkpair( IMAGE *ref, IMAGE *sec, TIE_POINTS *points )
{
	int i;
	int x, y;
	double correlation;

	const int hcor = points->halfcorsize;
	const int harea = points->halfareasize;

	/* Check images.
	 */
	if( im_incheck( ref ) || im_incheck( sec ) ) 
		return( -1 );
	if( ref->Bands != sec->Bands || ref->BandFmt != sec->BandFmt || 
		ref->Coding != sec->Coding ) {
		im_errormsg( "im_chkpair: inputs incompatible"); 
		return( -1 ); 
	}
	if( ref->Bands != 1 || ref->BandFmt != IM_BANDFMT_UCHAR ) { 
		im_errormsg( "im_chkpair: help!" );
		return( -1 );
	}

	for( i = 0; i < points->nopoints; i++ ) {
		/* Find correlation point.
		 */
		if( im_correl( ref, sec, 
			points->x_reference[i], points->y_reference[i],
			points->x_reference[i], points->y_reference[i],
			hcor, harea, 
			&correlation, &x, &y ) ) 
			return( -1 );

		/* And note in x_secondary.
		 */
		points->x_secondary[i] = x;
		points->y_secondary[i] = y;
		points->correlation[i] = correlation;

		/* Note each dx, dy too.
		 */
		points->dx[i] = 
			points->x_secondary[i] - points->x_reference[i];
		points->dy[i] = 
			points->y_secondary[i] - points->y_reference[i];
	}

	return( 0 );
}
