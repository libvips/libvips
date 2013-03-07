/* @(#)  Functions which takes an initial estimate of deltax, deltay
 * @(#) between reference and secondary images (probably from the scanner),
 * @(#) and looks in three areas of the overlapping part of the reference image
 * @(#) corresponding to reference and secondary.  For every other halfreasize
 * @(#) point of the three areas of the reference image
 * @(#) the contrast is calculated
 * @(#) an area 2*halfcorsize+1 centered at this point
 * @(#) Results are saved in the structure points
 * @(#) The function expects the following valid data in points:
 * @(#) deltax, deltay, nopoints, halfcorsize, halfareasize
 * @(#) and fills in the memebers:
 * @(#) x, y_reference[], contrast and x,y_secondary[],
 * @(#) based on deltax and deltay
 * @(#) Input image should are either memory mapped or in a buffer.
 * @(#)  The initial setting checks all points of reference
 * @(#) in the overlapping area of the images to be mosaiced
 * @(#)  To speed up the procedure the ysize of the box can be reduced
 * @(#) during the calculation of the ysize
 * @(#) An easy way is to change FACTOR to 1 2 or 3.
 * @(#)  The calculation of the contrast is carried out based on bandno only.
 * @(#) The variable bandno should be between 1 and ref->Bands
 * @(#)
 * @(#) int im_lrcalcon( ref, sec, bandno, points )
 * @(#) IMAGE *ref, *sec;
 * @(#) int bandno;
 * @(#) TIE_POINTS *points; 	see mosaic.h
 * @(#) 
 * @(#) Returns 0 on sucess  and -1 on error.
 * @(#) 
 *
 * Copyright: 1990, N. Dessipris.
 *
 * Author: Nicos Dessipris
 * Written on: 20/12/1990
 * Modified on : 18/04/1991
 * 8/7/93 JC
 *	- now calls im_incheck()
 * 12/7/95 JC
 *	- reworked
 *	- what a lot of horrible old code there was too
 * 24/1/97 JC
 *	- now ignores black stuff (all bands zero) when selecting possible tie
 *	  points, part of new mosaic policy
 * 26/9/97 JC
 *	- now skips all-black windows, instead of any-black windows
 * 11/4/01 JC
 *	- ooops, < 0 should have been <= 0 
 * 10/3/03 JC
 *	- better error message for overlap too small
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
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
    02110-1301  USA

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

/* A position and contrast.
 */
typedef struct {
	int x, y;
	int cont;
} PosCont;

/* Search a window for black pelss ... true if window is all black.
 * One-band uchar only.
 */
static int
all_black( IMAGE *im, int xpos, int ypos, int winsize )
{
	const int hwinsize = (winsize - 1)/2;
	const int left = xpos - hwinsize;
	const int top = ypos - hwinsize;
	const int ls = im->Xsize;

	int x, y;
	VipsPel *line;

	/* Loop over image.
	 */
	line = im->data + top*ls + left;
	for( y = 0; y < winsize; y++ ) {
		for( x = 0; x < winsize; x++ ) 
			if( line[x] ) 
				/* Not all black.
				 */
				return( 0 );

		line += ls;
	}

	return( -1 );
}

/* Calculate a value for 'contrast' within a window
 * of (odd) size winsize*winsize centered at location (xpos, ypos).
 * One band uchar only, 
 */
static int 
calculate_contrast( IMAGE *im, int xpos, int ypos, int winsize )
{
	const int hwinsize = (winsize - 1)/2;
	const int left = xpos - hwinsize;
	const int top = ypos - hwinsize;
	const int ls = im->Xsize;

	int x, y;
	VipsPel *line, *p;
	int total;

	line = im->data + top*ls + left;
	for( total = 0, y = 0; y < winsize-1; y++ ) {
		p = line;

		for( x = 0; x < winsize-1; x++ ) {
			const int lrd = (int) p[0] - p[1];
			const int tbd = (int) p[0] - p[ls];

			total += abs( lrd ) + abs( tbd );
			p += 1;
		}

		line += ls;
	}

	return( total );
}

/* Compare two PosConts for qsort.
 */
static int
pos_compare( const void *vl, const void *vr )
{
	PosCont *l = (PosCont *) vl;
	PosCont *r = (PosCont *) vr;

	return( r->cont - l->cont );
}

/* Search an area for the n best contrast areas. 
 */
int 
im__find_best_contrast( IMAGE *im, 
	int xpos, int ypos, int xsize, int ysize,
	int xarray[], int yarray[], int cont[], 
	int nbest, int hcorsize )
{
	/* Geometry: we test squares of size windowsize, overlapping by 
	 * hcorsize.
	 */
	const int windowsize = 2 * hcorsize + 1;

	/* Number of squares we can fit in area.
	 */
	const int nacross = (xsize - windowsize + hcorsize) / hcorsize;
	const int ndown = (ysize - windowsize + hcorsize) / hcorsize;

	/* Number of squares we search.
	 */
	int elms;

	/* All points in this area.
	 */
	PosCont *pc;

	int x, y, i;

	if( nacross <= 0 || ndown <= 0 ) {
		im_error( "im__lrcalcon", "%s", 
			_( "overlap too small for your search size" ) );
		return( -1 );
	}

	/* Malloc space for 3 int arrays, to keep the int coordinates and
 	 * the contrast.
	 */
	if( !(pc = IM_ARRAY( NULL, nacross * ndown, PosCont )) )
		return( -1 );

	/* Find contrast for each area.
	 */
	for( i = 0, y = 0; y < ndown; y++ ) 
		for( x = 0; x < nacross; x++ ) {
			const int left = xpos + x * hcorsize;
			const int top = ypos + y * hcorsize;

			/* Skip this position if it is all black.
			 */
			if( all_black( im, left, top, windowsize ) )
				continue;

			/* Find contrast and note.
			 */
			pc[i].x = left;
			pc[i].y = top;
			pc[i].cont = calculate_contrast( im, 
				left, top, windowsize );
			i++;
		}

	/* Note number found.
	 */
	elms = i;

	/* Found enough tie-points?
	 */
	if( elms < nbest ) {
		im_error( "im_mosaic", 
			_( "found %d tie-points, need at least %d" ), 
			elms, nbest );
		im_free( pc );
		return( -1 );
	}

	/* Sort areas by contrast.
	 */
	qsort( pc, elms, sizeof( PosCont ), pos_compare );

	/* Copy the n best into our parent.
	 */
	for( i = 0; i < nbest; i++ ) {
		xarray[i] = pc[i].x;
		yarray[i] = pc[i].y;
		cont[i] = pc[i].cont;
	}
	im_free( pc );

	return( 0 );
}

int 
im__lrcalcon( IMAGE *ref, TIE_POINTS *points )
{
	/* Geometry: border we must leave around each area.
	 */
	const int border = points->halfareasize;

	/* Height of an area.
	 */
	const int aheight = ref->Ysize / AREAS;

	/* Number of points we find in each area.
	 */
	const int len = points->nopoints / AREAS;

	int i;
	Rect area;

	/* Make sure we can read image.
	 */
	if( im_incheck( ref ) )
		return( -1 );
	if( ref->Bands != 1 || ref->BandFmt != IM_BANDFMT_UCHAR ) { 
		im_error( "im__lrcalcon", "%s", _( "not 1-band uchar image" ) );
		return( -1 );
	}

	/* Define bits to search for high-contrast areas. Need to be able to
	 * fit at least 1 window in.
	 */
	area.height = aheight;
	area.width = ref->Xsize;
	area.left = 0;
	area.top = 0;
	im_rect_marginadjust( &area, -border );
	area.width--;
	area.height--;

	/* Loop over areas, finding points.
	 */
	for( i = 0; area.top < ref->Ysize; area.top += aheight, i++ ) 
		if( im__find_best_contrast( ref, 
			area.left, area.top, area.width, area.height,
			points->x_reference + i*len,
			points->y_reference + i*len,
			points->contrast + i*len, 
			len,
			points->halfcorsize ) )
			return( -1 );

	return( 0 );
}
