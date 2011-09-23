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
 * @(#) To make the calculation faster set FACTOR to 1, 2 or 3
 * @(#)  Calculations are based on bandno only.
 * @(#)  The function uses functions im_calculate_contrast() 
 * @(#) which is in im_lrcalcon()
 * @(#)
 * @(#) int im_tbcalcon( ref, sec, bandno, points )
 * @(#) IMAGE *ref, *sec;
 * @(#) int bandno;
 * @(#) TIE_POINTS *points; 	see mosaic.h
 * @(#) 
 * @(#) Returns 0 on sucess  and -1 on error.
 *
 * Copyright: 1990, N. Dessipris.
 *
 * Author: Nicos Dessipris
 * Written on: 20/12/1990
 * Modified on : 18/04/1991
 * 8/7/93 JC
 *	- allow IM_CODING_LABQ coding
 *	- now calls im_incheck()
 * 12/7/95 JC
 *	- reworked
 *	- what a lot of horrible old code there was too
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
#include <math.h>

#include <vips/vips.h>
#include <vips/internal.h>

#include "mosaic.h"

int 
im__tbcalcon( IMAGE *ref, TIE_POINTS *points )
{
	/* Geometry: border we must leave around each area.
	 */
	const int border = points->halfareasize;

	/* Width of an area.
	 */
	const int awidth = ref->Xsize / AREAS;

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
		im_error( "im__tbcalcon", "%s", _( "help!" ) );
		return( -1 );
	}

	/* Define bits to search for high-contrast areas.
	 */
	area.width = awidth;
	area.height = ref->Ysize;
	area.left = 0;
	area.top = 0;
	im_rect_marginadjust( &area, -border );
	area.width--;
	area.height--;
	if( area.width < 0 || area.height < 0 ) {
		im_error( "im__tbcalcon", "%s", _( "overlap too small" ) );
		return( -1 );
	}

	/* Loop over areas, finding points.
	 */
	for( i = 0; area.left < ref->Xsize; area.left += awidth, i++ ) 
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
