/* @(#)  Function which averages the difference x_secondary[] - x_reference[]
 * @(#) and y_secondary[] - y_reference[] of the structure points;
 * @(#)  The rounded integer result is returnd into dx, dy
 * @(#) No IMAGES are involved in this function.
 * @(#)
 * @(#) int im_avgdxdy( points, dx, dy )
 * @(#) TIE_POINTS *points;
 * @(#) int *dx, *dy;
 * @(#) 
 * @(#) Returns 0 on sucess  and -1 on error.
 *
 * Copyright: 1990, N. Dessipris.
 *
 * Author: Nicos Dessipris
 * Written on: 20/12/1990
 * Modified on : 18/04/1991
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

#include "mosaic.h"

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

int 
im__avgdxdy( TIE_POINTS *points, int *dx, int *dy )
{
	int sumdx, sumdy;
	int i;

	if( points->nopoints == 0 ) {
		im_errormsg( "im_avgdxdy: no points to average" );
		return( -1 );
	}

	/* Lots of points.
	 */
	sumdx = 0;
	sumdy = 0;
	for( i = 0; i < points->nopoints; i++ ) {
		sumdx += points->x_secondary[i] - points->x_reference[i];
		sumdy += points->y_secondary[i] - points->y_reference[i];
	}

	*dx =  IM_RINT( (double) sumdx / (double) points->nopoints );
	*dy =  IM_RINT( (double) sumdy / (double) points->nopoints );

	return( 0 );
}
