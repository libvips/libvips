/* @(#)  Function which improves the selection of tiepoints carried out by 
 * @(#) im_clinear() until no points have deviation greater than 1 pixel
 * @(#) No reference or secondary images are involved
 * @(#) Function im_improve assumes that im_clinear has been applied on points
 * @(#) No IMAGES are involved in this function and the result is
 * @(#) returned in outpoints which is declared as a pointer in the
 * @(#) calling routine. Space for outpoints should be allocated in the calling 
 * @(#) routine
 * @(#)
 * @(#) int im_improve( inpoints, outpoints )
 * @(#) TIE_POINTS *inpoints, *outpoints;
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
#include <string.h>

#include <vips/vips.h>

#include "mosaic.h"

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

static void
copypoints( TIE_POINTS *pnew, TIE_POINTS *pold )
{
        int i;

        pnew->reference = pold->reference;
        pnew->secondary = pold->secondary;

        pnew->deltax = pold->deltax;
        pnew->deltay = pold->deltay;
        pnew->nopoints = pold->nopoints;
        pnew->halfcorsize = pold->halfcorsize;
	pnew->halfareasize = pold->halfareasize;

        for( i = 0; i < pold->nopoints; i++ ) {
		pnew->x_reference[i] = pold->x_reference[i];
		pnew->y_reference[i] = pold->y_reference[i];
		pnew->x_secondary[i] = pold->x_secondary[i];
		pnew->y_secondary[i] = pold->y_secondary[i];
		pnew->contrast[i] = pold->contrast[i];
		pnew->correlation[i] = pold->correlation[i];
		pnew->deviation[i] = pold->deviation[i];
		pnew->dx[i] = pold->dx[i];
		pnew->dy[i] = pold->dy[i];
	}

	pnew->l_scale = pold->l_scale;
	pnew->l_angle = pold->l_angle;
	pnew->l_deltax = pold->l_deltax;
	pnew->l_deltay = pold->l_deltay;
}

/* exclude all points with deviation greater or equal to 1.0 pixel
 */
static int
copydevpoints( TIE_POINTS *pnew, TIE_POINTS *pold )
{
        int i;
        int j;
	double thresh_dev,max_dev, min_dev;
	double *corr;

	min_dev = 9999.0;
	max_dev = 0.0;
	corr = &pold->correlation[0];

	for( i = 0; i < pold->nopoints; i++ )
		if( corr[i] > 0.01 ) { 
			if( pold->deviation[i]/corr[i] < min_dev )
				min_dev = pold->deviation[i]/corr[i] ;
			if( pold->deviation[i]/corr[i] > max_dev )
				max_dev = pold->deviation[i]/corr[i];
	        }

	thresh_dev = min_dev + (max_dev - min_dev)*0.3;
	if( thresh_dev <= 1.0 ) 
		thresh_dev = 1.0;

        for( i = 0, j = 0; i < pold->nopoints; i++ ) 
		if( pold->correlation[i] > 0.01 )
                	if( pold->deviation[i]/corr[i] <= thresh_dev ) {
				pnew->x_reference[j] = pold->x_reference[i];
				pnew->y_reference[j] = pold->y_reference[i];
				pnew->x_secondary[j] = pold->x_secondary[i];
				pnew->y_secondary[j] = pold->y_secondary[i];
				pnew->contrast[j] = pold->contrast[i];
				pnew->correlation[j] = pold->correlation[i];
				pnew->deviation[j] = pold->deviation[i];
				pnew->dx[j] = pold->dx[i];
				pnew->dy[j] = pold->dy[i];
				j++;
			}
        pnew->nopoints = j;

	for( i = j; i < IM_MAXPOINTS; i++ ) {
		pnew->x_reference[i] = 0;
		pnew->y_reference[i] = 0;
		pnew->x_secondary[i] = 0;
		pnew->y_secondary[i] = 0;
		pnew->contrast[i] = 0;
		pnew->correlation[i] = 0.0;
		pnew->deviation[i] = 0.0;
		pnew->dx[i] = 0.0;
		pnew->dy[i] = 0.0;
	}

	/* Return non-zero if we changed something.
	 */
	if( j != pold->nopoints )
		return( -1 );

	return( 0 );
}

#define SWAP( A, B ) { void *t = (A); A = B; B = t; }

int 
im__improve( TIE_POINTS *inpoints, TIE_POINTS *outpoints )
{
	TIE_POINTS points1, points2;
	TIE_POINTS *p = &points1;
	TIE_POINTS *q = &points2;

	/* p has the current state - make a new state, q, with only those
	 * points which have a small deviation.
	 */
	for( copypoints( p, inpoints ); 
		copypoints( q, p ), copydevpoints( q, p ); ) {
		/* If there are only a few left, jump out.
		 */
		if( q->nopoints < 2 )
			break;

		/* Fit the model to the new set of points.
		 */
		if( im__clinear( q ) )
			return( -1 );

		/* And loop.
		 */
		SWAP( p, q );
	}

	/* q has the output - copy to outpoints.
	 */
	copypoints( outpoints, q );

	return( 0 );
}
