/* @(#)  Function which calculates the coefficients between corresponding
 * @(#) points from reference and secondary images (probably from the scanner),
 * @(#) previously calculated using the functions im_calcon() and im_chpair()
 * @(#) It is assummed that a selection of the best(?) possible points has
 * @(#) been already carried out and that those nopoints points are in arrays
 * @(#) x1, y1 and x2, y2
 * @(#) No IMAGES are involved in this function and the calculated parameters
 * @(#) are returned in scale angle deltax and deltay of the TIE_POINTS struct.
 * @(#)
 * @(#) int im_clinear( points )
 * @(#) TIE_POINTS *points;
 * @(#) 
 * @(#) Returns 0 on sucess  and -1 on error.
 *
 * Copyright: 1990, N. Dessipris.
 *
 * Author: Nicos Dessipris
 * Written on: 20/12/1990
 * Modified on : 18/04/1991
 * 24/1/97 JC
 *	- tiny mem leak fixed
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

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

int 
im__clinear( TIE_POINTS *points )
{
	double **mat;  /* matrix mar[4][4] */
	double *g;	/* vector g[1][4] */
	double value;
	double sx1=0.0, sx1x1=0.0, sy1=0.0, sy1y1=0.0, sx1y1 = 0.0;
	double sx2x1=0.0, sx2y1=0.0, sx2=0.0, sy2=0.0, sy2y1=0.0, sy2x1=0.0;

	int i, j;
	int elms;
	double scale, angle, xdelta, ydelta;
	int *xref, *yref, *xsec, *ysec;
	double *dx, *dy, *dev;
        double resx, resy;

	xref = &points->x_reference[0];
	yref = &points->y_reference[0];
	xsec = &points->x_secondary[0];
	ysec = &points->y_secondary[0];
	dx = &points->dx[0];
	dy = &points->dy[0];
	dev = &points->deviation[0];
	elms = points->nopoints;

	if( !(mat = im_dmat_alloc( 0, 3, 0, 3 )) )
		return( -1 );
	if( !(g = im_dvector( 0, 3 )) ) {
		im_free_dmat( mat, 0, 3, 0, 3 );
		return( -1 );
	}

	resx = 0.0;
	resy = 0.0;
	for( i = 0; i < points->nopoints; i++ ) {
		sx1 += xref[i];
		sx1x1 += xref[i] * xref[i];
		sy1 += yref[i];
		sy1y1 += yref[i] * yref[i];
		sx1y1 += xref[i] * yref[i];
		sx2x1 += xsec[i] * xref[i];
		sx2y1 += xsec[i] * yref[i];
		sy2y1 += ysec[i] * yref[i];
		sy2x1 += ysec[i] * xref[i];
		sx2 += xsec[i];
		sy2 += ysec[i];
	}

	resx = fabs( sx1-sx2 )/points->nopoints;
	resy = fabs( sy1-sy2 )/points->nopoints;

	mat[0][0] = sx1x1 + sy1y1;
	mat[0][1] = 0;
	mat[0][2] = sx1;
	mat[0][3] = sy1;

	mat[1][0] = 0;
	mat[1][1] = sx1x1 + sy1y1;
	mat[1][2] = -sy1;
	mat[1][3] = sx1;

	mat[2][0] = sx1;
	mat[2][1] = -sy1;
	mat[2][2] = (double)elms;
	mat[2][3] = 0.0;

	mat[3][0] = sy1;
	mat[3][1] = sx1;
	mat[3][2] = 0.0;
	mat[3][3] = (double)elms;

	g[0] = sx2x1 + sy2y1;
	g[1] = -sx2y1 + sy2x1;
	g[2] = sx2;
	g[3] = sy2;

	if( im_invmat( mat, 4 ) ) {
		im_free_dmat( mat, 0, 3, 0, 3 );
		im_free_dvector( g, 0, 3 );
		im_error( "im_clinear", "%s", _( "im_invmat failed" ) ); 
		return( -1 );
	}
	
	scale = 0.0; angle = 0.0;
	xdelta = 0.0; ydelta = 0.0;

	for( j = 0; j < 4; j++ ) {
		scale += mat[0][j] * g[j];
		angle += mat[1][j] * g[j];
		xdelta += mat[2][j] * g[j];
		ydelta += mat[3][j] * g[j];
	}

	/* find the deviation of each point for the estimated variables
	 * if it greater than 1 then the solution is not good enough
	 * but this is handled by the main program 
	 */
	for( i = 0; i < points->nopoints; i++ ) {
		dx[i] = xsec[i] - 
			((scale * xref[i]) - (angle * yref[i]) + xdelta);

		dy[i] = ysec[i] - 
			((angle * xref[i]) + (scale * yref[i]) + ydelta);

		value = sqrt( dx[i]*dx[i] + dy[i]*dy[i] );
		dev[i] = value;
	}

	points->l_scale = scale;
	points->l_angle = angle;
	points->l_deltax = xdelta;
	points->l_deltay = ydelta;

	im_free_dmat( mat, 0, 3, 0, 3 );
	im_free_dvector( g, 0, 3 );

	return( 0 );
}
