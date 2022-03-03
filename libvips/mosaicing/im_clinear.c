/* @(#)  Function which calculates the coefficients between corresponding
 * @(#) points from reference and secondary images (probably from the scanner),
 * @(#) previously calculated using the functions vips__{lr,bt}calcon() and vips_chpair()
 * @(#) It is assumed that a selection of the best(?) possible points has
 * @(#) been already carried out and that those nopoints points are in arrays
 * @(#) x1, y1 and x2, y2
 * @(#) No images are involved in this function and the calculated parameters
 * @(#) are returned in scale angle deltax and deltay of the TiePoints struct.
 * @(#)
 * @(#) int vips_clinear( points )
 * @(#) TiePoints *points;
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
 * 18/6/20 kleisauke
 * 	- convert to vips8
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
#include <glib/gi18n-lib.h>

#include <stdio.h>
#include <math.h>

#include <vips/vips.h>
#include <vips/internal.h>

#include "pmosaicing.h"

int 
vips__clinear( TiePoints *points )
{
	VipsImage *mat, *matinv;
	double *g;
	double value;
	double sx1 = 0.0, sx1x1 = 0.0, sy1 = 0.0, sy1y1 = 0.0;
	double sx2x1 = 0.0, sx2y1 = 0.0, sx2 = 0.0, sy2 = 0.0, sy2y1 = 0.0, sy2x1 = 0.0;

	int i, j;
	int elms;
	double scale, angle, xdelta, ydelta;
	int *xref, *yref, *xsec, *ysec;
	double *dx, *dy, *dev;

	xref = &points->x_reference[0];
	yref = &points->y_reference[0];
	xsec = &points->x_secondary[0];
	ysec = &points->y_secondary[0];
	dx = &points->dx[0];
	dy = &points->dy[0];
	dev = &points->deviation[0];
	elms = points->nopoints;

	if( !(mat = vips_image_new_matrix( 4, 4 )) )
		return( -1 );
	if( !(g = VIPS_ARRAY( NULL, 4, double )) ) {
		g_object_unref( mat );
		return( -1 );
	}

	for( i = 0; i < points->nopoints; i++ ) {
		sx1 += xref[i];
		sx1x1 += xref[i] * xref[i];
		sy1 += yref[i];
		sy1y1 += yref[i] * yref[i];
		sx2x1 += xsec[i] * xref[i];
		sx2y1 += xsec[i] * yref[i];
		sy2y1 += ysec[i] * yref[i];
		sy2x1 += ysec[i] * xref[i];
		sx2 += xsec[i];
		sy2 += ysec[i];
	}

	*VIPS_MATRIX( mat, 0, 0 ) = sx1x1 + sy1y1;
	*VIPS_MATRIX( mat, 1, 0 ) = 0;
	*VIPS_MATRIX( mat, 2, 0 ) = sx1;
	*VIPS_MATRIX( mat, 3, 0 ) = sy1;

	*VIPS_MATRIX( mat, 0, 1 ) = 0;
	*VIPS_MATRIX( mat, 1, 1 ) = sx1x1 + sy1y1;
	*VIPS_MATRIX( mat, 2, 1 ) = -sy1;
	*VIPS_MATRIX( mat, 3, 1 ) = sx1;

	*VIPS_MATRIX( mat, 0, 2 ) = sx1;
	*VIPS_MATRIX( mat, 1, 2 ) = -sy1;
	*VIPS_MATRIX( mat, 2, 2 ) = (double) elms;
	*VIPS_MATRIX( mat, 3, 2 ) = 0.0;

	*VIPS_MATRIX( mat, 0, 3 ) = sy1;
	*VIPS_MATRIX( mat, 1, 3 ) = sx1;
	*VIPS_MATRIX( mat, 2, 3 ) = 0.0;
	*VIPS_MATRIX( mat, 3, 3 ) = (double) elms;

	g[0] = sx2x1 + sy2y1;
	g[1] = -sx2y1 + sy2x1;
	g[2] = sx2;
	g[3] = sy2;

	if( vips_matrixinvert( mat, &matinv, NULL ) ) {
		g_object_unref( mat );
		g_free( g );
		vips_error( "vips_clinear", "%s", _( "vips_invmat failed" ) ); 
		return( -1 );
	}

	scale = 0.0; angle = 0.0;
	xdelta = 0.0; ydelta = 0.0;

	for( j = 0; j < 4; j++ ) {
		scale += *VIPS_MATRIX( matinv, j, 0 ) * g[j];
		angle += *VIPS_MATRIX( matinv, j, 1 ) * g[j];
		xdelta += *VIPS_MATRIX( matinv, j, 2 ) * g[j];
		ydelta += *VIPS_MATRIX( matinv, j, 3 ) * g[j];
	}

	g_object_unref( mat );
	g_object_unref( matinv );
	g_free( g );

	/* find the deviation of each point for the estimated variables
	 * if it greater than 1 then the solution is not good enough
	 * but this is handled by the main program 
	 */
	for( i = 0; i < points->nopoints; i++ ) {
		dx[i] = xsec[i] - 
			((scale * xref[i]) - (angle * yref[i]) + xdelta);

		dy[i] = ysec[i] - 
			((angle * xref[i]) + (scale * yref[i]) + ydelta);

		value = sqrt( dx[i] * dx[i] + dy[i] * dy[i] );
		dev[i] = value;
	}

	points->l_scale = scale;
	points->l_angle = angle;
	points->l_deltax = xdelta;
	points->l_deltay = ydelta;

	return( 0 );
}
