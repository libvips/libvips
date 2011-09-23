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

int 
im__initialize( TIE_POINTS *points )
{
	if( im__clinear( points ) ) {
		/* im_clinear failed! Set some sensible fallback values.
		 */
		int i, j;
		double xdelta, ydelta, max_cor;
		double a1, a2;

		int *xref = &points->x_reference[0];
		int *yref = &points->y_reference[0];
		int *xsec = &points->x_secondary[0];
		int *ysec = &points->y_secondary[0];

		double *corr = &points->correlation[0];
		double *dx = &points->dx[0];
		double *dy = &points->dy[0];

		int npt = points->nopoints;

		max_cor = 0.0;
		for( i = 0; i < npt; i++ )
			if( corr[i] > max_cor )
				max_cor = corr[i];

		max_cor = max_cor - 0.04;
		xdelta = 0.0;
		ydelta = 0.0;
		j = 0;
		for( i = 0; i < npt; i++ )
			if( corr[i] >= max_cor ) {
				xdelta += xsec[i] - xref[i];
				ydelta += ysec[i] - yref[i];
				++j;
			}

		xdelta = xdelta/j;
		ydelta = ydelta/j;
		for(i = 0; i < npt; i++ ) {
			dx[i] = (xsec[i] - xref[i]) - xdelta;
			dy[i] = (ysec[i] - yref[i]) - ydelta;
		}

		for( i = 0; i < npt; i++ ) {
			a1 = dx[i];
			a2 = dy[i];
			points->deviation[i] = sqrt( a1*a1 + a2*a2 );
		}	

		points->l_scale = 1.0;
		points->l_angle = 0.0;
		points->l_deltax = xdelta;
		points->l_deltay = ydelta;
	}

	return( 0 );
}
