/* @(#) Local definitions used by the mosaicing program 
 * @(#) If MAXPOINTS change please ensure that it is still a multiple of
 * @(#) AREAS or else AREAS must change as well.  Initial setup is for
 * @(#) MAXPOINTS = 60, AREAS = 3.
 * @(#) 
 * Copyright: 1990, 1991 N. Dessipris
 * Author: Nicos Dessipris
 * Written on: 07/11/1989
 * Modified on : 29/11/1989
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

#ifndef IM_MOSAIC_H
#define IM_MOSAIC_H

#define MAXPOINTS 60	/* MAXPOINTS % AREAS (in im_calcon) must be zero */

typedef struct {
        char *reference;	/* filename of reference */
        char *secondary;	/* filename of secondary */
        int deltax;		/* initial estimate of displacement */
        int deltay;		/* initial estimate of displacement */
        int nopoints;   	/* must be multiple of AREAS and <= MAXPOINTS */
        int halfcorsize;	/* recommended 5 */
        int halfareasize;	/* recommended 8 */

	/* x, y_reference and contrast found by im_calcon() 
	 */
        int x_reference[MAXPOINTS], y_reference[MAXPOINTS]; 
        int contrast[MAXPOINTS];

	/* x, y_secondary and correlation set by im_chkpair() 
	 */
        int x_secondary[MAXPOINTS], y_secondary[MAXPOINTS];

	/* returns the corrected best correlation
	 * as detected in 2*halfareasize+1
	 * centered at point (x2, y2) and using
	 * correlation area 2*halfareasize+1 
	 */
        double correlation[MAXPOINTS];

	/* Coefficients calculated by im_clinear() 
	 */
	double l_scale, l_angle, l_deltax, l_deltay;

	/* used by im_clinear() 
	 */
        double dx[MAXPOINTS], dy[MAXPOINTS];
        double deviation[MAXPOINTS];
} TIE_POINTS;

int im_clinear( TIE_POINTS *points );
int im__chkpair( IMAGE *, IMAGE *, TIE_POINTS *point );
int im__initialize( TIE_POINTS *points );
int im__improve( TIE_POINTS *inpoints, TIE_POINTS *outpoints );
int im__avgdxdy( TIE_POINTS *points, int *dx, int *dy );
int im__lrcalcon( IMAGE *ref, TIE_POINTS *points );
int im__tbcalcon( IMAGE *ref, TIE_POINTS *points );

#endif /*IM_MOSAIC_H*/
