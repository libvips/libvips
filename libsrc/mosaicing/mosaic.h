/*!\file mosaic.h
 * \brief Local definitions used by the mosaicing program.
 *
 * If IM_MAXPOINTS change please ensure that it is still a multiple of
 * AREAS or else AREAS must change as well.  Initial setup is for
 * IM_MAXPOINTS = 60, AREAS = 3.
 *  
 * Copyright: 1990, 1991 N. Dessipris
 * @Author: Nicos Dessipris, K Martinez, J Cupitt
 * Written on: 07/11/1989
 * Modified on : 29/11/1989
 */

/*

    Copyright (C) 1991-2003 The National Gallery

    This program is free software; you can redistribute it and/or modify
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

#define IM_MAXPOINTS (60)	/* IM_MAXPOINTS % AREAS must be zero */
#define AREAS (3)	
/**
* mosaic struct used to define all the parameters
*/
typedef struct {
        char *reference;	/**< filename of reference image*/
        char *secondary;	/**< filename of secondary image*/
        int deltax;		/**< initial estimate of displacement */
        int deltay;		/**< initial estimate of displacement */
        int nopoints;   	/**< must be multiple of AREAS and <= IM_MAXPOINTS */
        int halfcorsize;	/**< half the correlation area size: recommended 5 */
        int halfareasize;	/**< recommended 8 */

	/** x, y_reference and contrast found by im_calcon() 
	 */
        int x_reference[IM_MAXPOINTS], y_reference[IM_MAXPOINTS]; 
        int contrast[IM_MAXPOINTS];

	/** x, y_secondary and correlation set by im_chkpair() 
	 */
        int x_secondary[IM_MAXPOINTS], y_secondary[IM_MAXPOINTS];

	/** returns the corrected best correlation
	 * as detected in 2*halfareasize+1
	 * centered at point (x2, y2) and using
	 * correlation area 2*halfareasize+1 
	 */
        double correlation[IM_MAXPOINTS];

	/** Coefficients calculated by im_clinear() 
	 */
	double l_scale, l_angle, l_deltax, l_deltay;

	/* used by im_clinear() 
	 */
        double dx[IM_MAXPOINTS], dy[IM_MAXPOINTS];
        double deviation[IM_MAXPOINTS];
} TIE_POINTS;

extern int im__chkpair( IMAGE *, IMAGE *, TIE_POINTS *point );
extern int im__initialize( TIE_POINTS *points );
extern int im__improve( TIE_POINTS *inpoints, TIE_POINTS *outpoints );
extern int im__avgdxdy( TIE_POINTS *points, int *dx, int *dy );
extern int im__lrcalcon( IMAGE *ref, TIE_POINTS *points );
extern int im__tbcalcon( IMAGE *ref, TIE_POINTS *points );
extern int im__coeff( int xr1, int yr1, int xs1, int ys1, 
	int xr2, int yr2, int xs2, int ys2, 
	double *a, double *b, double *dx, double *dy );
extern int im__clinear( TIE_POINTS *points );
extern int im__find_lroverlap( IMAGE *ref_in, IMAGE *sec_in, IMAGE *out,
	int bandno_in, 
	int xref, int yref, int xsec, int ysec, 
	int halfcorrelation, int halfarea,
	int *dx0, int *dy0,
	double *scale1, double *angle1, double *dx1, double *dy1 );
extern int im__find_tboverlap( IMAGE *ref_in, IMAGE *sec_in, IMAGE *out,
	int bandno_in, 
	int xref, int yref, int xsec, int ysec, 
	int halfcorrelation, int halfarea,
	int *dx0, int *dy0,
	double *scale1, double *angle1, double *dx1, double *dy1 );
