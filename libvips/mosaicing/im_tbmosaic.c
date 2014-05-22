/* join top-bottom with an approximate overlap
 *
 * Copyright: 1990, N. Dessipris.
 *
 * Author: Nicos Dessipris
 * Written on: 07/11/1989
 * Modified on : 29/11/1989, 18/04/1991
 * Modified and debugged by Ahmed Abbood . 1995
 * 14/6/95 JC
 *	- adapted for new balance ideas
 *	- more bug-fixes
 * 1/11/95 JC
 *	- frees memory used by analysis phase as soon as possible
 *	- means large mosaics use significantly less peak memory
 * 26/3/96 JC
 *	- now calls im_tbmerge() rather than im__tbmerge()
 * 30/7/97 JC
 * 	- im__find_tboverlap() returns 1st order params too
 * 2/2/01 JC
 *	- added tunable max blend width
 * 24/2/05
 *	- im_scale() makes it work for any image type
 * 25/1/11
 * 	- gtk-doc
 * 	- remove balance stuff
 * 	- any mix of types and bands
 * 	- cleanups
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
#include <string.h>

#include <vips/vips.h>
#include <vips/internal.h>

#include "mosaic.h"

int 
im__find_tboverlap( IMAGE *ref_in, IMAGE *sec_in, IMAGE *out,
	int bandno_in, 
	int xref, int yref, int xsec, int ysec, 
	int halfcorrelation, int halfarea,
	int *dx0, int *dy0,
	double *scale1, double *angle1, double *dx1, double *dy1 )
{
	Rect top, bottom, overlap;
	IMAGE *ref, *sec;
	IMAGE *t[6];
	TIE_POINTS points, *p_points;		/* defined in mosaic.h */
	TIE_POINTS newpoints, *p_newpoints;
	int i;
	int dx, dy;

	/* Test cor and area.
	 */
	if( halfcorrelation < 0 || halfarea < 0 || 
		halfarea < halfcorrelation ) {
		im_error( "im_tbmosaic", "%s", _( "bad area parameters" ) );
		return( -1 );
	}

	/* Set positions of top and bottom.
	 */
	top.left = 0;
	top.top = 0;
	top.width = ref_in->Xsize;
	top.height = ref_in->Ysize;
	bottom.left = xref - xsec;
	bottom.top = yref - ysec;
	bottom.width = sec_in->Xsize;
	bottom.height = sec_in->Ysize;

	/* Find overlap.
	 */
	im_rect_intersectrect( &top, &bottom, &overlap );
	if( overlap.width < 2 * halfarea + 1 ||
		overlap.height < 2 * halfarea + 1 ) {
		im_error( "im_tbmosaic", "%s", 
			_( "overlap too small for search" ) );
		return( -1 );
	}

	/* Extract overlaps as 8-bit, 1 band.
	 */
	if( !(ref = im_open_local( out, "temp_one", "t" )) ||
		!(sec = im_open_local( out, "temp_two", "t" )) ||
		im_open_local_array( out, t, 6, "im_tbmosaic", "p" ) ||
		im_extract_area( ref_in, t[0], 
			overlap.left, overlap.top, 
			overlap.width, overlap.height ) ||
		im_extract_area( sec_in, t[1], 
			overlap.left - bottom.left, overlap.top - bottom.top, 
			overlap.width, overlap.height ) )
		return( -1 );
	if( ref_in->Coding == IM_CODING_LABQ ) {
		if( im_LabQ2Lab( t[0], t[2] ) || 
			im_LabQ2Lab( t[1], t[3] ) ||
	    		im_Lab2disp( t[2], t[4], im_col_displays( 1 ) ) || 
			im_Lab2disp( t[3], t[5], im_col_displays( 1 ) ) ||
			im_extract_band( t[4], ref, 1 ) ||
			im_extract_band( t[5], sec, 1 ) )
			return( -1 );
	}
	else if( ref_in->Coding == IM_CODING_NONE ) {
		if( im_extract_band( t[0], t[2], bandno_in ) ||
			im_extract_band( t[1], t[3], bandno_in ) ||
			im_scale( t[2], ref ) ||
			im_scale( t[3], sec ) )
			return( -1 );
	}
	else {
		im_error( "im_tbmosaic", "%s", _( "unknown Coding type" ) );
		return( -1 );
	}

	/* Initialise and fill TIE_POINTS 
	 */
	p_points = &points;
	p_newpoints = &newpoints;
	p_points->reference = ref_in->filename;
	p_points->secondary = sec_in->filename;
	p_points->nopoints = IM_MAXPOINTS;
	p_points->deltax = 0;
	p_points->deltay = 0;
	p_points->halfcorsize = halfcorrelation; 	
	p_points->halfareasize = halfarea;

	/* Initialise the structure 
	 */
	for( i = 0; i < IM_MAXPOINTS; i++ ) {
		p_points->x_reference[i] = 0;
		p_points->y_reference[i] = 0;
		p_points->x_secondary[i] = 0;
		p_points->y_secondary[i] = 0;
		p_points->contrast[i] = 0;
		p_points->correlation[i] = 0.0;
		p_points->dx[i] = 0.0;
		p_points->dy[i] = 0.0;
		p_points->deviation[i] = 0.0;
	}

	/* Search ref for possible tie-points. Sets: p_points->contrast, 
	 * p_points->x,y_reference.
 	 */
	if( im__tbcalcon( ref, p_points ) )
		return( -1 ); 

	/* For each candidate point, correlate against corresponding part of
	 * sec. Sets x,y_secondary and fills correlation and dx, dy.
 	 */
	if( im__chkpair( ref, sec, p_points ) )
		return( -1 );

	/* First call to im_clinear().
	 */
  	if( im__initialize( p_points ) )
		return( -1 );

	/* Improve the selection of tiepoints until all abs(deviations) are 
	 * < 1.0 by deleting all wrong points.
 	 */
	if( im__improve( p_points, p_newpoints ) )
		return( -1 );

	/* Average remaining offsets.
	 */
	if( im__avgdxdy( p_newpoints, &dx, &dy ) )
		return( -1 );

	/* Offset with overlap position.
	 */
	*dx0 = -bottom.left + dx;
	*dy0 = -bottom.top + dy;

	/* Write 1st order parameters too.
	 */
	*scale1 = newpoints.l_scale;
	*angle1 = newpoints.l_angle;
	*dx1 = newpoints.l_deltax;
	*dy1 = newpoints.l_deltay;

	return( 0 );
}

int 
im_tbmosaic( IMAGE *ref, IMAGE *sec, IMAGE *out, 
	int bandno,
	int xref, int yref, int xsec, int ysec, 
	int hwindowsize, int hsearchsize,
	int balancetype,
	int mwidth )
{
	int dx0, dy0;
	double scale1, angle1, dx1, dy1;
	IMAGE *dummy;

	/* Correct overlap. dummy is just a placeholder used to ensure that
	 * memory used by the analysis phase is freed as soon as possible.
	 */
	if( !(dummy = im_open( "placeholder:1", "p" )) )
		return( -1 );
	if( im__find_tboverlap( ref, sec, dummy,
		bandno, 
		xref, yref, xsec, ysec,
		hwindowsize, hsearchsize,
		&dx0, &dy0,
		&scale1, &angle1, &dx1, &dy1 ) ) {
		im_close( dummy );
		return( -1 );
	}
	im_close( dummy );

	/* Merge top-bottom.
	 */
        if( im_tbmerge( ref, sec, out, dx0, dy0, mwidth ) )
		return( -1 ); 

	return( 0 );
}

