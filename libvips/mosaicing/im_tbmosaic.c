/* @(#)  Program to calculate the best possible tie points
 * @(#) in the overlapping part between the primary and the secondary picture
 * @(#)
 * @(#)  Right call:
 * @(#)  int im_tbmosaic( reference, secondary, out, bandno,
 * @(#)      xref, yref, xsec, ysec, halfcorrelation, halfarea, balancetype )
 * @(#)  IMAGE *reference, *secondary, *out;
 * @(#)  int bandno;
 * @(#)  int xref, yref, xsec, ysec;
 * @(#)  int halfcorrelation, halfarea;
 * @(#)  int balancetype;
 * @(#)  
 * @(#)  Returns 0 on success and -1 on error
 * @(#)  
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
#include <string.h>

#include <vips/vips.h>
#include <vips/internal.h>

#include "mosaic.h"

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

int 
im__find_tboverlap( IMAGE *ref_in, IMAGE *sec_in, IMAGE *out,
	int bandno_in, 
	int xref, int yref, int xsec, int ysec, 
	int halfcorrelation, int halfarea,
	int *dx0, int *dy0,
	double *scale1, double *angle1, double *dx1, double *dy1 )
{
	IMAGE *ref, *sec;
	TIE_POINTS points, *p_points;		/* defined in mosaic.h */
	TIE_POINTS newpoints, *p_newpoints;
	int i;
	int dx, dy;

	Rect top, bottom, overlap;

	/* Check ref and sec are compatible.
	 */
	if( ref_in->Bands != sec_in->Bands || 
		ref_in->BandFmt != sec_in->BandFmt ||
		ref_in->Coding != sec_in->Coding ) {
		im_error( "im_tbmosaic", "%s", _( "input images incompatible" ) );
		return( -1 );
	}

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
	if( overlap.width < 2*halfarea + 1 ||
		overlap.height < 2*halfarea + 1 ) {
		im_error( "im_tbmosaic", "%s", _( "overlap too small for search" ) );
		return( -1 );
	}

	/* Extract overlaps.
	 */
	ref = im_open_local( out, "temp_one", "t" );
	sec = im_open_local( out, "temp_two", "t" );
	if( !ref || !sec )
		return( -1 );
	if( ref_in->Coding == IM_CODING_LABQ ) {
		IMAGE *t1 = im_open_local( out, "temp:3", "p" );
		IMAGE *t2 = im_open_local( out, "temp:4", "p" );
		IMAGE *t3 = im_open_local( out, "temp:5", "p" );
		IMAGE *t4 = im_open_local( out, "temp:6", "p" );
		IMAGE *t5 = im_open_local( out, "temp:7", "p" );
		IMAGE *t6 = im_open_local( out, "temp:8", "p" );

		if( !t1 || !t2 || !t3 || !t4 || !t5 || !t6 )
			return( -1 );
		if( im_extract_area( ref_in, t1, 
			overlap.left, overlap.top, 
			overlap.width, overlap.height ) )
			return( -1 );
		if( im_extract_area( sec_in, t2, 
			overlap.left - bottom.left, overlap.top - bottom.top, 
			overlap.width, overlap.height ) )
			return( -1 );
		if( im_LabQ2Lab( t1, t3 ) || im_LabQ2Lab( t2, t4 ) ||
	    		im_Lab2disp( t3, t5, im_col_displays( 1 ) ) || 
			im_Lab2disp( t4, t6, im_col_displays( 1 ) ) )
			return( -1 );
		
		/* Extract the green.
		 */
		if( im_extract_band( t5, ref, 1 ) ||
			im_extract_band( t6, sec, 1 ) )
			return( -1 );
	}
	else if( ref_in->Coding == IM_CODING_NONE ) {
		IMAGE *t1 = im_open_local( out, "temp:9", "p" );
		IMAGE *t2 = im_open_local( out, "temp:10", "p" );
		IMAGE *t3 = im_open_local( out, "temp:11", "p" );
		IMAGE *t4 = im_open_local( out, "temp:12", "p" );

		if( !t1 || !t2 || !t3 || !t4 )
			return( -1 );
		if( im_extract_area( ref_in, t1, 
			overlap.left, overlap.top, 
			overlap.width, overlap.height ) )
			return( -1 );
		if( im_extract_area( sec_in, t2, 
			overlap.left - bottom.left, overlap.top - bottom.top, 
			overlap.width, overlap.height ) )
			return( -1 );
		if( im_extract_band( t1, t3, bandno_in ) ||
			im_extract_band( t2, t4, bandno_in ) )
			return( -1 );
		if( im_scale( t3, ref ) ||
			im_scale( t4, sec ) )
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
	int halfcorrelation, int halfarea,
	int balancetype,
	int mwidth )
{
	int dx0, dy0;
	double scale1, angle1, dx1, dy1;
	IMAGE *ref2, *sec2;
	IMAGE *dummy;

	/* Correct overlap. dummy is just a placeholder used to ensure that
	 * memory used by the analysis phase is freed as soon as possible.
	 */
	if( !(dummy = im_open( "placeholder:1", "p" )) )
		return( -1 );
	if( im__find_tboverlap( ref, sec, dummy,
		bandno, 
		xref, yref, xsec, ysec,
		halfcorrelation, halfarea,
		&dx0, &dy0,
		&scale1, &angle1, &dx1, &dy1 ) ) {
		im_close( dummy );
		return( -1 );
	}
	im_close( dummy );

	/* Balance.
	 */
	if( im__balance( ref, sec, out,
		&ref2, &sec2,
		dx0, dy0, balancetype ) )
		return( -1 );

	/* Merge top-bottom.
	 */
        if( im_tbmerge( ref2, sec2, out, dx0, dy0, mwidth ) )
		return( -1 ); 

	return( 0 );
}

