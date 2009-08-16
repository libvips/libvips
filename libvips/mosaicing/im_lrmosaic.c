/* @(#)  Program to calculate the best possible tie points
 * @(#) in the overlapping part between the primary and the secondary picture
 * @(#)
 * @(#)  Right call:
 * @(#)  int im_lrmosaic( reference, secondary, out, bandno, 
 * @(#)      xref, yref, xsec, ysec, halfcorrelation, halfarea )
 * @(#)  IMAGE *reference, *secondary, *out;
 * @(#)  int bandno;
 * @(#)  int xref, yref, xsec, ysec;
 * @(#)  int halfcorrelation, halfarea;
 * @(#)  
 * @(#)  Returns 0 on success and -1 on error
 * @(#)  
 *
 * Copyright: 1990, N. Dessipris.
 *
 * Author: Nicos Dessipris
 * Written on: 07/11/1989
 * Modified on : 29/11/1989, 18/04/1991
 *
 *
 * Modified and debugged by Ahmed Abbood . 1995
 * 14/6/95 JC
 *	- rewritten for new balance ideas
 *	- more bug-fixes
 * 1/11/95 JC
 *	- frees memory used by analysis phase as soon as possible
 *	- means large mosaics use significantly less peak memory
 * 26/3/96 JC
 *	- now calls im_lrmerge() rather than im__lrmerge()
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

#include "mosaic.h"

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

#ifdef DEBUG
static void
im__print_mdebug( TIE_POINTS *points )
{
	int i;
	double adx = 0.0;
	double ady = 0.0;
	double acor = 0.0;

	for( i = 0; i < points->nopoints; i++ ) {
		adx += points->dx[i];
		ady += points->dy[i];
		acor += points->correlation[i];
	}
	adx = adx / (double) points->nopoints;
	ady = ady / (double) points->nopoints;
	acor = acor / (double) points->nopoints;

	printf( "points: %d\n", points->nopoints );
	printf( "average dx, dy: %g %g\n", adx, ady );
	printf( "average correlation: %g\n", acor );
	printf( "deltax, deltay: %g %g\n", points->l_deltax, points->l_deltay );
}
#endif /*DEBUG*/

int 
im__find_lroverlap( IMAGE *ref_in, IMAGE *sec_in, IMAGE *out,
	int bandno_in, 
	int xref, int yref, int xsec, int ysec, 
	int halfcorrelation, int halfarea,
	int *dx0, int *dy0,
	double *scale1, double *angle1, double *dx1, double *dy1 )
{
	IMAGE *ref, *sec;
	TIE_POINTS points, *p_points;
	TIE_POINTS newpoints, *p_newpoints;
	int dx, dy;
	int i;

	Rect left, right, overlap;

	/* Check ref and sec are compatible.
	 */
	if( ref_in->Bands != sec_in->Bands || 
		ref_in->BandFmt != sec_in->BandFmt ||
		ref_in->Coding != sec_in->Coding ) {
		im_errormsg( "im_lrmosaic: input images incompatible" );
		return( -1 );
	}

	/* Test cor and area.
	 */
	if( halfcorrelation < 0 || halfarea < 0 || 
		halfarea < halfcorrelation ) {
		im_errormsg( "im_lrmosaic: bad area parameters" );
		return( -1 );
	}

	/* Set positions of left and right.
	 */
	left.left = 0;
	left.top = 0;
	left.width = ref_in->Xsize;
	left.height = ref_in->Ysize;
	right.left = xref - xsec;
	right.top = yref - ysec;
	right.width = sec_in->Xsize;
	right.height = sec_in->Ysize;

	/* Find overlap.
	 */
	im_rect_intersectrect( &left, &right, &overlap );
	if( overlap.width < 2*halfarea + 1 ||
		overlap.height < 2*halfarea + 1 ) {
		im_errormsg( "im_lrmosaic: overlap too small for search" );
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
			overlap.left - right.left, overlap.top - right.top, 
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
			overlap.left - right.left, overlap.top - right.top, 
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
		im_errormsg( "im_lrmosaic: unknown Coding type" );
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
	if( im__lrcalcon( ref, p_points ) )
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
	*dx0 = -right.left + dx;
	*dy0 = -right.top + dy;

	/* Write 1st order parameters too.
	 */
	*scale1 = newpoints.l_scale;
	*angle1 = newpoints.l_angle;
	*dx1 = newpoints.l_deltax;
	*dy1 = newpoints.l_deltay;

	return( 0 );
}

/* Scale im by fac with a lut.
 */
static IMAGE *
transform( IMAGE *out, IMAGE *im, double fac )
{
	IMAGE *t1 = im_open_local( out, "transform:1", "p" );
	IMAGE *t2 = im_open_local( out, "transform:2", "p" );
	IMAGE *t3 = im_open_local( out, "transform:3", "p" );
	IMAGE *t4 = im_open_local( out, "transform:4", "p" );

	if( !t1 || !t2 || !t3 || !t4 )
		return( NULL );

	if( fac == 1.0 )
		/* Easy!
		 */
		return( im );

	if( im_identity( t1, 1 ) || 
		im_lintra( fac, t1, 0.0, t2 ) ||
		im_clip( t2, t3 ) ||
		im_maplut( im, t4, t3 ) )
		return( NULL );

	return( t4 );
}

/* Balance two images. dx, dy parameters as for im_??merge, etc.
 */
int 
im__balance( IMAGE *ref, IMAGE *sec, IMAGE *out,
	IMAGE **ref_out, IMAGE **sec_out, int dx, int dy, int balancetype )
{
	double lavg, ravg;
	double lfac, rfac;
	Rect left, right, overlap;
	IMAGE *t1, *t2;

	/* Test balancetype.
	 */
	if( balancetype < 0 || balancetype > 3 ) {
		im_errormsg( "im_mosaic: bad balancetype parameter" );
		return( -1 );
	}

	/* No balance - easy!
	 */
	if( balancetype == 0 ) {
		*ref_out = ref;
		*sec_out = sec;

		return( 0 );
	}

	/* Must be uchar uncoded.
	 */
	if( ref->Coding != IM_CODING_NONE || 
		ref->BandFmt != IM_BANDFMT_UCHAR ) {
		im_errormsg( "im_mosaic: uncoded uchar only for balancing" );
		return( -1 );
	}

	/* Set positions of left and right.
	 */
	left.left = 0;
	left.top = 0;
	left.width = ref->Xsize;
	left.height = ref->Ysize;
	right.left = -dx;
	right.top = -dy;
	right.width = sec->Xsize;
	right.height = sec->Ysize;

	/* Find overlap.
	 */
	im_rect_intersectrect( &left, &right, &overlap );

	/* Extract overlaps.
	 */
	t1 = im_open_local( out, "temp_one", "p" );
	t2 = im_open_local( out, "temp_two", "p" );
	if( !t1 || !t2 )
		return( -1 );

	if( im_extract_area( ref, t1, 
		overlap.left, overlap.top, 
		overlap.width, overlap.height ) )
		return( -1 );
	if( im_extract_area( sec, t2, 
		overlap.left - right.left, overlap.top - right.top, 
		overlap.width, overlap.height ) )
		return( -1 );

	/* And find the average.
	 */
	if( im_avg( t1, &lavg ) || im_avg( t2, &ravg ) )
		return( -1 );

	/* Compute scale factors.
	 */
	switch( balancetype ) {
	case 1:
		/* Ajust left.
		 */
		rfac = 1.0;
		lfac = ravg / lavg;
		break;

	case 2:
		/* Adjust right.
		 */
		lfac = 1.0;
		rfac = lavg / ravg;
		break;

	case 3:
		{
			/* Adjust both to weighted average.
			 */
			double ltot = (double) ref->Xsize * ref->Ysize;
			double rtot = (double) sec->Xsize * sec->Ysize;
			double rat = ltot / (ltot + rtot);
			double navg = rat * (lavg - ravg) + ravg;

			lfac = navg / lavg;
			rfac = navg / ravg;
		}
		break;
	
	default:
		error_exit( "internal error #897624395" );
		return( -1 );
	}

	/* Transform the left and right images.
	 */
	if( !(*ref_out = transform( out, ref, lfac )) )
		return( -1 );
	if( !(*sec_out = transform( out, sec, rfac )) )
		return( -1 );

	return( 0 );
}

int 
im_lrmosaic( IMAGE *ref, IMAGE *sec, IMAGE *out, 
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
	if( im__find_lroverlap( ref, sec, dummy,
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

	/* Merge left right.
	 */
        if( im_lrmerge( ref2, sec2, out, dx0, dy0, mwidth ) )
		return( -1 ); 

	return( 0 );
}
