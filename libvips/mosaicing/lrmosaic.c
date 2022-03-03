/* join left-right with an approximate overlap
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
 * 25/1/11
 * 	- gtk-doc
 * 	- remove balance stuff
 * 	- any mix of types and bands
 * 	- cleanups
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

/* Define for debug output.
#define DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <glib/gi18n-lib.h>

#include <stdio.h>
#include <string.h>

#include <vips/vips.h>
#include <vips/internal.h>

#include "pmosaicing.h"

#ifdef DEBUG
static void
vips__print_mdebug( TiePoints *points )
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
vips__find_lroverlap( VipsImage *ref_in, VipsImage *sec_in, VipsImage *out,
	int bandno_in, 
	int xref, int yref, int xsec, int ysec, 
	int halfcorrelation, int halfarea,
	int *dx0, int *dy0,
	double *scale1, double *angle1, double *dx1, double *dy1 )
{
	VipsImage **t = (VipsImage **)
		vips_object_local_array( VIPS_OBJECT( out ), 6 );

	VipsRect left, right, overlap;
	TiePoints points, *p_points;
	TiePoints newpoints, *p_newpoints;
	int i;
	int dx, dy;

	/* Test cor and area.
	 */
	if( halfcorrelation < 0 || halfarea < 0 || 
		halfarea < halfcorrelation ) {
		vips_error( "vips__lrmosaic", "%s", _( "bad area parameters" ) );
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
	vips_rect_intersectrect( &left, &right, &overlap );
	if( overlap.width < 2 * halfarea + 1 ||
		overlap.height < 2 * halfarea + 1 ) {
		vips_error( "vips__lrmosaic", 
			"%s", _( "overlap too small for search" ) );
		return( -1 );
	}

	/* Extract overlaps as 8-bit, 1 band.
	 */
	if( vips_extract_area( ref_in, &t[0],
			overlap.left, overlap.top, 
			overlap.width, overlap.height, NULL ) ||
		vips_extract_area( sec_in, &t[1], 
			overlap.left - right.left, overlap.top - right.top, 
			overlap.width, overlap.height, NULL ) )
		return( -1 );
	if( ref_in->Coding == VIPS_CODING_LABQ ) {
		if( vips_LabQ2sRGB( t[0], &t[2], NULL ) ||
			vips_LabQ2sRGB( t[1], &t[3], NULL ) ||
			vips_extract_band( t[2], &t[4], 1, NULL ) ||
			vips_extract_band( t[3], &t[5], 1, NULL ) )
			return( -1 );
	}
	else if( ref_in->Coding == VIPS_CODING_NONE ) {
		if( vips_extract_band( t[0], &t[2], bandno_in, NULL ) ||
			vips_extract_band( t[1], &t[3], bandno_in, NULL ) ||
			vips_scale( t[2], &t[4], NULL ) ||
			vips_scale( t[3], &t[5], NULL ) )
			return( -1 );
	}
	else {
		vips_error( "vips__lrmosaic", "%s", _( "unknown Coding type" ) );
		return( -1 );
	}

	/* Initialise and fill TiePoints 
	 */
	p_points = &points;
	p_newpoints = &newpoints;
	p_points->reference = ref_in->filename;
	p_points->secondary = sec_in->filename;
	p_points->nopoints = VIPS_MAXPOINTS;
	p_points->deltax = 0;
	p_points->deltay = 0;
	p_points->halfcorsize = halfcorrelation; 	
	p_points->halfareasize = halfarea;

	/* Initialise the structure 
	 */
	for( i = 0; i < VIPS_MAXPOINTS; i++ ) {
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
	if( vips__lrcalcon( t[4], p_points ) )
		return( -1 ); 

	/* For each candidate point, correlate against corresponding part of
	 * sec. Sets x,y_secondary and fills correlation and dx, dy.
 	 */
	if( vips__chkpair( t[4], t[5], p_points ) )
		return( -1 );

	/* First call to vips_clinear().
	 */
  	if( vips__initialize( p_points ) )
		return( -1 );

	/* Improve the selection of tiepoints until all abs(deviations) are 
	 * < 1.0 by deleting all wrong points.
 	 */
	if( vips__improve( p_points, p_newpoints ) )
		return( -1 );

	/* Average remaining offsets.
	 */
	if( vips__avgdxdy( p_newpoints, &dx, &dy ) )
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

int 
vips__lrmosaic( VipsImage *ref, VipsImage *sec, VipsImage *out, 
	int bandno, 
	int xref, int yref, int xsec, int ysec, 
	int hwindowsize, int hsearchsize,
	int mwidth )
{
	int dx0, dy0;
	double scale1, angle1, dx1, dy1;
	VipsImage *dummy;
	VipsImage *x;

	/* Correct overlap. dummy is just a placeholder used to ensure that
	 * memory used by the analysis phase is freed as soon as possible.
	 */
	dummy = vips_image_new();
	if( vips__find_lroverlap( ref, sec, dummy,
		bandno, 
		xref, yref, xsec, ysec,
		hwindowsize, hsearchsize,
		&dx0, &dy0,
		&scale1, &angle1, &dx1, &dy1 ) ) {
		g_object_unref( dummy );
		return( -1 );
	}
	g_object_unref( dummy );

	/* Merge left right.
	 */
	if( vips_merge( ref, sec, &x, VIPS_DIRECTION_HORIZONTAL, dx0, dy0, 
		"mblend", mwidth,
		NULL ) )
		return( -1 ); 
	if( vips_image_write( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}
