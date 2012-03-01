/* im_measure.c
 *
 * Modified: 
 * 19/8/94 JC
 *	- now uses doubles for addressing
 *	- could miss by up to h pixels previously!
 *	- ANSIfied
 *	- now issues warning if any deviations are greater than 20% of the
 *	  mean
 * 31/10/95 JC
 *	- more careful about warning for averages <0, or averages near zero
 *	- can get these cases with im_measure() of IM_TYPE_LAB images
 * 28/10/02 JC
 *	- number bands from zero in error messages
 * 7/7/04
 *	- works on labq
 * 18/8/08
 * 	- add gtkdoc comments
 * 	- remove deprecated im_extract()
 * 30/11/09
 * 	- changes for im_extract() broke averaging
 * 9/11/11
 * 	- moved to deprecated, the new VipsMeasure does not have the
 * 	  select-patches thing, so we have to keep this around
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

/* Measure into array.
 */
static int
measure_patches( IMAGE *im, double *coeff, 
	int left, int top, int width, int height, 
	int u, int v, int *sel, int nsel )
{	
	IMAGE *tmp;
	int patch;
	int i, j;
	int m, n;
	double avg, dev;
	int x, y, w, h;

	/* How large are the patches we are to measure?
	 */
	double pw = (double) width / (double) u;
	double ph = (double) height / (double) v;

	/* Set up sub to be the size we need for a patch.
	 */
	w = (pw + 1) / 2;
	h = (ph + 1) / 2;

	/* Loop through sel, picking out areas to measure.
	 */
	for( j = 0, patch = 0; patch < nsel; patch++ ) {
		/* Sanity check. Is the patch number sensible?
		 */
		if( sel[patch] <= 0 || sel[patch] > u * v ) {
			im_error( "im_measure", 
				_( "patch %d is out of range" ),
				sel[patch] );
			return( 1 );
		}

		/* Patch coordinates.
		 */
		m = (sel[patch] - 1) % u;  
		n = (sel[patch] - 1) / u;

		/* Move sub to correct position.
		 */
		x = left + m * pw + (pw + 2) / 4;
		y = top + n * ph + (ph + 2) / 4;

		/* Loop through bands.
		 */
		for( i = 0; i < im->Bands; i++, j++ ) {
			/* Make temp buffer to extract to.
			 */
			if( !(tmp = im_open( "patch", "t" )) ) 
				return( -1 );
			
			/* Extract and measure.
			 */
			if( im_extract_areabands( im, tmp, x, y, w, h, i, 1 ) ||
				im_avg( tmp, &avg ) ||
				im_deviate( tmp, &dev ) ) {
				im_close( tmp );
				return( -1 );
			}
			im_close( tmp );

			/* Is the deviation large compared with the average?
			 * This could be a clue that our parameters have
			 * caused us to miss the patch. Look out for averages
			 * <0, or averages near zero (can get these if use
			 * im_measure() on IM_TYPE_LAB images).
			 */
			if( dev * 5 > fabs( avg ) && fabs( avg ) > 3 )
				im_warn( "im_measure",
					_( "patch %d, band %d: "
						"avg = %g, sdev = %g" ), 
					patch, i, avg, dev );

			/* Save results.
			 */
			coeff[j] = avg;
		}
	}

	return( 0 );
}

static DOUBLEMASK *
internal_im_measure_area( IMAGE *im, 
	int left, int top, int width, int height, 
	int u, int v, 
	int *sel, int nsel, const char *name )
{	
	DOUBLEMASK *mask;

	if( im_check_uncoded( "im_measure", im ) ||
		im_check_noncomplex( "im_measure", im ) )
		return( NULL );

	/* Default to all patches if sel == NULL.
	 */
	if( sel == NULL ) {
		int i;

		nsel = u * v;
		if( !(sel = IM_ARRAY( im, nsel, int )) )
			return( NULL );
		for( i = 0; i < nsel; i++ )
			sel[i] = i + 1;
	}

	/* What size mask do we need?
	 */
	if( !(mask = im_create_dmask( name, im->Bands, nsel )) )
		return( NULL );

	/* Perform measure and return.
	 */
	if( measure_patches( im, mask->coeff, left, top, width, height, 
		u, v, sel, nsel ) ) {
		im_free_dmask( mask );
		return( NULL );
	}

	return( mask );
}

DOUBLEMASK *
im_measure_area( IMAGE *im, 
	int left, int top, int width, int height, 
	int u, int v, 
	int *sel, int nsel, const char *name )
{
	DOUBLEMASK *mask;
	VipsImage *t;

	/* The old im_measure() worked on labq.
	 */
	if( im->Coding == IM_CODING_LABQ ) {
		if( !(t = im_open( "measure-temp", "p" )) )
			return( NULL );
		if( im_LabQ2Lab( im, t ) ||
			!(mask = im_measure_area( t, 
				left, top, width, height,
				u, v, 
				sel, nsel, name )) ) {
			g_object_unref( t );
			return( NULL );
		}
		g_object_unref( t );

		return( mask );
	}

	if( sel )
		return( internal_im_measure_area( im, 
			left, top, width, height, u, v, sel, nsel, name ) );
	else {
		if( vips_measure( im, &t, u, v, 
			"left", left,
			"top", top,
			"width", width,
			"height", height,
			NULL ) )
			return( NULL );
		if( !(mask = im_vips2mask( t, name )) ) {
			g_object_unref( t );
			return( NULL );
		}
		g_object_unref( t );

		return( mask );
	}
}
