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

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

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

/**
 * im_measure_area:
 * @im: image to measure
 * @left: area of image containing chart
 * @top: area of image containing chart
 * @width: area of image containing chart
 * @height: area of image containing chart
 * @h: patches across chart
 * @v: patches down chart
 * @sel: array of patch numbers to measure (numbered from 1 in row-major order)
 * @nsel: length of patch number array
 * @name: name to give to returned @DOUBLEMASK
 *
 * Analyse a grid of colour patches, producing a #DOUBLEMASK of patch averages.
 * The mask has a row for each measured patch, and a column for each image
 * band. The operations issues a warning if any patch has a deviation more 
 * than 20% of
 * the mean. Only the central 50% of each patch is averaged. If @sel is %NULL
 * then all patches are measured.
 *
 * Example: 6 band image of 4x2 block of colour patches.
 *
 * <tgroup cols='4' align='left' colsep='1' rowsep='1'>
 *   <tbody>
 *     <row>
 *       <entry>1</entry>
 *       <entry>2</entry>
 *       <entry>3</entry>
 *       <entry>4</entry>
 *     </row>
 *     <row>
 *       <entry>5</entry>
 *       <entry>6</entry>
 *       <entry>7</entry>
 *       <entry>8</entry>
 *     </row>
 *   </tbody>
 * </tgroup>
 *
 * Then call im_measure( im, box, 4, 2, { 2, 4 }, 2, "fred" ) makes a mask
 * "fred" which has 6 columns, two rows. The first row contains the averages
 * for patch 2, the second for patch 4.
 *
 * See also: im_avg(), im_deviate(), im_stats().
 * 
 * Returns: #DOUBLEMASK of measurements.
 */
DOUBLEMASK *
im_measure_area( IMAGE *im, 
	int left, int top, int width, int height, 
	int u, int v, 
	int *sel, int nsel, const char *name )
{	
	DOUBLEMASK *mask;

	/* Check input image.
	 */
	if( im->Coding == IM_CODING_LABQ ) {
		IMAGE *t1;
		
		if( !(t1 = im_open( "measure-temp", "p" )) )
			return( NULL );
		if( im_LabQ2Lab( im, t1 ) ||
			!(mask = im_measure_area( t1, 
				left, top, width, height,
				u, v, 
				sel, nsel, name )) ) {
			im_close( t1 );
			return( NULL );
		}

		im_close( t1 );

		return( mask );
	}

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
