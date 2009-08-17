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
measure_patches( IMAGE *im, double *coeff, IMAGE_BOX *box, 
	int h, int v, int *sel, int nsel )
{	
	IMAGE *tmp;
	int patch;
	IMAGE_BOX sub;
	int i, j;
	int m, n;
	double avg, dev;

	/* How large are the patches we are to measure?
	 */
	double pw = (double) box->xsize / (double) h;
	double ph = (double) box->ysize / (double) v;

	/* Set up sub to be the size we need for a patch.
	 */
	sub.xsize = (pw + 1) / 2;
	sub.ysize = (ph + 1) / 2;

	/* Loop through sel, picking out areas to measure.
	 */
	for( j = 0, patch = 0; patch < nsel; patch++ ) {
		/* Sanity check. Is the patch number sensible?
		 */
		if( sel[patch] <= 0 || sel[patch] > h*v ) {
			im_error( "im_measure", 
				_( "patch %d is out of range" ),
				sel[patch] );
			return( 1 );
		}

		/* Patch coordinates.
		 */
		m = (sel[patch] - 1) % h;  
		n = (sel[patch] - 1) / h;

		/* Move sub to correct position.
		 */
		sub.xstart = box->xstart + m*pw + (pw + 2)/4;
		sub.ystart = box->ystart + n*ph + (ph + 2)/4;

		/* Loop through bands.
		 */
		for( i = 0; i < im->Bands; i++, j++ ) {
			/* Make temp buffer to extract to.
			 */
			if( !(tmp = im_open( "patch", "t" )) ) 
				return( -1 );
			
			/* Extract and measure.
			 */
			sub.chsel = i;
			if( im_extract( im, tmp, &sub ) ||
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
			if( dev*5 > fabs( avg ) && fabs( avg ) > 3 )
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
 * im_measure:
 * @im: image to measure
 * @box: box containing chart
 * @h: patches across chart
 * @v: patches down chart
 * @sel: array of patch numbers to measure (numbered from 1 in row-major order)
 * @nsel: length of patch number array
 * @name: name to give to returned @DOUBLEMASK
 *
 * Analyse a grid of colour patches, producing a #DOUBLEMASK of patch averages.
 * The operations issues a warning if any patch has a deviation more than 20% of
 * the mean. Only the central 50% of each patch is averaged.
 *
 * Example: 6 band image of 4x2 block of colour patches.
 * 
 *	+---+---+---+---+
 *	| 1 | 2 | 3 | 4 |
 *	+---+---+---+---+
 *	| 5 | 6 | 7 | 8 |
 *	+---+---+---+---+
 *
 * Then call im_measure( im, box, 4, 2, { 2, 4 }, 2, "fred" ) makes a mask
 * "fred" which has 6 columns, two rows. The first row contains the averages
 * for patch 2, the second for patch 4.
 *
 * Returns: #DOUBLEMASK with a row for each selected patch, a column for each
 * image band. 
 *
 * Related: im_avg(), im_deviate(), im_stats().
 */
DOUBLEMASK *
im_measure( IMAGE *im, IMAGE_BOX *box, int h, int v, 
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
			!(mask = im_measure( t1, 
				box, h, v, sel, nsel, name )) ) {
			im_close( t1 );
			return( NULL );
		}

		im_close( t1 );

		return( mask );
	}

	if( im->Coding != IM_CODING_NONE ) {
		im_error( "im_measure", "%s", _( "not uncoded" ) );
		return( NULL );
	}
	if( im_iscomplex( im ) ) {
		im_error( "im_measure", "%s", _( "bad input type" ) );
		return( NULL );
	}

	/* What size mask do we need?
	 */
	if( !(mask = im_create_dmask( name, im->Bands, nsel )) )
		return( NULL );

	/* Perform measure and return.
	 */
	if( measure_patches( im, mask->coeff, box, h, v, sel, nsel ) ) {
		im_free_dmask( mask );
		return( NULL );
	}

	return( mask );
}
