/* im_label_regions.c
 *
 * 5/11/09
 *	- renamed from im_segment()
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

#include <vips/vips.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/**
 * im_label_regions:
 * @test: image to test
 * @mask: write labelled regions here
 * @segments: return number of regions here
 *
 * im_label_regions() repeatedly scans @test for regions of 4-connected pixels
 * with the same pixel value. Every time a region is discovered, those
 * pixels are marked in @mask with a unique serial number. Once all pixels
 * have been labelled, the operation returns, setting @segments to the number
 * of discrete regions which were detected.
 *
 * @mask is always a 1-band %IM_BANDFMT_UINT image of the same dimensions as
 * @test.
 *
 * This operation is useful for, for example, blob counting. You can use the
 * morphological operators to detect and isolate a series of objects, then use
 * im_label_regions() to number them all.
 *
 * Use im_histindexed() to (for example) find blob coordinates.
 *
 * See also: im_histindexed()
 *
 * Returns: 0 on success, -1 on error.
 */
int
im_label_regions( IMAGE *test, IMAGE *mask, int *segments )
{
	IMAGE *t[2];
	int serial;
	int *m;
	int x, y;

	/* Create the zero mask image.
	 */
	if( im_open_local_array( mask, t, 2, "im_label_regions", "p" ) ||
		im_black( t[0], test->Xsize, test->Ysize, 1 ) ||
		im_clip2fmt( t[0], t[1], IM_BANDFMT_INT ) ) 
		return( -1 );

	/* Search the mask image, flooding as we find zero pixels.
	 */
	if( im_rwcheck( t[1] ) )
		return( -1 );
	serial = 0;
	m = (int *) t[1]->data;
	for( y = 0; y < test->Ysize; y++ ) {
		for( x = 0; x < test->Xsize; x++ ) {
			if( !m[x] ) {
				/*
				if( im_flood_other_old( t[1], test, 
					x, y, serial ) )
				 */
				if( im_flood_other( test, t[1], 
					x, y, serial, NULL ) )
//				if( im_flood_other_old( t[1], test,
//					x, y, serial ) )
					return( -1 );

				serial += 1;
			}
		}

		m += test->Xsize;
	}

	/* Copy result to mask.
	 */
	if( im_copy( t[1], mask ) )
		return( -1 );
	if( segments )
		*segments = serial;

	return( 0 );
}
