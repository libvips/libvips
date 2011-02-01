/* make an xy index image 
 *
 * 21/4/04
 *	- from im_grey
 * 1/2/11
 * 	- gtk-doc
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
#include <stdlib.h>
#include <math.h>

#include <vips/vips.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* Generate function.
 */
static int
make_xy_gen( REGION *or, void *seq, void *a, void *b )
{
	Rect *r = &or->valid;
	int le = r->left;
	int to = r->top;
	int ri = IM_RECT_RIGHT( r );
	int bo = IM_RECT_BOTTOM( r );

	int x, y;

	for( y = to; y < bo; y++ ) {
		unsigned int *q = (unsigned int *) IM_REGION_ADDR( or, le, y );

		for( x = le; x < ri; x++ ) {
			q[0] = x;
			q[1] = y;
			q += 2;
		}
	}

	return( 0 );
}

/**
 * im_make_xy:
 * @out: output image
 * @xsize: image size
 * @ysize: image size
 *
 * Create a two-band uint32 image where the elements in the first band have the
 * value of their x coordinate and elements in the second band have their y
 * coordinate. 
 *
 * You can make any image where the value of a pixel is a function of its (x,
 * y) coordinate by combining this operator with the arithmetic operators. 
 *
 * See also: im_grey(), im_identity().
 *
 * Returns: 0 on success, -1 on error
 */
int
im_make_xy( IMAGE *out, const int xsize, const int ysize )
{
	/* Check args.
	 */
	if( xsize <=0 || ysize <= 0 ) { 
		im_error( "im_make_xy", "%s", _( "bad size" ) ); 
		return( -1 ); 
	}
	if( im_poutcheck( out ) )
		return( -1 );

	/* Set image.
	 */
	im_initdesc( out, xsize, ysize, 2, IM_BBITS_INT, IM_BANDFMT_UINT, 
		IM_CODING_NONE, IM_TYPE_MULTIBAND, 1.0, 1.0, 0, 0 );

	/* Set hints - ANY is ok with us.
	 */
	if( im_demand_hint( out, IM_ANY, NULL ) )
		return( -1 );
	
	/* Generate image.
	 */
	if( im_generate( out, NULL, make_xy_gen, NULL, NULL, NULL ) )
		return( -1 );

	return( 0 );
}
