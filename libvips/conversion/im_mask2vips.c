/* im_mask2vips
 *
 * Author: J.Cupitt
 * Written on: 6/6/94
 * Modified on:
 * 7/10/94 JC
 *	- new IM_ARRAY()
 * 1/2/10
 * 	- gtkdoc
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

#include <vips/vips.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/**
 * im_mask2vips:
 * @in: input mask
 * @out output image
 *
 * Write a one-band, #IM_BANDFMT_DOUBLE image to @out based on mask @in.
 *
 * See also: im_vips2mask().
 *
 * Returns: 0 on success, -1 on error
 */
int
im_mask2vips( DOUBLEMASK *in, IMAGE *out )
{
	int x, y;
	double *buf, *p, *q;

	/* Check the mask.
	 */
	if( !in || !in->coeff ) {
		im_error( "im_mask2vips", "%s", _( "bad input mask" ) );
		return( -1 );
	}

	/* Make the output image.
	 */
	im_initdesc( out, in->xsize, in->ysize, 1, 
		IM_BBITS_DOUBLE, IM_BANDFMT_DOUBLE, 
		IM_CODING_NONE, 
		IM_TYPE_B_W, 
		1.0, 1.0, 
		0, 0 );
	if( im_setupout( out ) )
		return( -1 );

	/* Make an output buffer.
	 */
	if( !(buf = IM_ARRAY( out, in->xsize, double )) )
		return( -1 );

	/* Write!
	 */
	for( p = in->coeff, y = 0; y < out->Ysize; y++ ) {
		q = buf;

		for( x = 0; x < out->Xsize; x++ )
			*q++ = *p++;

		if( im_writeline( y, out, (void *) buf ) )
			return( -1 );
	}

	return( 0 );
}

