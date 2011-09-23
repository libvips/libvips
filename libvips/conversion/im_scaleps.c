/* im_scaleps
 *
 * Copyright: 1990, N. Dessipris.
 *
 * Author: Nicos Dessipris
 * Written on: 02/05/1990
 * Modified on: 14/03/1991
 * 15/6/93 J.Cupitt
 *	- externs fixed
 *	- includes fixed
 * 13/2/95 JC
 *	- ANSIfied
 *	- cleaned up
 * 11/7/02 JC
 *	- rewritten ... got rid of the stuff for handling -ves, never used
 *	  (and was broken anyway)
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
#include <math.h>

#include <vips/vips.h>

/**
 * im_scaleps:
 * @in: input image
 * @out: output image
 *
 * Scale a power spectrum. Transform with log10(1.0 + pow(x, 0.25)) + .5, 
 * then scale so max == 255.
 *
 * See also: im_scale().
 *
 * Returns: 0 on success, -1 on error
 */
int 
im_scaleps( IMAGE *in, IMAGE *out )
{
	IMAGE *t[4];
	double mx;
	double scale;

	if( im_open_local_array( out, t, 4, "im_scaleps-1", "p" ) || 
		im_max( in, &mx ) )
		return( -1 );

	if( mx <= 0.0 ) 
		/* Range of zero: just return black.
		 */
		return( im_black( out, in->Xsize, in->Ysize, in->Bands ) );

	scale = 255.0 / log10( 1.0 + pow( mx, .25 ) );

	/* Transform!
	 */
	if( im_powtra( in, t[0], 0.25 ) ||
		im_lintra( 1.0, t[0], 1.0, t[1] ) ||
		im_log10tra( t[1], t[2] ) ||
		im_lintra( scale, t[2], 0.0, t[3] ) ||
		im_clip2fmt( t[3], out, IM_BANDFMT_UCHAR ) )
		return( -1 );

	return( 0 );
}

