/* Turn XYZ to Yxy colourspace. 
 *
 * Modified:
 * 29/5/02 JC
 *	- from lab2xyz
 * 2/11/09
 * 	- gtkdoc
 * 	- cleanups
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
#include <vips/internal.h>

/* Process a buffer of data.
 */
void
imb_XYZ2Yxy( float *p, float *q, int n )
{
	int i;

	for( i = 0; i < n; i++ ) {
		float X = p[0];
		float Y = p[1];
		float Z = p[2];
		double total = X + Y + Z;

		float x, y;

		p += 3;

	        x = X / total;
		y = Y / total;

		q[0] = Y;
		q[1] = x;
		q[2] = y;
		q += 3;
	}
}

/**
 * im_XYZ2Yxy:
 * @in: input image
 * @out: output image
 *
 * Turn XYZ to Yxy.
 *
 * Returns: 0 on success, -1 on error.
 */
int 
im_XYZ2Yxy( IMAGE *in, IMAGE *out )
{	
	return( im__colour_unary( "im_XYZ2Yxy", in, out, IM_TYPE_YXY,
		(im_wrapone_fn) imb_XYZ2Yxy, NULL, NULL ) );
}

