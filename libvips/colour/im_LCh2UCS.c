/* im_LCh2UCS
 *
 * Modified:
 * 2/11/09
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
#include <math.h>

#include <vips/vips.h>
#include <vips/internal.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* Our main loop.
 */
void
imb_LCh2UCS( float *p, float *q, int n )
{
	int x;

	for( x = 0; x < n; x++ ) {
		float L = p[0];
		float C = p[1];
		float h = p[2];
		p += 3;

		/* Turn to UCS.
		 */
		q[0] = im_col_L2Lucs( L );
		q[1] = im_col_C2Cucs( C );
		q[2] = im_col_Ch2hucs( C, h );
		q += 3;
	}
}

/**
 * im_LCh2UCS:
 * @in: input image
 * @out: output image
 *
 * Turn LCh to UCS.
 *
 * Returns: 0 on success, -1 on error.
 */
int 
im_LCh2UCS( IMAGE *in, IMAGE *out )
{	
	return( im__colour_unary( "im_LCh2UCS", in, out, IM_TYPE_UCS,
		(im_wrapone_fn) imb_LCh2UCS, NULL, NULL ) );
}
