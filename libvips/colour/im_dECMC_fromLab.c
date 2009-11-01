/* im_dECMC_fromLab.c
 *
 * 5/8/98 JC
 *	- oops, wasn't testing input args correctly
 * 30/10/09
 * 	- use im__colour_binary()
 * 	- gtkdoc comment
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

#include <vips/vips.h>
#include <vips/internal.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* Process a buffer.
 */
void
imb_dECMC_fromLab( float **p, float *q, int n )
{
	float *p1 = p[0];
	float *p2 = p[1];
	int x;

	for( x = 0; x < n; x++ ) {
		float L1 = p1[0];
		float a1 = p1[1];
		float b1 = p1[2];
		float L2 = p2[0];
		float a2 = p2[1];
		float b2 = p2[2];

		p1 += 3;
		p2 += 3;

		q[x] = im_col_dECMC( L1, a1, b1, L2, a2, b2 );
	}
}

/**
 * im_dECMC_fromLab:
 * @in1: first input image
 * @in2: second input image
 * @out: output image
 *
 * Calculate dE CMC from two Lab images.
 *
 * Returns: 0 on success, -1 on error.
 */
int 
im_dECMC_fromLab( IMAGE *in1, IMAGE *in2, IMAGE *out )
{
	return( im__colour_difference( "im_dECMC_fromLab",
		in1, in2, out, 
		(im_wrapmany_fn) imb_dECMC_fromLab, NULL, NULL ) );
}
