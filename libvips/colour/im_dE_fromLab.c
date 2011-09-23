/* im_dE_fromLab.c
 *
 * Modified:
 * 16/11/94 JC
 *	- partialed!
 * 31/10/09
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

/* Find the difference between two buffers of LAB data.
 */
void
imb_dE_fromLab( float **p, float *q, int n )
{
	float *p1 = p[0];
	float *p2 = p[1];
	int x;

	for( x = 0; x < n; x++ ) {
		q[x] = im_col_pythagoras( 
			p1[0], p1[1], p1[2], p2[0], p2[1], p2[2] );

		p1 += 3;
		p2 += 3;
	}
}

/**
 * im_dE_fromLab:
 * @in1: first input image
 * @in2: second input image
 * @out: output image
 *
 * Calculate CIE dE 1976 from two Lab images.
 *
 * Returns: 0 on success, -1 on error.
 */
int 
im_dE_fromLab( IMAGE *in1, IMAGE *in2, IMAGE *out )
{
	return( im__colour_difference( "im_dE_fromLab",
		in1, in2, out, 
		(im_wrapmany_fn) imb_dE_fromLab, NULL, NULL ) );
}
