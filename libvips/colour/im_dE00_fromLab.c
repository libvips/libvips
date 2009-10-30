/* im_dE00_fromLab.c
 *
 * 10/10/02 JC
 *	- from dECMC
 * 30/10/09
 * 	- add im__colour_binary() and use it
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

#include <stdio.h>
#include <math.h>

#include <vips/vips.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* An n-input colour operation. Cast the inputs to three-band float and call.
 */
int
im__colour_binary( const char *domain,
	IMAGE *in1, IMAGE *in2, int bands, IMAGE *out, 
	im_wrapmany_fn buffer_fn, void *a, void *b )
{
	IMAGE *t[3];

	if( im_check_uncoded( domain, in1 ) ||
		im_check_uncoded( domain, in2 ) ||
		im_check_bands( domain, in1, 3 ) ||
		im_check_bands( domain, in2, 3 ) ||
		im_check_same_size( domain, in1, in2 ) ||
		im_open_local_array( out, t, 2, domain, "p" ) ||
		im_clip2fmt( in1, t[0], IM_BANDFMT_FLOAT ) ||
		im_clip2fmt( in2, t[1], IM_BANDFMT_FLOAT ) )
		return( -1 );

	if( im_cp_descv( out, t[0], t[1], NULL ) )
		return( -1 );
	out->Bands = bands;

	t[2] = NULL;
	if( im_wrapmany( t, out, buffer_fn, a, b ) )
		return( -1 );

	return( 0 );
}

/* Process a buffer.
 */
void
imb_dE00_fromLab( float **p, float *q, int n )
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

		q[x] = im_col_dE00( L1, a1, b1, L2, a2, b2 );
	}
}

/**
 * im_dE00_fromLab:
 * @in1: first input image
 * @in2: second input image
 * @out: output image
 *
 * Calculate CIE dE00 from two Lab images.
 *
 * Returns: 0 on success, -1 on error.
 */
int 
im_dE00_fromLab( IMAGE *in1, IMAGE *in2, IMAGE *out )
{
	if( im__colour_binary( "im_dE00_fromLab",
		in1, in2, 1, out, 
		(im_wrapmany_fn) imb_dE00_fromLab, NULL, NULL ) )
		return( -1 );

	out->Type = IM_TYPE_B_W;

	return( 0 );
}
