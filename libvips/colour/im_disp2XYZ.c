/* @(#) Turn displayable rgb files to XYZ.
 * @(#) 
 * @(#) Usage: 	
 * @(#) 	im_disp2XYZ( imagein, imageout, display )
 * @(#) 	IMAGE		*imagein, *imageout;
 * @(#)		struct im_col_display	*display;
 * @(#) 
 * @(#) uchar in, float out.
 * @(#) 
 * @(#) Returns: -1 on error, else 0
 * Modified:
 * 15/11/94 JC
 *	- memory leak fixed
 *	- error message added
 * 16/11/94 JC
 *	- partialed
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

/* Convert a buffer.
 */
void
imb_disp2XYZ( PEL *p, float *q, int n, struct im_col_display *d )
{
	int x;

	for( x = 0; x < n; x++ ) {
		int r = p[0];
		int g = p[1];
		int b = p[2];
		float X, Y, Z;
		p += 3;

		im_col_rgb2XYZ( d, r, g, b, &X, &Y, &Z );

		q[0] = X;
		q[1] = Y;
		q[2] = Z;
		q += 3;
	}
}

int 
im_disp2XYZ( IMAGE *in, IMAGE *out, struct im_col_display *d )
{	
	/* Check input image.
	 */
	if( in->Bands != 3 || in->BandFmt != IM_BANDFMT_UCHAR || 
		in->Coding != IM_CODING_NONE ) {
		im_error( "im_disp2XYZ", 
			"%s", _( "input not 3-band uncoded char" ) );
		return( -1 );
	}

	/* Prepare the output image 
	 */
	if( im_cp_desc( out, in ) )
		return( -1 );
	out->BandFmt = IM_BANDFMT_FLOAT;
	out->Type = IM_TYPE_XYZ;

	/* Do the processing.
	 */
	if( im_wrapone( in, out,
		(im_wrapone_fn) imb_disp2XYZ, d, NULL ) )
		return( -1 );

	return( 0 );
}
