/* @(#) Turn Yxy to XYZ colourspace. 
 * @(#) 
 * @(#) Usage: 	
 * @(#) 	im_Yxy2XYZ( imagein, imageout )
 * @(#) 	IMAGE *imagein, *imageout;
 * @(#) 
 * @(#) Float in, float out.
 * @(#) 
 * @(#) Returns: -1 on error, else 0
 * Modified:
 * 29/5/02 JC
 *	- from lab2xyz
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

/* Process a buffer of data.
 */
void
imb_Yxy2XYZ( float *p, float *q, int n )
{
	int i;

	for( i = 0; i < n; i++ ) {
		float Y = p[0];
		float x = p[1];
		float y = p[2];

		double total;
		float X, Z;

		p += 3;

		total = Y / y;
		X = x * total;
	        Z = (X - x * X - x * Y) / x;

		q[0] = X;
		q[1] = Y;
		q[2] = Z;
		q += 3;
	}
}

int 
im_Yxy2XYZ( IMAGE *in, IMAGE *out )
{	
	if( in->Bands != 3 || in->BandFmt != IM_BANDFMT_FLOAT || 
		in->Coding != IM_CODING_NONE ) {
		im_error( "im_Yxy2XYZ", "%s", 
			_( "3-band uncoded float input only" ) );
		return( -1 );
	}

	if( im_cp_desc( out, in ) )
		return( -1 );
	out->Type = IM_TYPE_XYZ;

	if( im_wrapone( in, out, 
		(im_wrapone_fn) imb_Yxy2XYZ, NULL, NULL ) )
		return( -1 );

	return( 0 );
}

