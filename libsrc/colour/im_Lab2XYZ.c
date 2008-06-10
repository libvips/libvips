/* @(#) Turn Lab to XYZ colourspace. 
 * @(#) 
 * @(#) Usage: 	
 * @(#) 	im_Lab2XYZ( imagein, imageout )
 * @(#) 	IMAGE *imagein, *imageout;
 * @(#) 
 * @(#) Float in, float out.
 * @(#) 
 * @(#) Returns: -1 on error, else 0
 * Modified:
 * 15/11/94 JC
 *	- ANSIfied
 *	- sets Type of output
 *	- better error messages
 * 16/11/94 JC
 *	- partialed
 *	- in-line conversion
 * 8/2/95 JC
 *	- new im_wrapone function
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
imb_Lab2XYZ( float *p, float *q, int n, im_colour_temperature *temp )
{
	int x;

	for( x = 0; x < n; x++ ) {
		float L, a, b;
		float X, Y, Z;
		double cby, tmp;

		L = p[0];
		a = p[1];
		b = p[2];
		p += 3;

		if( L < 8.0 ) {
			Y = (L * temp->Y0) / 903.3;
			cby = 7.787 * (Y / temp->Y0) + 16.0 / 116.0;
		}
		else {
			cby = (L + 16.0) / 116.0;
			Y = temp->Y0 * cby * cby * cby;
		}

		tmp = a / 500.0 + cby;
		if( tmp < 0.2069 )
			X = temp->X0 * (tmp - 0.13793) / 7.787;
		else    
			X = temp->X0 * tmp * tmp * tmp;

		tmp = cby - b / 200.0;
		if( tmp < 0.2069 )
			Z = temp->Z0 * (tmp - 0.13793) / 7.787;
		else    
			Z = temp->Z0 * tmp * tmp * tmp;

		/* Write.
		 */
		q[0] = X;
		q[1] = Y;
		q[2] = Z;
		q += 3;
	}
}

int 
im_Lab2XYZ_temp( IMAGE *in, IMAGE *out, double X0, double Y0, double Z0 )
{	
	im_colour_temperature *temp;

	/* Check input image.
	 */
	if( !(temp = IM_NEW( out, im_colour_temperature )) )
		return( -1 );
	if( in->Bands != 3 || 
		in->BandFmt != IM_BANDFMT_FLOAT || 
		in->Coding != IM_CODING_NONE ) {
		im_error( "im_Lab2XYZ", _( "not 3-band uncoded float" ) );
		return( -1 );
	}

	/* Prepare the output image.
	 */
	if( im_cp_desc( out, in ) )
		return( -1 );
	out->Type = IM_TYPE_XYZ;

	/* Process!
	 */
	temp->X0 = X0;
	temp->Y0 = Y0;
	temp->Z0 = Z0;
	if( im_wrapone( in, out, 
		(im_wrapone_fn) imb_Lab2XYZ, temp, NULL ) )
		return( -1 );

	return( 0 );
}

int 
im_Lab2XYZ( IMAGE *in, IMAGE *out )
{
	return( im_Lab2XYZ_temp( in, out, IM_D65_X0, IM_D65_Y0, IM_D65_Z0 ) );
}
