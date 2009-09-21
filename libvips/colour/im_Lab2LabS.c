/* @(#) im_Lab2LabS: quantise FLOAT Lab image into signed short format
 * 12/12/02 JC
 *	- from im_Lab2LabQ
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

void
imb_Lab2LabS( float *in, signed short *out, int n )
{
	float *p = in;
	signed short *q = out;
	int c;
	
	for( c = 0; c < n; c++ ) {
		q[0] = p[0] * (32767.0 / 100.0);
		q[1] = p[1] * (32768.0 / 128.0);
		q[2] = p[2] * (32768.0 / 128.0);

		q += 3;
		p += 3;
	}
}

int
im_Lab2LabS( IMAGE *labim, IMAGE *outim )
{
	/* Check for uncoded Lab type 
	 */
	if( labim->Coding != IM_CODING_NONE ) {
		im_error( "im_Lab2LabS", "%s", 
			_( "uncoded input only" ) );
		return( -1 );
	}
	if( labim->BandFmt != IM_BANDFMT_FLOAT || labim->Bands != 3 ) {
		im_error( "im_Lab2LabS", "%s", 
			_( "three-band float input only" ) );
		return( -1 );
	}

	/* Set up output image.
	 */
	if( im_cp_desc( outim, labim ) ) 
		return( -1 );
	outim->Type = IM_TYPE_LABS;
	outim->BandFmt = IM_BANDFMT_SHORT;
	outim->Bbits = IM_BBITS_SHORT;

	/* Process.
	 */
	if( im_wrapone( labim, outim, 
		(im_wrapone_fn) imb_Lab2LabS, NULL, NULL ) )
		return( -1 );

	return( 0 );
}
