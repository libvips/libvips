/* @(#) im_LabS2Lab() - convert short LAB format to Lab.
 * @(#) 
 * @(#) int im_LabS2Lab( IMAGE *in, IMAGE *out )
 * @(#) 
 * @(#) 
 *
 * 12/12/02 JC
 * 	- adapted from im_LabS2LabQ()
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

#include <vips/vips.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* Convert n pels from signed short to Lab.
 */
void
imb_LabS2Lab( signed short *in, float *out, int n )        
{
	signed short *p = in;
	float *q = out;
	int c;

	for( c = 0; c < n; c++ ) {
		q[0] = p[0] / (32767.0 / 100.0);
		q[1] = p[1] / (32768.0 / 128.0);
		q[2] = p[2] / (32768.0 / 128.0);

		p += 3;
		q += 3;
	}
}

int
im_LabS2Lab( IMAGE *in, IMAGE *out )
{
	/* Check type.
	 */
	if( in->Coding != IM_CODING_NONE ) {
		im_errormsg( "im_LabS2Lab: not an uncoded image" );
		return( -1 );
	}
	if( in->BandFmt != IM_BANDFMT_SHORT || in->Bands != 3 ) {
		im_errormsg( "im_LabS2Lab: not a 3-band signed short image" );
		return( -1 );
	}

	/* Set up output image 
	 */
	if( im_cp_desc( out, in ) )
		return( -1 );
	out->Type = IM_TYPE_LAB;
	out->BandFmt = IM_BANDFMT_FLOAT;
	out->Bbits = IM_BBITS_FLOAT;

	if( im_wrapone( in, out, 
		(im_wrapone_fn) imb_LabS2Lab, NULL, NULL ) )
		return( -1 );

	return( 0 );
}
