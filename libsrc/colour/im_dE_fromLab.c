/* @(#) Calculate dE (CIELAB standard) from two LAB images.
 * @(#) 
 * @(#) Usage: 	
 * @(#) 	im_dE_fromLab( im1, *im2, im_out )
 * @(#) 	IMAGE		*im1, *im2, *im_out;
 * @(#) 
 * @(#) float out.
 * @(#) 
 * @(#) Returns: -1 on error, else 0
 * Modified:
 * 16/11/94 JC
 *	- partialed!
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

/* Find the difference between two buffers of LAB data.
 */
void
imb_dE_fromLab( float **p, float *q, int n )
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
		float dL, da, db;

		p1 += 3;
		p2 += 3;

		dL = L1 - L2;
		da = a1 - a2;
		db = b1 - b2;

		*q++ = sqrt( dL*dL + da*da + db*db );
	}
}

int 
im_dE_fromLab( IMAGE *im1, IMAGE *im2, IMAGE *out )
{	
	IMAGE *invec[3];

	/* Check input image.
	 */
	if( im1->Bands != 3 || im1->BandFmt != IM_BANDFMT_FLOAT || 
		im1->Coding != IM_CODING_NONE ||
		im2->Bands != 3 || im2->BandFmt != IM_BANDFMT_FLOAT || 
		im2->Coding != IM_CODING_NONE ) {
		im_errormsg( "im_dE_fromLab: inputs should be 3 band float");
		return( -1 );
	}

	/* Prepare the output image 
	 */
	if( im_cp_descv( out, im1, im2, NULL ) )
		return( -1 );
	out->Bbits = IM_BBITS_FLOAT;
	out->Bands = 1;
	out->BandFmt = IM_BANDFMT_FLOAT;
	out->Type = IM_TYPE_B_W;

	/* Do the processing.
	 */
	invec[0] = im1; invec[1] = im2; invec[2] = NULL;
	if( im_wrapmany( invec, out,
		(im_wrapmany_fn) imb_dE_fromLab, NULL, NULL ) )
		return( -1 );

	return( 0 );
}
