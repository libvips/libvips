/* @(#) im_LabQ2LabS() - convert IM_CODING_LABQ format to three band signed short. 
 * @(#) Justify to get msb in bit 15. 
 * @(#) 
 * @(#) int im_LabQ2LabS( IMAGE *in, IMAGE *out )
 * @(#) 
 * @(#) 
 *
 * 17/11/93 JC
 * 	- adapted from im_LabQ2Lab()
 * 16/11/94 JC
 *	- uses new im_wrap_oneonebuf() fn
 * 9/2/95 JC
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

#include <vips/vips.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* CONVERT n pels from packed 32bit Lab to signed short.
 */
void
imb_LabQ2LabS( unsigned char *in, signed short *out, int n )        
{
	int c;
	unsigned char *p = in;
	unsigned char ext;
	signed short *q = out;
	signed short l, a, b;

	for( c = 0; c < n; c++ ) {
		/* Get most significant 8 bits of lab.
		 */
		l = p[0] << 7;
		a = p[1] << 8;
		b = p[2] << 8;

		/* Get x-tra bits.
		 */
		ext = p[3];
		p += 4;

		/* Shift and mask in to lab.
		 */
		l |= (unsigned char) (ext & 0xc0) >> 1;
		a |= (ext & 0x38) << 2;
		b |= (ext & 0x7) << 5;

		/* Write!
		 */
		q[0] = l;
		q[1] = a;
		q[2] = b;
		q += 3;
	}
}

/* unpack a Lab32 ie 10,11,11 Lab image into signed short image
this is a wrapper around the buffer processing function
(C) K.Martinez 2/5/93
*/

int
im_LabQ2LabS( IMAGE *labim, IMAGE *outim )
{
	/* check for coded Lab type 
	 */
	if( labim->Coding != IM_CODING_LABQ ) {
		im_errormsg( "im_LabQ2LabS: not a packed Lab image" );
		return( -1 );
	}

	/* set up output image 
	 */
	if( im_cp_desc( outim, labim ) )
		return( -1 );
	outim->Bands = 3;
	outim->Type = IM_TYPE_LABS;
	outim->BandFmt = IM_BANDFMT_SHORT;
	outim->Bbits = IM_BBITS_SHORT;
	outim->Coding = IM_CODING_NONE;

	/* Produce output.
	 */
	if( im_wrapone( labim, outim, 
		(im_wrapone_fn) imb_LabQ2LabS, NULL, NULL ) )
		return( -1 );

	return( 0 );
}
