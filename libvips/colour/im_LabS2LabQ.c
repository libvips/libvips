/* @(#) im_LabS2LabQ() - convert short LAB format to IM_CODING_LABQ.
 * @(#) 
 * @(#) int im_LabS2LabQ( IMAGE *in, IMAGE *out )
 * @(#) 
 * @(#) 
 *
 * 17/11/93 JC
 * 	- adapted from im_LabQ2LabS()
 * 16/11/94 JC
 *	- adapted to new im_wrap_oneonebuf() function
 * 15/6/95 JC
 *	- oops! rounding was broken
 * 6/6/95 JC
 *	- added round-to-nearest
 *	- somewhat slower ...
 * 21/12/99 JC
 * 	- a/b ==0 rounding was broken
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

/* Convert n pels from signed short to IM_CODING_LABQ.
 */
void
imb_LabS2LabQ( signed short *in, unsigned char *out, int n )        
{
	int c;
	signed short *p = in;
	int l, a, b;
	unsigned char *q = out;
	unsigned char ext;

	for( c = 0; c < n; c++ ) {
		/* Get LAB, rounding to 10, 11, 11. 
		 */
		l = p[0] + 16;
		if( l < 0 )
			l = 0;
		else if( l > 32767 )
			l = 32767;
		l >>= 5;

		/* Make sure we round -ves in the right direction!
		 */
		a = p[1];
		if( a >= 0 )
			a += 16;
		else
			a -= 16;
		if( a < -32768 )
			a = -32768;
		else if( a > 32767 )
			a = 32767;
		a >>= 5;

		b = p[2];
		if( b >= 0 )
			b += 16;
		else
			b -= 16;
		if( b < -32768 )
			b = -32768;
		else if( b > 32767 )
			b = 32767;
		b >>= 5;

		p += 3;

		/* Extract top 8 bits.
		 */
		q[0] = l >> 2;
		q[1] = a >> 3;
		q[2] = b >> 3;

		/* Form extension byte.
		 */
		ext = (l << 6) & 0xc0;
		ext |= (a << 3) & 0x38;
		ext |= b & 0x7;
		q[3] = ext;
		q += 4;
	}
}

int
im_LabS2LabQ( IMAGE *in, IMAGE *out )
{
	/* Check type.
	 */
	if( in->Coding != IM_CODING_NONE ) {
		im_error( "im_LabS2LabQ", "%s", 
			_( "not an uncoded image" ) );
		return( -1 );
	}
	if( in->BandFmt != IM_BANDFMT_SHORT || in->Bands != 3 ) {
		im_error( "im_LabS2LabQ", "%s", 
			_( "not a 3-band signed short image" ) );
		return( -1 );
	}

	/* Set up output image 
	 */
	if( im_cp_desc( out, in ) )
		return( -1 );
	out->Bands = 4;
	out->Type = IM_TYPE_LAB;
	out->BandFmt = IM_BANDFMT_UCHAR;
	out->Bbits = 8;
	out->Coding = IM_CODING_LABQ;

	if( im_wrapone( in, out, 
		(im_wrapone_fn) imb_LabS2LabQ, NULL, NULL ) )
		return( -1 );

	return( 0 );
}
