/* @(#) im_Lab2LabQ: quantise FLOAT Lab image into 10 11 11 format
 * 4 bytes per pel: l a b lsbs
 * this is an image wrapper which calls line-wise packing
 * Copyright K.Martinez 3/5/93
 * Modified:
 * 7/6/93 JC
 *	- adapted for partial v2
 * 5/5/94 JC
 *	- some nint->+0.5, for speed and to ease portability
 *	- other nint->rint
 *	- now inclues <math.h>!
 * 15/11/94 JC
 *	- all nint(), rint() removed for speed
 *	- now -128 rather than -127 for a, b
 *	- checks input type properly
 * 16/11/94 JC
 *	- uses new im_wrap_oneonebuf()
 * 22/5/95 JC
 *	- changed L to scale by 10.24, not 10.23
 * 11/7/95 JC
 *	- now uses IM_RINT() for rounding
 * 4/9/97 JC
 *	- L* = 100.0 now allowed
 * 5/11/00 JC
 *	- go int earlier for speed up
 * 20/6/02 JC
 *	- oops, were not clipping a/b range correctly
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

/* @(#) convert float Lab to packed Lab32 format 10 11 11 bits
 * works only on buffers, not IMAGEs
 * Copyright 1993 K.Martinez
 * Modified: 3/5/93, 16/6/93
 */
void
imb_Lab2LabQ( float *inp, unsigned char *outbuf, int n )
{
	float *f, fval;
	int lsbs, intv;
	int Xc;
	unsigned char *out;

	out = outbuf;
	f = inp;
	for( Xc = 0; Xc < n; Xc++) {
		/* Scale L up to 10 bits. Add 0.5 rather than call IM_RINT for 
		 * speed. This will not round negatives correctly! But this 
		 * does not matter, since L is >0. L*=100.0 -> 1023.
		 */
		intv = 10.23 * f[0] + 0.5;	/* scale L up to 10 bits */
		if( intv > 1023 )
			intv = 1023;
		if( intv < 0 )
			intv = 0;
		lsbs = (intv & 0x3) << 6;       /* 00000011 -> 11000000 */
		out[0] = (intv >> 2); 		/* drop bot 2 bits and store */

		fval = 8.0 * f[1];              /* do a */
		intv = IM_RINT( fval );
		if( intv > 1023 )
			intv = 1023;
		else if( intv < -1024 )
			intv = -1024;

		/* Break into bits.
		 */
		lsbs |= (intv & 0x7) << 3;      /* 00000111 -> 00111000 */
		out[1] = (intv >> 3);   	/* drop bot 3 bits & store */

		fval = 8.0 * f[2];              /* do b */
		intv = IM_RINT( fval );
		if( intv > 1023 )
			intv = 1023;
		else if( intv < -1024 )
			intv = -1024;

		lsbs |= (intv & 0x7);
		out[2] = (intv >> 3);

		out[3] = lsbs;                /* store lsb band */

		f += 3;
		out += 4;
	}
}

int
im_Lab2LabQ( IMAGE *labim, IMAGE *outim )
{
	/* Check for uncoded Lab type 
	 */
	if( labim->Coding != IM_CODING_NONE ) {
		im_errormsg( "im_Lab2LabQ: uncoded input only" );
		return( -1 );
	}
	if( labim->BandFmt != IM_BANDFMT_FLOAT || labim->Bands != 3 ) {
		im_errormsg( "im_Lab2LabQ: three-band float input only" );
		return( -1 );
	}

	/* Set up output image.
	 */
	if( im_cp_desc( outim, labim ) ) 
		return( -1 );
	outim->Bands = 4;
	outim->Type = IM_TYPE_LAB;
	outim->BandFmt = IM_BANDFMT_UCHAR;
	outim->Bbits = 8;
	outim->Coding = IM_CODING_LABQ;

	/* Process.
	 */
	if( im_wrapone( labim, outim, 
		(im_wrapone_fn) imb_Lab2LabQ, NULL, NULL ) )
		return( -1 );

	return( 0 );
}
