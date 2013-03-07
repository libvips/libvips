/* @(#) Function to perform black level correction given black image
 * @(#) designed for PAD camera single field black to apply in blocks
 * @(#) as each is reused for higher resolution pels (eg: 6 8 for Progres)
 * @(#) IM_BANDFMT_UCHAR images only. Always writes UCHAR.
 * @(#) int im_clamp(in, w, out, hstep, vstep)
 * @(#) IMAGE *in, *w, *out;  int hstep, vstep;
 * @(#)	   - Compute clip(image - (black)) ie subtract black no negatives
 * @(#) scales for low res Progres images to replicate black value
 * @(#) Returns 0 on success and -1 on error
 * fiddle at your peril - nasty code
 * Copyright: 1993 KM
 * 20/8/93
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
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
    02110-1301  USA

 */

/*

    These files are distributed with VIPS - http://www.vips.ecs.soton.ac.uk

 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <stdlib.h>

#include <vips/vips.h>
#include <vips/internal.h>

int
im_clamp( in, out,black, hstep, vstep )
IMAGE *in, *black, *out;
int hstep, vstep;
{	PEL *p, *blk, *bline, *bexp;
PEL *q, *outbuf;
int rep;
int x, y, bnd;
int temp, blacky, newblacky;

if( im_iocheck( in, out ) ) 
	return( -1 );
if( in->Bbits != 8 || 
	in->Coding != IM_CODING_NONE || in->BandFmt != IM_BANDFMT_UCHAR ) {
	im_error( "im_clamp", "%s", _( "bad input format" ) ); 
	return( -1 );
}
if(  black->Bbits != 8 || 
	black->Coding != IM_CODING_NONE || black->BandFmt != IM_BANDFMT_UCHAR ) { 
	im_error( "im_clamp", "%s", _( "bad black format" ) );
	return( -1 );
}

/* Set up the output header.  
 */
if( im_cp_desc( out, in ) ) 
	return( -1 );
if( im_setupout( out ) )
	return( -1 );

/* Make buffer for expanded black line
 */
if( !(bline = (PEL *) im_malloc( out, black->Bands * hstep * in->Xsize )) )  
	return( -1 ); 
/* Make buffer we write to.  
 */
if( !(outbuf = (PEL *) im_malloc( out, out->Bands * out->Xsize )) )  
	return( -1 ); 
blacky = -1;
p = (PEL *) in->data;

for( y = 0; y < in->Ysize; y++ ) {
	/* calc corresponding black line - get new one if different */
	newblacky = (vstep * black->Ysize - in->Ysize + y)/vstep;
	if( newblacky != blacky){
		blacky = newblacky;
		/* time to expand a new black line */
		blk = (PEL *) (black->data + 
			black->Xsize * black->Bands * blacky);
		for(bexp = bline, x = 0; x < black->Xsize; x++){
			for(rep = 0; rep < hstep; rep++)
				for(q=blk, bnd = 0; bnd < in->Bands; bnd++)
					*bexp++ = *q++;
		blk += black->Bands;
		}
	}

	/* correct a line of image */
	bexp = bline;
	q = outbuf;
	for( x = 0; x < (out->Bands * out->Xsize); x++ ) {
		temp = ((int) *p++ - *bexp++);
		if( temp < 0 ) temp = 0; 
		*q++ = (PEL)temp;
		}

	if( im_writeline( y, out, outbuf ) ) 
		return( -1 );
} /* end of a line */

return( 0 );
}
