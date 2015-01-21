/* @(#) Function to perform lighting correction. 
 * @(#) One band IM_BANDFMT_UCHAR images only. Always writes UCHAR.
 * @(#)
 * @(#) Function im_litecor() assumes that imin
 * @(#) is either memory mapped or in a buffer.
 * @(#)
 * @(#) int im_litecor(in, w, out, clip, factor)
 * @(#) IMAGE *in, *w, *out;
 * @(#) int clip;
 * @(#) double factor;
 * @(#)
 * @(#) clip==1	
 * @(#)	   - Compute max(white)*factor*(image/white), Clip to 255.
 * @(#)	clip==0
 * @(#)	   - Compute factor for you.
 * @(#)
 * @(#)
 * @(#)
 * @(#)
 * @(#) Returns 0 on success and -1 on error
 *
 * Copyright: 1990, J. Cupitt, 1991 N. Dessipris
 *
 * Author: J. Cupitt, N. Dessipris
 * Written on: 02/08/1990
 * Modified on : 6/11/1991, by ND to produce a UCHAR output
 * 1/4/93 J.Cupitt
 *	- bugs if white is smaller than image fixed
 *	- im_warning() now called
 *	- clip==0 case not tested or changed! do not use!
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

/*   If maximum output is > 255 scale output between minout and maxout,
 * by normalising maxout to 255.
 *   If maximum output is < 255 do the light correction without scaling
 */
static int
im_litecor0( IMAGE *in, IMAGE *white, IMAGE *out )
{	PEL *p, *w;
	PEL *q, *bu;
	int c;
	int x, y;
	float xrat = (float) in->Xsize / white->Xsize;
	float yrat = (float) in->Ysize / white->Ysize;
	int xstep = (int) xrat;
	int ystep = (int) yrat;
	double max;
	int wtmp, maxw, maxout, temp;

	/* Check white is some simple multiple of image.  
	 */
	if( xrat < 1.0 || xrat != xstep || yrat < 1.0 || yrat != ystep ) {
		im_error( "im_litecor", "white not simple scale of image" );
		return( -1 );
	}

	/* Find the maximum of the white.  
	 */
	if( im_max( white, &max ) )
		return( -1 );
	maxw = (int)max;

	/* Set up the output header.  
	 */
	if( im_cp_desc( out, in ) ) 
		return( -1 );
	if( im_setupout( out ) )
		return( -1 );

	/* Make buffer for outputting to.  
	 */
	if( !(bu = (PEL *) im_malloc( out, out->Xsize )) )  
		return( -1 ); 

	/* Find largest value we might generate if factor == 1.0
	 */
	maxout = -1;
	p = (PEL *) in->data;
	for( y = 0; y < in->Ysize; y++ ) {
		/* Point w to the start of the line in the white
		 * corresponding to the line we are about to correct. c counts
		 * up to xstep; each time it wraps, we should move w on one.
		 */
		w = (PEL *) (white->data + white->Xsize * (int)(y/ystep));
		c = 0;

		/* Scan along line.  
		 */
		for( x = 0; x < out->Xsize; x++ ) {
			wtmp = (int)*w;
			temp = ( maxw * (int) *p++ + (wtmp>>1) ) / wtmp; 
			if (temp > maxout )
				maxout = temp;

			/* Move white pointer on if necessary.  */
			c++;
			if( c == xstep ) { 
				w++; 
				c = 0; 
			}
		}
	}

	/* Do exactly the same as above by scaling the result with respect to
	 * maxout
	 */
	p = (PEL *) in->data;
	if (maxout <= 255 )	/* no need for rescaling output */
		{
		for( y = 0; y < in->Ysize; y++ ) 
			{
			q = bu;
			w = (PEL *) (white->data + 
				white->Xsize * (int)(y/ystep));
			c = 0;

			/* Scan along line.  */
			for( x = 0; x < in->Xsize; x++ ) 
				{
				wtmp = (int)*w;
				*q++ = (PEL)
				( ( maxw * (int) *p++ + (wtmp>>1) ) / wtmp ); 
				/* Move white pointer on if necessary.
				 */
				c++;
				if( c == xstep ) { w++; c = 0; }
				}
			if( im_writeline( y, out, bu ) ) 
				{
				im_error("im_litecor", "im_writeline failed");
				return( -1 );
				}
			}
		}
	else		/* rescale output wrt maxout */
		{
		for( y = 0; y < in->Ysize; y++ ) 
			{
			q = bu;
			w = (PEL *) (white->data + 
				white->Xsize * (int)(y/ystep));
			c = 0;

			/* Scan along line.  */
			for( x = 0; x < in->Xsize; x++ ) 
				{
				wtmp = maxout * ((int)*w);
				*q++ = (PEL)
				 ( ( maxw * (int) *p++ * 255  + (wtmp>>1)) / wtmp );
				/* Move white pointer on if necessary.
				 */
				c++;
				if( c == xstep ) { w++; c = 0; }
				}
			if( im_writeline( y, out, bu ) ) 
				{
				im_error("im_litecor", "im_writeline failed");
				return( -1 );
				}
			}
		}

	return( 0 );
}

/* Clip all corrected values above 255, if any.
 */
static int
im_litecor1( IMAGE *in, IMAGE *white, IMAGE *out, double factor )
{	PEL *p, *w;
	PEL *q, *bu;
	int c;
	int x, y;
	float xrat = (float) in->Xsize / white->Xsize;
	float yrat = (float) in->Ysize / white->Ysize;
	int xstep = (int) xrat;
	int ystep = (int) yrat;
	double max;
	double maxw, temp;
	int nclipped = 0;

	/* Check white is some simple multiple of image.  
	 */
	if( xrat < 1.0 || xrat != xstep || yrat < 1.0 || yrat != ystep ) {
		im_error( "im_litecor", "white not simple scale of image" );
		return( -1 );
	}

	/* Find the maximum of the white.  
	 */
	if( im_max( white, &max ) )
		return( -1 );
	maxw = max;

	/* Set up the output header.  
	 */
	if( im_cp_desc( out, in ) ) 
		return( -1 );
	if( im_setupout( out ) )
		return( -1 );

	/* Make buffer we write to.  
	 */
	if( !(bu = (PEL *) im_malloc( out, out->Xsize )) )  
		return( -1 ); 

	/* Loop through sorting max output  
	 */
	p = (PEL *) in->data;
	for( y = 0; y < in->Ysize; y++ ) {
		q = bu;
		w = (PEL *) (white->data + white->Xsize * (int)(y / ystep));
		c = 0;

		for( x = 0; x < out->Xsize; x++ ) {
			temp = ((factor * maxw * (int) *p++)/((int) *w)) + 0.5;
			if( temp > 255.0 ) { 
				temp = 255; 
				nclipped++; 
			}
			*q++ = temp;

			/* Move white pointer on if necessary.
			 */
			c++;
			if( c == xstep ) { 
				w++; 
				c = 0; 
			}
		}

		if( im_writeline( y, out, bu ) ) 
			return( -1 );
	}

	if( nclipped )
		im_warn( "im_litecor", "%d pels over 255 clipped", nclipped );

	return( 0 );
}

/* Lighting correction. One band uchar images only.
 * Assumes the white is some simple multiple of the image in size; ie. the
 * white has been taken with some smaller or equal set of resolution
 * parameters.
 */
int
im_litecor( IMAGE *in, IMAGE *white, IMAGE *out, int clip, double factor )
{	/* Check our args. 
	 */
	if( im_iocheck( in, out ) ) 
		return( -1 );
	if( in->Bands != 1 || 
		in->Coding != IM_CODING_NONE || in->BandFmt != IM_BANDFMT_UCHAR ) {
		im_error( "im_litecor", "bad input format" ); 
		return( -1 );
	}
	if( white->Bands != 1 || 
		white->Coding != IM_CODING_NONE || white->BandFmt != IM_BANDFMT_UCHAR ) { 
		im_error( "im_litecor", "bad white format" );
		return( -1 );
	}

	switch( clip ) {
	case 1:
		return( im_litecor1( in, white, out, factor ) );
		
	case 0: 
		return( im_litecor0( in, white, out ) );

	default:
		im_error( "im_litecor", "unknown flag %d", clip ); 
		return( -1 );
	}
}
