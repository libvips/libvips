/* @(#) Function to write an IMAGE to a DOUBLEMASK. One band IM_BANDFMT_DOUBLE 
 * @(#) images, or n-band by 1 pixel double images.
 * @(#)
 * @(#) DOUBLEMASK *
 * @(#) im_vips2mask( IMAGE *in, char *out )
 * @(#)
 * @(#) The function returns NULL on error and a new DOUBLEMASK on success
 * Author: J.Cupitt
 * Written on: 6/6/94
 * Modified on:
 *
 * 16/10/06
 * 	- allow 1xn-band images too
 * 23/2/07
 * 	- oop, broken for nx1 m-band images 
 * 	- now casts to double for you
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

#include <string.h>

#include <vips/vips.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

DOUBLEMASK *
im_vips2mask( IMAGE *in, const char *outname )
{
	int width, height;
	DOUBLEMASK *out;

	/* double* only: cast if necessary.
	 */
	if( in->BandFmt != IM_BANDFMT_DOUBLE ) {
		IMAGE *t;

		if( !(t = im_open( "im_vips2mask", "p" )) )
			return( NULL );
		if( im_clip2d( in, t ) ||
			!(out = im_vips2mask( t, outname )) ) {
			im_close( t );
			return( NULL );
		}
		im_close( t );

		return( out );
	}

	/* Check the image.
	 */
	if( im_incheck( in ) ) 
		return( NULL );
	if( in->Coding != IM_CODING_NONE ) {
		im_error( "im_vips2mask", _( "uncoded images only" ) );
		return( NULL );
	}
	if( in->Bands == 1 ) {
		width = in->Xsize;
		height = in->Ysize;
	}
	else if( in->Xsize == 1 ) {
		width = in->Bands;
		height = in->Ysize;
	}
	else if( in->Ysize == 1 ) {
		width = in->Xsize;
		height = in->Bands;
	}
	else {
		im_error( "im_vips2mask", 
			_( "one band, nx1, or 1xn images only" ) );
		return( NULL );
	}

	if( !(out = im_create_dmask( outname, width, height )) )
		return( NULL );
	if( in->Bands > 1 && in->Ysize == 1 ) {
		double *data = (double *) in->data;
		int x, y;

		/* Need to transpose: the image is RGBRGBRGB, we need RRRGGGBBB.
		 */
		for( y = 0; y < height; y++ )
			for( x = 0; x < width; x++ )
				out->coeff[x + y * width] =
					data[x * height + y];
	}
	else
		memcpy( out->coeff, in->data, 
			width * height * sizeof( double ) );

	return( out );
}

