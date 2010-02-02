/* im_vips2mask
 *
 * Author: J.Cupitt
 * Written on: 6/6/94
 * Modified on:
 *
 * 16/10/06
 * 	- allow 1xn-band images too
 * 23/2/07
 * 	- oop, broken for nx1 m-band images 
 * 	- now casts to double for you
 * 1/2/10
 * 	- gtkdoc
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

/**
 * im_vips2mask:
 * @in: input image
 * @outname: name for output mask 
 *
 * Make a mask from an image. All images are cast to %IM_BANDFMT_DOUBLE
 * before processing. There are two cases for handling bands:
 *
 * If the image has a single band, im_vips2mask() will write a mask the same
 * size as the image.
 *
 * If the image has more than one band, it must be one pixel high or wide. In
 * this case the output mask uses that axis to represent band values.
 *
 * See also: im_mask2vips(), im_measure_area().
 *
 * Returns: a #DOUBLEMASK with @outname set as the name, or NULL on error
 */
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
		if( im_clip2fmt( in, t, IM_BANDFMT_DOUBLE ) ||
			!(out = im_vips2mask( t, outname )) ) {
			im_close( t );
			return( NULL );
		}
		im_close( t );

		return( out );
	}

	/* Check the image.
	 */
	if( im_incheck( in ) ||
		im_check_uncoded( "im_vips2mask", in ) )
		return( NULL );

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
			"%s", _( "one band, nx1, or 1xn images only" ) );
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

