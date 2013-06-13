/* make a test pattern to show the eye's frequency response
 *
 * Copyright: 1990, 1991, N.Dessipris.
 *
 * Author N. Dessipris
 * Written on 30/05/1990
 * Updated on: 27/01/1991, 07/03/1991,
 * 22/7/93 JC
 *	- im_outcheck() added
 * 30/8/95 JC
 *	- modernized
 * 1/2/11
 * 	- gtk-doc
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
#include <math.h>

#include <vips/vips.h>

/**
 * im_feye:
 * @out: output image
 * @xsize: image size
 * @ysize: image size
 * @factor: image size
 *
 * Create a test pattern with increasing spatial frequence in X and 
 * amplitude in Y. @factor should be between 0 and 1 and determines the 
 * maximum spatial frequency.
 *
 * Creates an one band float image with values in +1 to -1.
 *
 * See also: im_eye().
 *
 * Returns: 0 on success, -1 on error
 */
int 
im_feye( IMAGE *out, const int xsize, const int ysize, const double factor )
{
	int x, y;
	double constant;
	double *lut;
	float *line;

	/* Check input args 
	 */
	if( im_outcheck( out ) )
		return( -1 );
	if( factor > 1.0 || factor <= 0.0 ) { 
		im_error( "im_feye", "%s", _( "factor should be in [1,0)" ) );
		return( -1 );
	}

	/* Set image descriptor 
	 */
        im_initdesc( out, xsize, ysize, 1, IM_BBITS_FLOAT, IM_BANDFMT_FLOAT,
		IM_CODING_NONE, IM_TYPE_B_W, 1.0, 1.0, 0, 0 );
        if( im_setupout( out ) )
                return( -1 );

	/* Allocate space for line buffer.
	 */
        if( !(line = IM_ARRAY( out, xsize, float )) )
                return( -1 );

	/* Make a lut for easy calculations.
	 */
	if( !(lut = IM_ARRAY( out, xsize, double )) )
		return( -1 );
	constant = factor * IM_PI / (2 * (xsize - 1));
	for( x = 0; x < xsize; x++ )
		lut[x] = cos( constant * x * x ) / ((ysize - 1) * (ysize - 1));

	/* Make image.
	 */
	for( y = 0; y < ysize; y++ ) {
		for( x = 0; x < xsize; x++ )
			line[x] = y * y * lut[x];
		if( im_writeline( y, out, (VipsPel *) line ) )
			return( -1 ); 
	}

	return( 0 );
}

/**
 * im_eye:
 * @out: output image
 * @xsize: image size
 * @ysize: image size
 * @factor: image size
 *
 * Exactly as im_feye(), but make a UCHAR image with pixels in the range [0,
 * 255].
 *
 * See also: im_feye().
 *
 * Returns: 0 on success, -1 on error
 */
int
im_eye( IMAGE *out, const int xsize, const int ysize, const double factor )
{
	IMAGE *t[2];

	/* Change range to [0,255].
	 */
	if( im_open_local_array( out, t, 2, "im_grey", "p" ) ||
		im_feye( t[0], xsize, ysize, factor ) || 
		im_lintra( 127.5, t[0], 127.5, t[1] ) ||
		im_clip2fmt( t[1], out, IM_BANDFMT_UCHAR ) )
		return( -1 );

	return( 0 );
}

