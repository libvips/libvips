/* @(#) test pattern with increasing spatial frequence in X and amplitude in Y
 * @(#) factor should be between 0 and 1 and determines the spatial frequencies
 * @(#)  Creates an one band float image 
 * @(#)  Image has values between +ysize*ysize and -ysize*ysize
 * @(#)
 * @(#) int im_eye(image, xsize, ysize, factor)
 * @(#) IMAGE *image;
 * @(#) int xsize, ysize;
 * @(#) double factor;
 * @(#)
 * @(#) Returns -1 on error and 0 on success
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
#include <stdlib.h>
#include <math.h>

#include <vips/vips.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

int 
im_feye( IMAGE *image, const int xsize, const int ysize, const double factor )
{
	int x, y;
	double constant;
	double *lut;
	float *line;

	/* Check input args 
	 */
	if( im_outcheck( image ) )
		return( -1 );
	if( factor > 1.0 || factor <= 0.0 ) { 
		im_error( "im_feye", "%s", _( "factor should be in [1,0)" ) );
		return( -1 );
	}

	/* Set image descriptor 
	 */
        im_initdesc( image, xsize, ysize, 1, IM_BBITS_FLOAT, IM_BANDFMT_FLOAT,
		IM_CODING_NONE, IM_TYPE_B_W, 1.0, 1.0, 0, 0 );
        if( im_setupout( image ) )
                return( -1 );

	/* Allocate space for line buffer.
	 */
        if( !(line = IM_ARRAY( image, xsize, float )) )
                return( -1 );

	/* Make a lut for easy calculations.
	 */
	if( !(lut = IM_ARRAY( image, image->Xsize, double )) )
		return( -1 );
	constant = factor * IM_PI/(2*(xsize - 1));
	for( x = 0; x < image->Xsize; x++ )
		lut[x] = cos( constant*x*x ) / ((ysize - 1)*(ysize - 1));

	/* Make image.
	 */
	for( y = 0; y < image->Ysize; y++ ) {
		for( x = 0; x < image->Xsize; x++ )
			line[x] = y*y*lut[x];
		if( im_writeline( y, image, (PEL *) line ) )
			return( -1 ); 
	}

	return( 0 );
}

/* As above, but make a IM_BANDFMT_UCHAR image.
 */
int
im_eye( IMAGE *image, const int xsize, const int ysize, const double factor )
{
	IMAGE *t1 = im_open_local( image, "im_eye:1", "p" );
	IMAGE *t2 = im_open_local( image, "im_eye:2", "p" );

	if( !t1 )
		return( -1 );

	/* Change range to [0,255].
	 */
	if( im_feye( t1, xsize, ysize, factor ) || 
		im_lintra( 127.5, t1, 127.5, t2 ) ||
		im_clip2fmt( t2, image, IM_BANDFMT_UCHAR ) )
		return( -1 );

	return( 0 );
}

