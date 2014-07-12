/* im_point_bilinear.c
 *
 * Copyright: 2006, The Nottingham Trent University
 *
 * Author: Tom Vajzovic
 *
 * Written on: 2006-09-26
 *
 * 9/9/09
 * 	- rewrite in terms of im_affinei() and im_avg()
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
#endif /* HAVE_CONFIG_H */
#include <vips/intl.h>

#include <math.h>

#include <vips/vips.h>

/**
 * im_point:
 * @im: image to read from
 * @interpolate: interpolator to sample points with
 * @x: x position to interpolate
 * @y: y position to interpolate
 * @band: band to read
 * @out: return interpolated value
 *
 * Find the value at (@x, @y) in given band of image.
 * Non-integral values are calculated using the supplied @interpolate.
 *
 * See also: im_avg(), #VipsInterpolate
 *
 * Returns: 0 on success, -1 on error
 */
int 
im_point( IMAGE *im, VipsInterpolate *interpolate, 
	double x, double y, int band, double *out )
{
	IMAGE *mem;
	IMAGE *t[2];

	if( band >= im->Bands || 
		x < 0.0 || y < 0.0 || 
		x > im->Xsize || y > im->Ysize ) {
		im_error( "im_point_bilinear", "%s", 
			_( "coords outside image" ) );
		return( -1 );
	}

	if( !(mem = im_open( "im_point", "p" )) )
		return( -1 );
	if( im_open_local_array( mem, t, 2, "im_point", "p" ) ||
		im_extract_band( im, t[0], band ) ||
		im_affinei( t[0], t[1], 
			interpolate,
			1, 0, 0, 1,
			floor( x ) - x, floor( y ) - y,
			floor( x ), floor( y ), 1, 1 ) ||
		im_avg( t[1], out ) ) {
		im_close( mem );
		return( -1 );
	}
	im_close( mem );

	return( 0 );
}

/**
 * im_point_bilinear:
 * @im: image to read from
 * @x: x position to interpolate
 * @y: y position to interpolate
 * @band: band to read
 * @out: return interpolated value
 *
 * Find the value at (@x,@y) in given band of image.
 * Use bilinear interpolation if @x or @y are non-integral. 
 *
 * See also: im_avg(), im_point().
 *
 * Returns: 0 on success, -1 on error
 */
int 
im_point_bilinear( IMAGE *im, double x, double y, int band, double *out )
{
	return( im_point( im, vips_interpolate_bilinear_static(),
		x, y, band, out ) ); 
}

