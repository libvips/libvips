/* im_compass
 * 
 * Author: N. Dessipris (Copyright, N. Dessipris 1991)
 * Written on: 08/05/1991
 * Modified on: 
 * 11/3/01 JC
 *	- rewritten, calling im_conv() and im_maxvalue()
 * 3/2/10
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

#include <vips/vips.h>

/**
 * im_compass:
 * @in: input image
 * @out: output image
 * @mask: convolution mask
 *
 * @in is convolved 8 times with @mask, each time @mask is rotated by 45
 * degrees. Each output pixel is the largest absolute value of the 8
 * convolutions.
 *
 * See also: im_lindetect(), im_gradient(), im_conv().
 *
 * Returns: 0 on success, -1 on error
 */
int 
im_compass( IMAGE *in, IMAGE *out, INTMASK *mask )
{
	IMAGE *filtered[8];
	IMAGE *absed[8];
	int i;

	if( im_open_local_array( out, filtered, 8, "im_compass:1", "p" ) ||
		im_open_local_array( out, absed, 8, "im_compass:2", "p" ) )
		return( -1 );

	for( i = 0; i < 8; i++ ) {
		if( im_conv( in, filtered[i], mask ) ||
			!(mask = im_local_imask( out, 
				im_rotate_imask45( mask, mask->filename ) )) )
			return( -1 );
	}

	for( i = 0; i < 8; i++ ) 
		if( im_abs( filtered[i], absed[i] ) )
			return( -1 );

	return( im_maxvalue( absed, out, 8 ) );
}

/**
 * im_lindetect:
 * @in: input image
 * @out: output image
 * @mask: convolution mask
 *
 * @in is convolved four times with @mask, each time @mask is rotated by 45
 * degrees. Each output pixel is the largest absolute value of the four
 * convolutions.
 *
 * See also: im_compass(), im_gradient(), im_conv().
 *
 * Returns: 0 on success, -1 on error
 */
int 
im_lindetect( IMAGE *in, IMAGE *out, INTMASK *mask )
{
	IMAGE *filtered[4];
	IMAGE *absed[4];
	int i;

	if( im_open_local_array( out, filtered, 4, "im_lindetect:1", "p" ) ||
		im_open_local_array( out, absed, 4, "im_lindetect:2", "p" ) )
		return( -1 );

	for( i = 0; i < 4; i++ ) {
		if( im_conv( in, filtered[i], mask ) ||
			!(mask = im_local_imask( out, 
				im_rotate_imask45( mask, mask->filename ) )) )
			return( -1 );
	}

	for( i = 0; i < 4; i++ ) 
		if( im_abs( filtered[i], absed[i] ) )
			return( -1 );

	return( im_maxvalue( absed, out, 4 ) );
}

/**
 * im_gradient:
 * @in: input image
 * @out: output image
 * @mask: convolution mask
 *
 * @in is convolved with @mask and with @mask after a 90 degree rotation. The
 * result is the sum of the absolute value of the two convolutions. 
 *
 * See also: im_lindetect(), im_gradient(), im_conv().
 *
 * Returns: 0 on success, -1 on error
 */
int
im_gradient( IMAGE *in, IMAGE *out, INTMASK *mask )
{
	IMAGE *t[4];
	INTMASK *rmask;

	if( im_open_local_array( out, t, 4, "im_gradient", "p" ) )
		return( -1 );

	if( !(rmask = im_local_imask( out, 
		im_rotate_imask90( mask, mask->filename ) )) ) 
		return( -1 );

	if( im_conv( in, t[0], mask ) ||
		im_conv( in, t[1], rmask ) ||
		im_abs( t[0], t[2] ) ||
		im_abs( t[1], t[3] ) ||
		im_add( t[2], t[3], out ) )
		return( -1 );

	return( 0 );
}
