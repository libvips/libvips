/* Histogram-equalise an image.
 *
 * Copyright: 1991, N. Dessipris.
 *
 * Author: Nicos Dessipris
 * Written on: 27/03/1991
 * Modified on : 
 * 16/6/93 J.Cupitt
 *	- im_ioflag() changed to im_iocheck()
 * 24/5/95 JC
 *	- ANSIfied and tidied up
 * 3/3/01 JC
 *	- more cleanup
 * 23/3/10
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

#include <vips/vips.h>

/**
 * im_heq:
 * @in: input image
 * @out: output image
 * @bandno: band to equalise
 *
 * Histogram-equalise @in. Equalise using band @bandno, or if @bandno is -1,
 * equalise all bands.
 *
 * See also: im_lhisteq(), im_histgr(), im_histeq().
 *
 * Returns: 0 on success, -1 on error
 */
int 
im_heq( IMAGE *in, IMAGE *out, int bandno )
{
	IMAGE *t[2];

	if( im_open_local_array( out, t, 2, "im_heq", "p" ) ||
		im_histgr( in, t[0], bandno ) ||
		im_histeq( t[0], t[1] ) ||
		im_maplut( in, out, t[1] ) )
		return( -1 );

	return( 0 );
}
