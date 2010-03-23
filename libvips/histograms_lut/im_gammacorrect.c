/* Gamma-correct image with factor gammafactor.
 *
 * Copyright: 1990, N. Dessipris.
 * 
 * Written on: 19/07/1990
 * Modified on:
 * 19/6/95 JC
 *	- redone as library function
 * 23/3/10
 * 	- gtkdoc
 * 	- 16 bit as well
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

#include <vips/vips.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/**
 * im_gammacorrect:
 * @in: input image
 * @out: output image
 * @exponent: gamma factor
 *
 * Gamma-correct an 8- or 16-bit unsigned image with a lookup table. The
 * output format is the same as the input format.
 *
 * See also: im_identity(), im_powtra(), im_maplut()
 *
 * Returns: 0 on success, -1 on error
 */
int 
im_gammacorrect( IMAGE *in, IMAGE *out, double exponent )
{
	IMAGE *t[4];
	double mx1, mx2;

	if( im_open_local_array( out, t, 4, "im_gammacorrect", "p" ) ||
		im_check_u8or16( "im_gammacorrect", in ) ||
		im_piocheck( in, out ) ||
		(in->BandFmt == IM_BANDFMT_UCHAR ?
			im_identity( t[0], 1 ) :
			im_identity_ushort( t[0], 1, 65536 )) ||
		im_powtra( t[0], t[1], exponent ) ||
		im_max( t[0], &mx1 ) ||
		im_max( t[1], &mx2 ) ||
		im_lintra( mx1 / mx2, t[1], 0, t[2] ) ||
		im_clip2fmt( t[2], t[3], in->BandFmt ) ||
		im_maplut( in, out, t[3] ) )
		return( -1 );

	return( 0 );
}
