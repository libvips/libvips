/* match histograms
 *
 * Copyright: 1990, N. Dessipris.
 *
 * Author: Nicos Dessipris
 * Written on: 08/05/1990
 * Modified on : 
 * 16/6/93 J.Cupitt
 *	- im_ioflag() call changed to im_iocheck()
 * 25/5/95 JC
 *	- revised
 * 24/3/10
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
 * im_hsp:
 * @in: input image
 * @ref: reference histogram 
 * @out: output image
 *
 * Maps image @in to image @out, adjusting the histogram to match image @ref.
 * Both images should have the same number of bands.
 *
 * See also: im_histspec(), im_histgr().
 *
 * Returns: 0 on success, -1 on error
 */
int 
im_hsp( IMAGE *in, IMAGE *ref, IMAGE *out )
{
	IMAGE *t[3];

	if( im_open_local_array( out, t, 3, "im_hsp", "p" ) ||
		im_histgr( in, t[0], -1 ) || 
		im_histgr( ref, t[1], -1 ) ||
		im_histspec( t[0], t[1], t[2] ) ||
		im_maplut( in, out, t[2] ) )
		return( -1 );

	return( 0 );
}
