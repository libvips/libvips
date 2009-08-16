/* @(#)  Maps imagein to imageout with histogram specified by imageref
 * @(#) Both images should have the same number of bands
 * @(#) Each band of the output image is specified according to the distribution
 * @(#) of grey levels of the reference image
 * @(#)
 * @(#)  Usage:
 * @(#)  int im_hsp(in, ref, out)
 * @(#)  IMAGE *in, *ref, *out;
 * @(#)  
 * @(#)  Return 0 on success and -1 on error
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

int 
im_hsp( IMAGE *in, IMAGE *ref, IMAGE *out )
{
	IMAGE *histin = im_open_local( out, "im_hsp:#1", "p" );
	IMAGE *histref = im_open_local( out, "im_hsp:#2", "p" );
	IMAGE *lut = im_open_local( out, "im_hsp:#3", "p" );

	if( !histin || !histref || !lut ||
		im_histgr( in, histin, -1 ) || 
		im_histgr( ref, histref, -1 ) ||
		im_histspec( histin, histref, lut ) ||
		im_maplut( in, out, lut ) )
		return( -1 );

	return( 0 );
}
