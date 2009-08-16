/* @(#)  To join two images left right.  The resultant image has
 * @(#) Xsize = im1.Xsize + im2.Xsize and Ysize the min of im1.Ysize, im2.Ysize
 * @(#) Input images should have the same number of Bands and BandFmt
 * @(#)
 * @(#)  Usage:
 * @(#)  int im_lrjoin( IMAGE *left, IMAGE *right, IMAGE *out)
 * @(#)  IMAGE *left, *right, *out;
 * @(#)  
 * @(#)  
 *
 * Copyright 1990, 1991: Kirk Martinez, N. Dessipris
 * Author: Kirk Martinez, N. Dessipris
 * Written on: 9/6/90
 * Modified on: 17/04/1991
 * 31/8/93 JC
 *	- args to memcpy() were reversed
 * 14/11/94 JC
 *	- tided up and ANSIfied
 * 	- now accepts IM_CODING_LABQ
 *	- memory leaks removed
 *	- bug in calculation of output Xsize removed (thanks Thomson!)
 *	- bug in checking of image compatibility fixed
 * 23/10/95 JC
 *	- rewritten in terms of im_insert()
 * 14/4/04 
 *	- sets Xoffset / Yoffset
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

#include <vips/vips.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

int 
im_lrjoin( IMAGE *left, IMAGE *right, IMAGE *out )
{
	IMAGE *t1 = im_open_local( out, "im_lrjoin:1", "p" );

	/* Paste right and left together.
	 */
	if( !t1 || im_insert( left, right, t1, left->Xsize, 0 ) )
		return( -1 );

	/* Extract the part which the old im_lrjoin() would have made.
	 */
	if( im_extract_area( t1, out, 
		0, 0, t1->Xsize, IM_MIN( left->Ysize, right->Ysize ) ) )
		return( -1 );

	out->Xoffset = left->Xsize;
	out->Yoffset = 0;

	return( 0 );
}
