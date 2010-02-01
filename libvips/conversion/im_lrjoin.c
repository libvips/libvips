/* im_lrjoin
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
 * 1/2/10
 * 	- gtkdoc
 * 	- cleanups
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


/**
 * im_lrjoin:
 * @left: image to go on left
 * @right: image to go on right
 * @out: output image
 *
 * Join @left and @right together, left-right. If one is taller than the
 * other, @out will be has high as the smaller.
 *
 * If the number of bands differs, one of the images 
 * must have one band. In this case, an n-band image is formed from the 
 * one-band image by joining n copies of the one-band image together, and then
 * the two n-band images are operated upon.
 *
 * The two input images are cast up to the smallest common type (see table 
 * Smallest common format in 
 * <link linkend="VIPS-arithmetic">arithmetic</link>).
 *
 * See also: im_insert(), im_tbjoin().
 *
 * Returns: 0 on success, -1 on error
 */
int 
im_lrjoin( IMAGE *left, IMAGE *right, IMAGE *out )
{
	IMAGE *t1;

	/* Paste right and left together, trim the bottom edge.
	 */
	if( !(t1 = im_open_local( out, "im_lrjoin:1", "p" )) ||
		im_insert( left, right, t1, left->Xsize, 0 ) ||
		im_extract_area( t1, out, 
			0, 0, t1->Xsize, IM_MIN( left->Ysize, right->Ysize ) ) )
		return( -1 );

	out->Xoffset = left->Xsize;
	out->Yoffset = 0;

	return( 0 );
}
