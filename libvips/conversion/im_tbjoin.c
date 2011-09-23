/* im_tbjoin
 *
 * Copyright: 1990, 1991 Kirk Martinez, N. Dessipris
 * Author: Kirk Martinez, N. Dessipris
 * Written on: 9/6/90
 * Updated: 15/03/1991, N. Dessipris
 * 31/8/93 JC
 *	- externs removed
 * 14/11/94 JC
 *	- tidied up
 *	- now works for IM_CODING_LABQ too
 *	- image compatibility bug fixed
 * 28/4/95 JC
 *	- y arg to 2nd set of im_writeline()s was wrong
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

/**
 * im_tbjoin:
 * @top: image to go on top
 * @bottom: image to go on bottom
 * @out: output image
 *
 * Join @top and @bottom together, up-down. If one is wider than the
 * other, @out will be has wide as the smaller.
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
im_tbjoin( IMAGE *top, IMAGE *bottom, IMAGE *out )
{
	IMAGE *t1;

	/* Paste top and bottom together, cut off any leftovers.
	 */
	if( !(t1 = im_open_local( out, "im_tbjoin:1", "p" )) ||
		im_insert( top, bottom, t1, 0, top->Ysize ) ||
		im_extract_area( t1, out, 
			0, 0, IM_MIN( top->Xsize, bottom->Xsize ), t1->Ysize ) )
		return( -1 );

	out->Xoffset = 0;
	out->Yoffset = top->Ysize;

	return( 0 );
}
