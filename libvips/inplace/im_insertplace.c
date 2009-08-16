/* @(#) Insert an image into another. Like im_insert, but an `in-place'
 * @(#) operation. small must fit entirely inside big - no clipping is
 * @(#) performed.
 * @(#) 
 * @(#) int 
 * @(#) im_insertplace( big, small, x, y )
 * @(#) IMAGE *big, *small;
 * @(#) int x, y;
 * @(#) 
 *
 * Copyright: J. Cupitt
 * Written: 15/06/1992
 * 22/7/93 JC
 *	- im_incheck() added
 * 16/8/94 JC
 *	- im_incheck() changed to im_makerw()
 * 1/9/04 JC
 *	- checks bands/types/etc match (thanks Matt)
 *	- smarter pixel size calculations
 * 5/12/06
 * 	- im_invalidate() after paint
 * 24/3/09
 * 	- added IM_CODING_RAD support
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
#include <string.h>

#include <vips/vips.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* Like im_insert, but perform an in-place insertion.
 */
int
im_insertplace( IMAGE *big, IMAGE *small, int x, int y )
{	
	Rect br, sr;
	PEL *p, *q;
	int z;

	/* Check IO.
	 */
	if( im_rwcheck( big ) || im_incheck( small ) )
		return( -1 );

	/* Check compatibility.
	 */
        if( big->BandFmt != small->BandFmt || big->Bands != small->Bands ||
                big->Coding != small->Coding ) {
                im_error( "im_insertplace", "%s", 
			_( "inputs differ in format" ) );
                return( -1 );
        }
        if( big->Coding != IM_CODING_NONE && 
		big->Coding != IM_CODING_LABQ &&
		big->Coding != IM_CODING_RAD ) {
                im_error( "im_insertplace", "%s", 
			_( "Coding should be NONE, LABQ or RAD" ) ); 
                return( -1 );
        }

	/* Make rects for big and small.
	 */
	br.left = 0;
	br.top = 0;
	br.width = big->Xsize;
	br.height = big->Ysize;
	sr.left = x;
	sr.top = y;
	sr.width = small->Xsize;
	sr.height = small->Ysize;

	/* Small fits inside big?
	 */
	if( !im_rect_includesrect( &br, &sr ) ) {
		im_error( "im_insertplace", 
			"%s", _( "small not inside big" ) );
		return( -1 );
	}

	/* Loop, memcpying small to big.
	 */
	p = (PEL *) IM_IMAGE_ADDR( small, 0, 0 );
	q = (PEL *) IM_IMAGE_ADDR( big, x, y );
	for( z = 0; z < small->Ysize; z++ ) {
		memcpy( (char *) q, (char *) p, IM_IMAGE_SIZEOF_LINE( small ) );
		p += IM_IMAGE_SIZEOF_LINE( small );
		q += IM_IMAGE_SIZEOF_LINE( big );
	}

	im_invalidate( big );

	return( 0 );
}
