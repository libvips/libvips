/* in-place insert
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
 * 21/10/09
 * 	- allow small to be outside big
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vips/vips.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/**
 * im_insertplace:
 * @big: main image
 * @small: sub-image to insert
 * @x: position to insert
 * @y: position to insert
 *
 * Copy @small into @big at position @x, @y. The two images must match in
 * format, bands and coding.
 *
 * This an inplace operation, so @big is changed. It does not thread and will
 * not work well as part of a pipeline.
 *
 * See also: im_insert().
 *
 * Returns: 0 on success, or -1 on error.
 */
int
im_insertplace( IMAGE *big, IMAGE *small, int x, int y )
{	
	Rect br, sr, clip;
	PEL *p, *q;
	int z;

	/* Check compatibility.
	 */
	if( im_rwcheck( big ) || 
		im_incheck( small ) ||
		im_check_known_coded( "im_insertplace", big ) ||
		im_check_known_coded( "im_insertplace", small ) ||
		im_check_same_format( "im_insertplace", big, small ) ||
		im_check_same_bands( "im_insertplace", big, small ) )
		return( -1 );

	/* Make rects for big and small and clip.
	 */
	br.left = 0;
	br.top = 0;
	br.width = big->Xsize;
	br.height = big->Ysize;
	sr.left = x;
	sr.top = y;
	sr.width = small->Xsize;
	sr.height = small->Ysize;
	im_rect_intersectrect( &br, &sr, &clip );
	if( im_rect_isempty( &clip ) )
		return( 0 );

	/* Loop, memcpying small to big.
	 */
	p = (PEL *) IM_IMAGE_ADDR( small, clip.left - x, clip.top - y );
	q = (PEL *) IM_IMAGE_ADDR( big, clip.left, clip.top );
	for( z = 0; z < clip.height; z++ ) {
		memcpy( (char *) q, (char *) p, 
			clip.width * IM_IMAGE_SIZEOF_PEL( small ) );
		p += IM_IMAGE_SIZEOF_LINE( small );
		q += IM_IMAGE_SIZEOF_LINE( big );
	}

	im_invalidate( big );

	return( 0 );
}
