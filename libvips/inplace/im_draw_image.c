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
 * 	- allow sub to be outside main
 * 	- gtkdoc
 * 6/3/10
 * 	- don't im_invalidate() after paint, this now needs to be at a higher
 * 	  level
 * 25/8/10
 * 	- cast and bandalike sub to main
 * 22/9/10
 * 	- rename to im_draw_image()
 * 	- gtk-doc
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
#include <vips/internal.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* The common part of most binary inplace operators. 
 *
 * Unlike im__formatalike() and friends, we can only change one of the images,
 * since the other is being updated. 
 */
VipsImage *
im__inplace_base( const char *domain, 
	VipsImage *main, VipsImage *sub, VipsImage *out ) 
{
	VipsImage *t[2];

	if( im_rwcheck( main ) || 
		im_pincheck( sub ) ||
		im_check_coding_known( domain, main ) ||
		im_check_coding_same( domain, main, sub ) ||
		im_check_bands_1orn_unary( domain, sub, main->Bands ) )
		return( NULL );

	/* Cast sub to match main in bands and format.
	 */
	if( im_open_local_array( out, t, 2, domain, "p" ) ||
		im__bandup( sub, t[0], main->Bands ) ||
		im_clip2fmt( t[0], t[1], main->BandFmt ) )
		return( NULL );

	return( t[1] );
}

/**
 * im_draw_image:
 * @image: image to draw on
 * @sub: image to draw
 * @x: position to insert
 * @y: position to insert
 *
 * Draw @sub on top of @image at position @x, @y. The two images must have the 
 * same
 * Coding. If @sub has 1 band, the bands will be duplicated to match the
 * number of bands in @image. @sub will be converted to @image's format, see
 * im_clip2fmt().
 *
 * This an inplace operation, so @image is changed. It does not thread and will
 * not work well as part of a pipeline.
 *
 * See also: im_insert().
 *
 * Returns: 0 on success, or -1 on error.
 */
int
im_draw_image( VipsImage *image, VipsImage *sub, int x, int y )
{	
	Rect br, sr, clip;
	PEL *p, *q;
	int z;

	/* Make rects for main and sub and clip.
	 */
	br.left = 0;
	br.top = 0;
	br.width = image->Xsize;
	br.height = image->Ysize;
	sr.left = x;
	sr.top = y;
	sr.width = sub->Xsize;
	sr.height = sub->Ysize;
	im_rect_intersectrect( &br, &sr, &clip );
	if( im_rect_isempty( &clip ) )
		return( 0 );

	if( !(sub = im__inplace_base( "im_draw_image", image, sub, image )) ||
		im_rwcheck( image ) ||
		im_incheck( sub ) )
		return( -1 );

	/* Loop, memcpying sub to main.
	 */
	p = (PEL *) IM_IMAGE_ADDR( sub, clip.left - x, clip.top - y );
	q = (PEL *) IM_IMAGE_ADDR( image, clip.left, clip.top );
	for( z = 0; z < clip.height; z++ ) {
		memcpy( (char *) q, (char *) p, 
			clip.width * IM_IMAGE_SIZEOF_PEL( sub ) );
		p += IM_IMAGE_SIZEOF_LINE( sub );
		q += IM_IMAGE_SIZEOF_LINE( image );
	}

	return( 0 );
}
