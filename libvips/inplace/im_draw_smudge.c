/* Smudge a piece of image. 
 *
 * Copyright: J. Cupitt
 * Written: 15/06/1992
 * 22/7/93 JC
 *	- im_incheck() added
 * 16/8/94 JC
 *	- im_incheck() changed to im_makerw()
 * ? JC
 *	- im_makerw() changed to im_rwcheck()
 * 5/12/06
 * 	- im_invalidate() after paint
 * 6/3/10
 * 	- don't im_invalidate() after paint, this now needs to be at a higher
 * 	  level
 * 30/9/10
 * 	- gtk-doc
 * 	- deprecate im_smear()
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

/* The mask we use for blurring.
 */
static INTMASK *blur = NULL;

/**
 * im_draw_smudge:
 * @image: image to smudge
 * @left: area to smudge
 * @top: area to smudge
 * @width: area to smudge
 * @height: area to smudge
 *
 * Smudge a section of @image. Each pixel in the area @left, @top, @width,
 * @height is replaced by the average of the surrounding 3x3 pixels. 
 *
 * This an inplace operation, so @image is changed. It does not thread and will
 * not work well as part of a pipeline. On 32-bit machines it will be limited
 * to 2GB images.
 *
 * See also: im_draw_line().
 *
 * Returns: 0 on success, or -1 on error.
 */
int
im_draw_smudge( VipsImage *im, int left, int top, int width, int height )
{
	Rect area, image, clipped;
	IMAGE *t[2];

	area.left = left;
	area.top = top;
	area.width = width;
	area.height = height;
	image.left = 0;
	image.top = 0;
	image.width = im->Xsize;
	image.height = im->Ysize;
	im_rect_intersectrect( &area, &image, &clipped );
	if( im_rect_isempty( &clipped ) )
		return( 0 );

	if( !blur ) {
		blur = im_create_imaskv( "im_draw_smudge", 3, 1, 1, 2, 1 );
		blur->scale = 4;
	}

	if( !(t[0] = im_open( "im_draw_smudge", "p" )) )
		return( -1 );
	if( !(t[1] = im_open_local( t[0], "im_draw_smudge", "p" )) ||
		im_convsep( im, t[0], blur ) ||
		im_extract_area( t[0], t[1], 
			clipped.left, clipped.top, 
			clipped.width, clipped.height ) ||
		im_draw_image( im, t[1], clipped.left, clipped.top ) ) {
		im_close( t[0] );
		return( -1 );
	}
	im_close( t[0] );

	return( 0 );
}
