/* Simple rectangle algebra. Should build rectangle list algebra on top of
 * this.
 *
 * J. Cupitt, 8/4/93.
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
 * Rect:
 * @left: left edge of rectangle
 * @top: top edge of rectangle
 * @width: width of rectangle
 * @height: height of rectangle
 *
 * A #Rect is a rectangular area of pixels. 
 */

/* Move the margins of a rect. +1 means out one pixel.
 */
void
im_rect_marginadjust( Rect *r, int n )
{	
	r->left -= n;
	r->top -= n;
	r->width += 2 * n;
	r->height += 2 * n;
}

/* Does rect contain a point?
 */
int
im_rect_includespoint( Rect *r, int x, int y )
{	
	return( r->left <= x &&
		r->top <= y &&
		r->left + r->width > x &&
		r->top + r->height > y );
}

/* Is r2 a subset of r1? 
 */
int
im_rect_includesrect( Rect *r1, Rect *r2 )
{
	return( r1->left <= r2->left &&
		r1->top <= r2->top &&
		r1->left + r1->width >= r2->left + r2->width &&
		r1->top + r1->height >= r2->top + r2->height );
}

/* Fill r3 with the intersection of r1 and r2. r3 can equal r1 or r2.
 */
void
im_rect_intersectrect( Rect *r1, Rect *r2, Rect *r3 )
{	
	int left = IM_MAX( r1->left, r2->left );
	int top = IM_MAX( r1->top, r2->top );
	int right = IM_MIN( IM_RECT_RIGHT( r1 ), IM_RECT_RIGHT( r2 ) );
	int bottom = IM_MIN( IM_RECT_BOTTOM( r1 ), IM_RECT_BOTTOM( r2 ) );
	int width = IM_MAX( 0, right - left );
	int height = IM_MAX( 0, bottom - top );

	r3->left = left;
	r3->top = top;
	r3->width = width;
	r3->height = height;
}

/* Is a rect empty? ie. zero width or height.
 */
int
im_rect_isempty( Rect *r )
{	
	return( r->width <= 0 || r->height <= 0 );
}

/* Fill r3 with the set union of r1 and r2. Can't do this very well, as can
 * only have rectangular areas. Just set to smallest box that encloses both r1
 * and r2. If either is empty, can just return the other.
 */
void
im_rect_unionrect( Rect *r1, Rect *r2, Rect *r3 )
{	
	if( im_rect_isempty( r1 ) )
		*r3 = *r2;
	else if( im_rect_isempty( r2 ) )
		*r3 = *r1;
	else {
		int left = IM_MIN( r1->left, r2->left );
		int top = IM_MIN( r1->top, r2->top );
		int width = IM_MAX( IM_RECT_RIGHT( r1 ), 
			IM_RECT_RIGHT( r2 ) ) - left;
		int height = IM_MAX( IM_RECT_BOTTOM( r1 ), 
			IM_RECT_BOTTOM( r2 ) )- top;

		r3->left = left;
		r3->top = top;
		r3->width = width;
		r3->height = height;
	}
}

/* Test for equality.
 */
int
im_rect_equalsrect( Rect *r1, Rect *r2 )
{	
	return( r1->left == r2->left && r1->top == r2->top &&
		r1->width == r2->width && r1->height == r2->height );
}

/* DUP a rect.
 */
Rect *
im_rect_dup( Rect *r )
{
	Rect *out = IM_NEW( NULL, Rect );

	if( !out )
		return( NULL );

	*out = *r;
	return( out );
}

/* Make sure width and height are >0.
 */
void
im_rect_normalise( Rect *r )
{
	if( r->width < 0 ) {
		r->left += r->width;
		r->width *= -1;
	}
	if( r->height < 0 ) {
		r->top += r->height;
		r->height *= -1;
	}
}
