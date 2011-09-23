/* Simple rectangle algebra. Should build rectangle list algebra on top of
 * this.
 *
 * J. Cupitt, 8/4/93.
 *
 * 17/3/11
 * 	- move to vips_ prefix
 * 	- gtk-doc comments
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

/**
 * SECTION: rect
 * @short_description: the VIPS rectangle class
 * @stability: Stable
 * @see_also: <link linkend="libvips-region">region</link>
 * @include: vips/vips.h
 *
 * The #VipsRect class and associated types and macros.
 */

/**
 * VipsRect:
 * @left: left edge of rectangle
 * @top: top edge of rectangle
 * @width: width of rectangle
 * @height: height of rectangle
 *
 * A #VipsRect is a rectangular area of pixels. This is a struct for
 * performing simple rectangle algebra. 
 */

/**
 * vips_rect_includespoint:
 * @r: rectangle to test 
 * @x: position to test for
 * @y: position to test for 
 *
 * Does @r contain point (@x, @y)?
 *
 * Returns: %TRUE if @r contains (@x, @y).
 */
gboolean
vips_rect_includespoint( const VipsRect *r, int x, int y )
{	
	return( r->left <= x &&
		r->top <= y &&
		r->left + r->width > x &&
		r->top + r->height > y );
}

/**
 * vips_rect_isempty:
 * @r: rectangle to test
 *
 * Is @r empty? ie. zero width or height.
 *
 * Returns: %TRUE if @r contains no pixels.
 */
gboolean
vips_rect_isempty( const VipsRect *r )
{	
	return( r->width <= 0 || r->height <= 0 );
}

/**
 * vips_rect_includesrect:
 * @r1: outer rectangle
 * @r2: inner rectangle
 *
 * Is @r2 a subset of @r1? 
 *
 * Returns: %TRUE if @r2 is a subset of @r1.
 */
gboolean
vips_rect_includesrect( const VipsRect *r1, const VipsRect *r2 )
{
	return( r1->left <= r2->left &&
		r1->top <= r2->top &&
		r1->left + r1->width >= r2->left + r2->width &&
		r1->top + r1->height >= r2->top + r2->height );
}

/**
 * vips_rect_equalsrect:
 * @r1: first rectangle
 * @r2: second rectangle
 *
 * Is @r1 equal to @r2? 
 *
 * Returns: %TRUE if @r1 is equal to @r2.
 */
gboolean
vips_rect_equalsrect( const VipsRect *r1, const VipsRect *r2 )
{	
	return( r1->left == r2->left && r1->top == r2->top &&
		r1->width == r2->width && r1->height == r2->height );
}

/**
 * vips_rect_marginadjust:
 * @r: rectangle to adjust
 * @n: enlarge by
 *
 * Enlarge @r by @n. +1 means out one pixel.
 */
void
vips_rect_marginadjust( VipsRect *r, int n )
{	
	r->left -= n;
	r->top -= n;
	r->width += 2 * n;
	r->height += 2 * n;
}

/**
 * vips_rect_intersectrect:
 * @r1: input rectangle 1
 * @r2: input rectangle 2
 * @out: output rectangle 
 *
 * Fill @out with the intersection of @r1 and @r2. @out can equal @r1 or @r2.
 */
void
vips_rect_intersectrect( const VipsRect *r1, const VipsRect *r2, VipsRect *out )
{	
	int left = VIPS_MAX( r1->left, r2->left );
	int top = VIPS_MAX( r1->top, r2->top );
	int right = VIPS_MIN( VIPS_RECT_RIGHT( r1 ), VIPS_RECT_RIGHT( r2 ) );
	int bottom = VIPS_MIN( VIPS_RECT_BOTTOM( r1 ), VIPS_RECT_BOTTOM( r2 ) );
	int width = VIPS_MAX( 0, right - left );
	int height = VIPS_MAX( 0, bottom - top );

	out->left = left;
	out->top = top;
	out->width = width;
	out->height = height;
}

/**
 * vips_rect_unionrect:
 * @r1: input rectangle 1
 * @r2: input rectangle 2
 * @out: output rectangle 
 *
 * Fill @out with the bounding box of @r1 and @r2. @out can equal @r1 or @r2.
 */
void
vips_rect_unionrect( const VipsRect *r1, const VipsRect *r2, VipsRect *out )
{	
	if( vips_rect_isempty( r1 ) )
		*out = *r2;
	else if( vips_rect_isempty( r2 ) )
		*out = *r1;
	else {
		int left = VIPS_MIN( r1->left, r2->left );
		int top = VIPS_MIN( r1->top, r2->top );
		int width = VIPS_MAX( VIPS_RECT_RIGHT( r1 ), 
			VIPS_RECT_RIGHT( r2 ) ) - left;
		int height = VIPS_MAX( VIPS_RECT_BOTTOM( r1 ), 
			VIPS_RECT_BOTTOM( r2 ) )- top;

		out->left = left;
		out->top = top;
		out->width = width;
		out->height = height;
	}
}

/**
 * vips_rect_dup:
 * @r: rectangle to duplicate
 *
 * Duplicate a rect to the heap. You need to free the result with vips_free().
 *
 * Returns: a pointer to copy of @r allocated on the heap.
 */
VipsRect *
vips_rect_dup( const VipsRect *r )
{
	VipsRect *out;

	if( !(out = VIPS_NEW( NULL, VipsRect )) )
		return( NULL );
	*out = *r;

	return( out );
}

/**
 * vips_rect_normalise:
 * @r: rect to normalise
 *
 * Make sure width and height are >0 by moving the origin and flipping the
 * rect.
 */
void
vips_rect_normalise( VipsRect *r )
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
