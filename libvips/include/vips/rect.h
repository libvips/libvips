/* Simple rectangle algebra.
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

#ifndef IM_RECT_H
#define IM_RECT_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

/* A rectangle.
 */
typedef struct im_rect_struct {
	int left, top, width, height;
} Rect;

#define IM_RECT_RIGHT(R) ((R)->left + (R)->width)
#define IM_RECT_BOTTOM(R) ((R)->top + (R)->height)
#define IM_RECT_HCENTRE(R) ((R)->left + (R)->width / 2)
#define IM_RECT_VCENTRE(R) ((R)->top + (R)->height / 2)

/* Rectangle algebra functions.
 */
void im_rect_marginadjust( Rect *r, int n );
int im_rect_includespoint( Rect *r, int x, int y );
int im_rect_includesrect( Rect *r1, Rect *r2 );
void im_rect_intersectrect( Rect *r1, Rect *r2, Rect *r3 );
int im_rect_isempty( Rect *r );
void im_rect_unionrect( Rect *r1, Rect *r2, Rect *r3 );
int im_rect_equalsrect( Rect *r1, Rect *r2 );
Rect *im_rect_dup( Rect *r );
void im_rect_normalise( Rect *r );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*IM_RECT_H*/
