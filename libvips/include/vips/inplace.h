/* inplace.h
 *
 * 3/11/09
 * 	- from proto.h
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

#ifndef IM_INPLACE_H
#define IM_INPLACE_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

int im_plotmask( IMAGE *im, int ix, int iy, PEL *ink, PEL *mask, Rect *r );
int im_smear( IMAGE *im, int ix, int iy, Rect *r );
int im_smudge( IMAGE *im, int ix, int iy, Rect *r );

int im_draw_rect( IMAGE *image, 
	int left, int top, int width, int height, int fill, PEL *ink );
int im_draw_circle( IMAGE *im, 
	int cx, int cy, int radius, gboolean fill, PEL *ink );

int im_draw_image( IMAGE *main, int x, int y, IMAGE *sub );
int im_draw_line( IMAGE *im, int x1, int y1, int x2, int y2, PEL *pel );

int im_fastlineuser( IMAGE *im, 
	int x1, int y1, int x2, int y2, 
	int (*fn)(), void *client1, void *client2, void *client3 );
int im_readpoint( IMAGE *im, int x, int y, PEL *pel );

int im_flood( IMAGE *im, int x, int y, PEL *ink, Rect *dout );
int im_flood_blob( IMAGE *im, int x, int y, PEL *ink, Rect *dout );
int im_flood_other( IMAGE *test, IMAGE *mark, 
	int x, int y, int serial, Rect *dout );

int im_lineset( IMAGE *in, IMAGE *out, IMAGE *mask, IMAGE *ink,
	int n, int *x1v, int *y1v, int *x2v, int *y2v );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*IM_INPLACE_H*/
