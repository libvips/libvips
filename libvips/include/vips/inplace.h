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

int im_draw_rect( VipsImage *image, 
	int left, int top, int width, int height, int fill, PEL *ink );
int im_draw_circle( VipsImage *image, 
	int x, int y, int radius, gboolean fill, PEL *ink );

int im_draw_image( VipsImage *image, VipsImage *sub, int x, int y );

typedef int (*VipsPlotFn)( VipsImage *image, int x, int y, 
	void *a, void *b, void *c );
int im_draw_line_user( VipsImage *image, 
	int x1, int y1, int x2, int y2, 
	VipsPlotFn plot, void *a, void *b, void *c );
int im_draw_line( VipsImage *image, int x1, int y1, int x2, int y2, PEL *ink );
int im_lineset( VipsImage *in, VipsImage *out, VipsImage *mask, VipsImage *ink,
	int n, int *x1v, int *y1v, int *x2v, int *y2v );

int im_draw_flood( VipsImage *image, int x, int y, PEL *ink, VipsRect *dout );
int im_draw_flood_blob( VipsImage *image, int x, int y, PEL *ink, VipsRect *dout );
int im_draw_flood_other( VipsImage *image, VipsImage *test, 
	int x, int y, int serial, VipsRect *dout );

int im_draw_mask( VipsImage *image, 
	VipsImage *mask_im, int x, int y, PEL *ink );

int im_draw_point( VipsImage *image, int x, int y, PEL *ink );
int im_read_point( VipsImage *image, int x, int y, PEL *ink );

int im_draw_smudge( VipsImage *image, 
	int left, int top, int width, int height );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*IM_INPLACE_H*/
