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

int im_plotmask( IMAGE *, int, int, PEL *, PEL *, Rect * );
int im_smear( IMAGE *, int, int, Rect * );
int im_smudge( IMAGE *, int, int, Rect * );
int im_paintrect( IMAGE *, Rect *, PEL * );
int im_circle( IMAGE *, int, int, int, int );
int im_insertplace( IMAGE *, IMAGE *, int, int );
int im_line( IMAGE *, int, int, int, int, int );
int im_fastlineuser();
int im_readpoint( IMAGE *, int, int, PEL * );
int im_flood( IMAGE *, int, int, PEL *, Rect * );
int im_flood_blob( IMAGE *, int, int, PEL *, Rect * );
int im_flood_blob_copy( IMAGE *in, IMAGE *out, int x, int y, PEL *ink );
int im_flood_other( IMAGE *mask, IMAGE *test, int x, int y, int serial );
int im_flood_other_copy( IMAGE *mask, IMAGE *test, IMAGE *out, 
	int x, int y, int serial );
int im_segment( IMAGE *test, IMAGE *mask, int *segments );
int im_lineset( IMAGE *in, IMAGE *out, IMAGE *mask, IMAGE *ink,
	int n, int *x1v, int *y1v, int *x2v, int *y2v );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*IM_INPLACE_H*/
