/* morphology.h
 *
 * 20/9/09
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
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
    02110-1301  USA

 */

/*

    These files are distributed with VIPS - http://www.vips.ecs.soton.ac.uk

 */

#ifndef IM_MORPHOLOGY_H
#define IM_MORPHOLOGY_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

int im_dilate( VipsImage *in, VipsImage *out, INTMASK *mask );
int im_erode( VipsImage *in, VipsImage *out, INTMASK *mask );

int im_rank( VipsImage *in, VipsImage *out, int width, int height, int index );
int im_rank_image( VipsImage **in, VipsImage *out, int n, int index );
int im_maxvalue( VipsImage **in, VipsImage *out, int n );

int im_cntlines( VipsImage *im, double *nolines, int flag );
int im_zerox( VipsImage *in, VipsImage *out, int sign );
int im_profile( VipsImage *in, VipsImage *out, int dir );
int im_label_regions( VipsImage *test, VipsImage *mask, int *segments );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*IM_MORPHOLOGY_H*/
