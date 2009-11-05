/* convolution.h
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
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

 */

/*

    These files are distributed with VIPS - http://www.vips.ecs.soton.ac.uk

 */

#ifndef IM_CONVOLUTION_H
#define IM_CONVOLUTION_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

int im_conv( IMAGE *in, IMAGE *out, INTMASK *mask );
int im_convf( IMAGE *in, IMAGE *out, DOUBLEMASK *mask );
int im_convsep( IMAGE *in, IMAGE *out, INTMASK *mask );
int im_convsepf( IMAGE *in, IMAGE *out, DOUBLEMASK *mask );

int im_compass( IMAGE *in, IMAGE *out, INTMASK *mask );
int im_gradient( IMAGE *in, IMAGE *out, INTMASK *mask );
int im_lindetect( IMAGE *in, IMAGE *out, INTMASK *mask );

int im_sharpen( IMAGE *in, IMAGE *out, 
	int mask_size, 
	double x1, double y2, double y3, 
	double m1, double m2 );

int im_grad_x( IMAGE *in, IMAGE *out );
int im_grad_y( IMAGE *in, IMAGE *out );

int im_fastcor( IMAGE *in, IMAGE *ref, IMAGE *out );
int im_spcor( IMAGE *in, IMAGE *ref, IMAGE *out );
int im_gradcor( IMAGE *in, IMAGE *ref, IMAGE *out );
int im_contrast_surface( IMAGE *in, IMAGE *out, 
	int half_win_size, int spacing );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*IM_CONVOLUTION_H*/
