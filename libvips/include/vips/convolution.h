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

int im_rank( IMAGE *in, IMAGE *out, int width, int height, int rank );
int im_rank_image( IMAGE **in, IMAGE *out, int n, int index );
int im_rank_raw( IMAGE *in, IMAGE *out, int xsize, int ysize, int n );
int im_zerox( IMAGE *, IMAGE *, int );

int im_sharpen( IMAGE *, IMAGE *, int, double, double, double, double, double );
int im_addgnoise( IMAGE *, IMAGE *, double );
int im_gaussnoise( IMAGE *, int, int, double, double );

int im_maxvalue( IMAGE **in, IMAGE *out, int n );
int im_compass( IMAGE *, IMAGE *, INTMASK * );
int im_gradient( IMAGE *, IMAGE *, INTMASK * );
int im_lindetect( IMAGE *, IMAGE *, INTMASK * );
int im_conv( IMAGE *, IMAGE *, INTMASK * );
int im_conv_raw( IMAGE *, IMAGE *, INTMASK * );
int im_convf( IMAGE *, IMAGE *, DOUBLEMASK * );
int im_convf_raw( IMAGE *, IMAGE *, DOUBLEMASK * );
int im_convsep( IMAGE *, IMAGE *, INTMASK * );
int im_convsep_raw( IMAGE *, IMAGE *, INTMASK * );
int im_convsepf( IMAGE *, IMAGE *, DOUBLEMASK * );
int im_convsepf_raw( IMAGE *, IMAGE *, DOUBLEMASK * );
int im_convsub( IMAGE *, IMAGE *, INTMASK *, int, int );

int im_grad_x( IMAGE *in, IMAGE *out );
int im_grad_y( IMAGE *in, IMAGE *out );

int im_phasecor_fft( IMAGE *in1, IMAGE *in2, IMAGE *out );
int im_fastcor( IMAGE *, IMAGE *, IMAGE * );
int im_fastcor_raw( IMAGE *, IMAGE *, IMAGE * );
int im_spcor( IMAGE *, IMAGE *, IMAGE * );
int im_spcor_raw( IMAGE *, IMAGE *, IMAGE * );
int im_gradcor( IMAGE *, IMAGE *, IMAGE * );
int im_gradcor_raw( IMAGE *, IMAGE *, IMAGE * );
int im_contrast_surface( IMAGE *, IMAGE *, int, int );
int im_contrast_surface_raw( IMAGE *, IMAGE *, int, int );

int im_resize_linear( IMAGE *, IMAGE *, int, int );
int im_mpercent( IMAGE *, double, int * );
int im_embed( IMAGE *, IMAGE *, int, int, int, int, int );

int im_stretch3( IMAGE *in, IMAGE *out, double dx, double dy );
int im_shrink( IMAGE *, IMAGE *, double, double );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*IM_CONVOLUTION_H*/
