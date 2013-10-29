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
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
    02110-1301  USA

 */

/*

    These files are distributed with VIPS - http://www.vips.ecs.soton.ac.uk

 */

#ifndef IM_CONVOLUTION_H
#define IM_CONVOLUTION_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

typedef enum {
	VIPS_PRECISION_INTEGER,
	VIPS_PRECISION_FLOAT,
	VIPS_PRECISION_APPROXIMATE,
	VIPS_PRECISION_LAST
} VipsPrecision;

typedef enum {
	VIPS_COMBINE_MAX,
	VIPS_COMBINE_SUM,
	VIPS_COMBINE_LAST
} VipsCombine;

/** 
 * VipsOperationMorphology:
 * @VIPS_OPERATION_MORPHOLOGY_ERODE: true if all set
 * @VIPS_OPERATION_MORPHOLOGY_DILATE: true if one set
 *
 * More like hit-miss, really. 
 *
 * See also: vips_morph().
 */

typedef enum {
	VIPS_OPERATION_MORPHOLOGY_ERODE,
	VIPS_OPERATION_MORPHOLOGY_DILATE,
	VIPS_OPERATION_MORPHOLOGY_LAST
} VipsOperationMorphology;

int vips_conv( VipsImage *in, VipsImage **out, VipsImage *mask, ... )
	__attribute__((sentinel));
int vips_compass( VipsImage *in, VipsImage **out, VipsImage *mask, ... )
	__attribute__((sentinel));
int vips_convsep( VipsImage *in, VipsImage **out, VipsImage *mask, ... )
	__attribute__((sentinel));

int vips_morph( VipsImage *in, VipsImage **out, VipsImage *mask, 
	VipsOperationMorphology morph, ... )
	__attribute__((sentinel));

void vips_convolution_operation_init( void );




int im_sharpen( VipsImage *in, VipsImage *out, 
	int mask_size, 
	double x1, double y2, double y3, 
	double m1, double m2 );

int im_grad_x( VipsImage *in, VipsImage *out );
int im_grad_y( VipsImage *in, VipsImage *out );

int im_fastcor( VipsImage *in, VipsImage *ref, VipsImage *out );
int im_spcor( VipsImage *in, VipsImage *ref, VipsImage *out );
int im_gradcor( VipsImage *in, VipsImage *ref, VipsImage *out );
int im_contrast_surface( VipsImage *in, VipsImage *out, 
	int half_win_size, int spacing );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*IM_CONVOLUTION_H*/
