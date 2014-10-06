/* cimg_funcs.h
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

#ifndef IM_CIMG_FUNCS_H
#define IM_CIMG_FUNCS_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

#include <vips/vips.h>

int im_greyc_mask( VipsImage *in, VipsImage *out, VipsImage *mask, 
	int iterations, float amplitude, float sharpness, float anisotropy, 
	float alpha, float sigma, float dl, float da, float gauss_prec, 
	int interpolation, int fast_approx );

int vips_gmic( int n, VipsImage** out, const char* command, 
	int padding, float x_scale, float y_scale, ... )
	__attribute__((sentinel));

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*IM_CIMG_FUNCS_H*/
