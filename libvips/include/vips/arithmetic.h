/* Headers for arithmetic
 *
 * 30/6/09
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

#ifndef IM_ARITHMETIC_H
#define IM_ARITHMETIC_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

/** 
 * VipsMathOperation:
 * @VIPS_MATH_OPERATION_SIN: sin(), angles in degrees
 * @VIPS_MATH_OPERATION_COS: cos(), angles in degrees
 * @VIPS_MATH_OPERATION_TAN: tan(), angles in degrees
 * @VIPS_MATH_OPERATION_ASIN: asin(), angles in degrees
 * @VIPS_MATH_OPERATION_ACOS: acos(), angles in degrees
 * @VIPS_MATH_OPERATION_ATAN: atan(), angles in degrees
 * @VIPS_MATH_OPERATION_LOG: log base e 
 * @VIPS_MATH_OPERATION_LOG10: log base 10 
 * @VIPS_MATH_OPERATION_EXP: e to the something
 * @VIPS_MATH_OPERATION_EXP10: 10 to the something
 *
 * See also: vips_math().
 */
typedef enum {
	VIPS_MATH_OPERATION_SIN,
	VIPS_MATH_OPERATION_COS,
	VIPS_MATH_OPERATION_TAN,
	VIPS_MATH_OPERATION_ASIN,
	VIPS_MATH_OPERATION_ACOS,
	VIPS_MATH_OPERATION_ATAN,
	VIPS_MATH_OPERATION_LOG,
	VIPS_MATH_OPERATION_LOG10,
	VIPS_MATH_OPERATION_EXP,
	VIPS_MATH_OPERATION_EXP10,
	VIPS_MATH_OPERATION_LAST
} VipsMathOperation;

int vips_add( VipsImage *left, VipsImage *right, VipsImage **out, ... )
	__attribute__((sentinel));
int vips_subtract( VipsImage *in1, VipsImage *in2, VipsImage **out, ... )
	__attribute__((sentinel));
int vips_multiply( VipsImage *left, VipsImage *right, VipsImage **out, ... )
	__attribute__((sentinel));
int vips_divide( VipsImage *left, VipsImage *right, VipsImage **out, ... )
	__attribute__((sentinel));
int vips_avg( VipsImage *in, double *out, ... )
	__attribute__((sentinel));
int vips_deviate( VipsImage *in, double *out, ... )
	__attribute__((sentinel));
int vips_min( VipsImage *in, double *out, ... )
	__attribute__((sentinel));
int vips_max( VipsImage *in, double *out, ... )
	__attribute__((sentinel));
int vips_invert( VipsImage *in, VipsImage **out, ... )
	__attribute__((sentinel));
int vips_linear( VipsImage *in, VipsImage **out, 
	double *a, double *b, int n, ... )
	__attribute__((sentinel));
int vips_linear1( VipsImage *in, VipsImage **out, double a, double b, ... )
	__attribute__((sentinel));
int vips_math( VipsImage *in, VipsImage **out, 
	VipsMathOperation operation, ... )
	__attribute__((sentinel));
int vips_abs( VipsImage *in, VipsImage **out, ... )
	__attribute__((sentinel));
int vips_sign( VipsImage *in, VipsImage **out, ... )
	__attribute__((sentinel));
int vips_stats( VipsImage *in, VipsImage **out, ... )
	__attribute__((sentinel));
int vips_measure( VipsImage *in, VipsImage **out, int h, int v, ... )
	__attribute__((sentinel));




int im_maxpos_avg( VipsImage *im, double *xpos, double *ypos, double *out );
int im_maxpos_vec( VipsImage *im, int *xpos, int *ypos, double *maxima, int n );
int im_minpos_vec( VipsImage *im, int *xpos, int *ypos, double *minima, int n );
int im_bandmean( VipsImage *in, VipsImage *out );

int im_remainder( VipsImage *in1, VipsImage *in2, VipsImage *out );
int im_remainder_vec( VipsImage *in, VipsImage *out, int n, double *c );
int im_remainderconst( VipsImage *in, VipsImage *out, double c );
int im_recomb( VipsImage *in, VipsImage *out, DOUBLEMASK *recomb );

int im_floor( VipsImage *in, VipsImage *out );
int im_rint( VipsImage *in, VipsImage *out );
int im_ceil( VipsImage *in, VipsImage *out );

int im_linreg( VipsImage **ins, VipsImage *out, double *xs );
int im_point( VipsImage *im, VipsInterpolate *interpolate, 
	double x, double y, int band, double *out );
int im_point_bilinear( VipsImage *im, 
	double x, double y, int band, double *out );

int im_powtra( VipsImage *in, VipsImage *out, double e );
int im_powtra_vec( VipsImage *in, VipsImage *out, int n, double *e );
int im_expntra( VipsImage *in, VipsImage *out, double e );
int im_expntra_vec( VipsImage *in, VipsImage *out, int n, double *e );

int im_cross_phase( VipsImage *a, VipsImage *b, VipsImage *out );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*IM_ARITHMETIC_H*/
