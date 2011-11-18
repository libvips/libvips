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
 * VipsOperationMath:
 * @VIPS_OPERATION_MATH_SIN: sin(), angles in degrees
 * @VIPS_OPERATION_MATH_COS: cos(), angles in degrees
 * @VIPS_OPERATION_MATH_TAN: tan(), angles in degrees
 * @VIPS_OPERATION_MATH_ASIN: asin(), angles in degrees
 * @VIPS_OPERATION_MATH_ACOS: acos(), angles in degrees
 * @VIPS_OPERATION_MATH_ATAN: atan(), angles in degrees
 * @VIPS_OPERATION_MATH_LOG: log base e 
 * @VIPS_OPERATION_MATH_LOG10: log base 10 
 * @VIPS_OPERATION_MATH_EXP: e to the something
 * @VIPS_OPERATION_MATH_EXP10: 10 to the something
 *
 * See also: vips_math().
 */
typedef enum {
	VIPS_OPERATION_MATH_SIN,
	VIPS_OPERATION_MATH_COS,
	VIPS_OPERATION_MATH_TAN,
	VIPS_OPERATION_MATH_ASIN,
	VIPS_OPERATION_MATH_ACOS,
	VIPS_OPERATION_MATH_ATAN,
	VIPS_OPERATION_MATH_LOG,
	VIPS_OPERATION_MATH_LOG10,
	VIPS_OPERATION_MATH_EXP,
	VIPS_OPERATION_MATH_EXP10,
	VIPS_OPERATION_MATH_LAST
} VipsOperationMath;

/** 
 * VipsOperationMath2:
 * @VIPS_OPERATION_MATH_POW: pow( left, right )
 * @VIPS_OPERATION_MATH_WOP: pow( right, left ) 
 *
 * See also: vips_math().
 */
typedef enum {
	VIPS_OPERATION_MATH2_POW,
	VIPS_OPERATION_MATH2_WOP,
	VIPS_OPERATION_MATH2_LAST
} VipsOperationMath2;

/** 
 * VipsOperationRound:
 * @VIPS_OPERATION_ROUND_NEAREST: round to nearest
 * @VIPS_OPERATION_ROUND_FLOOR: largest integral value not greater than
 * @VIPS_OPERATION_ROUND_CEIL: the smallest integral value not less than
 *
 * See also: vips_round().
 */
typedef enum {
	VIPS_OPERATION_ROUND_NEAREST,
	VIPS_OPERATION_ROUND_CEIL,
	VIPS_OPERATION_ROUND_FLOOR,
	VIPS_OPERATION_ROUND_LAST
} VipsOperationRound;

/** 
 * VipsOperationRelational:
 * @VIPS_OPERATION_RELATIONAL_EQUAL: ==
 * @VIPS_OPERATION_RELATIONAL_NOTEQUAL: !=
 * @VIPS_OPERATION_RELATIONAL_LESS: <
 * @VIPS_OPERATION_RELATIONAL_LESSEQ: <=
 * @VIPS_OPERATION_RELATIONAL_MORE: >
 * @VIPS_OPERATION_RELATIONAL_MOREEQ: >=
 *
 * See also: vips_relational().
 */
typedef enum {
	VIPS_OPERATION_RELATIONAL_EQUAL,
	VIPS_OPERATION_RELATIONAL_NOTEQUAL,
	VIPS_OPERATION_RELATIONAL_LESS,
	VIPS_OPERATION_RELATIONAL_LESSEQ,
	VIPS_OPERATION_RELATIONAL_MORE,
	VIPS_OPERATION_RELATIONAL_MOREEQ,
	VIPS_OPERATION_RELATIONAL_LAST
} VipsOperationRelational;

/** 
 * VipsOperationBoolean:
 * @VIPS_OPERATION_BOOLEAN_AND: &
 * @VIPS_OPERATION_BOOLEAN_OR: |
 * @VIPS_OPERATION_BOOLEAN_EOR: ^
 *
 * See also: vips_boolean().
 */
typedef enum {
	VIPS_OPERATION_BOOLEAN_AND,
	VIPS_OPERATION_BOOLEAN_OR,
	VIPS_OPERATION_BOOLEAN_EOR,
	VIPS_OPERATION_BOOLEAN_LSHIFT,
	VIPS_OPERATION_BOOLEAN_RSHIFT,
	VIPS_OPERATION_BOOLEAN_LAST
} VipsOperationBoolean;

int vips_add( VipsImage *left, VipsImage *right, VipsImage **out, ... )
	__attribute__((sentinel));
int vips_subtract( VipsImage *in1, VipsImage *in2, VipsImage **out, ... )
	__attribute__((sentinel));
int vips_multiply( VipsImage *left, VipsImage *right, VipsImage **out, ... )
	__attribute__((sentinel));
int vips_divide( VipsImage *left, VipsImage *right, VipsImage **out, ... )
	__attribute__((sentinel));
int vips_linear( VipsImage *in, VipsImage **out, 
	double *a, double *b, int n, ... )
	__attribute__((sentinel));
int vips_linear1( VipsImage *in, VipsImage **out, double a, double b, ... )
	__attribute__((sentinel));
int vips_invert( VipsImage *in, VipsImage **out, ... )
	__attribute__((sentinel));
int vips_math( VipsImage *in, VipsImage **out, 
	VipsOperationMath math, ... )
	__attribute__((sentinel));
int vips_abs( VipsImage *in, VipsImage **out, ... )
	__attribute__((sentinel));
int vips_sign( VipsImage *in, VipsImage **out, ... )
	__attribute__((sentinel));
int vips_round( VipsImage *in, VipsImage **out, VipsOperationRound round, ... )
	__attribute__((sentinel));
int vips_relational( VipsImage *left, VipsImage *right, VipsImage **out, 
	VipsOperationRelational relational, ... )
	__attribute__((sentinel));
int vips_relational_const( VipsImage *in, VipsImage **out, 
	VipsOperationRelational relational, double *c, int n, ... )
	__attribute__((sentinel));
int vips_relational_const1( VipsImage *in, VipsImage **out, 
	VipsOperationRelational relational, double c, ... )
	__attribute__((sentinel));
int vips_remainder( VipsImage *left, VipsImage *right, VipsImage **out, ... )
	__attribute__((sentinel));
int vips_remainder_const( VipsImage *in, VipsImage **out, 
	double *c, int n, ... )
	__attribute__((sentinel));
int vips_remainder_const1( VipsImage *in, VipsImage **out, 
	double c, ... )
	__attribute__((sentinel));

int vips_boolean( VipsImage *left, VipsImage *right, VipsImage **out, 
	VipsOperationBoolean boolean, ... )
	__attribute__((sentinel));
int vips_andimage( VipsImage *left, VipsImage *right, VipsImage **out, ... )
	__attribute__((sentinel));
int vips_orimage( VipsImage *left, VipsImage *right, VipsImage **out, ... )
	__attribute__((sentinel));
int vips_eorimage( VipsImage *left, VipsImage *right, VipsImage **out, ... )
	__attribute__((sentinel));
int vips_lshift( VipsImage *left, VipsImage *right, VipsImage **out, ... )
	__attribute__((sentinel));
int vips_rshift( VipsImage *left, VipsImage *right, VipsImage **out, ... )
	__attribute__((sentinel));

int vips_boolean_const( VipsImage *in, VipsImage **out, 
	VipsOperationBoolean boolean, double *c, int n, ... )
	__attribute__((sentinel));
int vips_andimage_const( VipsImage *in, VipsImage **out, double *c, int n, ... )
	__attribute__((sentinel));
int vips_orimage_const( VipsImage *in, VipsImage **out, double *c, int n, ... )
	__attribute__((sentinel));
int vips_eorimage_const( VipsImage *in, VipsImage **out, double *c, int n, ... )
	__attribute__((sentinel));
int vips_lshift_const( VipsImage *in, VipsImage **out, double *c, int n, ... )
	__attribute__((sentinel));
int vips_rshift_const( VipsImage *in, VipsImage **out, double *c, int n, ... )
	__attribute__((sentinel));
int vips_andimage_const1( VipsImage *in, VipsImage **out, double c, ... )
	__attribute__((sentinel));
int vips_orimage_const1( VipsImage *in, VipsImage **out, double c, ... )
	__attribute__((sentinel));
int vips_eorimage_const1( VipsImage *in, VipsImage **out, double c, ... )
	__attribute__((sentinel));
int vips_lshift_const1( VipsImage *in, VipsImage **out, double c, ... )
	__attribute__((sentinel));
int vips_rshift_const1( VipsImage *in, VipsImage **out, double c, ... )
	__attribute__((sentinel));

int vips_math2( VipsImage *left, VipsImage *right, VipsImage **out, 
	VipsOperationMath2 math2, ... )
	__attribute__((sentinel));
int vips_math2_const( VipsImage *in, VipsImage **out, 
	VipsOperationMath2 math2, double *c, int n, ... )
	__attribute__((sentinel));
int vips_math2_const1( VipsImage *in, VipsImage **out, 
	VipsOperationMath2 math2, double c, ... )
	__attribute__((sentinel));

int vips_recomb( VipsImage *in, VipsImage **out, VipsImage *m, ... )
	__attribute__((sentinel));

int vips_avg( VipsImage *in, double *out, ... )
	__attribute__((sentinel));
int vips_deviate( VipsImage *in, double *out, ... )
	__attribute__((sentinel));
int vips_min( VipsImage *in, double *out, ... )
	__attribute__((sentinel));
int vips_max( VipsImage *in, double *out, ... )
	__attribute__((sentinel));
int vips_stats( VipsImage *in, VipsImage **out, ... )
	__attribute__((sentinel));
int vips_measure( VipsImage *in, VipsImage **out, int h, int v, ... )
	__attribute__((sentinel));




int im_maxpos_avg( VipsImage *im, double *xpos, double *ypos, double *out );
int im_maxpos_vec( VipsImage *im, int *xpos, int *ypos, double *maxima, int n );
int im_minpos_vec( VipsImage *im, int *xpos, int *ypos, double *minima, int n );
int im_bandmean( VipsImage *in, VipsImage *out );

int im_linreg( VipsImage **ins, VipsImage *out, double *xs );
int im_point( VipsImage *im, VipsInterpolate *interpolate, 
	double x, double y, int band, double *out );
int im_point_bilinear( VipsImage *im, 
	double x, double y, int band, double *out );

int im_cross_phase( VipsImage *a, VipsImage *b, VipsImage *out );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*IM_ARITHMETIC_H*/
