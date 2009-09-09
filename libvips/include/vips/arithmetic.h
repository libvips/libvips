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

/* arithmetic
 */
DOUBLEMASK *im_measure( IMAGE *im, IMAGE_BOX *box, int h, int v, 
	int *sel, int nsel, const char *name );
DOUBLEMASK *im_stats( IMAGE *in );
int im_abs( IMAGE *in, IMAGE *out );
int im_max( IMAGE *in, double *out );
int im_min( IMAGE *in, double *out );
int im_avg( IMAGE *in, double *out );
int im_deviate( IMAGE *in, double *out );
int im_maxpos( IMAGE *in, int *xpos, int *ypos, double *out );
int im_minpos( IMAGE *in, int *xpos, int *ypos, double *out );
int im_maxpos_avg( IMAGE *im, double *xpos, double *ypos, double *out );
int im_maxpos_vec( IMAGE *im, int *xpos, int *ypos, double *maxima, int n );
int im_minpos_vec( IMAGE *im, int *xpos, int *ypos, double *minima, int n );
int im_add( IMAGE *in1, IMAGE *in2, IMAGE *out );
int im_subtract( IMAGE *in1, IMAGE *in2, IMAGE *out );
int im_invert( IMAGE *in, IMAGE *out );
int im_linreg( IMAGE **ins, IMAGE *out, double *xs );
int im_lintra( double a, IMAGE *in, double b, IMAGE *out );
int im_lintra_vec( int n, double *a, IMAGE *in, double *b, IMAGE *out );
int im_multiply( IMAGE *in1, IMAGE *in2, IMAGE *out );
int im_divide( IMAGE *in1, IMAGE *in2, IMAGE *out );
int im_point( IMAGE *im, VipsInterpolate *interpolate, 
	double x, double y, int band, double *out );
int im_point_bilinear( IMAGE *im, double x, double y, int band, double *out );
int im_powtra( IMAGE *in, IMAGE *out, double e );
int im_powtra_vec( IMAGE *in, IMAGE *out, int n, double *e );
int im_exptra( IMAGE *in, IMAGE *out );
int im_exp10tra( IMAGE *in, IMAGE *out );
int im_expntra( IMAGE *in, IMAGE *out, double e );
int im_expntra_vec( IMAGE *in, IMAGE *out, int n, double *e );
int im_logtra( IMAGE *in, IMAGE *out );
int im_log10tra( IMAGE *in, IMAGE *out );
int im_remainder( IMAGE *in1, IMAGE *in2, IMAGE *out );
int im_remainderconst( IMAGE *in, IMAGE *out, double c );
int im_remainderconst_vec( IMAGE *in, IMAGE *out, int n, double *c );
int im_floor( IMAGE *in, IMAGE *out );
int im_rint( IMAGE *in, IMAGE *out );
int im_ceil( IMAGE *in, IMAGE *out );
int im_sintra( IMAGE *in, IMAGE *out );
int im_sign( IMAGE *in, IMAGE *out );
int im_costra( IMAGE *in, IMAGE *out );
int im_tantra( IMAGE *in, IMAGE *out );
int im_asintra( IMAGE *in, IMAGE *out );
int im_acostra( IMAGE *in, IMAGE *out );
int im_atantra( IMAGE *in, IMAGE *out );
int im_cmulnorm( IMAGE *in1, IMAGE *in2, IMAGE *out );
int im_fav4( IMAGE **, IMAGE * );
int im_gadd( double, IMAGE *, double, IMAGE *, double, IMAGE *);
int im_litecor( IMAGE *, IMAGE *, IMAGE *, int, double );
int im_bandmean( IMAGE *in, IMAGE *out );
int im_cross_phase( IMAGE *a, IMAGE *b, IMAGE *out );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*IM_ARITHMETIC_H*/
