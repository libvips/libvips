/* resample.h
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

#ifndef VIPS_RESAMPLE_H
#define VIPS_RESAMPLE_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

int im_match_linear( VipsImage *ref, VipsImage *sec, VipsImage *out,
	int xr1, int yr1, int xs1, int ys1,
	int xr2, int yr2, int xs2, int ys2 );
int im_match_linear_search( VipsImage *ref, VipsImage *sec, VipsImage *out,
	int xr1, int yr1, int xs1, int ys1,
	int xr2, int yr2, int xs2, int ys2,
	int hwindowsize, int hsearchsize );



int vips_quadratic( VipsImage *in, VipsImage **out, VipsImage *coeff, ... )
	__attribute__((sentinel));
int vips_shrink( VipsImage *in, VipsImage **out, 
	double xshrink, double yshrink, ... )
	__attribute__((sentinel));
int vips_affine( VipsImage *in, VipsImage **out, 
	double a, double b, double c, double d, ... )
	__attribute__((sentinel));

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*VIPS_RESAMPLE_H*/
