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

#ifndef IM_RESAMPLE_H
#define IM_RESAMPLE_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

int im_affinei( IMAGE *in, IMAGE *out, 
	VipsInterpolate *interpolate,
	double a, double b, double c, double d, double dx, double dy, 
	int ox, int oy, int ow, int oh );
int im_affinei_all( IMAGE *in, IMAGE *out, VipsInterpolate *interpolate,
	double a, double b, double c, double d, double dx, double dy ) ;

int im_stretch3( IMAGE *in, IMAGE *out, double dx, double dy );

int im_shrink( IMAGE *in, IMAGE *out, double xshrink, double yshrink );
int im_rightshift_size( IMAGE *in, IMAGE *out, int xshift, int yshift, int band_fmt );

int im_match_linear( IMAGE *ref, IMAGE *sec, IMAGE *out,
	int xr1, int yr1, int xs1, int ys1,
	int xr2, int yr2, int xs2, int ys2 );
int im_match_linear_search( IMAGE *ref, IMAGE *sec, IMAGE *out,
	int xr1, int yr1, int xs1, int ys1,
	int xr2, int yr2, int xs2, int ys2,
	int hwindowsize, int hsearchsize );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*IM_RESAMPLE_H*/
