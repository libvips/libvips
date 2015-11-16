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
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
    02110-1301  USA

 */

/*

    These files are distributed with VIPS - http://www.vips.ecs.soton.ac.uk

 */

#ifndef VIPS_RESAMPLE_H
#define VIPS_RESAMPLE_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

int vips_shrink( VipsImage *in, VipsImage **out, 
	double xshrink, double yshrink, ... )
	__attribute__((sentinel));
int vips_shrinkh( VipsImage *in, VipsImage **out, int xshrink, ... );
int vips_shrinkv( VipsImage *in, VipsImage **out, int yshrink, ... );
int vips_shrink2( VipsImage *in, VipsImage **out, 
	double xshrink, double yshrink, ... );

int vips_similarity( VipsImage *in, VipsImage **out, ... )
	__attribute__((sentinel));
int vips_affine( VipsImage *in, VipsImage **out, 
	double a, double b, double c, double d, ... )
	__attribute__((sentinel));

int vips_resize( VipsImage *in, VipsImage **out, double scale, ... )
	__attribute__((sentinel));

int vips_index( VipsImage *in, VipsImage **out, VipsImage *index, ... ) 
	__attribute__((sentinel));

int vips_quadratic( VipsImage *in, VipsImage **out, VipsImage *coeff, ... )
	__attribute__((sentinel));

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*VIPS_RESAMPLE_H*/
