/* other.h
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

#ifndef IM_OTHER_H
#define IM_OTHER_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

int im_grey( VipsImage *out, const int xsize, const int ysize );
int im_fgrey( VipsImage *out, const int xsize, const int ysize );
int im_make_xy( VipsImage *out, const int xsize, const int ysize );

int im_feye( VipsImage *out,
	const int xsize, const int ysize, const double factor );
int im_eye( VipsImage *out,
	const int xsize, const int ysize, const double factor );
int im_zone( VipsImage *out, int size );
int im_fzone( VipsImage *out, int size );
int im_sines( VipsImage *out,
	int xsize, int ysize, double horfreq, double verfreq );

int im_benchmarkn( VipsImage *in, VipsImage *out, int n );
int im_benchmark2( VipsImage *in, double *out );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*IM_OTHER_H*/
