/* create.h
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

#ifndef VIPS_CREATE_H
#define VIPS_CREATE_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

void vips_create_operation_init( void );

int vips_black( VipsImage **out, int width, int height, ... )
	__attribute__((sentinel));

int vips_xyz( VipsImage **out, int width, int height, ... )
	__attribute__((sentinel));
int vips_grey( VipsImage **out, int width, int height, ... )
	__attribute__((sentinel));
int vips_gaussmat( VipsImage **out, double sigma, double min_ampl, ... )
	__attribute__((sentinel));
int vips_logmat( VipsImage **out, double sigma, double min_ampl, ... )
	__attribute__((sentinel));

int vips_text( VipsImage **out, const char *text, ... )
	__attribute__((sentinel));

int vips_gaussnoise( VipsImage **out, int width, int height, ... )
	__attribute__((sentinel));
int vips_eye( VipsImage **out, int width, int height, ... )
	__attribute__((sentinel));
int vips_sines( VipsImage **out, int width, int height, ... )
	__attribute__((sentinel));
int vips_zone( VipsImage **out, int width, int height, ... )
	__attribute__((sentinel));

int vips_identity( VipsImage **out, ... )
	__attribute__((sentinel));
int vips_buildlut( VipsImage *in, VipsImage **out, ... )
	__attribute__((sentinel));
int vips_invertlut( VipsImage *in, VipsImage **out, ... )
	__attribute__((sentinel));
int vips_tonelut( VipsImage **out, ... )
	__attribute__((sentinel));

int vips_mask_ideal( VipsImage **out, int width, int height, 
	double frequency_cutoff, ... )
	__attribute__((sentinel));
int vips_mask_ideal_ring( VipsImage **out, int width, int height, 
	double frequency_cutoff, double bandwidth, ... )
	__attribute__((sentinel));
int vips_mask_ideal_band( VipsImage **out, int width, int height, 
	double frequency_cutoff_x, double frequency_cutoff_y, double r, ... )
	__attribute__((sentinel));
int vips_mask_butterworth( VipsImage **out, int width, int height, 
	double order, double frequency_cutoff, double amplitude_cutoff, ... )
	__attribute__((sentinel));
int vips_mask_butterworth_ring( VipsImage **out, int width, int height, 
	double order, double frequency_cutoff, double amplitude_cutoff, 
	double ringwidth, ... )
	__attribute__((sentinel));
int vips_mask_butterworth_band( VipsImage **out, int width, int height, 
	double order, double frequency_cutoff_x, double frequency_cutoff_y, 
	double r, double amplitude_cutoff, ... )
	__attribute__((sentinel));
int vips_mask_gaussian( VipsImage **out, int width, int height, 
	double frequency_cutoff, double amplitude_cutoff, ... )
	__attribute__((sentinel));
int vips_mask_gaussian_ring( VipsImage **out, int width, int height, 
	double frequency_cutoff, double amplitude_cutoff, double ringwidth, 
	... )
	__attribute__((sentinel));

int im_benchmarkn( VipsImage *in, VipsImage *out, int n );
int im_benchmark2( VipsImage *in, double *out );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*VIPS_CREATE_H*/
