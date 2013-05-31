/* freq_filt.h
 *
 * 2/11/09
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

#ifndef IM_FREQ_H
#define IM_FREQ_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

#include <vips/vips.h>

typedef enum {
        VIPS_MASK_IDEAL_HIGHPASS = 0,
        VIPS_MASK_IDEAL_LOWPASS = 1,
        VIPS_MASK_BUTTERWORTH_HIGHPASS = 2,
        VIPS_MASK_BUTTERWORTH_LOWPASS = 3,
        VIPS_MASK_GAUSS_HIGHPASS = 4,
        VIPS_MASK_GAUSS_LOWPASS = 5,

        VIPS_MASK_IDEAL_RINGPASS = 6,
        VIPS_MASK_IDEAL_RINGREJECT = 7,
        VIPS_MASK_BUTTERWORTH_RINGPASS = 8,
        VIPS_MASK_BUTTERWORTH_RINGREJECT = 9,
        VIPS_MASK_GAUSS_RINGPASS = 10,
        VIPS_MASK_GAUSS_RINGREJECT = 11,

        VIPS_MASK_IDEAL_BANDPASS = 12,
        VIPS_MASK_IDEAL_BANDREJECT = 13,
        VIPS_MASK_BUTTERWORTH_BANDPASS = 14,
        VIPS_MASK_BUTTERWORTH_BANDREJECT = 15,
        VIPS_MASK_GAUSS_BANDPASS = 16,
        VIPS_MASK_GAUSS_BANDREJECT = 17,

        VIPS_MASK_FRACTAL_FLT = 18
} VipsMaskType;

int im_fwfft( VipsImage *in, VipsImage *out );
int im_invfft( VipsImage *in, VipsImage *out );
int im_invfftr( VipsImage *in, VipsImage *out );

int im_freqflt( VipsImage *in, VipsImage *mask, VipsImage *out );
int im_disp_ps( VipsImage *in, VipsImage *out );
int im_phasecor_fft( VipsImage *in1, VipsImage *in2, VipsImage *out );

int im_flt_image_freq( VipsImage *in, VipsImage *out, VipsMaskType flag, ... );
int im_create_fmask( VipsImage *out, 
	int xsize, int ysize, VipsMaskType flag, ... );
int im_fractsurf( VipsImage *out, int size, double frd );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*IM_FREQ_H*/
