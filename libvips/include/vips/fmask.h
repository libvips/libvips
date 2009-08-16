/* @(#) Typical filter function
 * va_list is filter parameters
 * lowpass highpass filters
 * flag = 0 -> idealhpf, parameters: frequency cutoff
 * flag = 1 -> ideallpf, parameters: frequency cutoff
 * flag = 2 -> buthpf, parameters: order, frequency cutoff, amplitude cutoff
 * flag = 3 -> butlpf, parameters: order, frequency cutoff, amplitude cutoff
 * flag = 4 -> gaussianlpf, parameters: frequency cutoff, amplitude cutoff
 * flag = 5 -> gaussianhpf, parameters: frequency cutoff, amplitude cutoff
 * ring pass ring reject filters
 * flag = 6 -> idealrpf, parameters: frequency cutoff, width
 * flag = 7 -> idealrrf, parameters: frequency cutoff, width
 * flag = 8 -> butrpf, parameters: order, freq cutoff, width, ampl cutoff
 * flag = 9 -> butrrf, parameters: order, freq cutoff, width, ampl cutoff
 * flag = 10 -> gaussianrpf, parameters: frequency cutoff, width, ampl cutoff
 * flag = 11 -> gaussianrrf, parameters: frequency cutoff, width, ampl cutoff
 * bandpass bandreject filters
 * flag = 12 -> idealbpf, parameters: center frequency, 2*radius
 * flag = 13 -> idealbrf, parameters: centre frequency, 2*radius
 * flag = 14 -> butbpf, parameters: order, frequency, 2*radius, ampl cutoff
 * flag = 15 -> butbrf, parameters: order, frequency, 2*radius, ampl cutoff
 * flag = 16 -> gaussianbpf, parameters: frequency cutoff, width, ampl cutoff
 * flag = 17 -> gaussianbrf, parameters: frequency cutoff, width, ampl cutoff
 * fractal filters (for filtering gaussian noises only)
 * flag = 18 -> fractal, parameters: fractal dimension
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

#ifndef IM_FMASK_H
#define IM_FMASK_H

typedef enum mask_type {
        MASK_IDEAL_HIGHPASS = 0,
        MASK_IDEAL_LOWPASS = 1,
        MASK_BUTTERWORTH_HIGHPASS = 2,
        MASK_BUTTERWORTH_LOWPASS = 3,
        MASK_GAUSS_HIGHPASS = 4,
        MASK_GAUSS_LOWPASS = 5,

        MASK_IDEAL_RINGPASS = 6,
        MASK_IDEAL_RINGREJECT = 7,
        MASK_BUTTERWORTH_RINGPASS = 8,
        MASK_BUTTERWORTH_RINGREJECT = 9,
        MASK_GAUSS_RINGPASS = 10,
        MASK_GAUSS_RINGREJECT = 11,

        MASK_IDEAL_BANDPASS = 12,
        MASK_IDEAL_BANDREJECT = 13,
        MASK_BUTTERWORTH_BANDPASS = 14,
        MASK_BUTTERWORTH_BANDREJECT = 15,
        MASK_GAUSS_BANDPASS = 16,
        MASK_GAUSS_BANDREJECT = 17,

        MASK_FRACTAL_FLT = 18
} MaskType;

int im_flt_image_freq( IMAGE *in, IMAGE *out, MaskType flag, ... );
int im_create_fmask( IMAGE *out, int xsize, int ysize, MaskType flag, ... );
int im__fmaskcir( IMAGE *out, MaskType flag, va_list ap );

#endif /*IM_FMASK_H*/
