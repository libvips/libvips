/* Create masks and filter with them.
 *
 * Copyright: N. Dessipris 1991,
 * Written on: Nov 1991
 * Updated on: Dec 1991
 * 20/9/95 JC
 *	- modernised 
 * 22/3/10
 * 	- gtkdoc
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <math.h>
#include <stdarg.h>

#include <vips/vips.h>
#include <vips/internal.h>

/* Create the final mask by copying the 1/4 of the mask held by coeff
 *  The final mask is written onto image on a line by line basis
 *  The buffer coeff should hold (xsize/2+1)*(ysize/2+1) elms
 *  The created mask is not rotated; so the center is at (0, 0)
 */
static int 
copy_quarter( IMAGE *out, float *coeff_s )
{
	float *line, *cpline;
	float *coeff, *cpcoeff;
	int x, y;
	int hxsplus1;
	
	if( !(line = IM_ARRAY( out, out->Xsize, float )) )
		return( -1 );

	hxsplus1 = out->Xsize/2 + 1;
	coeff = coeff_s;
        for( y = 0; y < out->Ysize/2; y++ ) {
                cpline = line;
                cpcoeff = coeff; coeff += hxsplus1;

                for( x = 0; x < out->Xsize/2; x++ )
                        *cpline++ = *cpcoeff++;
                for( x = out->Xsize/2; x < out->Xsize; x++ )
                        *cpline++ = *cpcoeff--;
                if( im_writeline( y, out, (VipsPel *) line ) )
                        return( -1 );
	}

        for( y = out->Ysize/2; y < out->Ysize; y++ ) {
                cpline = line;
                cpcoeff = coeff; coeff -= hxsplus1;

                for( x = 0; x < out->Xsize/2; x++ )
                        *cpline++ = *cpcoeff++;
                for( x = out->Xsize/2; x < out->Xsize; x++ )
                        *cpline++ = *cpcoeff--;
                if( im_writeline( y, out, (VipsPel *) line ) )
                        return( -1 );
	}

	return( 0 );
}

/* Make a mask image.
 */
static int 
build_freq_mask( IMAGE *out, int xs, int ys, VipsMaskType flag, va_list ap )
{
	float *coeff;
	extern float *im__create_quarter( IMAGE *, 
		int, int, VipsMaskType, va_list );

	/* Check sizes and create one quarter of the final mask 
	 */
	if( !im_ispoweroftwo( xs ) || !im_ispoweroftwo( ys ) ) {
		im_error( "im_freq_mask", "%s", 
			_( "mask sizes power of 2 only" ) );
		return( -1 );
	}

	/* Create the output image.
	 */
        im_initdesc( out, xs, ys, 1, IM_BBITS_FLOAT, IM_BANDFMT_FLOAT,
		IM_CODING_NONE, IM_TYPE_B_W, 1.0, 1.0, 0, 0 );
        if( im_setupout( out ) )
                return( -1 );

	switch( flag ) {
	case VIPS_MASK_IDEAL_HIGHPASS:
	case VIPS_MASK_IDEAL_LOWPASS:
	case VIPS_MASK_BUTTERWORTH_HIGHPASS:
	case VIPS_MASK_BUTTERWORTH_LOWPASS:
	case VIPS_MASK_GAUSS_HIGHPASS:
	case VIPS_MASK_GAUSS_LOWPASS:

	case VIPS_MASK_IDEAL_RINGPASS:
	case VIPS_MASK_IDEAL_RINGREJECT:
	case VIPS_MASK_BUTTERWORTH_RINGPASS:
	case VIPS_MASK_BUTTERWORTH_RINGREJECT:
	case VIPS_MASK_GAUSS_RINGPASS:
	case VIPS_MASK_GAUSS_RINGREJECT:

	case VIPS_MASK_FRACTAL_FLT:
		/* All these are created as a quarter and duplicated.
		 */
		if( !(coeff = im__create_quarter( out, xs, ys, flag, ap )) ||
			copy_quarter( out, coeff ) )
			return( -1 );
		break;

	case VIPS_MASK_IDEAL_BANDPASS:
	case VIPS_MASK_IDEAL_BANDREJECT:
	case VIPS_MASK_BUTTERWORTH_BANDPASS:
	case VIPS_MASK_BUTTERWORTH_BANDREJECT:
	case VIPS_MASK_GAUSS_BANDPASS:
	case VIPS_MASK_GAUSS_BANDREJECT:
		/* Created all in one go.
		 */
		if( im__fmaskcir( out, flag, ap ) )
			return( -1 );
		break;

	default:
	       im_error( "im_freq_mask", "%s", _( "unimplemented mask type" ) );
	       return( -1 );
	}

	return( 0 );
}

/**
 * im_flt_image_freq: 
 * @in: input image
 * @out: output image
 * @flag: mask type
 * @Varargs: mask parameters
 *
 * Creates a mask (see im_create_fmask()) and filters an image with it (see
 * im_freqflt()).
 *
 * See also: im_create_fmask(), im_freqflt(), 
 *
 * Returns: 0 on success, -1 on error
 */
int 
im_flt_image_freq( IMAGE *in, IMAGE *out, VipsMaskType flag, ... )
{
        IMAGE *mask = im_open_local( out, "tempmask", "p" );
	va_list ap;

        if( !mask )
		return( -1 );

	/* Generate mask.
	 */
        va_start( ap, flag );
        if( build_freq_mask( mask, in->Xsize, in->Ysize, flag, ap ) )
                return( -1 );
        va_end( ap );

        if( im_freqflt( in, mask, out ) )
                return( -1 );

        return( 0 );
}

/**
 * im_create_fmask:
 * @out: image to write to
 * @xsize: image size
 * @ysize: image size
 * @flag: mask type
 * @Varargs: mask parameters
 *
 * This operation creates a one-band float image of the specified size. The
 * image must be square, and the sides must be a power of two. The image has
 * values in the range [0, 1] and is typically used for multiplying against 
 * frequency domain images to filter them.
 *
 * All masks are created with the DC component at (0, 0), so you might want to
 * rotate the quadrants with im_rotquad() before viewing. The DC pixel always
 * has the value 1.0.
 *
 * The value of @flag sets the type pf mask created, and extra parameters set
 * the exact mask shape. All extra parameters are doubles. This table 
 * summarises the possible values:
 *
 * <table>
 *   <title>Parameters for im_create_fmask()</title>
 *   <tgroup cols='2' align='left' colsep='1' rowsep='1'>
 *     <thead>
 *       <row>
 *         <entry>#VipsMaskType</entry>
 *         <entry>nargs</entry>
 *         <entry>Parameters (all double)</entry>
 *       </row>
 *     </thead>
 *     <tbody>
 *       <row>
 *         <entry>#VIPS_MASK_IDEAL_HIGHPASS</entry>
 *         <entry>1</entry>
 *         <entry>frequency_cutoff</entry>
 *       </row>
 *       <row>
 *         <entry>#VIPS_MASK_IDEAL_LOWPASS</entry>
 *         <entry>1</entry>
 *         <entry>frequency_cutoff</entry>
 *       </row>
 *       <row>
 *         <entry>#VIPS_MASK_BUTTERWORTH_HIGHPASS</entry>
 *         <entry>3</entry>
 *         <entry>order, frequency_cutoff, amplitude_cutoff</entry>
 *       </row>
 *       <row>
 *         <entry>#VIPS_MASK_BUTTERWORTH_LOWPASS</entry>
 *         <entry>3</entry>
 *         <entry>order, frequency_cutoff, amplitude_cutoff</entry>
 *       </row>
 *       <row>
 *         <entry>#VIPS_MASK_GAUSS_HIGHPASS</entry>
 *         <entry>2</entry>
 *         <entry>frequency_cutoff, amplitude_cutoff</entry>
 *       </row>
 *       <row>
 *         <entry>#VIPS_MASK_GAUSS_LOWPASS</entry>
 *         <entry>2</entry>
 *         <entry>frequency_cutoff, amplitude_cutoff</entry>
 *       </row>
 *       <row>
 *         <entry>#VIPS_MASK_IDEAL_RINGPASS</entry>
 *         <entry>2</entry>
 *         <entry>frequency_cutoff, width</entry>
 *       </row>
 *       <row>
 *         <entry>#VIPS_MASK_IDEAL_RINGREJECT</entry>
 *         <entry>2</entry>
 *         <entry>frequency_cutoff, width</entry>
 *       </row>
 *       <row>
 *         <entry>#VIPS_MASK_BUTTERWORTH_RINGPASS</entry>
 *         <entry>4</entry>
 *         <entry>order, frequency_cutoff, width, amplitude_cutoff</entry>
 *       </row>
 *       <row>
 *         <entry>#VIPS_MASK_BUTTERWORTH_RINGREJECT</entry>
 *         <entry>4</entry>
 *         <entry>order, frequency_cutoff, width, amplitude_cutoff</entry>
 *       </row>
 *       <row>
 *         <entry>#VIPS_MASK_GAUSS_RINGPASS</entry>
 *         <entry>3</entry>
 *         <entry>frequency_cutoff, width, amplitude_cutoff</entry>
 *       </row>
 *       <row>
 *         <entry>#VIPS_MASK_GAUSS_RINGREJECT</entry>
 *         <entry>3</entry>
 *         <entry>frequency_cutoff, width, amplitude_cutoff</entry>
 *       </row>
 *       <row>
 *         <entry>#VIPS_MASK_IDEAL_BANDPASS</entry>
 *         <entry>3</entry>
 *         <entry>frequency_cutoffx, frequency_cutoffy, radius</entry>
 *       </row>
 *       <row>
 *         <entry>#VIPS_MASK_IDEAL_BANDREJECT</entry>
 *         <entry>3</entry>
 *         <entry>frequency_cutoffx, frequency_cutoffy, radius</entry>
 *       </row>
 *       <row>
 *         <entry>#VIPS_MASK_BUTTERWORTH_BANDPASS</entry>
 *         <entry>5</entry>
 *         <entry>order, frequency_cutoffx, frequency_cutoffy, radius,
 *         amplitude_cutoff</entry>
 *       </row>
 *       <row>
 *         <entry>#VIPS_MASK_BUTTERWORTH_BANDREJECT</entry>
 *         <entry>5</entry>
 *         <entry>order, frequency_cutoffx, frequency_cutoffy, radius,
 *         amplitude_cutoff</entry>
 *       </row>
 *       <row>
 *         <entry>#VIPS_MASK_GAUSS_BANDPASS</entry>
 *         <entry>4</entry>
 *         <entry>frequency_cutoffx, frequency_cutoffy, radius, 
 *         amplitude_cutoff</entry>
 *       </row>
 *       <row>
 *         <entry>#VIPS_MASK_GAUSS_BANDREJECT</entry>
 *         <entry>4</entry>
 *         <entry>frequency_cutoffx, frequency_cutoffy, radius, 
 *         amplitude_cutoff</entry>
 *       </row>
 *       <row>
 *         <entry>#VIPS_MASK_FRACTAL_FLT</entry>
 *         <entry>1</entry>
 *         <entry>fractal_dimension</entry>
 *       </row>
 *     </tbody>
 *   </tgroup>
 * </table>
 *
 * Unless noted below, all parameters are expressed as percentages, scaled to
 * [0, 1].
 *
 * <emphasis>High-pass, low-pass masks:</emphasis> A high pass filter 
 * mask filters the low frequencies while allowing the high frequencies to 
 * get through.  The reverse happens with a low pass filter mask.  
 *
 * <emphasis>Ring-pass, ring-reject masks:</emphasis> A ring filter passes or
 * rejects a range of frequencies. The range is specified by the
 * @frequency_cutoff and the @width.
 * 
 * <emphasis>Band-pass, band-reject masks:</emphasis> These masks are used to
 * pass or remove spatial frequencies around a given frequency. The position
 * of the frequency to pass or remove is given by @frequency_cutoffx and
 * @frequency_cutoffy. The size of the region around the point is given by
 * @radius.
 *
 * <emphasis>Ideal filters:</emphasis> These filters pass or reject
 * frequencies with a sharp cutoff at the transition.
 *
 * <emphasis>Butterworth filters:</emphasis> These filters use a Butterworth
 * function to separate the frequencies (see Gonzalez and Wintz, Digital
 * Image Processing, 1987). The shape of the curve is controlled by @order:
 * higher values give a sharper transition.
 *
 * <emphasis>Gaussian filters:</emphasis> These filters have a smooth Gaussian
 * shape, controlled by @amplitude_cutoff.
 *
 * <emphasis>VIPS_MASK_FRACTAL_FLT:</emphasis> This mask is handy for
 * filtering images of gaussian noise in order to create surfaces of a given
 * fractal dimension. @fractal_dimension should be between 2 and 3.
 *
 * See also: im_flt_image_freq(), im_rotquad(), 
 *
 * Returns: 0 on success, -1 on error
 */
int 
im_create_fmask( IMAGE *out, int xsize, int ysize, VipsMaskType flag, ... )
{
	va_list ap;

	va_start( ap, flag );
	if( build_freq_mask( out, xsize, ysize, flag, ap ) )
		return( -1 );
	va_end( ap );

	return( 0 );
}
