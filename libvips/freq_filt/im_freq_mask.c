/* @(#) Filter functions
 * &(#) va_alist is a series of double variables
 * @(#)
 * @(#) Used to filter image in in the frequency domain, writes
 * @(#) the result in image out
 * @(#)
 * @(#) int im_flt_image_freq( in, out, flag, num_args, va_alist )
 * @(#) IMAGE *in, *out;
 * @(#) enum mask_type flag;
 * @(#) int num_args;
 * @(#)
 * @(#) Returns 0 on success and -1 on error
 * @(#)
 * @(#) Creates a filter mask used for filtering in the frequency domain
 * @(#) The resultant mask is held by image
 * @(#)
 * @(#) int im_create_fmask(image, xsize, ysize, flag, num_args, va_alist)
 * @(#) IMAGE *image;
 * @(#) int xsize, ysize;
 * @(#) enum mask_type flag;
 * @(#) int num_args;
 * @(#)
 * @(#) Returns 0 on success and -1 on error
 * @(#)
 * @(#) Creates a filter mask used for filtering in the frequency domain
 * @(#) The resultant mask is held by image
 * @(#) Function im_freq_mask() differs from im_create_fmask() in the last
 * @(#) argument only: the latter accepts a va_dcl whereas the former
 * @(#) accepts a va_list pointer pointing to the read arguments of va_dcl
 * @(#)
 * @(#) int im_freq_mask(image, xs, ys, flag, num_args, ap) 
 * @(#) IMAGE *image;
 * @(#) int xs, ys;
 * @(#) enum mask_type flag;
 * @(#) int num_args;
 * @(#) va_list ap;
 * @(#)
 * @(#) Returns 0 on success and -1 on error
 * @(#)
 * Copyright: N. Dessipris 1991,
 * Written on: Nov 1991
 * Updated on: Dec 1991
 * 20/9/95 JC
 *	- modernised 
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
#include <vips/fmask.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

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
                if( im_writeline( y, out, (PEL *) line ) )
                        return( -1 );
	}

        for( y = out->Ysize/2; y < out->Ysize; y++ ) {
                cpline = line;
                cpcoeff = coeff; coeff -= hxsplus1;

                for( x = 0; x < out->Xsize/2; x++ )
                        *cpline++ = *cpcoeff++;
                for( x = out->Xsize/2; x < out->Xsize; x++ )
                        *cpline++ = *cpcoeff--;
                if( im_writeline( y, out, (PEL *) line ) )
                        return( -1 );
	}

	return( 0 );
}

/* Make a mask image.
 */
static int 
build_freq_mask( IMAGE *out, int xs, int ys, MaskType flag, va_list ap )
{
	float *coeff;
	extern float *im__create_quarter( IMAGE *, 
		int, int, MaskType, va_list );

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
	case MASK_IDEAL_HIGHPASS:
	case MASK_IDEAL_LOWPASS:
	case MASK_BUTTERWORTH_HIGHPASS:
	case MASK_BUTTERWORTH_LOWPASS:
	case MASK_GAUSS_HIGHPASS:
	case MASK_GAUSS_LOWPASS:

	case MASK_IDEAL_RINGPASS:
	case MASK_IDEAL_RINGREJECT:
	case MASK_BUTTERWORTH_RINGPASS:
	case MASK_BUTTERWORTH_RINGREJECT:
	case MASK_GAUSS_RINGPASS:
	case MASK_GAUSS_RINGREJECT:

	case MASK_FRACTAL_FLT:
		/* All these are created as a quarter and duplicated.
		 */
		if( !(coeff = im__create_quarter( out, xs, ys, flag, ap )) ||
			copy_quarter( out, coeff ) )
			return( -1 );
		break;

	case MASK_IDEAL_BANDPASS:
	case MASK_IDEAL_BANDREJECT:
	case MASK_BUTTERWORTH_BANDPASS:
	case MASK_BUTTERWORTH_BANDREJECT:
	case MASK_GAUSS_BANDPASS:
	case MASK_GAUSS_BANDREJECT:
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

/* Create a mask, and filter an image with it.
 */
int 
im_flt_image_freq( IMAGE *in, IMAGE *out, MaskType flag, ... )
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

/* Create a filter mask.
 */
int 
im_create_fmask( IMAGE *out, int xsize, int ysize, MaskType flag, ... )
{
	va_list ap;

	va_start( ap, flag );
	if( build_freq_mask( out, xsize, ysize, flag, ap ) )
		return( -1 );
	va_end( ap );

	return( 0 );
}
