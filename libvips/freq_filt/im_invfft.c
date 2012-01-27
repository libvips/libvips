/* im_invfft
 *
 * Copyright: 1990, N. Dessipris.
 *
 * Author: Nicos Dessipris 
 * Written on: 12/04/1990
 * Modified on :
 * 28/6/95 JC
 *	- rewritten, based on new im_fwfft() code
 * 10/9/98 JC
 *	- frees memory more quickly
 * 2/4/02 JC
 *	- fftw code added
 * 13/7/02 JC
 *	- Type reset
 * 27/2/03 JC
 *	- tiny speed-up ... save 1 copy on write
 * 22/1/04 JC
 *	- oops, fix for segv on wider than high fftw transforms
 * 3/11/04
 *	- added fftw3 support
 * 7/2/10
 * 	- gtkdoc
 * 27/1/12
 * 	- better setting of interpretation
 * 	- remove own fft fallback code
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

#ifdef HAVE_FFTW
#include <fftw.h>
#endif /*HAVE_FFTW*/

#ifdef HAVE_FFTW3
#include <fftw3.h>
#endif /*HAVE_FFTW3*/

#include <vips/vips.h>
#include <vips/internal.h>

#ifdef HAVE_FFTW

/* Call fftw for a 1 band image.
 */
static int 
invfft1( IMAGE *dummy, IMAGE *in, IMAGE *out )
{
	fftwnd_plan plan;

	IMAGE *cmplx = im_open_local( out, "invfft1:1", "t" );

	/* Make dp complex image.
	 */
	if( !cmplx || im_pincheck( in ) || im_poutcheck( out ) )
		return( -1 );
	if( in->Coding != IM_CODING_NONE || in->Bands != 1 ) {
                im_error( "im_invfft", "%s", _( "one band uncoded only" ) );
                return( -1 );
	}
	if( im_clip2fmt( in, cmplx, IM_BANDFMT_DPCOMPLEX ) )
                return( -1 );

	/* Make the plan for the transform. Yes, they really do use nx for
	 * height and ny for width.
	 */
	if( !(plan = fftw2d_create_plan( in->Ysize, in->Xsize,
		FFTW_BACKWARD, 
		FFTW_MEASURE | FFTW_USE_WISDOM | FFTW_IN_PLACE )) ) {
                im_error( "im_invfft", 
			"%s", _( "unable to create transform plan" ) );
		return( -1 );
	}

	fftwnd_one( plan, (fftw_complex *) cmplx->data, NULL );

	fftwnd_destroy_plan( plan );

	cmplx->Type = IM_TYPE_B_W;

	/* Copy to out.
	 */
        if( im_copy( cmplx, out ) )
                return( -1 );

	return( 0 );
}

#elif defined HAVE_FFTW3

/* Complex to complex inverse transform.
 */
static int 
invfft1( IMAGE *dummy, IMAGE *in, IMAGE *out )
{
	fftw_plan plan;

	IMAGE *cmplx = im_open_local( out, "invfft1:1", "t" );

	/* We have to have a separate buffer for the planner to work on.
	 */
	double *planner_scratch = IM_ARRAY( dummy, 
		VIPS_IMAGE_N_PELS( in ) * 2, double );

	/* Make dp complex image.
	 */
	if( !cmplx || im_pincheck( in ) || im_poutcheck( out ) )
		return( -1 );
	if( in->Coding != IM_CODING_NONE || in->Bands != 1 ) {
                im_error( "im_invfft", 
			"%s", _( "one band uncoded only" ) );
                return( -1 );
	}
	if( im_clip2fmt( in, cmplx, IM_BANDFMT_DPCOMPLEX ) )
                return( -1 );

	/* Make the plan for the transform. Yes, they really do use nx for
	 * height and ny for width.
	 */
	if( !(plan = fftw_plan_dft_2d( in->Ysize, in->Xsize,
		(fftw_complex *) planner_scratch, 
		(fftw_complex *) planner_scratch,
		FFTW_BACKWARD, 
		0 )) ) {
                im_error( "im_invfft", 
			"%s", _( "unable to create transform plan" ) );
		return( -1 );
	}

	fftw_execute_dft( plan, 
		(fftw_complex *) cmplx->data, (fftw_complex *) cmplx->data );

	fftw_destroy_plan( plan );

	cmplx->Type = IM_TYPE_B_W;

	/* Copy to out.
	 */
        if( im_copy( cmplx, out ) )
                return( -1 );

	return( 0 );
}

#else 

static int 
invfft1( IMAGE *dummy, IMAGE *in, IMAGE *out )
{
	im_error( "im_invfft", 
		"%s", _( "vips configured without FFT support" ) );
	return( -1 );
}

#endif 

/**
 * im_invfft:
 * @in: input image
 * @out: output image
 *
 * Transform an image from Fourier space to real space. The result is complex.
 * If you are OK with a real result, use im_invfftr() instead, it's quicker.
 *
 * VIPS uses the fftw3 or fftw2 Fourier transform libraries if possible. If 
 * they were not available when VIPS was built, it falls back to it's own 
 * FFT functions which are slow and only work for square images whose sides
 * are a power of two.
 *
 * See also: im_invfftr(), im_fwfft(), im_disp_ps().
 *
 * Returns: 0 on success, -1 on error.
 */
int 
im_invfft( IMAGE *in, IMAGE *out )
{
	IMAGE *dummy = im_open( "im_invfft:1", "p" );

	if( !dummy )
		return( -1 );
	if( im__fftproc( dummy, in, out, invfft1 ) ) {
		im_close( dummy );
		return( -1 );
	}
	im_close( dummy );

	return( 0 );
}
