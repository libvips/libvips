/* im_invfftr
 *
 * Modified on :
 * 27/2/03 JC
 *	- from im_invfft.c
 * 22/1/04 JC
 *	- oops, fix for segv on wider than high fftw transforms
 * 3/11/04
 *	- added fftw3 support
 * 7/2/10
 * 	- gtkdoc
 * 27/1/12
 * 	- better setting of interpretation
 * 	- remove own fft fallback code
 * 	- remove fftw2 path
 * 	- reduce memuse
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
#include <fftw3.h>
#endif /*HAVE_FFTW*/

#include <vips/vips.h>
#include <vips/internal.h>

#ifdef HAVE_FFTW

/* Complex to real inverse transform.
 */
static int 
invfft1( IMAGE *dummy, IMAGE *in, IMAGE *out )
{
	const int half_width = in->Xsize / 2 + 1;

	IMAGE *cmplx;
	double *half_complex;
	IMAGE *real;
	double *planner_scratch;
	fftw_plan plan;
	int x, y;
	double *q, *p;

	/* Double-complex input.
	 */
	if( !(cmplx = im_open_local( dummy, "invfft:1", "t" )) ||
		im_clip2fmt( in, cmplx, IM_BANDFMT_DPCOMPLEX ) )
                return( -1 );

	/* Build half-complex image.
	 */
	if( !(half_complex = IM_ARRAY( dummy, 
		in->Ysize * half_width * 2, double )) )
		return( -1 );
	if( im_incheck( cmplx ) )
		return( -1 );
	q = half_complex;
	for( y = 0; y < cmplx->Ysize; y++ ) {
		p = ((double *) cmplx->data) + (guint64) y * in->Xsize * 2; 

		for( x = 0; x < half_width; x++ ) {
			q[0] = p[0];
			q[1] = p[1];
			p += 2;
			q += 2;
		}
	}

	/* Make mem buffer real image for output.
	 */
	if( !(real = im_open_local( out, "invfft1-2", "t" )) )
		return( -1 );
        if( im_cp_desc( real, in ) )
                return( -1 );
	real->BandFmt = IM_BANDFMT_DOUBLE;
	real->Type = IM_TYPE_B_W;
        if( im_setupout( real ) ||
		im_outcheck( real ) )
                return( -1 );

	/* Make the plan for the transform. Yes, they really do use nx for
	 * height and ny for width.
	 */
	if( !(planner_scratch = IM_ARRAY( dummy, 
		in->Ysize * half_width * 2, double )) )
		return( -1 );
	if( !(plan = fftw_plan_dft_c2r_2d( in->Ysize, in->Xsize,
		(fftw_complex *) planner_scratch, (double *) real->data,
		0 )) ) {
                im_error( "im_invfft", 
			"%s", _( "unable to create transform plan" ) );
		return( -1 );
	}

	fftw_execute_dft_c2r( plan,
		(fftw_complex *) half_complex, (double *) real->data );

	fftw_destroy_plan( plan );

        if( im_copy( real, out ) )
                return( -1 );

	return( 0 );
}

#else 

static int 
invfft1( IMAGE *dummy, IMAGE *in, IMAGE *out )
{
	im_error( "im_invfftr", 
		"%s", _( "vips configured without FFT support" ) );
	return( -1 );
}

#endif 

/**
 * im_invfftr:
 * @in: input image
 * @out: output image
 *
 * Transform an image from Fourier space to real space, giving a real result.
 * This is faster than im_invfft(), which gives a complex result. 
 *
 * VIPS uses the fftw3 or fftw2 Fourier transform libraries if possible. If 
 * they were not available when VIPS was built, it falls back to it's own 
 * FFT functions which are slow and only work for square images whose sides
 * are a power of two.
 *
 * See also: im_invfft(), im_fwfft(), im_disp_ps().
 *
 * Returns: 0 on success, -1 on error.
 */
int 
im_invfftr( IMAGE *in, IMAGE *out )
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
