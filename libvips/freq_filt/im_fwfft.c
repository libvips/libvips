/* im_fwfft
 *
 * Copyright: 1990, N. Dessipris.
 *
 * Author: Nicos Dessipris 
 * Written on: 12/04/1990
 * Modified on : 09/05/1990	to cope with float input
 * Modified on : 08/03/1991 	history removed
 * Modified on : 03/04/1991	to cope with any input
 *
 * 28/6/95 JC
 *	- rewritten to use im_clip2f() rather than own code
 * 	- memory leaks fixed
 * 10/9/98 JC
 *	- frees memory more quickly
 * 2/4/02 JC
 *	- fftw code added
 * 13/7/02 JC
 *	- output Type set to IM_TYPE_FOURIER to help nip
 * 27/2/03 JC
 *	- exploits real_to_complex() path in libfftw for real input (thanks
 *	  Matt) for a 2x speed-up
 * 17/11/03 JC
 *	- fix a segv for wider than high images in the real_to_complex() path
 *	  (thanks Andrey)
 *	- fixes to real_to_complex() path to give the correct result for
 *	  non-square images, including odd widths and heights
 * 3/11/04
 *	- added fftw3 support
 * 7/2/10
 * 	- cleanups
 * 	- gtkdoc
 * 25/3/10
 * 	- have a "t" image linked to out to keep the image alive for longer
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

/* Real to complex forward transform.
 */
static int 
rfwfft1( IMAGE *dummy, IMAGE *in, IMAGE *out )
{
	const guint64 size = VIPS_IMAGE_N_PELS( in );
	const int half_width = in->Xsize / 2 + 1;

	IMAGE *real;
	double *half_complex;
	double *planner_scratch;

	fftw_plan plan;
	double *buf, *q, *p;
	int x, y;

	if( vips_check_mono( "im_fwfft", in ) ||
		vips_check_uncoded( "im_fwfft", in ) )
                return( -1 );

	/* Convert input to a real double membuffer.
	 */
	if( !(real = im_open_local( dummy, "fwfft1:1", "t" )) ||
		im_clip2fmt( in, real, IM_BANDFMT_DOUBLE ) )
                return( -1 );

	/* Make the plan for the transform. Yes, they really do use nx for
	 * height and ny for width. Use a separate scratch buffer for the
	 * planner, we can't overwrite real->data
	 */
	if( !(planner_scratch = IM_ARRAY( dummy, 
		VIPS_IMAGE_N_PELS( in ), double )) )
		return( -1 );
	if( !(half_complex = IM_ARRAY( dummy, 
		in->Ysize * half_width * 2, double )) )
		return( -1 );
	if( !(plan = fftw_plan_dft_r2c_2d( in->Ysize, in->Xsize,
		planner_scratch, (fftw_complex *) half_complex,
		0 )) ) {
                im_error( "im_fwfft", 
			"%s", _( "unable to create transform plan" ) );
		return( -1 );
	}

	if( im_incheck( real ) )
		return( -1 );
	fftw_execute_dft_r2c( plan,
		(double *) real->data, (fftw_complex *) half_complex );

	fftw_destroy_plan( plan );

	/* WIO to out.
	 */
	if( im_outcheck( out ) ||
		im_cp_desc( out, in ) )
                return( -1 );
	out->BandFmt = IM_BANDFMT_DPCOMPLEX;
	out->Type = IM_TYPE_FOURIER;
        if( im_setupout( out ) )
                return( -1 );
	if( !(buf = (double *) IM_ARRAY( dummy, 
		IM_IMAGE_SIZEOF_LINE( out ), VipsPel )) )
		return( -1 );

	/* Copy to out and normalise. The right half is the up/down and 
	 * left/right flip of the left, but conjugated. Do the first 
	 * row separately, then mirror around the centre row.
	 */
	p = half_complex;
	q = buf;

	for( x = 0; x < half_width; x++ ) {
		q[0] = p[0] / size;
		q[1] = p[1] / size;
		p += 2;
		q += 2;
	}

	p = half_complex + ((in->Xsize + 1) / 2 - 1) * 2; 

	for( x = half_width; x < out->Xsize; x++ ) {
		q[0] = p[0] / size;
		q[1] = -1.0 * p[1] / size;
		p -= 2;
		q += 2;
	}

	if( im_writeline( 0, out, (VipsPel *) buf ) )
		return( -1 );

	for( y = 1; y < out->Ysize; y++ ) {
		p = half_complex + y * half_width * 2; 
		q = buf;

		for( x = 0; x < half_width; x++ ) {
			q[0] = p[0] / size;
			q[1] = p[1] / size;
			p += 2;
			q += 2;
		}

		/* Good grief. 
		 */
		p = half_complex + 2 *
			((out->Ysize - y + 1) * half_width - 2 + 
				(in->Xsize & 1));

		for( x = half_width; x < out->Xsize; x++ ) {
			q[0] = p[0] / size;
			q[1] = -1.0 * p[1] / size;
			p -= 2;
			q += 2;
		}

		if( im_writeline( y, out, (VipsPel *) buf ) )
			return( -1 );
	}

	return( 0 );
}

/* Complex to complex forward transform.
 */
static int 
cfwfft1( IMAGE *dummy, IMAGE *in, IMAGE *out )
{
	IMAGE *cmplx;
	fftw_plan plan;
	double *planner_scratch;
	double *buf, *q, *p;
	int x, y;

	if( vips_check_mono( "im_fwfft", in ) ||
		vips_check_uncoded( "im_fwfft", in ) )
                return( -1 );

	/* Double-complex input.
	 */
	if( !(cmplx = im_open_local( dummy, "fwfft1:1", "t" )) ||
		im_clip2fmt( in, cmplx, IM_BANDFMT_DPCOMPLEX ) )
                return( -1 );

	/* We have to have a separate buffer for the planner to work on.
	 */
	if( !(planner_scratch = IM_ARRAY( dummy, 
		VIPS_IMAGE_N_PELS( in ) * 2, double )) )
		return( -1 );

	/* Make the plan for the transform.
	 */
	if( !(plan = fftw_plan_dft_2d( in->Ysize, in->Xsize,
		(fftw_complex *) planner_scratch, 
		(fftw_complex *) planner_scratch,
		FFTW_FORWARD, 
		0 )) ) {
                im_error( "im_fwfft", 
			"%s", _( "unable to create transform plan" ) );
		return( -1 );
	}

	if( im_incheck( cmplx ) )
		return( -1 );
	fftw_execute_dft( plan,
		(fftw_complex *) cmplx->data, (fftw_complex *) cmplx->data );

	fftw_destroy_plan( plan );

	/* WIO to out.
	 */
	if( im_outcheck( out ) ||
		im_cp_desc( out, in ) )
                return( -1 );
	out->BandFmt = IM_BANDFMT_DPCOMPLEX;
	out->Type = IM_TYPE_FOURIER;
        if( im_setupout( out ) )
                return( -1 );
	if( !(buf = (double *) IM_ARRAY( dummy, 
		IM_IMAGE_SIZEOF_LINE( out ), VipsPel )) )
		return( -1 );

	/* Copy to out, normalise.
	 */
	for( p = (double *) cmplx->data, y = 0; y < out->Ysize; y++ ) {
		guint64 size = VIPS_IMAGE_N_PELS( out );

		q = buf;

		for( x = 0; x < out->Xsize; x++ ) {
			q[0] = p[0] / size;
			q[1] = p[1] / size;
			p += 2;
			q += 2;
		}

		if( im_writeline( y, out, (VipsPel *) buf ) )
			return( -1 );
	}

	return( 0 );
}

static int 
fwfft1( IMAGE *dummy, IMAGE *in, IMAGE *out )
{
	if( vips_bandfmt_iscomplex( in->BandFmt ) )
		return( cfwfft1( dummy, in, out ) );
	else
		return( rfwfft1( dummy, in, out ) );
}

#else 

static int 
fwfft1( IMAGE *dummy, IMAGE *in, IMAGE *out )
{
	im_error( "im_fwfft", 
		"%s", _( "vips configured without FFT support" ) );
	return( -1 );
}

#endif 

/* Transform an n-band image with a 1-band processing function.
 *
 * Memory strategy: we need memory buffers for the input and the output of
 * fftw. In some modes fftw generates only half the output and we construct
 * the rest.
 *
 * input pipeline -> 
 *   bandsplit -> 
 *     full memory image, freed when im_*fft*() exits -> 
 *       fftw ->
 *         half memory image, freed when im_*fft*() exits ->
 *           full memory image, freed when @out is freed ->
 *             partial bandjoin ->
 *               output pipeline
 *
 * im__fftproc() needs to just call im__fftproc_fn directly for 1 band images,
 * so we can't cache the output in this fn.
 */
int 
im__fftproc( IMAGE *dummy, IMAGE *in, IMAGE *out, im__fftproc_fn fn )
{
	IMAGE **bands;
	IMAGE **fft;
	int b;

	if( in->Bands == 1 ) 
		return( fn( dummy, in, out ) );

	if( !(bands = IM_ARRAY( dummy, in->Bands, IMAGE * )) ||
		im_open_local_array( dummy, bands, in->Bands, "bands", "p" ) )
		return( -1 );

	if( !(fft = IM_ARRAY( out, in->Bands, IMAGE * )) ||
		im_open_local_array( out, fft, in->Bands, "fft", "p" ) )
		return( -1 );

	for( b = 0; b < in->Bands; b++ ) 
		if( im_extract_band( in, bands[b], b ) ||
			fn( dummy, bands[b], fft[b] ) )
			return( -1 );

	if( im_gbandjoin( fft, out, in->Bands ) )
		return( -1 );

	return( 0 );
}

/**
 * im_fwfft:
 * @in: input image
 * @out: output image
 *
 * Transform an image to Fourier space.
 *
 * VIPS uses the fftw Fourier Transform library. If this library was not
 * available when VIPS was configured, these functions will fail.
 *
 * See also: im_invfft(), im_disp_ps().
 *
 * Returns: 0 on success, -1 on error.
 */
int 
im_fwfft( IMAGE *in, IMAGE *out )
{
	IMAGE *dummy;

	if( !(dummy = im_open( "im_fwfft:1", "p" )) )
		return( -1 );
	if( im__fftproc( dummy, in, out, fwfft1 ) ) {
		im_close( dummy );
		return( -1 );
	}
	im_close( dummy );

	return( 0 );
}
