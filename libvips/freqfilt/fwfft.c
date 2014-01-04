/* forward FFT
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
 * 3/1/14
 * 	- redone as a class
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <stdlib.h>

#include <vips/vips.h>
#include "pfreqfilt.h"

#ifdef HAVE_FFTW

#include <fftw3.h>

typedef struct _VipsFwfft {
	VipsFreqfilt parent_instance;

} VipsFwfft;

typedef VipsFreqfiltClass VipsFwfftClass;

G_DEFINE_TYPE( VipsFwfft, vips_fwfft, VIPS_TYPE_FREQFILT );

/* Real to complex forward transform.
 */
static int 
rfwfft1( VipsObject *object, VipsImage *in, VipsImage **out )
{
	VipsFwfft *fwfft = (VipsFwfft *) object;
	VipsImage **t = (VipsImage **) vips_object_local_array( object, 4 );
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( fwfft );
	const guint64 size = VIPS_IMAGE_N_PELS( in );
	const int half_width = in->Xsize / 2 + 1;

	double *half_complex;
	double *planner_scratch;

	fftw_plan plan;
	double *buf, *q, *p;
	int x, y;

	if( vips_check_mono( class->nickname, in ) ||
		vips_check_uncoded( class->nickname, in ) )
                return( -1 );

	/* Convert input to a real double membuffer.
	 */
	t[1] = vips_image_new_buffer();
	if( vips_cast_double( in, &t[0], NULL ) ||
		vips_image_write( t[0], t[1] ) ); 

	/* Make the plan for the transform. Yes, they really do use nx for
	 * height and ny for width. Use a separate scratch buffer for the
	 * planner, we can't overwrite real->data
	 */
	if( !(planner_scratch = VIPS_ARRAY( fwfft, 
		VIPS_IMAGE_N_PELS( in ), double )) )
		return( -1 );
	if( !(half_complex = VIPS_ARRAY( fwfft, 
		in->Ysize * half_width * 2, double )) )
		return( -1 );
	if( !(plan = fftw_plan_dft_r2c_2d( in->Ysize, in->Xsize,
		planner_scratch, (fftw_complex *) half_complex,
		0 )) ) {
                vips_error( class->nickname, 
			"%s", _( "unable to create transform plan" ) );
		return( -1 );
	}

	fftw_execute_dft_r2c( plan,
		(double *) t[1]->data, (fftw_complex *) half_complex );

	fftw_destroy_plan( plan );

	/* Write to out as another memory buffer. 
	 */
	*out = vips_image_new_buffer();
	if( vips_image_pipelinev( *out, VIPS_DEMAND_STYLE_ANY, in, NULL ) )
                return( -1 );
	(*out)->BandFmt = VIPS_FORMAT_DPCOMPLEX;
	(*out)->Type = VIPS_INTERPRETATION_FOURIER;
	if( !(buf = VIPS_ARRAY( fwfft, VIPS_IMAGE_N_PELS( *out ), double )) )
		return( -1 );

	/* Copy and normalise. The right half is the up/down and 
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

	for( x = half_width; x < (*out)->Xsize; x++ ) {
		q[0] = p[0] / size;
		q[1] = -1.0 * p[1] / size;
		p -= 2;
		q += 2;
	}

	if( vips_image_write_line( *out, 0, (VipsPel *) buf ) )
		return( -1 );

	for( y = 1; y < (*out)->Ysize; y++ ) {
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
			(((*out)->Ysize - y + 1) * half_width - 2 + 
				(in->Xsize & 1));

		for( x = half_width; x < (*out)->Xsize; x++ ) {
			q[0] = p[0] / size;
			q[1] = -1.0 * p[1] / size;
			p -= 2;
			q += 2;
		}

		if( vips_image_write_line( *out, y, (VipsPel *) buf ) )
			return( -1 );
	}

	return( 0 );
}

/* Complex to complex forward transform.
 */
static int 
cfwfft1( VipsObject *object, VipsImage *in, VipsImage **out )
{
	VipsFwfft *fwfft = (VipsFwfft *) object;
	VipsImage **t = (VipsImage **) vips_object_local_array( object, 4 );
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( fwfft );

	fftw_plan plan;
	double *planner_scratch;
	double *buf, *q, *p;
	int x, y;

	if( vips_check_mono( class->nickname, in ) ||
		vips_check_uncoded( class->nickname, in ) )
                return( -1 );

	/* Convert input to a complex double membuffer.
	 */
	t[1] = vips_image_new_buffer();
	if( vips_cast_dpcomplex( in, &t[0], NULL ) ||
		vips_image_write( t[0], t[1] ) ); 

	/* We have to have a separate buffer for the planner to work on.
	 */
	if( !(planner_scratch = VIPS_ARRAY( fwfft, 
		VIPS_IMAGE_N_PELS( in ) * 2, double )) )
		return( -1 );

	/* Make the plan for the transform.
	 */
	if( !(plan = fftw_plan_dft_2d( in->Ysize, in->Xsize,
		(fftw_complex *) planner_scratch, 
		(fftw_complex *) planner_scratch,
		FFTW_FORWARD, 
		0 )) ) {
                vips_error( class->nickname, 
			"%s", _( "unable to create transform plan" ) );
		return( -1 );
	}

	fftw_execute_dft( plan,
		(fftw_complex *) t[1]->data, (fftw_complex *) t[1]->data );

	fftw_destroy_plan( plan );

	/* Write to out as another memory buffer. 
	 */
	*out = vips_image_new_buffer();
	if( vips_image_pipelinev( *out, VIPS_DEMAND_STYLE_ANY, in, NULL ) )
                return( -1 );
	(*out)->BandFmt = VIPS_FORMAT_DPCOMPLEX;
	(*out)->Type = VIPS_INTERPRETATION_FOURIER;
	if( !(buf = VIPS_ARRAY( fwfft, VIPS_IMAGE_N_PELS( *out ), double )) )
		return( -1 );

	/* Copy to out, normalise.
	 */
	p = (double *) t[1]->data;
	for( y = 0; y < (*out)->Ysize; y++ ) {
		guint64 size = VIPS_IMAGE_N_PELS( *out );

		q = buf;

		for( x = 0; x < (*out)->Xsize; x++ ) {
			q[0] = p[0] / size;
			q[1] = p[1] / size;
			p += 2;
			q += 2;
		}

		if( vips_image_write_line( *out, y, (VipsPel *) buf ) )
			return( -1 );
	}

	return( 0 );
}

static int
vips_fwfft_build( VipsObject *object )
{
	VipsFreqfilt *freqfilt = VIPS_FREQFILT( object );
	VipsFwfft *fwfft = (VipsFwfft *) object;
	VipsImage **t = (VipsImage **) vips_object_local_array( object, 4 );

	if( VIPS_OBJECT_CLASS( vips_fwfft_parent_class )->
		build( object ) )
		return( -1 );

	if( vips_bandfmt_iscomplex( freqfilt->in->BandFmt ) ) {
		if( vips__fftproc( VIPS_OBJECT( fwfft ), freqfilt->in, &t[0], 
			cfwfft1 ) )
			return( -1 );
	}
	else {
		if( vips__fftproc( VIPS_OBJECT( fwfft ), freqfilt->in, &t[0], 
			rfwfft1 ) )
			return( -1 );
	}

	if( vips_image_write( t[0], freqfilt->out ) ) 
		return( -1 );

	return( 0 );
}

static void
vips_fwfft_class_init( VipsFwfftClass *class )
{
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	vobject_class->nickname = "fwfft";
	vobject_class->description = _( "forward FFT" );
	vobject_class->build = vips_fwfft_build;

}

static void
vips_fwfft_init( VipsFwfft *fwfft )
{
}

#endif /*HAVE_FFTW*/

/**
 * vips_fwfft:
 * @in: input image 
 * @out: output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Transform an image to Fourier space.
 *
 * VIPS uses the fftw Fourier Transform library. If this library was not
 * available when VIPS was configured, these functions will fail.
 *
 * See also: vips_invfft().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_fwfft( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "fwfft", ap, in, out );
	va_end( ap );

	return( result );
}

