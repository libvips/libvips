/* Inverse FFT
 *
 * Author: Nicos Dessipris 
 * Written on: 12/04/1990
 * Modified on :
 * 28/6/95 JC
 *	- rewritten, based on new im_invfft() code
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
#include <vips/internal.h>
#include "pfreqfilt.h"

#ifdef HAVE_FFTW

#include <fftw3.h>

typedef struct _VipsInvfft {
	VipsFreqfilt parent_instance;

	gboolean real;

} VipsInvfft;

typedef VipsFreqfiltClass VipsInvfftClass;

G_DEFINE_TYPE( VipsInvfft, vips_invfft, VIPS_TYPE_FREQFILT );

/* Complex to complex inverse transform.
 */
static int 
cinvfft1( VipsObject *object, VipsImage *in, VipsImage **out )
{
	VipsImage **t = (VipsImage **) vips_object_local_array( object, 4 );
	VipsInvfft *invfft = (VipsInvfft *) object;
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( invfft );

	fftw_plan plan;
	double *planner_scratch;

	if( vips_check_mono( class->nickname, in ) ||
		vips_check_uncoded( class->nickname, in ) )
                return( -1 );

	/* Convert input to a complex double membuffer.
	 */
	*out = vips_image_new_memory();
	if( vips_cast_dpcomplex( in, &t[0], NULL ) ||
		vips_image_write( t[0], *out ) )
		return( -1 ); 

	/* Make the plan for the transform. Yes, they really do use nx for
	 * height and ny for width.
	 */
	if( !(planner_scratch = VIPS_ARRAY( invfft, 
		VIPS_IMAGE_N_PELS( in ) * 2, double )) )
		return( -1 );
	if( !(plan = fftw_plan_dft_2d( in->Ysize, in->Xsize,
		(fftw_complex *) planner_scratch, 
		(fftw_complex *) planner_scratch,
		FFTW_BACKWARD, 
		0 )) ) {
                vips_error( class->nickname, 
			"%s", _( "unable to create transform plan" ) );
		return( -1 );
	}

	fftw_execute_dft( plan, 
		(fftw_complex *) (*out)->data, (fftw_complex *) (*out)->data );

	fftw_destroy_plan( plan );

	(*out)->Type = VIPS_INTERPRETATION_B_W;

	return( 0 );
}

/* Complex to real inverse transform.
 */
static int 
rinvfft1( VipsObject *object, VipsImage *in, VipsImage **out )
{
	VipsImage **t = (VipsImage **) vips_object_local_array( object, 4 );
	VipsInvfft *invfft = (VipsInvfft *) object;
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( invfft );
	const int half_width = in->Xsize / 2 + 1;

	double *half_complex;
	double *planner_scratch;
	fftw_plan plan;
	int x, y;
	double *q, *p;

	/* Convert input to a complex double membuffer.
	 */
	t[1] = vips_image_new_memory();
	if( vips_cast_dpcomplex( in, &t[0], NULL ) ||
		vips_image_write( t[0], t[1] ) )
		return( -1 ); 

	/* Build half-complex image.
	 */
	if( !(half_complex = VIPS_ARRAY( invfft, 
		t[1]->Ysize * half_width * 2, double )) )
		return( -1 );
	q = half_complex;
	for( y = 0; y < t[1]->Ysize; y++ ) {
		p = ((double *) t[1]->data) + (guint64) y * t[1]->Xsize * 2; 

		for( x = 0; x < half_width; x++ ) {
			q[0] = p[0];
			q[1] = p[1];
			p += 2;
			q += 2;
		}
	}

	/* Make mem buffer real image for output.
	 */
	*out = vips_image_new_memory();
	if( vips_image_pipelinev( *out, VIPS_DEMAND_STYLE_ANY, t[1], NULL ) )
                return( -1 );
	(*out)->BandFmt = VIPS_FORMAT_DOUBLE;
	(*out)->Type = VIPS_INTERPRETATION_B_W;
	if( vips_image_write_prepare( *out ) ) 
		return( -1 ); 

	/* Make the plan for the transform. Yes, they really do use nx for
	 * height and ny for width.
	 */
	if( !(planner_scratch = VIPS_ARRAY( invfft, 
		t[1]->Ysize * half_width * 2, double )) )
		return( -1 );
	if( !(plan = fftw_plan_dft_c2r_2d( t[1]->Ysize, t[1]->Xsize,
		(fftw_complex *) planner_scratch, (double *) (*out)->data,
		0 )) ) {
                vips_error( class->nickname,
			"%s", _( "unable to create transform plan" ) );
		return( -1 );
	}

	fftw_execute_dft_c2r( plan,
		(fftw_complex *) half_complex, (double *) (*out)->data );

	fftw_destroy_plan( plan );

	return( 0 );
}

static int
vips_invfft_build( VipsObject *object )
{
	VipsFreqfilt *freqfilt = VIPS_FREQFILT( object );
	VipsInvfft *invfft = (VipsInvfft *) object;
	VipsImage **t = (VipsImage **) vips_object_local_array( object, 4 );

	VipsImage *in;

	if( VIPS_OBJECT_CLASS( vips_invfft_parent_class )->
		build( object ) )
		return( -1 );

	in = freqfilt->in; 

	if( vips_image_decode( in, &t[0] ) )
		return( -1 );
	in = t[0]; 

	if( invfft->real ) {
		if( vips__fftproc( VIPS_OBJECT( invfft ), 
			in, &t[1], rinvfft1 ) )
			return( -1 );
	}
	else {
		if( vips__fftproc( VIPS_OBJECT( invfft ), 
			in, &t[1], cinvfft1 ) )
			return( -1 );
	}
	
	if( vips_image_write( t[1], freqfilt->out ) ) 
		return( -1 );

	return( 0 );
}

static void
vips_invfft_class_init( VipsInvfftClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "invfft";
	vobject_class->description = _( "inverse FFT" );
	vobject_class->build = vips_invfft_build;

	VIPS_ARG_BOOL( class, "real", 4, 
		_( "Real" ), 
		_( "Output only the real part of the transform" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsInvfft, real ),
		FALSE );

}

static void
vips_invfft_init( VipsInvfft *invfft )
{
}

#endif /*HAVE_FFTW*/

/**
 * vips_invfft:
 * @in: input image 
 * @out: output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @real: only output the real part
 *
 * Transform an image from Fourier space to real space. The result is complex.
 * If you are OK with a real result, set @real, it's quicker.
 *
 * VIPS uses the fftw Fourier Transform library. If this library was not
 * available when VIPS was configured, these functions will fail.
 *
 * See also: vips_fwfft().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_invfft( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "invfft", ap, in, out );
	va_end( ap );

	return( result );
}

