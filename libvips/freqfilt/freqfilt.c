/* base class for all Fourier stuff 
 *
 * properties:
 * 	- single output image
 */

/*

    Copyright (C) 1991-2005 The National Gallery

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License as published by the Free Software Foundation; either
    version 2.1 of the License, or (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU 
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this library; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
    02110-1301  USA

 */

/*

    These files are distributed with VIPS - http://www.vips.ecs.soton.ac.uk

 */

/*
#define DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <stdlib.h>
#include <math.h>

#include <vips/vips.h>
#include <vips/internal.h>

#include "pfreqfilt.h"

/**
 * SECTION: freqfilt
 * @short_description: fourier transforms and frequency-domin filters
 * @stability: Stable
 * @see_also: <link linkend="libvips-image">image</link>
 * @include: vips/vips.h
 *
 * To and from Fourier space, filter in Fourier space, convert Fourier-space
 * images to a displayable form.
 */

G_DEFINE_ABSTRACT_TYPE( VipsFreqfilt, vips_freqfilt, VIPS_TYPE_OPERATION );

static int
vips_freqfilt_build( VipsObject *object )
{
	VipsFreqfilt *freqfilt = VIPS_FREQFILT( object );

#ifdef DEBUG
	printf( "vips_freqfilt_build: " );
	vips_object_print_name( object );
	printf( "\n" );
#endif /*DEBUG*/

	g_object_set( freqfilt, "out", vips_image_new(), NULL ); 

	if( VIPS_OBJECT_CLASS( vips_freqfilt_parent_class )->build( object ) )
		return( -1 );

	return( 0 );
}

static void
vips_freqfilt_class_init( VipsFreqfiltClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "freqfilt";
	vobject_class->description = _( "frequency-domain filter operations" );
	vobject_class->build = vips_freqfilt_build;

	VIPS_ARG_IMAGE( class, "in", -1, 
		_( "in" ), 
		_( "Input image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsFreqfilt, in ) );

	VIPS_ARG_IMAGE( class, "out", 1, 
		_( "Output" ), 
		_( "Output image" ),
		VIPS_ARGUMENT_REQUIRED_OUTPUT, 
		G_STRUCT_OFFSET( VipsFreqfilt, out ) );
}

static void
vips_freqfilt_init( VipsFreqfilt *freqfilt )
{
}

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
vips__fftproc( VipsObject *context, 
	VipsImage *in, VipsImage **out, VipsFftProcessFn fn )
{
	VipsImage **bands = (VipsImage **) 
		vips_object_local_array( context, in->Bands );
	VipsImage **fft = (VipsImage **) 
		vips_object_local_array( context, in->Bands );

	int b;

	if( in->Bands == 1 ) 
		return( fn( context, in, out ) );

	for( b = 0; b < in->Bands; b++ ) 
		if( vips_extract_band( in, &bands[b], b, NULL ) ||
			fn( context, bands[b], &fft[b] ) )
			return( -1 );

	if( vips_bandjoin( fft, out, in->Bands, NULL ) )
		return( -1 );

	return( 0 );
}

/* Called from iofuncs to init all operations in this dir. Use a plugin system
 * instead?
 */
void
vips_freqfilt_operation_init( void )
{
#ifdef HAVE_FFTW
	extern GType vips_fwfft_get_type( void ); 
	extern GType vips_invfft_get_type( void ); 
#endif /*HAVE_FFTW*/
	extern GType vips_freqmult_get_type( void ); 
	extern GType vips_spectrum_get_type( void ); 
	extern GType vips_phasecor_get_type( void ); 

#ifdef HAVE_FFTW
	vips_fwfft_get_type(); 
	vips_invfft_get_type(); 
#endif /*HAVE_FFTW*/
	vips_freqmult_get_type(); 
	vips_spectrum_get_type(); 
	vips_phasecor_get_type(); 
}

