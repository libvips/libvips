/* make a displayable power spectrum for an image
 *
 * Author: Nicos Dessipris
 * Written on: 27/03/1991
 * Modified on : 
 * 16/6/93 J.Cupitt
 *	- im_ioflag() changed to im_iocheck()
 * 23/2/95 JC
 *	- rewritten for partials
 * 10/9/98 JC
 *	- frees memory more quickly
 * 2/4/02 JC
 *	- any number of bands
 * 7/2/10
 * 	- gtkdoc
 * 	- cleanups
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

typedef VipsFreqfilt VipsSpectrum;
typedef VipsFreqfiltClass VipsSpectrumClass;

G_DEFINE_TYPE( VipsSpectrum, vips_spectrum, VIPS_TYPE_FREQFILT );

static int
vips_spectrum_build( VipsObject *object )
{
	VipsFreqfilt *freqfilt = VIPS_FREQFILT( object );
	VipsImage **t = (VipsImage **) vips_object_local_array( object, 5 );

	VipsImage *in;

	if( VIPS_OBJECT_CLASS( vips_spectrum_parent_class )->
		build( object ) )
		return( -1 );

	in = freqfilt->in;

	if( in->BandFmt != VIPS_FORMAT_COMPLEX ) {
		if( vips_fwfft( in, &t[0], NULL ) )
			return( -1 );
		in = t[0];
	}

	if( vips_abs( in, &t[1], NULL ) ||
		vips_scale( t[1], &t[2], "log", TRUE, NULL ) || 
		vips_wrap( t[2], &t[3], NULL ) )
		return( -1 );

	if( vips_image_write( t[3], freqfilt->out ) )
		return( -1 );

	return( 0 );
}

static void
vips_spectrum_class_init( VipsSpectrumClass *class )
{
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	vobject_class->nickname = "spectrum";
	vobject_class->description = _( "make displayable power spectrum" );
	vobject_class->build = vips_spectrum_build;

}

static void
vips_spectrum_init( VipsSpectrum *spectrum )
{
}

/**
 * vips_spectrum:
 * @in: input image 
 * @out: output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Make a displayable (ie. 8-bit unsigned int) power spectrum.
 *
 * If @in is non-complex, it is transformed to Fourier space. Then the
 * absolute value is passed through vips_scale() in log mode, and vips_wrap().
 *
 * See also: vips_fwfft(), vips_scale(), vips_wrap().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_spectrum( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "spectrum", ap, in, out );
	va_end( ap );

	return( result );
}

