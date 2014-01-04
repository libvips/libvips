/* frequency-domain filter an image
 *
 * Author: Nicos Dessipris
 * Written on: 02/05/1990
 * Modified on : 08/03/1991
 * 16/6/93 J.Cupitt
 *	- im_multiply() called, rather than im_cmultim()
 * 27/10/93 JC
 *	- im_clip2*() called, rather than im_any2*()
 * 20/9/95 JC
 *	- rewritten
 * 10/9/98 JC
 *	- frees memory more quickly
 * 4/3/03 JC
 *	- use im_invfftr() to get real back for speedup
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

typedef struct _VipsFreqmult {
	VipsFreqfilt parent_instance;

	VipsImage *mask;
} VipsFreqmult;

typedef VipsFreqfiltClass VipsFreqmultClass;

G_DEFINE_TYPE( VipsFreqmult, vips_freqmult, VIPS_TYPE_FREQFILT );

static int
vips_freqmult_build( VipsObject *object )
{
	VipsFreqfilt *freqfilt = VIPS_FREQFILT( object );
	VipsFreqmult *freqmult = (VipsFreqmult *) object;
	VipsImage **t = (VipsImage **) vips_object_local_array( object, 5 );

	VipsImage *in;

	if( VIPS_OBJECT_CLASS( vips_freqmult_parent_class )->
		build( object ) )
		return( -1 );

	in = freqfilt->in;

	if( vips_bandfmt_iscomplex( in->BandFmt ) ) {
		if( vips_multiply( in, freqmult->mask, &t[0], NULL ) ||
			vips_invfft( t[0], &t[1], "real", TRUE, NULL ) ) 
			return( -1 );

		in = t[1];
	}
	else {
		/* Optimisation: output of vips_invfft() is double, we 
		 * will usually cast to char, so rather than keeping a
		 * large double buffer and partial to char from that, 
		 * cast to a memory buffer and copy to out from that.
		 *
		 * FIXME does this actually work now we're a class? test
		 * perhaps we need a temporary object
		 */
		t[4] = vips_image_new_buffer();

		if( vips_fwfft( in, &t[0], NULL ) ||
			vips_multiply( t[0], freqmult->mask, &t[1], NULL ) ||
			vips_invfft( t[1], &t[2], "real", TRUE, NULL ) ||
			vips_cast( t[2], &t[3], in->BandFmt, NULL ) ||
			vips_image_write( t[3], t[4] ) )
			return( -1 );

		in = t[4]; 
	}

	if( vips_image_write( in, freqfilt->out ) )
		return( -1 );

	return( 0 );
}

static void
vips_freqmult_class_init( VipsFreqmultClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "freqmult";
	vobject_class->description = _( "frequency-domain filtering" );
	vobject_class->build = vips_freqmult_build;

	VIPS_ARG_IMAGE( class, "mask", 0, 
		_( "mask" ), 
		_( "Input mask image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsFreqmult, mask ) );

}

static void
vips_freqmult_init( VipsFreqmult *freqmult )
{
}

/**
 * vips_freqmult:
 * @in: input image 
 * @mask: mask image
 * @out: output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Multiply @in by @mask in Fourier space.
 *
 * @in is transformed to Fourier space, multipled with @mask, then
 * transformed back to real space. If @in is already a complex image, just
 * multiply then inverse transform.
 *
 * See also: vips_invfft(), vips_mask_ideal().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_freqmult( VipsImage *in, VipsImage *mask, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "freqmult", ap, in, mask, out );
	va_end( ap );

	return( result );
}

