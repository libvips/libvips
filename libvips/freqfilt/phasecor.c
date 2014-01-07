/* Like spcor, but calculates phase correlation in the Fourier domain.
 *
 * Copyright: 2008, Nottingham Trent University
 *
 * Author: Tom Vajzovic
 * Written on: 2008-01-16
 * 7/2/10
 * 	- cleanups
 * 	- gtkdoc
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

typedef struct _VipsPhasecor {
	VipsFreqfilt parent_instance;

	VipsImage *in2;
} VipsPhasecor;

typedef VipsFreqfiltClass VipsPhasecorClass;

G_DEFINE_TYPE( VipsPhasecor, vips_phasecor, VIPS_TYPE_FREQFILT );

static int
vips_phasecor_build( VipsObject *object )
{
	VipsFreqfilt *freqfilt = VIPS_FREQFILT( object );
	VipsPhasecor *phasecor = (VipsPhasecor *) object;
	VipsImage **t = (VipsImage **) vips_object_local_array( object, 5 );

	VipsImage *in1, *in2;

	if( VIPS_OBJECT_CLASS( vips_phasecor_parent_class )->
		build( object ) )
		return( -1 );

	in1 = freqfilt->in;
	in2 = phasecor->in2;

	if( in1->BandFmt != VIPS_FORMAT_COMPLEX ) {
		if( vips_fwfft( in1, &t[0], NULL ) )
			return( -1 );
		in1 = t[0];
	}

	if( in2->BandFmt != VIPS_FORMAT_COMPLEX ) {
		if( vips_fwfft( in2, &t[1], NULL ) )
			return( -1 );
		in2 = t[1];
	}

	if( vips_cross_phase( in1, in2, &t[2], NULL ) ||
		vips_invfft( t[2], &t[3], "real", TRUE, NULL ) ||
		vips_image_write( t[3], freqfilt->out ) )
		return( -1 );

	return( 0 );
}

static void
vips_phasecor_class_init( VipsPhasecorClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "phasecor";
	vobject_class->description = _( "calculate phase correlation" );
	vobject_class->build = vips_phasecor_build;

	VIPS_ARG_IMAGE( class, "in2", 0, 
		_( "in2" ), 
		_( "Second input image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsPhasecor, in2 ) );

}

static void
vips_phasecor_init( VipsPhasecor *phasecor )
{
}

/**
 * vips_phasecor:
 * @in1: first input image
 * @in2: second input image
 * @out: output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Convert the two input images to Fourier space, calculate phase-correlation,
 * back to real space.
 *
 * See also: vips_fwfft(), vips_cross_phase(), 
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_phasecor( VipsImage *in1, VipsImage *in2, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "phasecor", ap, in1, in2, out );
	va_end( ap );

	return( result );
}

