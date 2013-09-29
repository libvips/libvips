/* Gamma-correct image with factor gammafactor.
 *
 * Copyright: 1990, N. Dessipris.
 * 
 * Written on: 19/07/1990
 * Modified on:
 * 19/6/95 JC
 *	- redone as library function
 * 23/3/10
 * 	- gtkdoc
 * 	- 16 bit as well
 * 1/8/13
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

#include <vips/vips.h>

#include "pconversion.h"

typedef struct _VipsGammacorrect {
	VipsConversion parent_instance;

	VipsImage *in;
	double exponent;
} VipsGammacorrect;

typedef VipsConversionClass VipsGammacorrectClass;

G_DEFINE_TYPE( VipsGammacorrect, vips_gammacorrect, VIPS_TYPE_CONVERSION );

static int
vips_gammacorrect_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsConversion *conversion = VIPS_CONVERSION( object );
	VipsGammacorrect *gammacorrect = (VipsGammacorrect *) object;
	VipsImage **t = (VipsImage **) vips_object_local_array( object, 5 );
	VipsImage *in = gammacorrect->in;

	double mx1, mx2;

	if( VIPS_OBJECT_CLASS( vips_gammacorrect_parent_class )->
		build( object ) )
		return( -1 );

	if( vips_check_u8or16( class->nickname, in ) ||
		vips_identity( &t[0], 
			"ushort", in->BandFmt == VIPS_FORMAT_USHORT,
			NULL ) ||
		vips_pow_const1( t[0], &t[1], gammacorrect->exponent, NULL ) ||
		vips_max( t[0], &mx1, NULL ) ||
		vips_max( t[1], &mx2, NULL ) ||
		vips_linear1( t[1], &t[2], mx1 / mx2, 0, NULL ) ||
		vips_cast( t[2], &t[3], in->BandFmt, NULL ) ||
		vips_maplut( in, &t[4], t[3], NULL ) ||
		vips_image_write( t[4], conversion->out ) ) 
		return( -1 );

	return( 0 );
}

static void
vips_gammacorrect_class_init( VipsGammacorrectClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );
	VipsOperationClass *operation_class = VIPS_OPERATION_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "gammacorrect";
	vobject_class->description = _( "gammacorrect a pair of images" );
	vobject_class->build = vips_gammacorrect_build;

	operation_class->flags = VIPS_OPERATION_SEQUENTIAL_UNBUFFERED;

	VIPS_ARG_IMAGE( class, "in", -1, 
		_( "in" ), 
		_( "Input image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsGammacorrect, in ) );

	VIPS_ARG_DOUBLE( class, "exponent", 0, 
		_( "exponent" ), 
		_( "Gamma factor" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsGammacorrect, exponent ),
		0.000001, 1000.0, 2.4 );

}

static void
vips_gammacorrect_init( VipsGammacorrect *gammacorrect )
{
	gammacorrect->exponent = 2.4;
}

/**
 * vips_gammacorrect:
 * @in: input image 
 * @out: output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * @exponent: gamma factor, default 2.4
 *
 * Gamma-correct an 8- or 16-bit unsigned image with a lookup table. The
 * output format is the same as the input format.
 *
 * See also: vips_identity(), vips_pow_const1(), vips_maplut()
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_gammacorrect( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "gammacorrect", ap, in, out );
	va_end( ap );

	return( result );
}
