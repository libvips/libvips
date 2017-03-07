/* Raise an image to a gamma factor
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
 * 11/11/13
 * 	- any format
 * 	- calculate pow(1/exp) rather than pow(exp) to be consistent with
 * 	  other packages
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

#include <math.h>

#include <vips/vips.h>

#include "pconversion.h"

typedef struct _VipsGamma {
	VipsConversion parent_instance;

	VipsImage *in;
	double exponent;
} VipsGamma;

typedef VipsConversionClass VipsGammaClass;

G_DEFINE_TYPE( VipsGamma, vips_gamma, VIPS_TYPE_CONVERSION );

/* For each input format, what we normalise the pow() about.
 */
static double vips_gamma_maxval[10] = {
/* UC  */	UCHAR_MAX,
/* C   */	SCHAR_MAX,
/* US  */	USHRT_MAX,
/* S   */	SHRT_MAX,
/* UI  */	UINT_MAX,
/* I  */	INT_MAX,
/* F  */	1.0,
/* X  */	1.0,
/* D  */	1.0,
/* DX */	1.0
};

static int
vips_gamma_build( VipsObject *object )
{
	VipsConversion *conversion = VIPS_CONVERSION( object );
	VipsGamma *gamma = (VipsGamma *) object;
	VipsImage **t = (VipsImage **) vips_object_local_array( object, 5 );
	VipsImage *in = gamma->in;
	double scale;

	if( VIPS_OBJECT_CLASS( vips_gamma_parent_class )->
		build( object ) )
		return( -1 );

	scale = pow( vips_gamma_maxval[in->BandFmt], 
			1.0 / gamma->exponent ) / 
			vips_gamma_maxval[in->BandFmt];

	if( in->BandFmt == VIPS_FORMAT_UCHAR ||
		in->BandFmt == VIPS_FORMAT_USHORT ) {
		if( vips_identity( &t[0], 
				"ushort", in->BandFmt == VIPS_FORMAT_USHORT,
				NULL ) ||
			vips_pow_const1( t[0], &t[1], 
				1.0 / gamma->exponent, NULL ) ||
			vips_linear1( t[1], &t[2], 1.0 / scale, 0, NULL ) ||
			vips_cast( t[2], &t[3], in->BandFmt, NULL ) ||
			vips_maplut( in, &t[4], t[3], NULL ) ||
			vips_image_write( t[4], conversion->out ) ) 
			return( -1 );
	} 
	else {
		if( vips_pow_const1( in, &t[1], 
				1.0 / gamma->exponent, NULL ) ||
			vips_linear1( t[1], &t[2], 1.0 / scale, 0, NULL ) ||
			vips_cast( t[2], &t[3], in->BandFmt, NULL ) ||
			vips_image_write( t[3], conversion->out ) ) 
			return( -1 );
	} 

	return( 0 );
}

static void
vips_gamma_class_init( VipsGammaClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );
	VipsOperationClass *operation_class = VIPS_OPERATION_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "gamma";
	vobject_class->description = _( "gamma an image" );
	vobject_class->build = vips_gamma_build;

	operation_class->flags = VIPS_OPERATION_SEQUENTIAL_UNBUFFERED;

	VIPS_ARG_IMAGE( class, "in", 1, 
		_( "in" ), 
		_( "Input image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsGamma, in ) );

	VIPS_ARG_DOUBLE( class, "exponent", 2, 
		_( "exponent" ), 
		_( "Gamma factor" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsGamma, exponent ),
		0.000001, 1000.0, 2.4 );

}

static void
vips_gamma_init( VipsGamma *gamma )
{
	gamma->exponent = 1.0 / 2.4;
}

/**
 * vips_gamma:
 * @in: input image 
 * @out: output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @exponent: gamma, default 1.0 / 2.4
 *
 * Calculate @in ** (1 / @exponent), normalising to the maximum range of the
 * input type. For float types use 1.0 as the maximum. 
 *
 * See also: vips_identity(), vips_pow_const1(), vips_maplut()
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_gamma( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "gamma", ap, in, out );
	va_end( ap );

	return( result );
}
