/* Turn XYZ to Luv colourspace. 
 *
 * 27/1/20
 * 	- from XYZ2Lab.c
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
#include <math.h>

#include <vips/vips.h>
#include <vips/internal.h>

#include "pcolour.h"

#ifndef HAVE_CBRT
#define cbrt( X ) pow( (X), 1.0 / 3.0 )
#endif /*!HAVE_CBRT*/

/* Lookup table size.
 */
#define QUANT_ELEMENTS (10000)

float cbrt_table[QUANT_ELEMENTS];

typedef struct _VipsXYZ2Luv {
	VipsColourTransform parent_instance;

	/* The colour temperature -- default to D65. 
	 */
	VipsArea *temp;

	/* Broken out as xyz.
	 */
	double X0;
	double Y0;
	double Z0;

	/* And as un', vn'.
	 */
	double unp;
	double vnp;

} VipsXYZ2Luv;

typedef VipsColourTransformClass VipsXYZ2LuvClass;

G_DEFINE_TYPE( VipsXYZ2Luv, vips_XYZ2Luv, VIPS_TYPE_COLOUR_TRANSFORM );

static void *
table_init( void *client )
{
	int i;

	for( i = 0; i < QUANT_ELEMENTS; i++ ) {
		float Y = (double) i / QUANT_ELEMENTS;

		/* (6 / 29) ** 3
		 */
		if( Y <= 0.008856 ) 
			/* (29 / 3) ** 3
			 */
			cbrt_table[i] = 903.2962962776 * Y;
		else 
			cbrt_table[i] = 116.0 * cbrt( Y ) - 16.0;
	}

	return( NULL );
}


/* Process a buffer of data.
 */
static void
vips_XYZ2Luv_line( VipsColour *colour, VipsPel *out, VipsPel **in, int width )
{
	static GOnce once = G_ONCE_INIT;

	VipsXYZ2Luv *XYZ2Luv = (VipsXYZ2Luv *) colour;
	float *p = (float *) in[0];
	float *q = (float *) out;

	int x;

	VIPS_ONCE( &once, table_init, NULL );

	for( x = 0; x < width; x++ ) {
		float X, Y, Z;
		float nY;
		int i;
		float f;
		float L;
		float d, up, vp, u, v;

		X = p[0];
		Y = p[1];
		Z = p[2];
		p += 3;

		nY = QUANT_ELEMENTS * Y / XYZ2Luv->Y0;
		i = VIPS_FCLIP( 0, nY, QUANT_ELEMENTS - 2 );
		f = nY - i;
		L = cbrt_table[i] + f * (cbrt_table[i + 1] - cbrt_table[i]);

		d = X + 15.0 * Y + 3.0 * Z;
		up = 4.0 * X / d;
		vp = 9.0 * Y / d;

		u = 13.0 * L * (up - XYZ2Luv->unp);
		v = 13.0 * L * (vp - XYZ2Luv->vnp);

		q[0] = L;
		q[1] = u;
		q[2] = v;
		q += 3;
	}
}

static int
vips_XYZ2Luv_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsXYZ2Luv *XYZ2Luv = (VipsXYZ2Luv *) object;

	if( XYZ2Luv->temp ) {
		if( vips_check_vector_length( class->nickname, 
			XYZ2Luv->temp->n, 3 ) )
			return( -1 );

		XYZ2Luv->X0 = ((double *) XYZ2Luv->temp->data)[0];
		XYZ2Luv->Y0 = ((double *) XYZ2Luv->temp->data)[1];
		XYZ2Luv->Z0 = ((double *) XYZ2Luv->temp->data)[2];

		XYZ2Luv->unp = 4.0 * XYZ2Luv->X0 / 
			(XYZ2Luv->X0 + 15.0 * XYZ2Luv->Y0 + 3.0 * XYZ2Luv->Z0);
		XYZ2Luv->vnp = 9.0 * XYZ2Luv->Y0 / 
			(XYZ2Luv->X0 + 15.0 * XYZ2Luv->Y0 + 3.0 * XYZ2Luv->Z0);
	}

	if( VIPS_OBJECT_CLASS( vips_XYZ2Luv_parent_class )->build( object ) )
		return( -1 );

	return( 0 );
}

static void
vips_XYZ2Luv_class_init( VipsXYZ2LuvClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsColourClass *colour_class = VIPS_COLOUR_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "XYZ2Luv";
	object_class->description = _( "transform XYZ to Luv" );
	object_class->build = vips_XYZ2Luv_build;

	colour_class->process_line = vips_XYZ2Luv_line;

	VIPS_ARG_BOXED( class, "temp", 110, 
		_( "Temperature" ), 
		_( "Colour temperature" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsXYZ2Luv, temp ),
		VIPS_TYPE_ARRAY_DOUBLE );
}

static void
vips_XYZ2Luv_init( VipsXYZ2Luv *XYZ2Luv )
{
	VipsColour *colour = VIPS_COLOUR( XYZ2Luv );

	XYZ2Luv->X0 = VIPS_D65_X0;
	XYZ2Luv->Y0 = VIPS_D65_Y0;
	XYZ2Luv->Z0 = VIPS_D65_Z0;

	colour->interpretation = VIPS_INTERPRETATION_LUV;
}

/**
 * vips_XYZ2Luv: (method)
 * @in: input image
 * @out: (out): output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @temp: #VipsArrayDouble, colour temperature
 *
 * Turn XYZ to Luv, optionally specifying the colour temperature. @temp
 * defaults to D65. 
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_XYZ2Luv( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "XYZ2Luv", ap, in, out );
	va_end( ap );

	return( result );
}

