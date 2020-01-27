/* Luv to XYZ.
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

/*
#define VIPS_DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <math.h>

#include <vips/vips.h>
#include <vips/debug.h>

#include "pcolour.h"

typedef struct _VipsLuv2XYZ {
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

} VipsLuv2XYZ;

typedef VipsColourTransformClass VipsLuv2XYZClass;

G_DEFINE_TYPE( VipsLuv2XYZ, vips_Luv2XYZ, VIPS_TYPE_COLOUR_TRANSFORM );

/* Process a buffer of data.
 */
static void
vips_Luv2XYZ_line( VipsColour *colour, VipsPel *out, VipsPel **in, int width )
{
	VipsLuv2XYZ *Luv2XYZ = (VipsLuv2XYZ *) colour;
	float * restrict p = (float *) in[0];
	float * restrict q = (float *) out;

	int x;

	VIPS_DEBUG_MSG( "vips_Luv2XYZ_line: X0 = %g, Y0 = %g, Z0 = %g\n",
		Luv2XYZ->X0, Luv2XYZ->Y0, Luv2XYZ->Z0 );

	for( x = 0; x < width; x++ ) {
		float L, u, v;
		float X, Y, Z;
		float up, vp;

		L = p[0];
		u = p[1];
		v = p[2];
		p += 3;

		up = u / (13.0 * L) + Luv2XYZ->unp;
		vp = v / (13.0 * L) + Luv2XYZ->vnp;

		if( L <= 8.0 )
			/* (3 / 29) ** 3
			 */
			Y = Luv2XYZ->Y0 * L * 0.0011070564;
		else {
			float f = (L + 16.0) / 116.0;

			Y = Luv2XYZ->Y0 * f * f * f;
		}

		X = Y * 9.0 * up / (4.0 * vp);
		Z = Y * 9.0 * (12.0 - 3.0 - up - 20.0 * vp) / (4.0 * vp);
			
		q[0] = X;
		q[1] = Y;
		q[2] = Z;
		q += 3;
	}
}

static int
vips_Luv2XYZ_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsLuv2XYZ *Luv2XYZ = (VipsLuv2XYZ *) object;

	if( Luv2XYZ->temp ) {
		if( vips_check_vector_length( class->nickname, 
			Luv2XYZ->temp->n, 3 ) )
			return( -1 );
		Luv2XYZ->X0 = ((double *) Luv2XYZ->temp->data)[0];
		Luv2XYZ->Y0 = ((double *) Luv2XYZ->temp->data)[1];
		Luv2XYZ->Z0 = ((double *) Luv2XYZ->temp->data)[2];

		Luv2XYZ->unp = 4.0 * Luv2XYZ->X0 / 
			(Luv2XYZ->X0 + 15.0 * Luv2XYZ->Y0 + 3.0 * Luv2XYZ->Z0);
		Luv2XYZ->vnp = 9.0 * Luv2XYZ->Y0 / 
			(Luv2XYZ->X0 + 15.0 * Luv2XYZ->Y0 + 3.0 * Luv2XYZ->Z0);
	}

	if( VIPS_OBJECT_CLASS( vips_Luv2XYZ_parent_class )->build( object ) )
		return( -1 );

	return( 0 );
}

static void
vips_Luv2XYZ_class_init( VipsLuv2XYZClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsColourClass *colour_class = VIPS_COLOUR_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "Luv2XYZ";
	object_class->description = _( "transform CIELUV to XYZ" );
	object_class->build = vips_Luv2XYZ_build;

	colour_class->process_line = vips_Luv2XYZ_line;

	VIPS_ARG_BOXED( class, "temp", 110, 
		_( "Temperature" ), 
		_( "Color temperature" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsLuv2XYZ, temp ),
		VIPS_TYPE_ARRAY_DOUBLE );
}

static void
vips_Luv2XYZ_init( VipsLuv2XYZ *Luv2XYZ )
{
	VipsColour *colour = VIPS_COLOUR( Luv2XYZ );

	Luv2XYZ->X0 = VIPS_D65_X0;
	Luv2XYZ->Y0 = VIPS_D65_Y0;
	Luv2XYZ->Z0 = VIPS_D65_Z0;

	colour->interpretation = VIPS_INTERPRETATION_XYZ;
}

/**
 * vips_Luv2XYZ: (method)
 * @in: input image
 * @out: (out): output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @temp: #VipsArrayDouble, colour temperature
 *
 * Turn Luv to XYZ. The colour temperature defaults to D65, but can be 
 * specified with @temp.
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_Luv2XYZ( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "Luv2XYZ", ap, in, out );
	va_end( ap );

	return( result );
}
