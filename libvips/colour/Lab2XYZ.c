/* Lab to XYZ.
 *
 * Modified:
 * 15/11/94 JC
 *	- ANSIfied
 *	- sets Type of output
 *	- better error messages
 * 16/11/94 JC
 *	- partialed
 *	- in-line conversion
 * 8/2/95 JC
 *	- new im_wrapone function
 * 2/11/09
 * 	- gtkdoc
 * 	- cleanups
 * 18/9/12
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
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

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

#include "colour.h"

typedef struct _VipsLab2XYZ {
	VipsColourSpace parent_instance;

	/* The colour temperature -- default to D65. 
	 */
	VipsArea *temp;

	/* Broken out as xyz.
	 */
	double X0;
	double Y0;
	double Z0;

} VipsLab2XYZ;

typedef VipsColourSpaceClass VipsLab2XYZClass;

G_DEFINE_TYPE( VipsLab2XYZ, vips_Lab2XYZ, VIPS_TYPE_COLOUR_SPACE );

/* Process a buffer of data.
 */
static void
vips_Lab2XYZ_line( VipsColour *colour, VipsPel *out, VipsPel **in, int width )
{
	VipsLab2XYZ *Lab2XYZ = (VipsLab2XYZ *) colour;
	float *p = (float *) in[0];
	float *q = (float *) out;

	int x;

	VIPS_DEBUG_MSG( "vips_Lab2XYZ_line: X0 = %g, Y0 = %g, Z0 = %g\n",
		Lab2XYZ->X0, Lab2XYZ->Y0, Lab2XYZ->Z0 );

	for( x = 0; x < width; x++ ) {
		float L, a, b;
		float X, Y, Z;
		double cby, tmp;

		L = p[0];
		a = p[1];
		b = p[2];
		p += 3;

		if( L < 8.0 ) {
			Y = (L * Lab2XYZ->Y0) / 903.3;
			cby = 7.787 * (Y / Lab2XYZ->Y0) + 16.0 / 116.0;
		}
		else {
			cby = (L + 16.0) / 116.0;
			Y = Lab2XYZ->Y0 * cby * cby * cby;
		}

		tmp = a / 500.0 + cby;
		if( tmp < 0.2069 )
			X = Lab2XYZ->X0 * (tmp - 0.13793) / 7.787;
		else    
			X = Lab2XYZ->X0 * tmp * tmp * tmp;

		tmp = cby - b / 200.0;
		if( tmp < 0.2069 )
			Z = Lab2XYZ->Z0 * (tmp - 0.13793) / 7.787;
		else    
			Z = Lab2XYZ->Z0 * tmp * tmp * tmp;

		/* Write.
		 */
		q[0] = X;
		q[1] = Y;
		q[2] = Z;
		q += 3;
	}
}

static int
vips_Lab2XYZ_build( VipsObject *object )
{
	VipsLab2XYZ *Lab2XYZ = (VipsLab2XYZ *) object;

	if( Lab2XYZ->temp ) {
		if( vips_check_vector_length( "VipsLab2XYZ", 
			Lab2XYZ->temp->n, 3 ) )
			return( -1 );
		Lab2XYZ->X0 = ((double *) Lab2XYZ->temp->data)[0];
		Lab2XYZ->Y0 = ((double *) Lab2XYZ->temp->data)[1];
		Lab2XYZ->Z0 = ((double *) Lab2XYZ->temp->data)[2];
	}

	if( VIPS_OBJECT_CLASS( vips_Lab2XYZ_parent_class )->build( object ) )
		return( -1 );

	return( 0 );
}

static void
vips_Lab2XYZ_class_init( VipsLab2XYZClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsColourClass *colour_class = VIPS_COLOUR_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "Lab2XYZ";
	object_class->description = _( "transform CIELAB to XYZ" );
	object_class->build = vips_Lab2XYZ_build;

	colour_class->process_line = vips_Lab2XYZ_line;

	VIPS_ARG_BOXED( class, "temp", 110, 
		_( "Temperature" ), 
		_( "Colour temperature" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsLab2XYZ, temp ),
		VIPS_TYPE_ARRAY_DOUBLE );
}

static void
vips_Lab2XYZ_init( VipsLab2XYZ *Lab2XYZ )
{
	VipsColour *colour = VIPS_COLOUR( Lab2XYZ );

	Lab2XYZ->X0 = VIPS_D65_X0;
	Lab2XYZ->Y0 = VIPS_D65_Y0;
	Lab2XYZ->Z0 = VIPS_D65_Z0;

	colour->interpretation = VIPS_INTERPRETATION_XYZ;
}

/**
 * vips_Lab2XYZ:
 * @in: input image
 * @out: output image
 *
 * optional arguments:
 *
 * @temp: colour temperature
 *
 * Turn Lab to XYZ. The colour temperature defaults to D65, but can be 
 * specified with @temp.
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_Lab2XYZ( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "Lab2XYZ", ap, in, out );
	va_end( ap );

	return( result );
}

/**
 * vips_col_Lab2XYZ:
 * @L: Input CIE Lab value
 * @a: Input CIE Lab value
 * @b: Input CIE Lab value
 * @X: Return CIE XYZ colour
 * @Y: Return CIE XYZ colour
 * @Z: Return CIE XYZ colour
 *
 * Calculate XYZ from Lab, D65.
 * 
 * See also: vips_Lab2XYZ().
 */
void
vips_col_Lab2XYZ( float L, float a, float b, float *X, float *Y, float *Z )
{	
	float in[3];
	float *x;
	float out[3];
	VipsLab2XYZ Lab2XYZ;

	in[0] = L;
	in[1] = a;
	in[2] = b;
	x = in;
	Lab2XYZ.X0 = VIPS_D65_X0;
	Lab2XYZ.Y0 = VIPS_D65_Y0;
	Lab2XYZ.Z0 = VIPS_D65_Z0;
	vips_Lab2XYZ_line( (VipsColour *) &Lab2XYZ, 
		(VipsPel *) out, (VipsPel **) &x, 1 );
	*X = out[0];
	*Y = out[1];
	*Z = out[2];
}

