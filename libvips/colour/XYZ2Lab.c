/* Turn XYZ to Lab colourspace. 
 *
 * Modifed:
 * 16/11/94 JC
 *	- uses im_wrapone()
 *	- in-line conversion
 * 27/1/03 JC
 *	- swapped cbrt() for pow(), more portable
 * 12/11/04
 * 	- swapped pow() for cbrt() again, pow() is insanely slow on win32
 * 	- added a configure test for cbrt().
 * 23/11/04
 *	- use a large LUT instead, about 5x faster
 * 23/11/06
 *	- ahem, build the LUT outside the eval thread
 * 2/11/09
 * 	- gtkdoc
 * 3/8/11
 * 	- fix a race in the table build
 * 19/9/12
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
#include <math.h>

#include <vips/vips.h>

#include "pcolour.h"

#ifndef HAVE_CBRT
#define cbrt( X ) pow( (X), 1.0 / 3.0 )
#endif /*!HAVE_CBRT*/

/* Lookup table size.
 */
#define QUANT_ELEMENTS (100000)

float cbrt_table[QUANT_ELEMENTS];

typedef struct _VipsXYZ2Lab {
	VipsColourSpace parent_instance;

	/* The colour temperature -- default to D65. 
	 */
	VipsArea *temp;

	/* Broken out as xyz.
	 */
	double X0;
	double Y0;
	double Z0;

} VipsXYZ2Lab;

typedef VipsColourSpaceClass VipsXYZ2LabClass;

G_DEFINE_TYPE( VipsXYZ2Lab, vips_XYZ2Lab, VIPS_TYPE_COLOUR_SPACE );

static void *
table_init( void *client )
{
	int i;

	for( i = 0; i < QUANT_ELEMENTS; i++ ) {
		float Y = (double) i / QUANT_ELEMENTS;

		if( Y < 0.008856 ) 
			cbrt_table[i] = 7.787 * Y + (16.0 / 116.0);
		else 
			cbrt_table[i] = cbrt( Y );
	}

	return( NULL );
}

static void
vips_XYZ2Lab_make_tables( void )
{
	static GOnce once = G_ONCE_INIT;

	(void) g_once( &once, table_init, NULL );
}

/* Process a buffer of data.
 */
static void
vips_XYZ2Lab_line( VipsColour *colour, VipsPel *out, VipsPel **in, int width )
{
	VipsXYZ2Lab *XYZ2Lab = (VipsXYZ2Lab *) colour;
	float *p = (float *) in[0];
	float *q = (float *) out;

	int x;

        vips_XYZ2Lab_make_tables();

	for( x = 0; x < width; x++ ) {
		float nX, nY, nZ;
		int i;
		float f;
		float cbx, cby, cbz;

		nX = QUANT_ELEMENTS * p[0] / XYZ2Lab->X0;
		nY = QUANT_ELEMENTS * p[1] / XYZ2Lab->Y0;
		nZ = QUANT_ELEMENTS * p[2] / XYZ2Lab->Z0;
		p += 3;

		i = VIPS_CLIP( 0, (int) nX, QUANT_ELEMENTS - 2 );
		f = nX - i;
		cbx = cbrt_table[i] + f * (cbrt_table[i + 1] - cbrt_table[i]);

		i = VIPS_CLIP( 0, (int) nY, QUANT_ELEMENTS - 2 );
		f = nY - i;
		cby = cbrt_table[i] + f * (cbrt_table[i + 1] - cbrt_table[i]);

		i = VIPS_CLIP( 0, (int) nZ, QUANT_ELEMENTS - 2 );
		f = nZ - i;
		cbz = cbrt_table[i] + f * (cbrt_table[i + 1] - cbrt_table[i]);

		q[0] = 116.0 * cby - 16.0;
		q[1] = 500.0 * (cbx - cby);
		q[2] = 200.0 * (cby - cbz);
		q += 3;
	}
}

/**
 * vips_col_XYZ2Lab:
 * @X: Input CIE XYZ colour
 * @Y: Input CIE XYZ colour
 * @Z: Input CIE XYZ colour
 * @L: Return CIE Lab value
 * @a: Return CIE Lab value
 * @b: Return CIE Lab value
 *
 * Calculate XYZ from Lab, D65.
 * 
 * See also: vips_XYZ2Lab().
 */
void
vips_col_XYZ2Lab( float X, float Y, float Z, float *L, float *a, float *b )
{	
	float in[3];
	float out[3];
	float *x;
	VipsXYZ2Lab XYZ2Lab;

	in[0] = X;
	in[1] = Y;
	in[2] = Z;
	x = in;
	XYZ2Lab.X0 = VIPS_D65_X0;
	XYZ2Lab.Y0 = VIPS_D65_Y0;
	XYZ2Lab.Z0 = VIPS_D65_Z0;
	vips_XYZ2Lab_line( (VipsColour *) &XYZ2Lab, 
		(VipsPel *) out, (VipsPel **) &x, 1 );
	*L = out[0];
	*a = out[1];
	*b = out[2];
}

static int
vips_XYZ2Lab_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsXYZ2Lab *XYZ2Lab = (VipsXYZ2Lab *) object;

	if( XYZ2Lab->temp ) {
		if( vips_check_vector_length( class->nickname, 
			XYZ2Lab->temp->n, 3 ) )
			return( -1 );
		XYZ2Lab->X0 = ((double *) XYZ2Lab->temp->data)[0];
		XYZ2Lab->Y0 = ((double *) XYZ2Lab->temp->data)[1];
		XYZ2Lab->Z0 = ((double *) XYZ2Lab->temp->data)[2];
	}

	if( VIPS_OBJECT_CLASS( vips_XYZ2Lab_parent_class )->build( object ) )
		return( -1 );

	return( 0 );
}

static void
vips_XYZ2Lab_class_init( VipsXYZ2LabClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsColourClass *colour_class = VIPS_COLOUR_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "XYZ2Lab";
	object_class->description = _( "transform XYZ to Lab" );
	object_class->build = vips_XYZ2Lab_build;

	colour_class->process_line = vips_XYZ2Lab_line;

	VIPS_ARG_BOXED( class, "temp", 110, 
		_( "Temperature" ), 
		_( "Colour temperature" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsXYZ2Lab, temp ),
		VIPS_TYPE_ARRAY_DOUBLE );
}

static void
vips_XYZ2Lab_init( VipsXYZ2Lab *XYZ2Lab )
{
	VipsColour *colour = VIPS_COLOUR( XYZ2Lab );

	XYZ2Lab->X0 = VIPS_D65_X0;
	XYZ2Lab->Y0 = VIPS_D65_Y0;
	XYZ2Lab->Z0 = VIPS_D65_Z0;

	colour->interpretation = VIPS_INTERPRETATION_LAB;
}

/**
 * vips_XYZ2Lab:
 * @in: input image
 * @out: output image
 *
 * optional arguments:
 *
 * @temp: colour temperature
 *
 * Turn XYZ to Lab, optionally specifying the colour temperature. @temp
 * defaults to D65. 
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_XYZ2Lab( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "XYZ2Lab", ap, in, out );
	va_end( ap );

	return( result );
}

