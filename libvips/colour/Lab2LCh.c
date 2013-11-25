/* Turn Lab to LCh
 *
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

typedef VipsColourSpace VipsLab2LCh;
typedef VipsColourSpaceClass VipsLab2LChClass;

G_DEFINE_TYPE( VipsLab2LCh, vips_Lab2LCh, VIPS_TYPE_COLOUR_SPACE );

/**
 * vips_col_ab2h:
 * @a: CIE a
 * @b: CIE b
 *
 * Returns: Hue (degrees) 
 */
double
vips_col_ab2h( double a, double b )
{
	double h;

	/* We have to get the right quadrant!
	 */
	if( a == 0 ) {
		if( b < 0.0 )
			h = 270;
		else if( b == 0.0 )
			h = 0;
		else
			h = 90;
	}
	else {
		double t = atan( b / a );

		if( a > 0.0 )
			if( b < 0.0 )
				h = VIPS_DEG( t + VIPS_PI * 2.0 );
			else
				h = VIPS_DEG( t );
		else
			h = VIPS_DEG( t + VIPS_PI );
	}

	return( h );
}

void
vips_col_ab2Ch( float a, float b, float *C, float *h )
{
	*h = vips_col_ab2h( a, b ); 
	*C = sqrt( a * a + b * b );
}

static void
vips_Lab2LCh_line( VipsColour *colour, VipsPel *out, VipsPel **in, int width )
{
	float *p;
	float *q;
	int x;

	p = (float *) in[0];
	q = (float *) out;

	for( x = 0; x < width; x++ ) {
		float L = p[0];
		float a = p[1];
		float b = p[2];
		float C, h;

		p += 3;

		C = sqrt( a * a + b * b );
		h = vips_col_ab2h( a, b );

		q[0] = L;
		q[1] = C;
		q[2] = h;

		q += 3;
	}
}

static void
vips_Lab2LCh_class_init( VipsLab2LChClass *class )
{
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsColourClass *colour_class = VIPS_COLOUR_CLASS( class );

	object_class->nickname = "Lab2LCh";
	object_class->description = _( "transform Lab to LCh" );

	colour_class->process_line = vips_Lab2LCh_line;
}

static void
vips_Lab2LCh_init( VipsLab2LCh *Lab2LCh )
{
	VipsColour *colour = VIPS_COLOUR( Lab2LCh );

	colour->interpretation = VIPS_INTERPRETATION_LCH;
}

/**
 * vips_Lab2LCh:
 * @in: input image
 * @out: output image
 *
 * Turn Lab to LCh.
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_Lab2LCh( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "Lab2LCh", ap, in, out );
	va_end( ap );

	return( result );
}
