/* Turn XYZ to Yxy colourspace. 
 *
 * Modified:
 * 29/5/02 JC
 *	- from lab2xyz
 * 2/11/09
 * 	- gtkdoc
 * 	- cleanups
 * 20/9/12
 * 	redo as a class
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <math.h>

#include <vips/vips.h>

#include "colour.h"

typedef VipsColourSpace VipsXYZ2Yxy;
typedef VipsColourSpaceClass VipsXYZ2YxyClass;

G_DEFINE_TYPE( VipsXYZ2Yxy, vips_XYZ2Yxy, VIPS_TYPE_COLOUR_SPACE );

static void
vips_XYZ2Yxy_line( VipsColour *colour, VipsPel *out, VipsPel **in, int width )
{
	float *p = (float *) in[0];
	float *q = (float *) out;

	int i;

	for( i = 0; i < width; i++ ) {
		float X = p[0];
		float Y = p[1];
		float Z = p[2];
		double total = X + Y + Z;

		float x, y;

		p += 3;

	        x = X / total;
		y = Y / total;

		q[0] = Y;
		q[1] = x;
		q[2] = y;
		q += 3;
	}
}

static void
vips_XYZ2Yxy_class_init( VipsXYZ2YxyClass *class )
{
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsColourClass *colour_class = VIPS_COLOUR_CLASS( class );

	object_class->nickname = "XYZ2Yxy";
	object_class->description = _( "transform XYZ to Yxy" );

	colour_class->process_line = vips_XYZ2Yxy_line;
	colour_class->interpretation = VIPS_INTERPRETATION_YXY;
}

static void
vips_XYZ2Yxy_init( VipsXYZ2Yxy *XYZ2Yxy )
{
}

/**
 * vips_XYZ2Yxy:
 * @in: input image
 * @out: output image
 *
 * Turn XYZ to Yxy.
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_XYZ2Yxy( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "XYZ2Yxy", ap, in, out );
	va_end( ap );

	return( result );
}
