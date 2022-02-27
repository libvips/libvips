/* Turn Yxy to XYZ colourspace. 
 *
 * Modified:
 * 29/5/02 JC
 *	- from lab2xyz
 * 2/11/09
 * 	- gtkdoc
 * 	- cleanups
 * 20/9/12
 * 	- redo as a class
 * 29/8/19
 * 	- avoid /0
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
#include <glib/gi18n-lib.h>

#include <stdio.h>
#include <math.h>

#include <vips/vips.h>

#include "pcolour.h"

typedef VipsColourTransform VipsYxy2XYZ;
typedef VipsColourTransformClass VipsYxy2XYZClass;

G_DEFINE_TYPE( VipsYxy2XYZ, vips_Yxy2XYZ, VIPS_TYPE_COLOUR_TRANSFORM );

void
vips_Yxy2XYZ_line( VipsColour *colour, VipsPel *out, VipsPel **in, int width )
{
	float * restrict p = (float *) in[0];
	float * restrict q = (float *) out;

	int i;

	for( i = 0; i < width; i++ ) {
		float Y = p[0];
		float x = p[1];
		float y = p[2];

		float X, Z;

		if( x == 0.0 ||
			y == 0.0 ) {
			X = 0.0;
			Z = 0.0;
		}
		else {
			double total;

			total = Y / y;
			X = x * total;
			Z = (X - x * X - x * Y) / x;
		}

		q[0] = X;
		q[1] = Y;
		q[2] = Z;

		p += 3;
		q += 3;
	}
}

static void
vips_Yxy2XYZ_class_init( VipsYxy2XYZClass *class )
{
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsColourClass *colour_class = VIPS_COLOUR_CLASS( class );

	object_class->nickname = "Yxy2XYZ";
	object_class->description = _( "transform Yxy to XYZ" );

	colour_class->process_line = vips_Yxy2XYZ_line;
}

static void
vips_Yxy2XYZ_init( VipsYxy2XYZ *Yxy2XYZ )
{
	VipsColour *colour = VIPS_COLOUR( Yxy2XYZ );

	colour->interpretation = VIPS_INTERPRETATION_XYZ;
}

/**
 * vips_Yxy2XYZ: (method)
 * @in: input image
 * @out: (out): output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Turn XYZ to Yxy.
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_Yxy2XYZ( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "Yxy2XYZ", ap, in, out );
	va_end( ap );

	return( result );
}

