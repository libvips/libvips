/* Turn XYZ to scRGB colourspace. 
 *
 * 11/12/12
 * 	- from Yxy2XYZ.c
 * 1/7/13
 * 	- remove any ICC profile
 * 25/11/14
 * 	- oh argh, revert the above
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

typedef VipsColourSpace VipsXYZ2scRGB;
typedef VipsColourSpaceClass VipsXYZ2scRGBClass;

G_DEFINE_TYPE( VipsXYZ2scRGB, vips_XYZ2scRGB, VIPS_TYPE_COLOUR_SPACE );

/* We used to have the comment:

	 * We've converted to sRGB without a profile. We must remove any ICC
	 * profile left over from import or there will be a mismatch between
	 * pixel values and the attached profile. 

   But this isn't right, we often call things sRGB that we know are not true 
   sRGB, for example:

   	vips sharpen k2.jpg x.jpg

   sharpen will treat k2 as being in sRGB space even if that image has a 
   profile. If we drop the profile, x.jpg is suddenly untagged.

 */

void
vips_XYZ2scRGB_line( VipsColour *colour, VipsPel *out, VipsPel **in, int width )
{
	float * restrict p = (float *) in[0];
	float * restrict q = (float *) out;

	int i;

	for( i = 0; i < width; i++ ) {
		float X = p[0];
		float Y = p[1];
		float Z = p[2];

		float R, G, B;

		p += 3;

		vips_col_XYZ2scRGB( X, Y, Z, &R, &G, &B );

		q[0] = R;
		q[1] = G;
		q[2] = B;

		q += 3;
	}
}

static void
vips_XYZ2scRGB_class_init( VipsXYZ2scRGBClass *class )
{
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsColourClass *colour_class = VIPS_COLOUR_CLASS( class );

	object_class->nickname = "XYZ2scRGB";
	object_class->description = _( "transform XYZ to scRGB" );

	colour_class->process_line = vips_XYZ2scRGB_line;
}

static void
vips_XYZ2scRGB_init( VipsXYZ2scRGB *XYZ2scRGB )
{
	VipsColour *colour = VIPS_COLOUR( XYZ2scRGB );

	colour->interpretation = VIPS_INTERPRETATION_scRGB;
}

/**
 * vips_XYZ2scRGB:
 * @in: input image
 * @out: output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Turn XYZ to scRGB.
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_XYZ2scRGB( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "XYZ2scRGB", ap, in, out );
	va_end( ap );

	return( result );
}

