/* Use lcms to move from CMYK to XYZ, if we can. This needs a working
 * vips_icc_import.
 *
 * 21/12/18
 *      - from CMYK2XYZ
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

#ifdef HAVE_LCMS2

#include <stdio.h>
#include <math.h>

#include <vips/vips.h>

#include "pcolour.h"

typedef VipsColourTransform VipsCMYK2XYZ;
typedef VipsColourTransformClass VipsCMYK2XYZClass;

G_DEFINE_TYPE( VipsCMYK2XYZ, vips_CMYK2XYZ, VIPS_TYPE_COLOUR_TRANSFORM );

void
vips_CMYK2XYZ_line( VipsColour *colour, VipsPel *out, VipsPel **in, int width )
{
        /* Or maybe subclass icc_import? */
}

static void
vips_CMYK2XYZ_class_init( VipsCMYK2XYZClass *class )
{
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsColourClass *colour_class = VIPS_COLOUR_CLASS( class );

	object_class->nickname = "CMYK2XYZ";
	object_class->description = _( "transform CMYK to XYZ" );

	colour_class->process_line = vips_CMYK2XYZ_line;
}

static void
vips_CMYK2XYZ_init( VipsCMYK2XYZ *CMYK2XYZ )
{
	VipsColour *colour = VIPS_COLOUR( CMYK2XYZ );

	colour->interpretation = VIPS_INTERPRETATION_XYZ;
}

#endif /*HAVE_LCMS2*/

/**
 * vips_CMYK2XYZ: (method)
 * @in: input image
 * @out: (out): output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Turn XYZ to CMYK.
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_CMYK2XYZ( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "CMYK2XYZ", ap, in, out );
	va_end( ap );

	return( result );
}
