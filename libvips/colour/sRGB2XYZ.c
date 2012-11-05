/* Turn displayable rgb files to XYZ.
 *
 * Modified:
 * 15/11/94 JC
 *	- memory leak fixed
 *	- error message added
 * 16/11/94 JC
 *	- partialed
 * 21/9/12
 * 	- redone as a class
 * 	- sRGB only, support for other RGBs is now via lcms
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

typedef VipsColourCode VipssRGB2XYZ;
typedef VipsColourCodeClass VipssRGB2XYZClass;

G_DEFINE_TYPE( VipssRGB2XYZ, vips_sRGB2XYZ, VIPS_TYPE_COLOUR_CODE );

/* Convert a buffer.
 */
static void
vips_sRGB2XYZ_line( VipsColour *colour, VipsPel *out, VipsPel **in, int width )
{
	VipsPel *p = in[0];
	float *q = (float *) out;

	int i;

	for( i = 0; i < width; i++ ) {
		int r = p[0];
		int g = p[1];
		int b = p[2];
		float X, Y, Z;

		p += 3;

		vips_col_sRGB2XYZ_8( r, g, b, &X, &Y, &Z );

		q[0] = X;
		q[1] = Y;
		q[2] = Z;

		q += 3;
	}
}

static void
vips_sRGB2XYZ_class_init( VipssRGB2XYZClass *class )
{
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsColourClass *colour_class = VIPS_COLOUR_CLASS( class );

	object_class->nickname = "sRGB2XYZ";
	object_class->description = _( "convert an sRGB image to XYZ" );

	colour_class->process_line = vips_sRGB2XYZ_line;
}

static void
vips_sRGB2XYZ_init( VipssRGB2XYZ *sRGB2XYZ )
{
	VipsColour *colour = VIPS_COLOUR( sRGB2XYZ );
	VipsColourCode *code = VIPS_COLOUR_CODE( sRGB2XYZ );

	colour->coding = VIPS_CODING_NONE;
	colour->interpretation = VIPS_INTERPRETATION_XYZ;
	colour->format = VIPS_FORMAT_FLOAT;
	colour->bands = 3;

	code->input_coding = VIPS_CODING_NONE;
	code->input_bands = 3;
	code->input_format = VIPS_FORMAT_UCHAR;
}

/**
 * vips_sRGB2XYZ:
 * @in: input image
 * @out: output image
 *
 * Convert an sRGB image to XYZ.
 *
 * See also: im_LabS2LabQ(), im_sRGB2XYZ(), im_rad2float().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_sRGB2XYZ( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "sRGB2XYZ", ap, in, out );
	va_end( ap );

	return( result );
}

