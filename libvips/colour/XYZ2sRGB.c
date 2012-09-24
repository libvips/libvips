/* Turn XYZ files into displayable rgb.
 *
 * Author: J-P. Laurent
 * Modified:
 * 15/11/94 JC
 *	- error message added
 *	- out->Type set to IM_TYPE_RGB
 *	- memory leak fixed
 * 16/11/94 JC
 *	- uses im_wrapone()
 * 15/2/95 JC
 *	- oops! now uses PEL, not float for output pointer
 * 2/1/96 JC
 *	- sometimes produced incorrect result at extrema
 *	- reformatted
 *	- now uses IM_RINT() and clip()
 * 18/9/96 JC
 *	- some speed-ups ... 3x faster
 *	- slightly less accurate, but who cares
 *	- added out-of-mem check for table build
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

typedef VipsColourCode VipsXYZ2sRGB;
typedef VipsColourCodeClass VipsXYZ2sRGBClass;

G_DEFINE_TYPE( VipsXYZ2sRGB, vips_XYZ2sRGB, VIPS_TYPE_COLOUR_CODE );

/* Process a buffer of data.
 */
static void
vips_XYZ2sRGB_line( VipsColour *colour, VipsPel *out, VipsPel **in, int width )
{
	float *p = (float *) in[0];
	VipsPel *q = (VipsPel *) out;

	int i;

	for( i = 0; i < width; i++ ) {
		float X = p[0];
		float Y = p[1];
		float Z = p[2];

		int r, g, b;
		int or;

		vips_col_XYZ2sRGB( X, Y, Z, &r, &g, &b, &or );

		p += 3;

		q[0] = r;
		q[1] = g;
		q[2] = b;

		q += 3;
	}
}

static void
vips_XYZ2sRGB_class_init( VipsXYZ2sRGBClass *class )
{
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsColourClass *colour_class = VIPS_COLOUR_CLASS( class );
	VipsColourCodeClass *code_class = VIPS_COLOUR_CODE_CLASS( class );

	object_class->nickname = "XYZ2sRGB";
	object_class->description = _( "convert an XYZ image to sRGB" ); 

	colour_class->process_line = vips_XYZ2sRGB_line;
	colour_class->coding = VIPS_CODING_NONE;
	colour_class->interpretation = VIPS_INTERPRETATION_sRGB;
	colour_class->format = VIPS_FORMAT_UCHAR;
	colour_class->bands = 3;

	code_class->input_coding = VIPS_CODING_NONE;
	code_class->input_bands = 3;
	code_class->input_format = VIPS_FORMAT_FLOAT;
}

static void
vips_XYZ2sRGB_init( VipsXYZ2sRGB *XYZ2sRGB )
{
}

/**
 * vips_XYZ2sRGB:
 * @in: input image
 * @out: output image
 *
 * Convert an XYZ image to sRGB.
 *
 * See also: im_LabS2LabQ(), im_XYZ2sRGB(), im_rad2float().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_XYZ2sRGB( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "XYZ2sRGB", ap, in, out );
	va_end( ap );

	return( result );
}

