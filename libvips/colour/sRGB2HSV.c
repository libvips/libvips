/* to HSV ... useful for compatibility with other packages
 *
 * 9/6/15
 * 	- from LabS2Lab.c
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

#include <vips/vips.h>

#include "pcolour.h"

typedef VipsColourCode VipssRGB2HSV;
typedef VipsColourCodeClass VipssRGB2HSVClass;

G_DEFINE_TYPE( VipssRGB2HSV, vips_sRGB2HSV, VIPS_TYPE_COLOUR_CODE );

static void
vips_sRGB2HSV_line( VipsColour *colour, VipsPel *out, VipsPel **in, int width )
{
	unsigned char *p = (unsigned char *) in[0];
	unsigned char *q = (unsigned char *) out;
	int i;

	float c1,c2,c3,c_max,c_min,delta,x;

	for( i = 0; i < width; i++ ) {

		c1=(float)p[0]/(float)255.0;
		c2=(float)p[1]/(float)255.0;
		c3=(float)p[2]/(float)255.0;

		c_max=VIPS_MAX(c1,VIPS_MAX(c2,c3));
		c_min=VIPS_MIN(c1,VIPS_MIN(c2,c3));

		delta=c_max-c_min;

		float normalization = 256.0/(float)6.0;

		if (delta == 0.0) {
			q[0] = 0;
		} else if (c_max == c1) {
			x = ((c2 - c3) / delta);
			if (c2 < c3) x += 6.0;
			q[0] = (int) x * normalization;
		} else if (c_max == c2) {
			q[0] = (int) (((c3 - c1) / delta) + 2) * normalization;
		} else if (c_max == c3) {
			q[0] = (int) (((c1 - c2) / delta) + 4) * normalization;
		}

		if (c_max == 0.0) {
			q[1]=0;
		} else {
			q[1]= (int) 256.0*delta/c_max;
		}

		q[2]=c_max;

		p += 3;
		q += 3;
	}
}

static void
vips_sRGB2HSV_class_init( VipssRGB2HSVClass *class )
{
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsColourClass *colour_class = VIPS_COLOUR_CLASS( class );

	object_class->nickname = "sRGB2HSV";
	object_class->description = _( "transform sRGB to HSV" );

	colour_class->process_line = vips_sRGB2HSV_line;
}

static void
vips_sRGB2HSV_init( VipssRGB2HSV *sRGB2HSV )
{
	VipsColour *colour = VIPS_COLOUR( sRGB2HSV );
	VipsColourCode *code = VIPS_COLOUR_CODE( sRGB2HSV );

	colour->interpretation = VIPS_INTERPRETATION_HSV;
	colour->format = VIPS_FORMAT_UCHAR;
	colour->bands = 3;
	colour->input_bands = 3;

	code->input_coding = VIPS_CODING_NONE;
	code->input_format = VIPS_FORMAT_UCHAR;
	code->input_interpretation = VIPS_INTERPRETATION_sRGB;
}

/**
 * vips_sRGB2HSV:
 * @in: input image
 * @out: output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Convert to HSV.
 *
 * See also: vips_HSV2sRGB().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_sRGB2HSV( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "sRGB2HSV", ap, in, out );
	va_end( ap );

	return( result );
}

