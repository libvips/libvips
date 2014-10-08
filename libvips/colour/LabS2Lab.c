/* LabS2Lab() 
 *
 * 12/12/02 JC
 * 	- adapted from im_LabS2LabQ()
 * 2/11/09
 * 	- gtkdoc, cleanup
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

typedef VipsColourCode VipsLabS2Lab;
typedef VipsColourCodeClass VipsLabS2LabClass;

G_DEFINE_TYPE( VipsLabS2Lab, vips_LabS2Lab, VIPS_TYPE_COLOUR_CODE );

/* Convert n pels from signed short to Lab.
 */
static void
vips_LabS2Lab_line( VipsColour *colour, VipsPel *out, VipsPel **in, int width )
{
	signed short *p = (signed short *) in[0];
	float *q = (float *) out;
	int i;

	for( i = 0; i < width; i++ ) {
		q[0] = p[0] / (32767.0 / 100.0);
		q[1] = p[1] / (32768.0 / 128.0);
		q[2] = p[2] / (32768.0 / 128.0);

		p += 3;
		q += 3;
	}
}

static void
vips_LabS2Lab_class_init( VipsLabS2LabClass *class )
{
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsColourClass *colour_class = VIPS_COLOUR_CLASS( class );

	object_class->nickname = "LabS2Lab";
	object_class->description = _( "transform signed short Lab to float" );

	colour_class->process_line = vips_LabS2Lab_line;
}

static void
vips_LabS2Lab_init( VipsLabS2Lab *LabS2Lab )
{
	VipsColour *colour = VIPS_COLOUR( LabS2Lab );
	VipsColourCode *code = VIPS_COLOUR_CODE( LabS2Lab );

	colour->interpretation = VIPS_INTERPRETATION_LAB;
	colour->format = VIPS_FORMAT_FLOAT;
	colour->input_bands = 3;
	colour->bands = 3;

	code->input_coding = VIPS_CODING_NONE;
	code->input_format = VIPS_FORMAT_SHORT;
}

/**
 * vips_LabS2Lab:
 * @in: input image
 * @out: output image
 *
 * Convert a LabS three-band signed short image to a three-band float image.
 *
 * See also: vips_LabS2Lab().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_LabS2Lab( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "LabS2Lab", ap, in, out );
	va_end( ap );

	return( result );
}

