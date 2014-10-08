/* Lab2LabS: quantise FLOAT Lab image into signed short format
 *
 * 12/12/02 JC
 *	- from im_Lab2LabS
 * 1/11/09
 *	- gtkdoc
 *	- cleanups
 * 20/9/12
 * 	- redo as a class
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

typedef VipsColourCode VipsLab2LabS;
typedef VipsColourCodeClass VipsLab2LabSClass;

G_DEFINE_TYPE( VipsLab2LabS, vips_Lab2LabS, VIPS_TYPE_COLOUR_CODE );

static void
vips_Lab2LabS_line( VipsColour *colour, VipsPel *out, VipsPel **in, int width )
{
	float * restrict p = (float *) in[0];
	signed short * restrict q = (signed short *) out;
	int i;

	for( i = 0; i < width; i++ ) {
		q[0] = p[0] * (32767.0 / 100.0);
		q[1] = p[1] * (32768.0 / 128.0);
		q[2] = p[2] * (32768.0 / 128.0);

		q += 3;
		p += 3;
	}
}

static void
vips_Lab2LabS_class_init( VipsLab2LabSClass *class )
{
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsColourClass *colour_class = VIPS_COLOUR_CLASS( class );

	object_class->nickname = "Lab2LabS";
	object_class->description = _( "transform float Lab to signed short" );

	colour_class->process_line = vips_Lab2LabS_line;
}

static void
vips_Lab2LabS_init( VipsLab2LabS *Lab2LabS )
{
	VipsColour *colour = VIPS_COLOUR( Lab2LabS );
	VipsColourCode *code = VIPS_COLOUR_CODE( Lab2LabS );

	colour->interpretation = VIPS_INTERPRETATION_LABS;
	colour->format = VIPS_FORMAT_SHORT;
	colour->input_bands = 3;
	colour->bands = 3;

	code->input_coding = VIPS_CODING_NONE;
	code->input_format = VIPS_FORMAT_FLOAT;
}

/**
 * vips_Lab2LabS:
 * @in: input image
 * @out: output image
 *
 * Turn Lab to LabS, signed 16-bit int fixed point.
 *
 * See also: vips_LabQ2Lab().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_Lab2LabS( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "Lab2LabS", ap, in, out );
	va_end( ap );

	return( result );
}

