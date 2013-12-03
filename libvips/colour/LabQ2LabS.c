/* LabQ2LabS
 *
 * 17/11/93 JC
 * 	- adapted from im_LabQ2LabS()
 * 16/11/94 JC
 *	- uses new im_wrap_oneonebuf() fn
 * 9/2/95 JC
 *	- new im_wrapone function
 * 2/11/09
 * 	- gtkdoc
 * 21/9/12
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

#include <vips/vips.h>

#include "pcolour.h"

typedef VipsColourCode VipsLabQ2LabS;
typedef VipsColourCodeClass VipsLabQ2LabSClass;

G_DEFINE_TYPE( VipsLabQ2LabS, vips_LabQ2LabS, VIPS_TYPE_COLOUR_CODE );

/* CONVERT n pels from packed 32bit Lab to signed short.
 */
static void
vips_LabQ2LabS_line( VipsColour *colour, VipsPel *out, VipsPel **in, int width )
{
	unsigned char * restrict p = (unsigned char *) in[0];
	signed short * restrict q = (signed short *) out;

	int i;
	unsigned char ext;
	signed short l, a, b;

	for( i = 0; i < width; i++ ) {
		/* Get most significant 8 bits of lab.
		 */
		l = p[0] << 7;
		a = p[1] << 8;
		b = p[2] << 8;

		/* Get x-tra bits.
		 */
		ext = p[3];
		p += 4;

		/* Shift and mask in to lab.
		 */
		l |= (unsigned char) (ext & 0xc0) >> 1;
		a |= (ext & 0x38) << 2;
		b |= (ext & 0x7) << 5;

		/* Write!
		 */
		q[0] = l;
		q[1] = a;
		q[2] = b;
		q += 3;
	}
}

static void
vips_LabQ2LabS_class_init( VipsLabQ2LabSClass *class )
{
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsColourClass *colour_class = VIPS_COLOUR_CLASS( class );

	object_class->nickname = "LabQ2LabS";
	object_class->description = _( "unpack a LabQ image to short Lab" );

	colour_class->process_line = vips_LabQ2LabS_line;
}

static void
vips_LabQ2LabS_init( VipsLabQ2LabS *LabQ2LabS )
{
	VipsColour *colour = VIPS_COLOUR( LabQ2LabS );
	VipsColourCode *code = VIPS_COLOUR_CODE( LabQ2LabS );

	colour->coding = VIPS_CODING_NONE;
	colour->interpretation = VIPS_INTERPRETATION_LABS;
	colour->format = VIPS_FORMAT_SHORT;
	colour->bands = 3;

	code->input_coding = VIPS_CODING_LABQ;
}

/**
 * vips_LabQ2LabS:
 * @in: input image
 * @out: output image
 *
 * Unpack a LabQ (#IM_CODING_LABQ) image to a three-band short image.
 *
 * See also: vips_LabS2LabQ(), vips_LabQ2LabS(), vips_rad2float().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_LabQ2LabS( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "LabQ2LabS", ap, in, out );
	va_end( ap );

	return( result );
}
