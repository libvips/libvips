/* LabS2LabQ()
 *
 * 17/11/93 JC
 * 	- adapted from im_LabS2LabQ()
 * 16/11/94 JC
 *	- adapted to new im_wrap_oneonebuf() function
 * 15/6/95 JC
 *	- oops! rounding was broken
 * 6/6/95 JC
 *	- added round-to-nearest
 *	- somewhat slower ...
 * 21/12/99 JC
 * 	- a/b ==0 rounding was broken
 * 2/11/09
 * 	- gtkdoc, cleanup
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

typedef VipsColourCode VipsLabS2LabQ;
typedef VipsColourCodeClass VipsLabS2LabQClass;

G_DEFINE_TYPE( VipsLabS2LabQ, vips_LabS2LabQ, VIPS_TYPE_COLOUR_CODE );

/* Convert n pels from signed short to IM_CODING_LABQ.
 */
static void
vips_LabS2LabQ_line( VipsColour *colour, VipsPel *out, VipsPel **in, int width )
{
	signed short *p = (signed short *) in[0];
	unsigned char *q = (unsigned char *) out;

	int i;

	for( i = 0; i < width; i++ ) {
		int l, a, b;
		unsigned char ext;

		/* Get LAB, rounding to 10, 11, 11. 
		 */
		l = p[0] + 16;
		l = VIPS_CLIP( 0, l, 32767 );
		l >>= 5;

		/* Make sure we round -ves in the right direction!
		 */
		a = p[1];
		if( a >= 0 )
			a += 16;
		else
			a -= 16;
		a = VIPS_CLIP( -32768, a, 32767 );
		a >>= 5;

		b = p[2];
		if( b >= 0 )
			b += 16;
		else
			b -= 16;
		b = VIPS_CLIP( -32768, b, 32767 );
		b >>= 5;

		p += 3;

		/* Extract top 8 bits.
		 */
		q[0] = l >> 2;
		q[1] = a >> 3;
		q[2] = b >> 3;

		/* Form extension byte.
		 */
		ext = (l << 6) & 0xc0;
		ext |= (a << 3) & 0x38;
		ext |= b & 0x7;
		q[3] = ext;

		q += 4;
	}
}

static void
vips_LabS2LabQ_class_init( VipsLabS2LabQClass *class )
{
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsColourClass *colour_class = VIPS_COLOUR_CLASS( class );

	object_class->nickname = "LabS2LabQ";
	object_class->description = _( "transform short Lab to LabQ coding" );

	colour_class->process_line = vips_LabS2LabQ_line;
}

static void
vips_LabS2LabQ_init( VipsLabS2LabQ *LabS2LabQ )
{
	VipsColour *colour = VIPS_COLOUR( LabS2LabQ );
	VipsColourCode *code = VIPS_COLOUR_CODE( LabS2LabQ );

	colour->coding = VIPS_CODING_LABQ;
	colour->interpretation = VIPS_INTERPRETATION_LABQ;
	colour->format = VIPS_FORMAT_UCHAR;
	colour->input_bands = 3;
	colour->bands = 4;

	code->input_coding = VIPS_CODING_NONE;
	code->input_format = VIPS_FORMAT_SHORT;
}

/**
 * vips_LabS2LabQ:
 * @in: input image
 * @out: output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Convert a LabS three-band signed short image to LabQ
 *
 * See also: vips_LabQ2LabS().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_LabS2LabQ( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "LabS2LabQ", ap, in, out );
	va_end( ap );

	return( result );
}
