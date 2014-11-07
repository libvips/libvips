/* LabQ2Lab
 *
 * Copyright Kirk Martinez 2/5/1993
 *
 * Modified: 16/6/93
 * 7/6/93 JC
 *	- adapted for partial v2
 * 16/11/94 JC
 *	- adapted to new im_wrap_oneonebuf() function.
 * 9/2/95 JC
 *	- new im_wrapone function
 * 22/5/95 JC
 *	- changed char to unsigned char for RS/6000 
 * 	- small tidies and speed-ups
 * 4/9/97 JC
 *	- L* = 100.0 now handled correctly
 * 2/11/09
 * 	- gtkdoc
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

#include <vips/vips.h>

#include "pcolour.h"

typedef VipsColourCode VipsLabQ2Lab;
typedef VipsColourCodeClass VipsLabQ2LabClass;

G_DEFINE_TYPE( VipsLabQ2Lab, vips_LabQ2Lab, VIPS_TYPE_COLOUR_CODE );

/* imb_LabQ2Lab: CONVERT n pels from packed 32bit Lab to float values
 * in a buffer
 * ARGS:   VipsPel *inp       pointer to first byte of Lab32 buffer
 * float *outbuf   destination buffer
 *	int n           number of pels to process
 * (C) K.Martinez 2/5/93
 */
static void
vips_LabQ2Lab_line( VipsColour *colour, VipsPel *out, VipsPel **in, int width )
{
	signed char * restrict p = (signed char *) in[0];
	float * restrict q = (float *) out;

	int l;
	int lsbs;               /* for lsbs byte */
	int i;                  /* counter      */

	/* Read input with a signed pointer to get signed ab easily.
	 */
	for( i = 0; i < width; i++ ) {
		/* Get extra bits.
		 */
		lsbs = ((unsigned char *) p)[3];

		/* Build L.
		 */
		l = ((unsigned char *)p)[0];
		l = (l << 2) | (lsbs >> 6);
		q[0] = (float) l * (100.0 / 1023.0);

		/* Build a.
		 */
		l = (p[1] << 3) | ((lsbs >> 3) & 0x7);
		q[1] = (float) l * 0.125;

		/* And b.
		 */
		l = (p[2] << 3) | (lsbs & 0x7);
		q[2] = (float) l * 0.125;        

		p += 4;
		q += 3;
	}
}

void
vips__LabQ2Lab_vec( float *out, VipsPel *in, int width )
{
	vips_LabQ2Lab_line( NULL, (VipsPel *) out, &in, width );
}

static void
vips_LabQ2Lab_class_init( VipsLabQ2LabClass *class )
{
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsColourClass *colour_class = VIPS_COLOUR_CLASS( class );

	object_class->nickname = "LabQ2Lab";
	object_class->description = _( "unpack a LabQ image to float Lab" );

	colour_class->process_line = vips_LabQ2Lab_line;
}

static void
vips_LabQ2Lab_init( VipsLabQ2Lab *LabQ2Lab )
{
	VipsColour *colour = VIPS_COLOUR( LabQ2Lab );
	VipsColourCode *code = VIPS_COLOUR_CODE( LabQ2Lab );

	colour->coding = VIPS_CODING_NONE;
	colour->interpretation = VIPS_INTERPRETATION_LAB;
	colour->format = VIPS_FORMAT_FLOAT;
	colour->bands = 3;

	code->input_coding = VIPS_CODING_LABQ;
}

/**
 * vips_LabQ2Lab:
 * @in: input image
 * @out: output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Unpack a LabQ (#IM_CODING_LABQ) image to a three-band float image.
 *
 * See also: vips_LabQ2Lab(), vips_LabQ2LabS(), vips_rad2float().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_LabQ2Lab( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "LabQ2Lab", ap, in, out );
	va_end( ap );

	return( result );
}
