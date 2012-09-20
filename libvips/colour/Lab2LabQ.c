/* @(#) im_Lab2LabQ: quantise FLOAT Lab image into 10 11 11 format
 * 4 bytes per pel: l a b lsbs
 * this is an image wrapper which calls line-wise packing
 * Copyright K.Martinez 3/5/93
 * Modified:
 * 7/6/93 JC
 *	- adapted for partial v2
 * 5/5/94 JC
 *	- some nint->+0.5, for speed and to ease portability
 *	- other nint->rint
 *	- now inclues <math.h>!
 * 15/11/94 JC
 *	- all nint(), rint() removed for speed
 *	- now -128 rather than -127 for a, b
 *	- checks input type properly
 * 16/11/94 JC
 *	- uses new im_wrap_oneonebuf()
 * 22/5/95 JC
 *	- changed L to scale by 10.24, not 10.23
 * 11/7/95 JC
 *	- now uses IM_RINT() for rounding
 * 4/9/97 JC
 *	- L* = 100.0 now allowed
 * 5/11/00 JC
 *	- go int earlier for speed up
 * 20/6/02 JC
 *	- oops, were not clipping a/b range correctly
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

typedef VipsColourCode VipsLab2LabQ;
typedef VipsColourCodeClass VipsLab2LabQClass;

G_DEFINE_TYPE( VipsLab2LabQ, vips_Lab2LabQ, VIPS_TYPE_COLOUR_CODE );

/* @(#) convert float Lab to packed Lab32 format 10 11 11 bits
 * works only on buffers, not IMAGEs
 * Copyright 1993 K.Martinez
 * Modified: 3/5/93, 16/6/93
 */
static void
vips_Lab2LabQ_line( VipsColour *colour, VipsPel *out, VipsPel **in, int width )
{
	float *p = (float *) in[0];

	float fval;
	int lsbs;
	int intv;
	int i;

	for( i = 0; i < width; i++) {
		/* Scale L up to 10 bits. Add 0.5 rather than call VIPS_RINT 
		 * for speed. This will not round negatives correctly! But 
		 * this does not matter, since L is >0. L*=100.0 -> 1023.
		 */
		intv = 10.23 * p[0] + 0.5;	/* scale L up to 10 bits */
		intv = VIPS_CLIP( 0, intv, 1023 );
		lsbs = (intv & 0x3) << 6;       /* 00000011 -> 11000000 */
		out[0] = (intv >> 2); 		/* drop bot 2 bits and store */

		fval = 8.0 * p[1];              /* do a */
		intv = VIPS_RINT( fval );
		intv = VIPS_CLIP( -1024, intv, 1023 );
		lsbs |= (intv & 0x7) << 3;      /* 00000111 -> 00111000 */
		out[1] = (intv >> 3);   	/* drop bot 3 bits & store */

		fval = 8.0 * p[2];              /* do b */
		intv = VIPS_RINT( fval );
		intv = VIPS_CLIP( -1024, intv, 1023 );
		lsbs |= (intv & 0x7);
		out[2] = (intv >> 3);

		out[3] = lsbs;                /* store lsb band */

		p += 3;
		out += 4;
	}
}

void
vips__Lab2LabQ_vec( VipsPel *out, float *in, int width )
{
	vips_Lab2LabQ_line( NULL, out, (VipsPel **) &in, width );
}

static void
vips_Lab2LabQ_class_init( VipsLab2LabQClass *class )
{
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsColourClass *colour_class = VIPS_COLOUR_CLASS( class );
	VipsColourCodeClass *code_class = VIPS_COLOUR_CODE_CLASS( class );

	object_class->nickname = "Lab2LabQ";
	object_class->description = _( "transform float Lab to LabQ coding" );

	colour_class->process_line = vips_Lab2LabQ_line;
	colour_class->coding = VIPS_CODING_LABQ;
	colour_class->interpretation = VIPS_INTERPRETATION_LABQ;
	colour_class->format = VIPS_FORMAT_UCHAR;
	colour_class->bands = 4;

	code_class->input_coding = VIPS_CODING_NONE;
	code_class->input_format = VIPS_FORMAT_FLOAT;
	code_class->input_bands = 3;
}

static void
vips_Lab2LabQ_init( VipsLab2LabQ *Lab2LabQ )
{
}

/**
 * vips_Lab2LabQ:
 * @in: input image
 * @out: output image
 *
 * Convert a Lab three-band float image to LabQ (#IM_CODING_LABQ).
 *
 * See also: im_LabQ2Lab().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_Lab2LabQ( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "Lab2LabQ", ap, in, out );
	va_end( ap );

	return( result );
}
