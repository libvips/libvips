/* Convert float to Radiance 32bit packed format
 *
 * 23/3/09
 * 	- from im_rad2float and Radiance sources
 * 2/11/09
 * 	- gtkdoc 
 * 20/9/12
 * 	redo as a class
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

/*

    Sections of this file from Greg Ward and Radiance with kind 
    permission. The Radience copyright notice appears below.

 */

/* ====================================================================
 * The Radiance Software License, Version 1.0
 *
 * Copyright (c) 1990 - 2009 The Regents of the University of California,
 * through Lawrence Berkeley National Laboratory.   All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *         notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *
 * 3. The end-user documentation included with the redistribution,
 *           if any, must include the following acknowledgment:
 *             "This product includes Radiance software
 *                 (http://radsite.lbl.gov/)
 *                 developed by the Lawrence Berkeley National Laboratory
 *               (http://www.lbl.gov/)."
 *       Alternately, this acknowledgment may appear in the software itself,
 *       if and wherever such third-party acknowledgments normally appear.
 *
 * 4. The names "Radiance," "Lawrence Berkeley National Laboratory"
 *       and "The Regents of the University of California" must
 *       not be used to endorse or promote products derived from this
 *       software without prior written permission. For written
 *       permission, please contact radiance@radsite.lbl.gov.
 *
 * 5. Products derived from this software may not be called "Radiance",
 *       nor may "Radiance" appear in their name, without prior written
 *       permission of Lawrence Berkeley National Laboratory.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.   IN NO EVENT SHALL Lawrence Berkeley National Laboratory OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of Lawrence Berkeley National Laboratory.   For more
 * information on Lawrence Berkeley National Laboratory, please see
 * <http://www.lbl.gov/>.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <math.h>

#include <vips/vips.h>

#include "colour.h"

/* Begin copy-paste from Radiance sources.
 */

#define  RED		0
#define  GRN		1
#define  BLU		2
#define  CIEX		0	/* or, if input is XYZ... */
#define  CIEY		1
#define  CIEZ		2
#define  EXP		3	/* exponent same for either format */
#define  COLXS		128	/* excess used for exponent */
#define  WHT		3	/* used for RGBPRIMS type */

#undef  BYTE
#define  BYTE 	unsigned char	/* 8-bit unsigned integer */

typedef BYTE  COLR[4];		/* red, green, blue (or X,Y,Z), exponent */

typedef float COLORV;
typedef COLORV  COLOR[3];	/* red, green, blue (or X,Y,Z) */

#define  copycolor(c1,c2)	((c1)[0]=(c2)[0],(c1)[1]=(c2)[1],(c1)[2]=(c2)[2])

static void
setcolr( COLR clr, double r, double g, double b )           /* assign a short color value */
{
        double  d;
        int  e;

        d = r > g ? r : g;
        if (b > d) d = b;

        if (d <= 1e-32) {
                clr[RED] = clr[GRN] = clr[BLU] = 0;
                clr[EXP] = 0;
                return;
        }

        d = frexp(d, &e) * 255.9999 / d;

        if (r > 0.0)
                clr[RED] = r * d;
        else
                clr[RED] = 0;
        if (g > 0.0)
                clr[GRN] = g * d;
        else
                clr[GRN] = 0;
        if (b > 0.0)
                clr[BLU] = b * d;
        else
                clr[BLU] = 0;

        clr[EXP] = e + COLXS;
}

/* End copy-paste from Radiance sources.
 */

typedef VipsColourCode VipsFloat2rad;
typedef VipsColourCodeClass VipsFloat2radClass;

G_DEFINE_TYPE( VipsFloat2rad, vips_float2rad, VIPS_TYPE_COLOUR_CODE );

static void
vips_float2rad_line( VipsColour *colour, VipsPel *out, VipsPel **in, int width )
{
	COLOR *inp = (COLOR *) in[0];
	COLR *outbuf = (COLR *) out;

	while( width-- > 0 ) {
		setcolr( outbuf[0], inp[0][RED], inp[0][GRN], inp[0][BLU] );
		inp++;
		outbuf++;
	}
}

static void
vips_float2rad_class_init( VipsFloat2radClass *class )
{
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsColourClass *colour_class = VIPS_COLOUR_CLASS( class );
	VipsColourCodeClass *code_class = VIPS_COLOUR_CODE_CLASS( class );

	object_class->nickname = "float2rad";
	object_class->description = 
		_( "transform float RGB to Radiance coding" );

	colour_class->process_line = vips_float2rad_line;
	colour_class->coding = VIPS_CODING_RAD;
	colour_class->interpretation = VIPS_INTERPRETATION_sRGB;
	colour_class->format = VIPS_FORMAT_UCHAR;
	colour_class->bands = 4;

	code_class->input_coding = VIPS_CODING_NONE;
	code_class->input_format = VIPS_FORMAT_FLOAT;
	code_class->input_bands = 3;
}

static void
vips_float2rad_init( VipsFloat2rad *float2rad )
{
}

/**
 * vips_float2rad:
 * @in: input image
 * @out: output image
 *
 * Convert a three-band float image to Radiance 32-bit packed format.
 *
 * See also: im_rad2float(), #VipsFormatRad, im_LabQ2Lab().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_float2rad( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "float2rad", ap, in, out );
	va_end( ap );

	return( result );
}
