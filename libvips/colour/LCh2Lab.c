/* im_LCh2Lab
 *
 * 15/11/94 JC
 *	- error messages added
 *	- memory leak fixed
 * 16/11/94 JC
 *	- uses im_wrap_oneonebuf() now
 * 8/2/95 JC
 *	- im_wrap v2
 * 2/11/09
 * 	- gtkdoc
 * 19/9/12
 * 	- redone as a class
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

typedef VipsColourSpace VipsLCh2Lab;
typedef VipsColourSpaceClass VipsLCh2LabClass;

G_DEFINE_TYPE( VipsLCh2Lab, vips_LCh2Lab, VIPS_TYPE_COLOUR_SPACE );

/* Process a buffer of data.
 */
static void
vips_LCh2Lab_line( VipsColour *colour, VipsPel *out, VipsPel **in, int width )
{		
	float *p = (float *) in[0];
	float *q = (float *) out;

	int x;

	for( x = 0; x < width; x++ ) {
		float L = p[0];
		float C = p[1];
		float h = p[2];
		float a, b;

		p += 3;

		a = C * cos( VIPS_RAD( h ) );
		b = C * sin( VIPS_RAD( h ) );

		q[0] = L;
		q[1] = a;
		q[2] = b;
		q += 3;
	}
}

/**
 * vips_col_Ch2ab:
 * @C: Chroma
 * @h: Hue angle (degrees)
 * @a: return CIE a* value
 * @b: return CIE b* value
 *
 * Calculate ab from Ch, h in degrees.
 */
void
vips_col_Ch2ab( float C, float h, float *a, float *b )
{
	float in[3], out[3];

	in[1] = C;
	in[2] = h;
	vips_LCh2Lab_line( NULL, (VipsPel *) out, (VipsPel **) &in, 1 );
	*a = out[1];
	*b = out[2];
}

static void
vips_LCh2Lab_class_init( VipsLCh2LabClass *class )
{
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsColourClass *colour_class = VIPS_COLOUR_CLASS( class );

	object_class->nickname = "LCh2Lab";
	object_class->description = _( "transform LCh to Lab" );

	colour_class->process_line = vips_LCh2Lab_line;
	colour_class->interpretation = VIPS_INTERPRETATION_LAB;
}

static void
vips_LCh2Lab_init( VipsLCh2Lab *LCh2Lab )
{
}

/**
 * vips_LCh2Lab:
 * @in: input image
 * @out: output image
 *
 * Turn LCh to Lab.
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_LCh2Lab( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "LCh2Lab", ap, in, out );
	va_end( ap );

	return( result );
}
