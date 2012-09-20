/* im_LCh2UCS
 *
 * Modified:
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

typedef VipsColourSpace VipsLCh2UCS;
typedef VipsColourSpaceClass VipsLCh2UCSClass;

G_DEFINE_TYPE( VipsLCh2UCS, vips_LCh2UCS, VIPS_TYPE_COLOUR_SPACE );

/**
 * vips_col_L2Lucs:
 * @L: CIE L*
 *
 * Calculate Lucs from L.
 *
 * Returns: Lucs
 */
float
vips_col_L2Lucs( float L )
{	
	float Lucs;

	if( L >= 16.0 )
		Lucs = (21.75 * log( L ) + 0.3838 * L - 38.54);
	else
		Lucs = 1.744 * L;

	return( Lucs );
}

/**
 * vips_col_C2Cucs:
 * @C: Chroma
 *
 * Calculate Cucs from C.
 *
 * Returns: Cucs.
 */
float
vips_col_C2Cucs( float C )
{	
	float Cucs;

	Cucs = 0.162 * C + 10.92 * log( 0.638 + 0.07216 * C ) + 4.907;
	if( Cucs < 0 ) 
		Cucs = 0;

	return( Cucs );
}

/**
 * vips_col_Ch2hucs:
 * @C: Chroma
 * @h: Hue (degrees)
 *
 * Calculate hucs from C and h.
 *
 * Returns: hucs.
 */
float
vips_col_Ch2hucs( float C, float h )
{	
	float P, D, f, g;
	float k4, k5, k6, k7, k8;
	float hucs;

	if( h < 49.1 ) {
		k4 = 133.87;
		k5 = -134.5;
		k6 = -.924;
		k7 = 1.727;
		k8 = 340.0;
	}
	else if( h < 110.1 ) {
		k4 = 11.78;
		k5 = -12.7;
		k6 = -.218;
		k7 = 2.12;
		k8 = 333.0;
	}
	else if( h < 269.6 ) {
		k4 = 13.87;
		k5 = 10.93;
		k6 = 0.14;
		k7 = 1.0;
		k8 = -83.0;
	}
	else {
		k4 = .14;
		k5 = 5.23;
		k6 = .17;
		k7 = 1.61;
		k8 = 233.0;
	}

	P = cos( VIPS_RAD( k8 + k7 * h ) );
	D = k4 + k5 * P * pow( fabs( P ), k6 );
	g = C * C * C * C;
	f = sqrt( g / (g + 1900.0) );
	hucs = h + D * f;

	return( hucs );
}

static void
vips_LCh2UCS_line( VipsColour *colour, VipsPel *out, VipsPel **in, int width )
{
	float *p = (float *) in[0];
	float *q = (float *) out;

	int x;

	for( x = 0; x < width; x++ ) {
		float L = p[0];
		float C = p[1];
		float h = p[2];

		p += 3;

		q[0] = vips_col_L2Lucs( L );
		q[1] = vips_col_C2Cucs( C );
		q[2] = vips_col_Ch2hucs( C, h );

		q += 3;
	}
}

static void
vips_LCh2UCS_class_init( VipsLCh2UCSClass *class )
{
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsColourClass *colour_class = VIPS_COLOUR_CLASS( class );

	object_class->nickname = "LCh2UCS";
	object_class->description = _( "transform LCh to UCS" );

	colour_class->process_line = vips_LCh2UCS_line;
	colour_class->interpretation = VIPS_INTERPRETATION_UCS;
}

static void
vips_LCh2UCS_init( VipsLCh2UCS *LCh2UCS )
{
}

/**
 * vips_LCh2UCS:
 * @in: input image
 * @out: output image
 *
 * Turn LCh to UCS.
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_LCh2UCS( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "LCh2UCS", ap, in, out );
	va_end( ap );

	return( result );
}
