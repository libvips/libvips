/* im_LCh2CMC
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

typedef VipsColourSpace VipsLCh2CMC;
typedef VipsColourSpaceClass VipsLCh2CMCClass;

G_DEFINE_TYPE( VipsLCh2CMC, vips_LCh2CMC, VIPS_TYPE_COLOUR_SPACE );

/**
 * vips_col_L2Lcmc:
 * @L: CIE L*
 *
 * Calculate Lcmc from L.
 *
 * Returns: Lcmc
 */
float
vips_col_L2Lcmc( float L )
{	
	float Lcmc;

	if( L >= 16.0 )
		Lcmc = (21.75 * log( L ) + 0.3838 * L - 38.54);
	else
		Lcmc = 1.744 * L;

	return( Lcmc );
}

/**
 * vips_col_C2Ccmc:
 * @C: Chroma
 *
 * Calculate Ccmc from C.
 *
 * Returns: Ccmc.
 */
float
vips_col_C2Ccmc( float C )
{	
	float Ccmc;

	Ccmc = 0.162 * C + 10.92 * log( 0.638 + 0.07216 * C ) + 4.907;
	if( Ccmc < 0 ) 
		Ccmc = 0;

	return( Ccmc );
}

/**
 * vips_col_Ch2hcmc:
 * @C: Chroma
 * @h: Hue (degrees)
 *
 * Calculate hcmc from C and h.
 *
 * Returns: hcmc.
 */
float
vips_col_Ch2hcmc( float C, float h )
{	
	float P, D, f, g;
	float k4, k5, k6, k7, k8;
	float hcmc;

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
	hcmc = h + D * f;

	return( hcmc );
}

static void
vips_LCh2CMC_line( VipsColour *colour, VipsPel *out, VipsPel **in, int width )
{
	float *p = (float *) in[0];
	float *q = (float *) out;

	int x;

	for( x = 0; x < width; x++ ) {
		float L = p[0];
		float C = p[1];
		float h = p[2];

		p += 3;

		q[0] = vips_col_L2Lcmc( L );
		q[1] = vips_col_C2Ccmc( C );
		q[2] = vips_col_Ch2hcmc( C, h );

		q += 3;
	}
}

static void
vips_LCh2CMC_class_init( VipsLCh2CMCClass *class )
{
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsColourClass *colour_class = VIPS_COLOUR_CLASS( class );

	object_class->nickname = "LCh2CMC";
	object_class->description = _( "transform LCh to CMC" );

	colour_class->process_line = vips_LCh2CMC_line;
}

static void
vips_LCh2CMC_init( VipsLCh2CMC *LCh2CMC )
{
	VipsColour *colour = VIPS_COLOUR( LCh2CMC );

	colour->interpretation = VIPS_INTERPRETATION_CMC;
}

/**
 * vips_LCh2CMC:
 * @in: input image
 * @out: output image
 *
 * Turn LCh to CMC.
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_LCh2CMC( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "LCh2CMC", ap, in, out );
	va_end( ap );

	return( result );
}
