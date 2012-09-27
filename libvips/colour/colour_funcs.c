/* Convert colours in various ways.
 *
 * Written: January 1990
 * Modified .. innumerable times
 * Code by: DS, JC, J-Ph.L.
 * 18/7/93 JC
 *	- final tidies before v7 release
 *	- ANSIfied
 *	- code for samples removed
 * 5/5/94 JC
 *	- nint() -> rint() to make ANSI easier
 * 14/3/96 JC
 *	- new display characterisation
 *	- speed-up to im_col_XYZ2rgb() and im_col_rgb2XYZ()
 * 4/3/98 JC
 *	- new display profile for ultra2
 *	- new sRGB profile
 * 17/8/98 JC
 *	- error_exit() removed, now clips
 * 26/11/03 Andrey Kiselev
 * 	- tiny clean-up for calcul_tables()
 * 	- some reformatting
 * 23/7/07
 * 	- tiny cleanup for make_hI() prevents cond jump on ui in valgrind
 * 14/3/08
 * 	- more tiny cond jump valgrind fixes
 * 23/10/09
 * 	- gtkdoc comments
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
#include <string.h>
#include <ctype.h>
#include <math.h>

#include <vips/vips.h>
#include <vips/internal.h>

/**
 * im_col_pythagoras:
 * @L1: Input coordinate 1
 * @a1: Input coordinate 1
 * @b1: Input coordinate 1
 * @L2: Input coordinate 2
 * @a2: Input coordinate 2
 * @b2: Input coordinate 2
 *
 * Pythagorean distance between two points in colour space. Lab/XYZ/UCS etc.
 */
float
im_col_pythagoras( float L1, float a1, float b1, float L2, float a2, float b2 )
{
	float dL = L1 - L2;
	float da = a1 - a2;
	float db = b1 - b2;

	return( sqrt( dL*dL + da*da + db*db ) );
}

/* Functions to convert from Lab to uniform colour space and back.  
 */

/**
 * im_col_dECMC:
 * @L1: Input coordinate 1
 * @a1: Input coordinate 1
 * @b1: Input coordinate 1
 * @L2: Input coordinate 2
 * @a2: Input coordinate 2
 * @b2: Input coordinate 2
 * 
 * CMC colour difference from a pair of Lab values.
 *
 * Returns: CMC(1:1) colour difference
 */
float 
im_col_dECMC( float L1, float a1, float b1, 
	float L2, float a2, float b2 )
{
	float h1, C1;
	float h2, C2;
	float Lucs1, Cucs1, hucs1;
	float Lucs2, Cucs2, hucs2;
	float aucs1, bucs1;
	float aucs2, bucs2;

	/* Turn to LCh.
	 */
	im_col_ab2Ch( a1, b1, &C1, &h1 );
	im_col_ab2Ch( a2, b2, &C2, &h2 );

	/* Turn to LCh in CMC space.
	 */
	Lucs1 = im_col_L2Lucs( L1 );
	Cucs1 = im_col_C2Cucs( C1 );
	hucs1 = im_col_Ch2hucs( C1, h1 );

	Lucs2 = im_col_L2Lucs( L2 );
	Cucs2 = im_col_C2Cucs( C2 );
	hucs2 = im_col_Ch2hucs( C2, h2 );

	/* Turn to Lab in CMC space.
	 */
	im_col_Ch2ab( Cucs1, hucs1, &aucs1, &bucs1 );
	im_col_Ch2ab( Cucs2, hucs2, &aucs2, &bucs2 );

	/* Find difference.
	 */
	return( im_col_pythagoras( Lucs1, aucs1, bucs1, Lucs2, aucs2, bucs2 ) );
}

/**
 * im_col_dE00:
 * @L1: Input coordinate 1
 * @a1: Input coordinate 1
 * @b1: Input coordinate 1
 * @L2: Input coordinate 2
 * @a2: Input coordinate 2
 * @b2: Input coordinate 2
 *
 * CIEDE2000, from: 
 * 
 * Luo, Cui, Rigg, "The Development of the CIE 2000 Colour-Difference 
 * Formula: CIEDE2000", COLOR research and application, pp 340
 *
 * Returns: CIE dE2000 colour difference.
 */
float 
im_col_dE00( float L1, float a1, float b1, 
	float L2, float a2, float b2 )
{
/* Code if you want XYZ params and the colour temp used in the reference

	float 
	im_col_dE00( float X1, float Y1, float Z1, 
		float X2, float Y2, float Z2 )
	{
		const double X0 = 94.811;
		const double Y0 = 100.0;
		const double Z0 = 107.304;

#define f(I) ((I) > 0.008856 ? \
	cbrt( (I), 1.0 / 3.0 ) : 7.7871 * (I) + (16.0 / 116.0))

		double nX1 = f( X1 / X0 );
		double nY1 = f( Y1 / Y0 );
		double nZ1 = f( Z1 / Z0 );

		double L1 = 116 * nY1 - 16;
		double a1 = 500 * (nX1 - nY1);
		double b1 = 200 * (nY1 - nZ1);

		double nX2 = f( X2 / X0 );
		double nY2 = f( Y2 / Y0 );
		double nZ2 = f( Z2 / Z0 );

		double L2 = 116 * nY2 - 16;
		double a2 = 500 * (nX2 - nY2);
		double b2 = 200 * (nY2 - nZ2);
 */

	/* Chroma and mean chroma (C bar)
	 */
	double C1 = sqrt( a1 * a1 + b1 * b1 );
	double C2 = sqrt( a2 * a2 + b2 * b2 );
	double Cb = (C1 + C2) / 2;

	/* G
	 */
	double Cb7 = Cb * Cb * Cb * Cb * Cb * Cb * Cb;
	double G = 0.5 * (1 - sqrt( Cb7 / (Cb7 + pow( 25, 7 )) ));

	/* L', a', b', C', h'
	 */
	double L1d = L1;
	double a1d = (1 + G) * a1;
	double b1d = b1;
	double C1d = sqrt( a1d * a1d + b1d * b1d );
	double h1d = im_col_ab2h( a1d, b1d );

	double L2d = L2;
	double a2d = (1 + G) * a2;
	double b2d = b2;
	double C2d = sqrt( a2d * a2d + b2d * b2d );
	double h2d = im_col_ab2h( a2d, b2d );

	/* L' bar, C' bar, h' bar
	 */
	double Ldb = (L1d + L2d) / 2;
	double Cdb = (C1d + C2d) / 2;
	double hdb = fabs( h1d - h2d ) < 180 ?
	 	(h1d + h2d) / 2 :
	 	fabs( h1d + h2d - 360 ) / 2;

	/* dtheta, RC
	 */
	double hdbd = (hdb - 275) / 25;
	double dtheta = 30 * exp( -(hdbd * hdbd) );
	double Cdb7 = Cdb * Cdb * Cdb * Cdb * Cdb * Cdb * Cdb;
	double RC = 2 * sqrt( Cdb7 / (Cdb7 + pow( 25, 7 )) );

	/* RT, T.
	 */
	double RT = -sin( IM_RAD( 2 * dtheta ) ) * RC;
	double T = 1 - 
		0.17 * cos( IM_RAD( hdb - 30 ) ) +
		0.24 * cos( IM_RAD( 2 * hdb ) ) +
		0.32 * cos( IM_RAD( 3 * hdb + 6 ) ) -
		0.20 * cos( IM_RAD( 4 * hdb - 63 ) );

	/* SL, SC, SH
	 */
	double Ldb50 = Ldb - 50;
	double SL = 1 + (0.015 * Ldb50 * Ldb50) / sqrt( 20 + Ldb50 * Ldb50);
	double SC = 1 + 0.045 * Cdb;
	double SH = 1 + 0.015 * Cdb * T;

	/* hue difference ... careful!
	 */
	double dhd = fabs( h1d - h2d ) < 180 ?
		h1d - h2d :
		360 - (h1d - h2d);

	/* dLd, dCd dHd
	 */
	double dLd = L1d - L2d;
	double dCd = C1d - C2d;
	double dHd = 2 * sqrt( C1d * C2d ) * sin( IM_RAD( dhd / 2 ) );

	/* Parametric factors for viewing parameters.
	 */
	const double kL = 1.0;
	const double kC = 1.0;
	const double kH = 1.0;

	/* Normalised terms.
	 */
	double nL = dLd / (kL * SL);
	double nC = dCd / (kC * SC);
	double nH = dHd / (kH * SH);

	/* dE00!!
	 */
	double dE00 = sqrt( nL * nL + nC * nC + nH * nH + RT * nC * nH );

	/*
	printf( "X1 = %g, Y1 = %g, Z1 = %g\n", X1, Y1, Z1 );
	printf( "X2 = %g, Y2 = %g, Z2 = %g\n", X2, Y2, Z2 );
	printf( "L1 = %g, a1 = %g, b1 = %g\n", L1, a1, b1 );
	printf( "L2 = %g, a2 = %g, b2 = %g\n", L2, a2, b2 );
	printf( "L1d = %g, a1d = %g, b1d = %g, C1d = %g, h1d = %g\n",
		L1d, a1d, b1d, C1d, h1d );
	printf( "L2d = %g, a2d = %g, b2d = %g, C2d = %g, h2d = %g\n",
		L2d, a2d, b2d, C2d, h2d );
	printf( "G = %g, T = %g, SL = %g, SC = %g, SH = %g, RT = %g\n",
		G, T, SL, SC, SH, RT );
	printf( "dE00 = %g\n", dE00 );
	 */

	return( dE00 );
}
