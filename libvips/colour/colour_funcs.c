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

/* Have the tables been made?
 */
static int made_ucs_tables = 0;

/* Arrays for lookup tables.
 */
static float LI[ 1001 ];
static float CI[ 3001 ];
static float hI[ 101 ][ 361 ];

/**
 * im_col_XYZ2Lab:
 * @X: Input CIE XYZ colour
 * @Y: Input CIE XYZ colour
 * @Z: Input CIE XYZ colour
 * @L: return CIE Lab value
 * @a: return CIE Lab value
 * @b: return CIE Lab value
 *
 * Calculate Lab from XYZ, D65.
 * 
 * See also: im_XYZ2Lab_temp().
 */
void
im_col_XYZ2Lab( float X, float Y, float Z, float *L, float *a, float *b )
{	
	float in[3], out[3];
	im_colour_temperature temp;

	in[0] = X;
	in[1] = Y;
	in[2] = Z;
	temp.X0 = IM_D65_X0;
	temp.Y0 = IM_D65_Y0;
	temp.Z0 = IM_D65_Z0;
	imb_XYZ2Lab( in, out, 1, &temp );
	*L = out[0];
	*a = out[1];
	*b = out[2];
}

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

/* Constants for Lucs.
 */
#define c1 21.75
#define c2 0.3838
#define c3 38.54

/**
 * im_col_L2Lucs:
 * @L: CIE L*
 *
 * Calculate Lucs from L.
 *
 * Returns: Lucs
 */
float
im_col_L2Lucs( float L )
{	
	float Lucs;

	if( L >= 16.0 )
		Lucs = (c1 * log( L ) + c2 * L - c3);
	else
		Lucs = 1.744 * L;

	return( Lucs );
}

/* Generate Ll and LI (inverse) tables. Don't call the above for speed.
 */
static void
make_LI( void )
{	
	int i, j=0;
	float L, Ll[ 1001 ];

	for( i = 0; i < 1001; i++ )
	{
		L = i / 10.0;
		if( L >= 16.0 )
			Ll[ i ] = (c1 * log( L ) + c2 * L - c3);
		else
			Ll[ i ] = 1.744 * L;
	}

	for( i = 0; i < 1001; i++ )
	{
		while ( (Ll[j]<=i/10.0) && ( j<1001) ) j++;
		LI[i] = (j-1)/10.0 + (i/10.0-Ll[j-1]) / ((Ll[j]-Ll[j-1])*10.0);
	}
}

/**
 * im_col_Lucs2L:
 * @Lucs: L ucs
 *
 * Calculate L from Lucs using a table. Call im_col_make_tables_UCS() at
 * least once before using this function.
 *
 * Returns: L*
 */
float
im_col_Lucs2L( float Lucs )
{	
	int known;	/* nearest input value in the table, <= Lucs */

	known = floor(Lucs*10.0);
	if( known < 0 )
		known = 0;
	if( known > 1000 )
		known = 1000;

	return( LI[known] + (LI[known+1]-LI[known])*(Lucs*10.0-known) );
}

/* Constants for Cucs.
 */
#define c4 0.162
#define c5 10.92
#define c6 0.638
#define c7 0.07216
#define c8 4.907

/**
 * im_col_C2Cucs:
 * @C: Chroma
 *
 * Calculate Cucs from C.
 *
 * Returns: Cucs.
 */
float
im_col_C2Cucs( float C )
{	
	float Cucs;

	Cucs = (c4 * C + c5 * (log( c6 + c7 * C )) + c8);
	if ( Cucs<0 ) Cucs = 0;

	return( Cucs );
}

/* Generate Cucs table. Again, inline the code above.
 */
static void
make_CI( void )
{	
	int i;
	float C;
	float Cl[3001];

	for( i = 0; i < 3001; i++ ) {
		C = i / 10.0;
		Cl[i] = (c4 * C + c5 * (log( c6 + c7 * C )) + c8);
	}

	for( i = 0; i < 3001; i++ ) {
		int j;

		for( j = 0; j < 3001 && Cl[j] <= i / 10.0; j++ )
			;
		CI[i] = (j - 1) / 10.0 + 
			(i / 10.0 - Cl[j - 1]) / ((Cl[j] - Cl[j - 1]) * 10.0);
	}

}

/**
 * im_col_Cucs2C:
 * @Cucs: Cucs
 *
 * Calculate C from Cucs using a table. 
 * Call im_col_make_tables_UCS() at
 * least once before using this function.
 *
 * Returns: C.
 */
float
im_col_Cucs2C( float Cucs )
{	
	int known;	/* nearest input value in the table, <= Cucs */

	known = floor(Cucs*10.0);
	if( known < 0 )
		known = 0;
	if( known > 3000 )
		known = 3000;

	return( CI[known] + (CI[known+1]-CI[known])*(Cucs*10.0-known) );
}

/**
 * im_col_Ch2hucs:
 * @C: Chroma
 * @h: Hue (degrees)
 *
 * Calculate hucs from C and h.
 *
 * Returns: hucs.
 */
float
im_col_Ch2hucs( float C, float h )
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

	P = cos( IM_RAD( k8 + k7 * h ) );
	D = k4 + k5 * P * pow( fabs( P ), k6 );
	g = C * C * C * C;
	f = sqrt( g / (g + 1900.0) );
	hucs = h + D * f;

	return( hucs );
}

/* The difficult one: hucs. Again, inline.
 */
static void
make_hI( void )
{	
	int i, j, k;
	float P, D, C, f, hl[101][361];
	float k4, k5, k6, k7, k8;

	for( i = 0; i < 361; i++ ) {
		if( i < 49.1 ) {
			k4 = 133.87;
			k5 = -134.5;
			k6 = -.924;
			k7 = 1.727;
			k8 = 340.0;
		}
		else if( i < 110.1 ) {
			k4 = 11.78;
			k5 = -12.7;
			k6 = -.218;
			k7 = 2.12;
			k8 = 333.0;
		}
		else if( i < 269.6 ) {
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

		P = cos( IM_RAD( k8 + k7 * i ) );
		D = k4 + k5 * P * pow( fabs( P ), k6 );

		for( j = 0; j < 101; j++ ) {
			float g;

			C = j * 2.0;
			g = C * C * C * C;
			f = sqrt( g / (g + 1900.0) );

			hl[j][i] = i + D * f;
		}

	}

	for( j = 0; j < 101; j++ ) {
		k = 0;
		for( i = 0; i < 361; i++ ) {
			while( k < 361 && hl[j][k] <= i ) 
				k++;
			hI[j][i] = k - 1 + (i - hl[j][k - 1]) / 
				(hl[j][k] - hl[j][k - 1]);
		}
	}
}

/**
 * im_col_Chucs2h:
 * @C: Chroma
 * @hucs: Hue ucs (degrees)
 *
 * Calculate h from C and hucs, using a table.
 * Call im_col_make_tables_UCS() at
 * least once before using this function.
 *
 * Returns: h.
 */
float
im_col_Chucs2h( float C, float hucs )
{	
	int r, known;	/* nearest input value in the table, <= hucs */

	/* Which row of the table?
	 */
	r = (int) ((C + 1.0) / 2.0);
	if( r < 0 )
		r = 0;
	if( r > 100 )
		r = 100;

	known = floor( hucs );
	if( known < 0 )
		known = 0;
	if( known > 360 )
		known = 360;

	return( hI[r][known] + 
		(hI[r][(known + 1) % 360] - hI[r][known]) * (hucs - known) );
}

/**
 * im_col_make_tables_UCS:
 * 
 * Make the lookup tables for ucs.
 */
void
im_col_make_tables_UCS( void )
{	
	if( !made_ucs_tables ) {
		make_LI();
		make_CI();
		make_hI();
		made_ucs_tables = -1;
	}
}

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

/* Quick hack wrappers for common colour functions in the new style.
 */

int
vips_LabQ2disp( VipsImage *in, VipsImage **out, 
	struct im_col_display *disp, ... )
{
	va_list ap;
	int result;

	va_start( ap, disp );
	result = vips_call_split( "im_LabQ2disp", ap, in, out, disp );
	va_end( ap );

	return( result );
}

int
vips_rad2float( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "im_rad2float", ap, in, out );
	va_end( ap );

	return( result );
}

int
vips_argb2rgba( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "im_argb2rgba", ap, in, out );
	va_end( ap );

	return( result );
}

int
vips_float2rad( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "im_float2rad", ap, in, out );
	va_end( ap );

	return( result );
}

int
vips_LabS2LabQ( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "im_LabS2LabQ", ap, in, out );
	va_end( ap );

	return( result );
}

int
vips_LabQ2Lab( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "im_LabQ2Lab", ap, in, out );
	va_end( ap );

	return( result );
}

int
vips_Lab2LabQ( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "im_Lab2LabQ", ap, in, out );
	va_end( ap );

	return( result );
}

int
vips_Yxy2Lab( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "im_Yxy2Lab", ap, in, out );
	va_end( ap );

	return( result );
}

int
vips_UCS2XYZ( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "im_UCS2XYZ", ap, in, out );
	va_end( ap );

	return( result );
}

int
vips_XYZ2disp( VipsImage *in, VipsImage **out, 
	struct im_col_display *disp, ... )
{
	va_list ap;
	int result;

	va_start( ap, disp );
	result = vips_call_split( "im_XYZ2disp", ap, in, out, disp );
	va_end( ap );

	return( result );
}


int
im__colour_unary( const char *domain,
	IMAGE *in, IMAGE *out, VipsType type,
	im_wrapone_fn buffer_fn, void *a, void *b )
{
	IMAGE *t[1];

	if( im_check_uncoded( domain, in ) ||
		im_check_bands( domain, in, 3 ) ||
		im_open_local_array( out, t, 1, domain, "p" ) ||
		im_clip2fmt( in, t[0], IM_BANDFMT_FLOAT ) )
		return( -1 );

	if( im_cp_desc( out, t[0] ) )
		return( -1 );
	out->Type = type;

	if( im_wrapone( t[0], out, 
		(im_wrapone_fn) buffer_fn, a, b ) )
		return( -1 );

	return( 0 );
}

