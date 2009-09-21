/* Convert colours in various ways.
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

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* Values for IM_TYPE_sRGB.
 */
static struct im_col_display srgb_profile = {
	"sRGB",
	DISP_DUMB,
	{			/* XYZ -> luminance matrix */
		{  3.2410, -1.5374, -0.4986 },
		{  -0.9692, 1.8760, 0.0416 },
		{  0.0556, -0.2040, 1.0570 }
	},	

	80.0,			/* Luminosity of reference white */
	.3127, .3291,		/* x, y for reference white */
	100, 100, 100,		/* Light o/p for reference white */
	255, 255, 255,		/* Pixel values for ref. white */
	1, 1, 1,		/* Residual light o/p for black pixel */
	2.4, 2.4, 2.4,		/* Gamma values for the three guns */
	100,			/* 'Background' (like brightness) */
	100			/* 'Picture' (like contrast) */
};

/* Values for my Ultra2, 20/2/98. Figures from a Minolta CA-100 CRT analyser.
 * Contrast at max, brightness at 42, room lights out.
 */
static struct im_col_display ultra2 = {
	"ultra2-20/2/98",
	DISP_DUMB,
	{			/* XYZ -> luminance matrix */
		{  .704, -0.302, -.103 },
		{ -.708, 1.317, .032 },
		{  .005, -.015, .071 }
	},	

	64.0,			/* Luminosity of reference white */
	.2137, .3291,		/* x, y for reference white */
	14.4, 44.0, 5.4,	/* Light o/p for reference white */
	255, 255, 255,		/* Pixel values for ref. white */
	0.03, 0.03, 0.03,	/* Residual light o/p for black pixel */
	2.5, 2.5, 2.4,		/* Gamma values for the three guns */
	100,			/* 'Background' (like brightness) */
	100			/* 'Picture' (like contrast) */
};

/* Values for our display. These were obtained with a TV analyser in late 
 * Feb. 1990. The reference white is simply r=g=b=255.			
 */
static struct im_col_display im_col_screen_white = {
	"Screen",
	DISP_DUMB,
	{			/* XYZ -> luminance matrix */
		{  .660, -0.276, -.10 },
		{ -.663, 1.293, .0265 },
		{  .003, -.017, .0734 }
	},	

	58.7,			/* Luminosity of reference white */
	.284, .273,		/* x, y for reference white */
	14.2, 38.4, 6.1, 	/* Light o/p for reference white */
	255, 255, 255,		/* Pixel values for ref. white */
	0.0, 0.0, 0.0,		/* Residual light o/p for black pixel */
	2.8, 2.9, 2.9,		/* Gamma values for the three guns */
	100,			/* 'Background' (like brightness) */
	100			/* 'Picture' (like contrast) */
};

/* Adjusted version of above for SPARCstation2 screens. Turn down the gamma
 * to make blacks blacker.
 */
static struct im_col_display im_col_SPARC_white = {
	"SPARC",
	DISP_DUMB,
	{			/* XYZ -> luminance matrix */
		{  .660, -0.276, -.10 },
		{ -.663, 1.293, .0265 },
		{  .003, -.017, .0734 }
	},	

	58.7,			/* Luminosity of reference white */
	.284, .273,		/* x, y for reference white */
	14.2, 38.4, 4,	 	/* Light o/p for reference white */
	255, 255, 255,		/* Pixel values for ref. white */
	0.0, 0.0, 0.0,		/* Residual light o/p for black pixel */
	2.0, 2.0, 2.0,		/* Gamma values for the three guns */
	100,			/* 'Background' (like brightness) */
	100			/* 'Picture' (like contrast) */
};

/* Values for D65 white. This gives a smaller range of colours than
 * screen_white. 
 */
static struct im_col_display im_col_D65_white = {
	"D65",
	DISP_DUMB,
	{			/* XYZ -> luminance matrix */
		{  .660, -0.276, -.10 },
		{ -.663, 1.293, .0265 },
		{  .003, -.017, .0734 }
	},	

	49.9,			/* Luminosity of reference white */
	.3127, .3290,		/* x, y for reference white */
	11.6, 35.0, 3.3, 	/* Light o/p for reference white */
	241, 255, 177,		/* Pixel values for ref. white */
	0.1, 0.1, 0.1,		/* Residual light o/p for black pixel */
	2.8, 2.9, 2.7,		/* Gamma values for the three guns */
	100,			/* 'Background' (like brightness) */
	100			/* 'Picture' (like contrast) */
};

/* Values for Barco calibrator monitor
 */
static struct im_col_display im_col_barco_white = {
	"Barco",
	DISP_DUMB,
	{                       /* XYZ -> luminance matrix */
		{  .749, -0.322, -.123 },
		{ -.755, 1.341, .033 },
		{  .007, -.019, .0898 }
	},        

	80.0,			/* Luminosity of reference white */
	.3128, .3292,		/* x, y for reference white */
	20.45, 52.73, 6.81,	/* Light o/p for reference white */
	255, 255, 255,		/* Pixel values for ref. white */
	0.02, 0.053, 0.007,	/* Residual light o/p for black pixel */
	2.23, 2.13, 2.12,	/* Gamma values for the three guns */
	100,			/* 'Background' (like brightness) */
	100			/* 'Picture' (like contrast) */
};

/* Values for Mitsubishi dye-sub colour printer.
 */
static struct im_col_display im_col_mitsubishi = {
	"Mitsubishi_3_colour",
	DISP_DUMB,
	{                       /* XYZ -> luminance matrix */
		{ 1.1997, -0.6296, -0.2755 },
		{ -1.1529, 1.7383, -0.1074 },
		{ -0.047, -0.109, 0.3829 }
	},        

	95,			/* Luminosity of reference white */
	.3152, .3316,		/* x, y for reference white */
	25.33, 42.57, 15.85,	/* Y all red, Y all green, Y all blue */
	255, 255, 255,		/* Pixel values for ref. white */
	1.0, 1.0, 1.0,		/* Residual light o/p for black pixel */
	1.0, 1.0, 1.0,		/* Gamma values for the three guns */
	100,			/* 'Background' (like brightness) */
	100			/* 'Picture' (like contrast) */
};

/* Display LAB of 100, 0, 0 as 255, 255, 255. 
 */
static struct im_col_display im_col_relative = {
	"relative",
	DISP_DUMB,
	{			/* XYZ -> luminance matrix */
		{  .660, -0.276, -.10 },
		{ -.663, 1.293, .0265 },
		{  .003, -.017, .0734 }
	},	

	100.0,			/* Luminosity of reference white */
	.284, .273,		/* x, y for reference white */
	24.23, 69.20, 6.57, 	/* Light o/p for reference white */
	255, 255, 255,		/* Pixel values for ref. white */
	0.0, 0.0, 0.0,		/* Residual light o/p for black pixel */
	2.3, 2.3, 2.3,		/* Gamma values for the three guns */
	100,			/* 'Background' (like brightness) */
	100			/* 'Picture' (like contrast) */
};

struct im_col_display *
im_col_displays( int n )
{
	static struct im_col_display *displays[] = {
		&im_col_screen_white,	/* index 0 */
		&im_col_SPARC_white,	/* index 1 */
		&im_col_D65_white,	/* index 2 */
		&im_col_barco_white,	/* index 3 */
		&im_col_mitsubishi,	/* index 4 */
		&im_col_relative,	/* index 5 */
		&ultra2,		/* index 6 */
		&srgb_profile,		/* index 7 */
		NULL
	};

	if( n < 0 || n > IM_NUMBER( displays ) )
		return( NULL );

	return( displays[n] );
}

struct im_col_display *
im_col_display_name( const char *name )
{
	int i;
	struct im_col_display *d;

	for( i = 0; (d = im_col_displays( i )); i++ )
		if( g_ascii_strcasecmp( d->d_name, name ) == 0 )
			return( d );

	return( NULL );
}

/* Have the tables been made?
 */
static int made_ucs_tables = 0;

/* Arrays for lookup tables.
 */
static float LI[ 1001 ];
static float CI[ 3001 ];
static float hI[ 101 ][ 361 ];

/* Calculate Ch from ab, h in degrees.
 */
void
im_col_ab2Ch( float a, float b, float *C, float *h )
{	
	float in[3], out[3];

	in[1] = a;
	in[2] = b;
	imb_Lab2LCh( in, out, 1 );
	*C = out[1];
	*h = out[2];
}

/* Calculate ab from Ch, h in degrees.
 */
void
im_col_Ch2ab( float C, float h, float *a, float *b )
{
	float in[3], out[3];

	in[1] = C;
	in[2] = h;
	imb_LCh2Lab( in, out, 1 );
	*a = out[1];
	*b = out[2];
}

/* Calculate Lab from XYZ.
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

/* Calculate XYZ from Lab.
 */
void
im_col_Lab2XYZ( float L, float a, float b, float *X, float *Y, float *Z )
{	
	float in[3], out[3];
	im_colour_temperature temp;

	in[0] = L;
	in[1] = a;
	in[2] = b;
	temp.X0 = IM_D65_X0;
	temp.Y0 = IM_D65_Y0;
	temp.Z0 = IM_D65_Z0;
	imb_Lab2XYZ( in, out, 1, &temp );
	*X = out[0];
	*Y = out[1];
	*Z = out[2];
}

/* Pythagorean distance between two points in colour space. Lab/XYZ/UCS etc.
 */
float
im_col_pythagoras( float L1, float a1, float b1, float L2, float a2, float b2 )
{
	float dL = L1 - L2;
	float da = a1 - a2;
	float db = b1 - b2;

	return( sqrt( dL*dL + da*da + db*db ) );
}

/* Make look_up tables for the Yr,Yb,Yg <=> r,g,b conversions.
 */
static void
calcul_tables( struct im_col_display *d, struct im_col_tab_disp	*table )
{
	int i;
	float a, ga_i, ga, c, f, yo, p;
	float maxr, maxg, maxb;

	c = (d->d_B - 100.0) / 500.0;

	/**** Red ****/
	yo = d->d_Y0R;
	a = d->d_YCR - yo;
	ga = d->d_gammaR;
	ga_i = 1.0 / ga;
	p = d->d_P / 100.0;
	f = d->d_Vrwr / p;

	maxr = (float) d->d_Vrwr;
	table->ristep = maxr / 1500.0;
	table->rstep = a / 1500.0;

	for( i = 0; i < 1501; i++ )
		table->t_Yr2r[i] = f * (pow( i * table->rstep / a, ga_i ) - c);

	for( i = 0; i < 1501; i++ )
		table->t_r2Yr[i] = yo + 
			a * pow( i * table->ristep / f + c, ga );

	/**** Green ****/
	yo = d->d_Y0G;
	a = d->d_YCG - yo;
	ga = d->d_gammaG;
	ga_i = 1.0 / ga;
	p = d->d_P / 100.0;
	f = d->d_Vrwg / p;

	maxg = (float)d->d_Vrwg;
	table->gistep = maxg / 1500.0;
	table->gstep = a / 1500.0;

	for( i = 0; i < 1501; i++ )
		table->t_Yg2g[i] = f * (pow( i * table->gstep / a, ga_i ) - c);

	for( i = 0; i < 1501; i++ )
		table->t_g2Yg[i] = yo + 
			a * pow( i * table->gistep / f + c, ga );

	/**** Blue ****/
	yo = d->d_Y0B;
	a = d->d_YCB - yo;
	ga = d->d_gammaB;
	ga_i = 1.0 / ga;
	p = d->d_P / 100.0;
	f = d->d_Vrwb / p;

	maxb = (float)d->d_Vrwb;
	table->bistep = maxb / 1500.0;
	table->bstep = a / 1500.0;

	for( i = 0; i < 1501; i++ )
		table->t_Yb2b[i] = f * (pow( i * table->bstep / a, ga_i ) - c);

	for( i = 0; i < 1501; i++ )
		table->t_b2Yb[i] = yo + 
			a * pow( i * table->bistep / f + c, ga );
}

/* Make the lookup tables for rgb. Pass an IMAGE to allocate memory from.
 */
struct im_col_tab_disp *
im_col_make_tables_RGB( IMAGE *im, struct im_col_display *d )
{
	struct im_col_tab_disp *table;
	double **temp;
	int i, j;

	if( !(table = IM_NEW( im, struct im_col_tab_disp )) )
		return( NULL );

	if( d->d_type == DISP_DUMB ) 
		calcul_tables( d, table );

	if( !(temp = im_dmat_alloc( 0, 2, 0, 2 )) )
		return( NULL );

	for( i = 0; i < 3; i++ )
		for( j = 0; j < 3; j++ ) {
			table->mat_XYZ2lum[i][j] = d->d_mat[i][j];
			temp[i][j] = d->d_mat[i][j];
		}

	if( im_invmat( temp, 3 ) ) {
		im_free_dmat( temp, 0, 2, 0, 2 );
		return( NULL );
	}

	for( i = 0; i < 3; i++ )
		for( j = 0; j < 3; j++ )
			table->mat_lum2XYZ[i][j] = temp[i][j];

	im_free_dmat( temp, 0, 2, 0, 2 );

	return( table );
}

/* Computes the transform: r,g,b => Yr,Yg,Yb. It finds Y values in 
 * lookup tables and calculates X, Y, Z.
 */
int
im_col_rgb2XYZ( struct im_col_display *d, struct im_col_tab_disp *table,
	int r, int g, int b, float *X, float *Y, float *Z )
{
	float Yr, Yg, Yb;
	float *mat = &table->mat_lum2XYZ[0][0];
	int i;

	if( r < 0 || r > 255 || g < 0 || g > 255 || b < 0 || b > 255 ) {
		im_error( "im_col_rgb2XYZ", "%s", _( "out of range [0,255]" ) );
		return( -1 );
	}

	switch( d->d_type ) {
	case DISP_DUMB:
		/* Convert rgb to Yr, Yg, Yb. 3 times: r, g, b.
	    	 */
		i = r / table->ristep;
		Yr = table->t_r2Yr[i];

		i = g / table->gistep;
		Yg = table->t_g2Yg[i];

		i = b / table->bistep;
		Yb = table->t_b2Yb[i];

		break;

	case DISP_BARCO:
		Yr = d->d_Y0R + r*(d->d_YCR-d->d_Y0R)/255.0;
		Yg = d->d_Y0G + g*(d->d_YCG-d->d_Y0G)/255.0;
		Yb = d->d_Y0B + b*(d->d_YCB-d->d_Y0B)/255.0;
		break;
	
	default:
		im_error( "im_col_rgb2XYZ", "%s", _( "bad display type" ) );
		return( -1 );
	}

	/* Multiply through the inverse matrix to get XYZ values. 
	 */
	*X = mat[0] * Yr + mat[1] * Yg + mat[2] * Yb;
	*Y = mat[3] * Yr + mat[4] * Yg + mat[5] * Yb;
	*Z = mat[6] * Yr + mat[7] * Yg + mat[8] * Yb;

	return( 0 );
}

/* Turn XYZ into display colour. Return or=1 for out of gamut - rgb will
 * contain an approximation of the right colour.
 */
int
im_col_XYZ2rgb( struct im_col_display *d, struct im_col_tab_disp *table, 
	float X, float Y, float Z, 
	int *r_ret, int *g_ret, int *b_ret, 
	int *or_ret )
{
	float *mat = &table->mat_XYZ2lum[0][0];
	int or = 0;		/* Out of range flag */

	float Yr, Yg, Yb;
	int Yint;
	int r, g, b;

	/* Multiply through the matrix to get luminosity values. 
	 */
	Yr = mat[0] * X + mat[1] * Y + mat[2] * Z;
	Yg = mat[3] * X + mat[4] * Y + mat[5] * Z;
	Yb = mat[6] * X + mat[7] * Y + mat[8] * Z;

	/* Any negatives? If yes, set the out-of-range flag and bump up.
	 */
	if( Yr < d->d_Y0R ) { 
		or = 1; 
		Yr = d->d_Y0R; 
	}
	if( Yg < d->d_Y0G ) { 
		or = 1; 
		Yg = d->d_Y0G; 
	}
	if( Yb < d->d_Y0B ) { 
		or = 1; 
		Yb = d->d_Y0B; 
	}

	/* Work out colour value (0-Vrw) to feed the tube to get that
	 * luminosity. Easy for BARCOs, harder for others.
	 */
	switch( d->d_type ) {
	case DISP_DUMB:
		Yint = (Yr - d->d_Y0R) / table->rstep;
		if( Yint > 1500 ) {
			or = 1;
			Yint = 1500;
		}
		r = IM_RINT( table->t_Yr2r[Yint] );

		Yint = (Yg - d->d_Y0G) / table->gstep;
		if( Yint > 1500 ) {
			or = 1;
			Yint = 1500;
		}
		g = IM_RINT( table->t_Yg2g[Yint] );

		Yint = (Yb - d->d_Y0B) / table->bstep;
		if( Yint > 1500 ) {
			or = 1;
			Yint = 1500;
		}
		b = IM_RINT( table->t_Yb2b[Yint] );

		break;

	case DISP_BARCO:
		r = IM_RINT( ((Yr - d->d_Y0R) / (d->d_YCR - d->d_Y0R)) * 255 );
		g = IM_RINT( ((Yg - d->d_Y0G) / (d->d_YCG - d->d_Y0G)) * 255 );
		b = IM_RINT( ((Yb - d->d_Y0B) / (d->d_YCB - d->d_Y0B)) * 255 );

		/* Any silly values? Set out of range and adjust.
		 */
		if( r > d->d_Vrwr ) { 
			or = 1; 
			r = d->d_Vrwr; 
		}
		if( g > d->d_Vrwg ) { 
			or = 1; 
			g = d->d_Vrwg; 
		}
		if( b > d->d_Vrwb ) { 
			or = 1; 
			b = d->d_Vrwb; 
		}
		if( r < 0 ) { 
			or = 1; 
			r = 0; 
		}
		if( g < 0 ) { 
			or = 1; 
			g = 0; 
		}
		if( b < 0 ) { 
			or = 1; 
			b = 0; 
		}

		break;

	default:
		im_error( "XYZ2rgb", "%s", _( "display unknown" ) );
		return( -1 );
		/*NOTREACHED*/
	}

	*r_ret = r;
	*g_ret = g;
	*b_ret = b;

	*or_ret = or; 

	return( 0 ); 
} 

/* Functions to convert from Lab to uniform colour space and back.  
 */

/* Constants for Lucs.
 */
#define c1 21.75
#define c2 0.3838
#define c3 38.54

/* Calculate Lucs from L.
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


/* Inverse of above using table.
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

/* Calculate Cucs from C.
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

/* Inverse of above using table.
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

/* Calculate hucs from h and C.
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

/* Inverse of above, using table.
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

/* Make the lookup tables for ucs.
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

/* CMC colour difference using the above.
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

/* Find h in degrees from a/b.
 */
double
im_col_ab2h( double a, double b )
{
	double h;

	/* We have to be careful we have the right quadrant!
	 */
	if( a == 0 ) {
		if( b < 0.0 )
			h = 270;
		else if( b == 0.0 )
			h = 0;
		else
			h = 90;
	}
	else {
		double t = atan( b / a );

		if( a > 0.0 )
			if( b < 0.0 )
				h = IM_DEG( t + IM_PI * 2.0 );
			else
				h = IM_DEG( t );
		else
			h = IM_DEG( t + IM_PI );
	}

	return( h );
}

/* CIEDE2000 ... from 

Luo, Cui, Rigg, "The Development of the CIE 2000 Colour-Difference 
Formula: CIEDE2000", COLOR research and application, pp 340

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

