/* Convert to and from display RGB
 *
 * 28/10/09
 * 	- from colour.c
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

/**
 * SECTION: disp
 * @short_description: convert to and from display RGB
 * @stability: Stable
 * @see_also: <link linkend="libvips-colour">colour</link>
 * @include: vips/vips.h
 *
 * Convert to and from display RGB. These functions are still used by nip2,
 * but most programs will be better off with im_icc_transform() and friends.
 */

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

