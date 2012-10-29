/* Turn Lab 32bit packed format into displayable rgb. Fast, but very
 * inaccurate: for display only! Note especially that this dithers and will
 * give different results on different runs.
 *
 * 5/11/97 Steve Perry
 *	- adapted from old ip code
 * 7/11/97 JC
 * 	- small tidies, added to VIPS
 * 	- LUT build split into separate function
 * 21/9/12
 * 	- redone as a class
 * 	- sRGB only, support for other RGBs is now via lcms
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
#include <vips/internal.h>

#include "colour.h"

typedef VipsColourCode VipsLabQ2sRGB;
typedef VipsColourCodeClass VipsLabQ2sRGBClass;

G_DEFINE_TYPE( VipsLabQ2sRGB, vips_LabQ2sRGB, VIPS_TYPE_COLOUR_CODE );

/* Structure for holding information about a display device. See the BARCO
 * papers for details on the fields.
 */
struct im_col_display {
	/* All private.
	 */
	char *d_name;			/* Display name */
	float d_mat[3][3]; 		/* XYZ -> luminance matrix */
	float d_YCW;			/* Luminosity of reference white */
	float d_xCW;			/* x, y for reference white */
	float d_yCW;
	float d_YCR;			/* Light o/p for reference white */
	float d_YCG;
	float d_YCB;
	int d_Vrwr;			/* Pixel values for ref. white */
	int d_Vrwg;
	int d_Vrwb;
	float d_Y0R;			/* Residual light for black pixel */
	float d_Y0G;
	float d_Y0B;
	float d_gammaR;			/* Gamma values for the three guns */
	float d_gammaG;
	float d_gammaB;
	float d_B;			/* 'Background' (like brightness) */
	float d_P;			/* 'Picture' (like contrast) */
};

/* Structure for holding the lookup tables for XYZ<=>rgb conversion.
 * Also holds the luminance to XYZ matrix and the inverse one.
 */
struct im_col_tab_disp {
	/*< private >*/
	float	t_Yr2r[1501];		/* Conversion of Yr to r */
	float	t_Yg2g[1501];		/* Conversion of Yg to g */
	float	t_Yb2b[1501];		/* Conversion of Yb to b */
	float	t_r2Yr[1501];		/* Conversion of r to Yr */
	float	t_g2Yg[1501];		/* Conversion of g to Yg */
	float	t_b2Yb[1501];		/* Conversion of b to Yb */
	float	mat_XYZ2lum[3][3];	/* XYZ to Yr, Yg, Yb matrix */
	float	mat_lum2XYZ[3][3];	/* Yr, Yg, Yb to XYZ matrix */
	float rstep, gstep, bstep;
	float ristep, gistep, bistep;
};

/* Do our own indexing of the arrays below to make sure we get efficient mults.
 */
#define INDEX( L, A, B ) (L + (A << 6) + (B << 12))

/* We used to have loads of these, now just sRGB.
 */
static struct im_col_display srgb_profile = {
	"sRGB",
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

/* A set of LUTs for quick LabQ->sRGB transforms.
 */
static VipsPel vips_red[64 * 64 * 64];
static VipsPel vips_green[64 * 64 * 64];
static VipsPel vips_blue[64 * 64 * 64];

/* Make look_up tables for the Yr,Yb,Yg <=> r,g,b conversions.
 */
static void *
calcul_tables( void *client )
{
	struct im_col_tab_disp *table = client;
	struct im_col_display *d = &srgb_profile;

	int i, j;
	float a, ga_i, ga, c, f, yo, p;
	float maxr, maxg, maxb;
	double **temp;

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

	return( NULL );
}

static struct im_col_tab_disp *
vips_col_make_tables_RGB( void )
{
	static struct im_col_tab_disp *table = NULL;

	/* We want to avoid having a mutex in this path, so use gonce and a
	 * static var instead.
	 */
	if( !table ) {
		static GOnce once = G_ONCE_INIT;
		static struct im_col_tab_disp table_memory;

		(void) g_once( &once, calcul_tables, &table_memory );
		table = &table_memory;
	}

	return( table );
}

/* Computes the transform: r,g,b => Yr,Yg,Yb. It finds Y values in 
 * lookup tables and calculates X, Y, Z.
 */
int
vips_col_sRGB2XYZ( int r, int g, int b, float *X, float *Y, float *Z )
{
	struct im_col_tab_disp *table = vips_col_make_tables_RGB();
	float *mat = &table->mat_lum2XYZ[0][0];

	float Yr, Yg, Yb;
	int i;

  	r = VIPS_CLIP( 0, r, 255 );
  	g = VIPS_CLIP( 0, g, 255 );
  	b = VIPS_CLIP( 0, b, 255 );

	i = r / table->ristep;
	Yr = table->t_r2Yr[i];

	i = g / table->gistep;
	Yg = table->t_g2Yg[i];

	i = b / table->bistep;
	Yb = table->t_b2Yb[i];

	*X = mat[0] * Yr + mat[1] * Yg + mat[2] * Yb;
	*Y = mat[3] * Yr + mat[4] * Yg + mat[5] * Yb;
	*Z = mat[6] * Yr + mat[7] * Yg + mat[8] * Yb;

	return( 0 );
}

/* Turn XYZ into display colour. Return or=1 for out of gamut - rgb will
 * contain an approximation of the right colour.
 */
int
vips_col_XYZ2sRGB( float X, float Y, float Z, 
	int *r_ret, int *g_ret, int *b_ret, 
	int *or_ret )
{
	struct im_col_display *d = &srgb_profile;
	struct im_col_tab_disp *table = vips_col_make_tables_RGB();
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
	 * luminosity. 
	 */
	Yint = (Yr - d->d_Y0R) / table->rstep;
	Yint = VIPS_CLIP( 0, Yint, 1500 ); 
	r = IM_RINT( table->t_Yr2r[Yint] );

	Yint = (Yg - d->d_Y0G) / table->gstep;
	Yint = VIPS_CLIP( 0, Yint, 1500 ); 
	g = IM_RINT( table->t_Yg2g[Yint] );

	Yint = (Yb - d->d_Y0B) / table->bstep;
	Yint = VIPS_CLIP( 0, Yint, 1500 ); 
	b = IM_RINT( table->t_Yb2b[Yint] );

	*r_ret = r;
	*g_ret = g;
	*b_ret = b;

	*or_ret = or; 

	return( 0 ); 
} 

/* Build Lab->disp tables. 
 */
static void *
build_tables( void *client )
{
        int l, a, b;
	int t;

        for( l = 0; l < 64; l++ ) {
                for( a = 0; a < 64; a++ ) {
                        for( b = 0; b < 64; b++ ) {
                                /* Scale to lab space.
                                 */
                                float L = (l << 2) * (100.0/256.0);
                                float A = (signed char) (a << 2);
                                float B = (signed char) (b << 2);
                                float X, Y, Z;
                                int rb, gb, bb;
                                int oflow;
 
                                vips_col_Lab2XYZ( L, A, B, &X, &Y, &Z );
                                vips_col_XYZ2sRGB( X, Y, Z, 
					&rb, &gb, &bb, &oflow );

				t = INDEX( l, a, b );
                                vips_red[t] = rb;
                                vips_green[t] = gb;
                                vips_blue[t] = bb;
                        }
                }
        }

	return( NULL );
}

static void
vips_col_make_tables_LabQ2sRGB( void )
{
	static GOnce once = G_ONCE_INIT;

	(void) g_once( &once, build_tables, NULL );
}

/* Process a buffer of data.
 */
static void
vips_LabQ2sRGB_line( VipsColour *colour, VipsPel *q, VipsPel **in, int width )
{ 
	unsigned char *p = (unsigned char *) in[0];

        int i, t;

	/* Current error.
	 */
	int le = 0;
	int ae = 0;
	int be = 0;

        for( i = 0; i < width; i++ ) {
		/* Get colour, add in error from previous pixel. 
		 */
                int L = p[0] + le;
                int A = (signed char) p[1] + ae;
                int B = (signed char) p[2] + be;

		p += 4;

		/* Look out for overflow.
		 */
		L = VIPS_MIN( 255, L );
		A = VIPS_MIN( 127, A );
		B = VIPS_MIN( 127, B );

		/* Find new quant error. This will always be +ve. 
		 */
		le = L & 3;
		ae = A & 3;
		be = B & 3;

		/* Scale to 0-63.
		 */
                L = (L >> 2) & 63;
                A = (A >> 2) & 63;
                B = (B >> 2) & 63;

		/* Convert to RGB.
		 */
		t = INDEX( L, A, B );
                q[0] = vips_red[t];
                q[1] = vips_green[t];
                q[2] = vips_blue[t];

                q += 3;
        }
}

static void
vips_LabQ2sRGB_class_init( VipsLabQ2sRGBClass *class )
{
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsColourClass *colour_class = VIPS_COLOUR_CLASS( class );

	object_class->nickname = "LabQ2sRGB";
	object_class->description = _( "unpack a LabQ image to short Lab" );

	colour_class->process_line = vips_LabQ2sRGB_line;

	vips_col_make_tables_LabQ2sRGB();
}

static void
vips_LabQ2sRGB_init( VipsLabQ2sRGB *LabQ2sRGB )
{
	VipsColour *colour = VIPS_COLOUR( LabQ2sRGB );
	VipsColourCode *code = VIPS_COLOUR_CODE( LabQ2sRGB );

	colour->coding = VIPS_CODING_NONE;
	colour->interpretation = VIPS_INTERPRETATION_sRGB;
	colour->format = VIPS_FORMAT_UCHAR;
	colour->bands = 3;

	code->input_coding = VIPS_CODING_LABQ;
}

/**
 * vips_LabQ2sRGB:
 * @in: input image
 * @out: output image
 *
 * Unpack a LabQ (#IM_CODING_LABQ) image to a three-band short image.
 *
 * See also: im_LabS2LabQ(), im_LabQ2sRGB(), im_rad2float().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_LabQ2sRGB( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "LabQ2sRGB", ap, in, out );
	va_end( ap );

	return( result );
}
