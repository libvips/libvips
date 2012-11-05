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
 * 1/11/12
 * 	- faster and more accurate sRGB <-> XYZ conversion
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

/* 8-bit linear -> sRGB lut. 
 *
 * There's an extra element at the end to let us do a +1 for interpolation.
 */
static int vips_Y2v_8[256 + 1];

/* 8-bit sRGB -> linear lut.
 */
static float vips_v2Y_8[256];

/* 16-bit linear -> sRGB lut. 
 *
 * There's an extra element at the end to let us do a +1 for interpolation.
 */
static int vips_16_Y2v[65536 + 1];

/* 16-bit sRGB -> linear lut.
 */
static float vips_16_v2Y[65536];

/* linear RGB -> XYZ matrix.
 */
static float vips_mat_RGB2XYZ[3][3] = {
	{ 0.4124, 0.3576, 0.18056 }, 
	{ 0.2126, 0.7152, 0.0722 },
	{ 0.0193, 0.1192, 0.9505 }
};

/* XYZ -> linear RGB matrix.
 */
static float vips_mat_XYZ2RGB[3][3] = {
	{ 3.2406, -1.5372, -0.4986 },
	{ -0.9689, 1.8758, 0.0415, },
	{ 0.0557, -0.2040, 1.0570 }
};

/* Do our own indexing of the arrays below to make sure we get efficient mults.
 */
#define INDEX( L, A, B ) (L + (A << 6) + (B << 12))

/* A set of LUTs for quick LabQ->sRGB transforms.
 */
static VipsPel vips_red[64 * 64 * 64];
static VipsPel vips_green[64 * 64 * 64];
static VipsPel vips_blue[64 * 64 * 64];

/* Create the sRGB linear and unlinear luts.
 */
static void *
calcul_tables_8( void *client )
{
	int i;

	for( i = 0; i < 256; i++ ) {
		float f = (float) i / (256 - 1);
		float v;

		if( f <= 0.0031308 )
			v = 12.92 * f; 
		else
			v = (1.0 + 0.055) * pow( f, 1.0 / 2.4 ) - 0.055;

		vips_Y2v_8[i] = 255.0 * v;
	}

	/* Copy the final element. This is used in the piecewise linear
	 * interpolator below.
	 */
	vips_Y2v_8[256] = vips_Y2v_8[256 - 1];

	for( i = 0; i < 256; i++ ) {
		float f = i / 255.0;

		if( f <= 0.04045 )
			vips_v2Y_8[i] = f / 12.92;
		else
			vips_v2Y_8[i] = pow( (f + 0.055) / (1 + 0.055), 2.4 );
	}

	return( NULL );
}

static void
vips_col_make_tables_RGB_8( void )
{
	static gboolean made_tables = FALSE;

	/* We want to avoid having a mutex in this path, so use gonce and a
	 * static var instead.
	 */
	if( !made_tables ) {
		static GOnce once = G_ONCE_INIT;

		(void) g_once( &once, calcul_tables_8, NULL );
		made_tables = TRUE;
	}
}

/* Computes the transform: r,g,b => Yr,Yg,Yb. It finds Y values in 
 * lookup tables and calculates X, Y, Z.
 */
int
vips_col_sRGB2XYZ_8( int r, int g, int b, float *X, float *Y, float *Z )
{
	float *lut = vips_v2Y_8;

	float Yr, Yg, Yb;
	int i;

	vips_col_make_tables_RGB_8();

  	i = VIPS_CLIP( 0, r, 255 );
	Yr = lut[i];

  	i = VIPS_CLIP( 0, g, 255 );
	Yg = lut[i];

  	i = VIPS_CLIP( 0, b, 255 );
	Yb = lut[i];

	/* The matrix already includes D65 channel weighting.
	 */
	*X = vips_mat_RGB2XYZ[0][0] * Yr + 
		vips_mat_RGB2XYZ[0][1] * Yg + vips_mat_RGB2XYZ[0][2] * Yb;
	*Y = vips_mat_RGB2XYZ[1][0] * Yr + 
		vips_mat_RGB2XYZ[1][1] * Yg + vips_mat_RGB2XYZ[1][2] * Yb;
	*Z = vips_mat_RGB2XYZ[2][0] * Yr + 
		vips_mat_RGB2XYZ[2][1] * Yg + vips_mat_RGB2XYZ[2][2] * Yb;

	*X *= VIPS_D65_Y0;
	*Y *= VIPS_D65_Y0;
	*Z *= VIPS_D65_Y0;

	return( 0 );
}

/* Turn XYZ into display colour. Return or=1 for out of gamut - rgb will
 * contain an approximation of the right colour.
 */
int
vips_col_XYZ2sRGB_8( float X, float Y, float Z, 
	int *r_ret, int *g_ret, int *b_ret, 
	int *or_ret )
{
	int *lut = vips_Y2v_8;

	int or;

	float Yr, Yg, Yb;
	float Yf;
	int Yi;
	float v;
	int r, g, b;

	vips_col_make_tables_RGB_8();

	/* The matrix already includes D65 channel weighting, just change from
	 * 0 - 100 to 0 - 1.
	 */
	X = X / VIPS_D65_Y0;
	Y = Y / VIPS_D65_Y0;
	Z = Z / VIPS_D65_Y0;

	/* Multiply through the matrix to get luminosity values. 
	 */
	Yr = vips_mat_XYZ2RGB[0][0] * X + 
		vips_mat_XYZ2RGB[0][1] * Y + vips_mat_XYZ2RGB[0][2] * Z;
	Yg = vips_mat_XYZ2RGB[1][0] * X + 
		vips_mat_XYZ2RGB[1][1] * Y + vips_mat_XYZ2RGB[1][2] * Z;
	Yb = vips_mat_XYZ2RGB[2][0] * X + 
		vips_mat_XYZ2RGB[2][1] * Y + vips_mat_XYZ2RGB[2][2] * Z;

	/* Clip range, set the out-of-range flag.
	 */
#define CLIP( L, V, H ) { \
	if( (V) < (L) ) { \
		(V) = (L); \
		or = 1; \
	} \
	if( (V) > (H) ) { \
		(V) = (H); \
		or = 1; \
	} \
}

	/* Look up with a float index: interpolate between the nearest two
	 * points.
	 *
	 * The +1 on the index is safe, see above.
	 */

	or = 0;

	Yf = Yr * (256 - 1);
	CLIP( 0, Yf, 256 - 1);
	Yi = (int) Yf;
	v = lut[Yi] + (lut[Yi + 1] - lut[Yi]) * (Yf - Yi);
	r = VIPS_RINT( v );

	Yf = Yg * (256 - 1);
	CLIP( 0, Yf, 256 - 1);
	Yi = (int) Yf;
	v = lut[Yi] + (lut[Yi + 1] - lut[Yi]) * (Yf - Yi);
	g = VIPS_RINT( v );

	Yf = Yb * (256 - 1);
	CLIP( 0, Yf, 256 - 1);
	Yi = (int) Yf;
	v = lut[Yi] + (lut[Yi + 1] - lut[Yi]) * (Yf - Yi);
	b = VIPS_RINT( v );

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
                                vips_col_XYZ2sRGB_8( X, Y, Z, 
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
 * Unpack a LabQ (#VIPS_CODING_LABQ) image to a three-band short image.
 *
 * See also: vips_LabS2LabQ(), vips_LabQ2sRGB(), vips_rad2float().
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
