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
 * 6/11/12
 * 	- added a 16-bit path
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
static int vips_Y2v_16[65536 + 1];

/* 16-bit sRGB -> linear lut.
 */
static float vips_v2Y_16[65536];

/* We need Y in 0 - 100. We can save three muls later if we pre-scale the
 * matrix.
 *
 * The matrix already includes the D65 channel weighting, so we just scale by
 * Y.
 */
#define SCALE (VIPS_D65_Y0 / 3.0)

/* linear RGB -> XYZ matrix. 
 */
static float vips_mat_RGB2XYZ[3][3] = {
	{ SCALE * 0.4124, SCALE * 0.3576, SCALE * 0.18056 }, 
	{ SCALE * 0.2126, SCALE * 0.7152, SCALE * 0.0722 },
	{ SCALE * 0.0193, SCALE * 0.1192, SCALE * 0.9505 }
};

/* XYZ -> linear RGB matrix.
 */
static float vips_mat_XYZ2RGB[3][3] = {
	{ 3.2406 / SCALE, -1.5372 / SCALE, -0.4986 / SCALE },
	{ -0.9689 / SCALE, 1.8758 / SCALE, 0.0415 / SCALE },
	{ 0.0557 / SCALE, -0.2040 / SCALE, 1.0570 / SCALE }
};

/* Do our own indexing of the arrays below to make sure we get efficient mults.
 */
#define INDEX( L, A, B ) (L + (A << 6) + (B << 12))

/* A set of LUTs for quick LabQ->sRGB transforms.
 */
static VipsPel vips_red[64 * 64 * 64];
static VipsPel vips_green[64 * 64 * 64];
static VipsPel vips_blue[64 * 64 * 64];

/* Create the sRGB linear and unlinear luts. @range is eg. 256 for 8-bit luts.
 */
static void 
calcul_tables( int range, int *Y2v, float *v2Y )
{
	int i;

	for( i = 0; i < range; i++ ) {
		float f = (float) i / (range - 1);
		float v;

		if( f <= 0.0031308 )
			v = 12.92 * f; 
		else
			v = (1.0 + 0.055) * pow( f, 1.0 / 2.4 ) - 0.055;

		Y2v[i] = (range - 1) * v;
	}

	/* Copy the final element. This is used in the piecewise linear
	 * interpolator below.
	 */
	Y2v[range] = Y2v[range - 1];

	for( i = 0; i < range; i++ ) {
		float f = (float) i / (range - 1);

		if( f <= 0.04045 )
			v2Y[i] = f / 12.92;
		else
			v2Y[i] = pow( (f + 0.055) / (1 + 0.055), 2.4 );
	}
}

static void *
calcul_tables_8( void *client )
{
	calcul_tables( 256, vips_Y2v_8, vips_v2Y_8 ); 

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
 *
 * @range is eg. 256 for 8-bit data,
 */
static int
vips_col_sRGB2XYZ( int range, float *lut, 
	int r, int g, int b, float *X, float *Y, float *Z )
{
	int maxval = range - 1;
	float Yr, Yg, Yb;
	int i;

  	i = VIPS_CLIP( 0, r, maxval );
	Yr = lut[i];

  	i = VIPS_CLIP( 0, g, maxval );
	Yg = lut[i];

  	i = VIPS_CLIP( 0, b, maxval );
	Yb = lut[i];

	*X = vips_mat_RGB2XYZ[0][0] * Yr + 
		vips_mat_RGB2XYZ[0][1] * Yg + vips_mat_RGB2XYZ[0][2] * Yb;
	*Y = vips_mat_RGB2XYZ[1][0] * Yr + 
		vips_mat_RGB2XYZ[1][1] * Yg + vips_mat_RGB2XYZ[1][2] * Yb;
	*Z = vips_mat_RGB2XYZ[2][0] * Yr + 
		vips_mat_RGB2XYZ[2][1] * Yg + vips_mat_RGB2XYZ[2][2] * Yb;

	return( 0 );
}

/* Computes the transform: r,g,b => Yr,Yg,Yb. It finds Y values in 
 * lookup tables and calculates X, Y, Z.
 *
 * rgb are in the range 0 to 255,
 */
int
vips_col_sRGB2XYZ_8( int r, int g, int b, float *X, float *Y, float *Z )
{
	vips_col_make_tables_RGB_8();

	return( vips_col_sRGB2XYZ( 256, vips_v2Y_8, r, g, b, X, Y, Z ) );
}

static void *
calcul_tables_16( void *client )
{
	calcul_tables( 65536, vips_Y2v_16, vips_v2Y_16 ); 

	return( NULL );
}

static void
vips_col_make_tables_RGB_16( void )
{
	static gboolean made_tables = FALSE;

	/* We want to avoid having a mutex in this path, so use gonce and a
	 * static var instead.
	 */
	if( !made_tables ) {
		static GOnce once = G_ONCE_INIT;

		(void) g_once( &once, calcul_tables_16, NULL );
		made_tables = TRUE;
	}
}

/* Computes the transform: r,g,b => Yr,Yg,Yb. It finds Y values in 
 * lookup tables and calculates X, Y, Z.
 *
 * rgb are in the range 0 to 65535,
 */
int
vips_col_sRGB2XYZ_16( int r, int g, int b, float *X, float *Y, float *Z )
{
	vips_col_make_tables_RGB_16();

	return( vips_col_sRGB2XYZ( 65536, vips_v2Y_16, r, g, b, X, Y, Z ) );
}

/* Turn XYZ into display colour. Return or=1 for out of gamut - rgb will
 * contain an approximation of the right colour.
 */
static int
vips_col_XYZ2sRGB( int range, int *lut, 
	float X, float Y, float Z, 
	int *r, int *g, int *b, 
	int *or_ret )
{
	int maxval = range - 1;

	float Yr, Yg, Yb;
	int or;
	float Yf;
	int Yi;
	float v;

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

	Yf = Yr * maxval;
	CLIP( 0, Yf, maxval);
	Yi = (int) Yf;
	v = lut[Yi] + (lut[Yi + 1] - lut[Yi]) * (Yf - Yi);
	*r = VIPS_RINT( v );

	Yf = Yg * maxval;
	CLIP( 0, Yf, maxval);
	Yi = (int) Yf;
	v = lut[Yi] + (lut[Yi + 1] - lut[Yi]) * (Yf - Yi);
	*g = VIPS_RINT( v );

	Yf = Yb * maxval;
	CLIP( 0, Yf, maxval);
	Yi = (int) Yf;
	v = lut[Yi] + (lut[Yi + 1] - lut[Yi]) * (Yf - Yi);
	*b = VIPS_RINT( v );

	if( or_ret )
		*or_ret = or; 

	return( 0 ); 
} 

/* Turn XYZ into display colour. Return or=1 for out of gamut - rgb will
 * contain an approximation of the right colour.
 *
 * r, g, b are scaled to fit the range 0 - 255.
 */
int
vips_col_XYZ2sRGB_8( float X, float Y, float Z, 
	int *r, int *g, int *b, 
	int *or )
{
	vips_col_make_tables_RGB_8();

	return( vips_col_XYZ2sRGB( 256, vips_Y2v_8, X, Y, Z, r, g, b, or ) ); 
}

/* Turn XYZ into display colour. Return or=1 for out of gamut - rgb will
 * contain an approximation of the right colour.
 *
 * r, g, b are scaled to fit the range 0 - 65535.
 */
int
vips_col_XYZ2sRGB_16( float X, float Y, float Z, 
	int *r, int *g, int *b, 
	int *or )
{
	vips_col_make_tables_RGB_16();

	return( vips_col_XYZ2sRGB( 65536, vips_Y2v_16, 
		X, Y, Z, r, g, b, or ) ); 
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
