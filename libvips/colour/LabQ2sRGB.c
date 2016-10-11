/* Turn Lab 32bit packed format into displayable rgb. Fast, but very
 * inaccurate: for display only! Note especially that this dithers and will
 * give different results on different runs.
 *
 * The XYZ <-> sRGB transform implemented is this one:
 *
 * http://en.wikipedia.org/wiki/SRGB
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
 * 11/12/12
 * 	- spot NaN, Inf in XYZ2RGB, they break LUT indexing
 * 	- split sRGB <-> XYZ into sRGB <-> scRGB <-> XYZ so we can support
 * 	  scRGB as a colourspace
 * 10/3/16 Lovell Fuller
 * 	- move vips_col_make_tables_LabQ2sRGB() to first pixel processing
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
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
    02110-1301  USA

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

#include "pcolour.h"

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

/* Do our own indexing of the arrays below to make sure we get efficient mults.
 */
#define INDEX( L, A, B ) (L + (A << 6) + (B << 12))

/* A set of LUTs for quick LabQ->sRGB transforms.
 */
static VipsPel vips_red[64 * 64 * 64];
static VipsPel vips_green[64 * 64 * 64];
static VipsPel vips_blue[64 * 64 * 64];

/* sRGB to scRGB. 
 *
 * @range is eg. 256 for 8-bit data.
 */
static int
vips_col_sRGB2scRGB( int range, float *lut, 
	int r, int g, int b, float *R, float *G, float *B )
{
	int maxval = range - 1;
	int i;

  	i = VIPS_CLIP( 0, r, maxval );
	*R = lut[i];

  	i = VIPS_CLIP( 0, g, maxval );
	*G = lut[i];

  	i = VIPS_CLIP( 0, b, maxval );
	*B = lut[i];

	return( 0 );
}

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

		Y2v[i] = VIPS_RINT( (range - 1) * v );
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
	static GOnce once = G_ONCE_INIT;

	(void) g_once( &once, calcul_tables_8, NULL );
}

int
vips_col_sRGB2scRGB_8( int r, int g, int b, float *R, float *G, float *B )
{
	vips_col_make_tables_RGB_8();

	return( vips_col_sRGB2scRGB( 256, vips_v2Y_8, r, g, b, R, G, B ) ); 
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
	static GOnce once = G_ONCE_INIT;

	(void) g_once( &once, calcul_tables_16, NULL );
}

int
vips_col_sRGB2scRGB_16( int r, int g, int b, float *R, float *G, float *B )
{
	vips_col_make_tables_RGB_16();

	return( vips_col_sRGB2scRGB( 65536, vips_v2Y_16, r, g, b, R, G, B ) ); 
}

/* The matrix already includes the D65 channel weighting, so we just scale by
 * Y.
 */
#define SCALE (VIPS_D65_Y0)

/* scRGB to XYZ. 
 */
int
vips_col_scRGB2XYZ( float R, float G, float B, float *X, float *Y, float *Z )
{
	*X = SCALE * 0.4124 * R + SCALE * 0.3576 * G + SCALE * 0.18056 * B;
	*Y = SCALE * 0.2126 * R + SCALE * 0.7152 * G + SCALE * 0.07220 * B;
	*Z = SCALE * 0.0193 * R + SCALE * 0.1192 * G + SCALE * 0.9505 * B;

	return( 0 );
}

/* Turn XYZ into scRGB. 
 */
int
vips_col_XYZ2scRGB( float X, float Y, float Z, float *R, float *G, float *B ) 
{
	*R =  3.2406 / SCALE * X + -1.5372 / SCALE * Y + -0.4986 / SCALE * Z;
	*G = -0.9689 / SCALE * X +  1.8758 / SCALE * Y +  0.0415 / SCALE * Z;
	*B =  0.0557 / SCALE * X + -0.2040 / SCALE * Y +  1.0570 / SCALE * Z;

	return( 0 ); 
} 

/* Turn scRGB into sRGB. Return og=1 for out of gamut - rgb will contain an 
 * approximation of the right colour.
 *
 * Return -1 for NaN, Inf etc. 
 */
static int
vips_col_scRGB2sRGB( int range, int *lut, 
	float R, float G, float B, 
	int *r, int *g, int *b, 
	int *og_ret )
{
	int maxval = range - 1;

	int og;
	float Yf;
	int Yi;
	float v;

	/* XYZ can be Nan, Inf etc. Throw those values out, they will break
	 * our clipping.
	 *
	 * Don't use isnormal(), it is false for 0.0 and for subnormal
	 * numbers. 
	 */
	if( VIPS_ISNAN( R ) || VIPS_ISINF( R ) ||
		VIPS_ISNAN( G ) || VIPS_ISINF( G ) ||
		VIPS_ISNAN( B ) || VIPS_ISINF( B ) ) {
		*r = 0; 
		*g = 0; 
		*b = 0; 

		return( -1 );
	}

	/* Clip range, set the out-of-gamut flag.
	 */
#define CLIP( L, V, H ) { \
	if( (V) < (L) ) { \
		(V) = (L); \
		og = 1; \
	} \
	if( (V) > (H) ) { \
		(V) = (H); \
		og = 1; \
	} \
}

	/* Look up with a float index: interpolate between the nearest two
	 * points.
	 *
	 * The +1 on the index is safe, see above.
	 */

	og = 0;

	Yf = R * maxval;
	CLIP( 0, Yf, maxval );
	Yi = (int) Yf;
	v = lut[Yi] + (lut[Yi + 1] - lut[Yi]) * (Yf - Yi);
	*r = VIPS_RINT( v );

	Yf = G * maxval;
	CLIP( 0, Yf, maxval );
	Yi = (int) Yf;
	v = lut[Yi] + (lut[Yi + 1] - lut[Yi]) * (Yf - Yi);
	*g = VIPS_RINT( v );

	Yf = B * maxval;
	CLIP( 0, Yf, maxval );
	Yi = (int) Yf;
	v = lut[Yi] + (lut[Yi + 1] - lut[Yi]) * (Yf - Yi);
	*b = VIPS_RINT( v );

	if( og_ret )
		*og_ret = og; 

	return( 0 ); 
} 

int
vips_col_scRGB2sRGB_8( float R, float G, float B, 
	int *r, int *g, int *b, int *og )
{
	vips_col_make_tables_RGB_8();

	return( vips_col_scRGB2sRGB( 256, vips_Y2v_8, R, G, B, r, g, b, og ) ); 
}

int
vips_col_scRGB2sRGB_16( float R, float G, float B, 
	int *r, int *g, int *b, int *og )
{
	vips_col_make_tables_RGB_16();

	return( vips_col_scRGB2sRGB( 65536, vips_Y2v_16, 
		R, G, B, r, g, b, og ) ); 
}

/* Turn scRGB into BW. Return or=1 for out of gamut - g will contain an 
 * approximation of the right colour.
 *
 * Return -1 for NaN, Inf etc. 
 */
static int
vips_col_scRGB2BW( int range, int *lut, float R, float G, float B, 
	int *g, int *og_ret )
{
	int maxval = range - 1;

	float Y;
	int og;
	float Yf;
	int Yi;
	float v;

	/* RGB can be Nan, Inf etc. Throw those values out, they will break
	 * our clipping.
	 *
	 * Don't use isnormal(), it is false for 0.0 and for subnormal
	 * numbers. 
	 */
	if( VIPS_ISNAN( R ) || VIPS_ISINF( R ) ||
		VIPS_ISNAN( G ) || VIPS_ISINF( G ) ||
		VIPS_ISNAN( B ) || VIPS_ISINF( B ) ) {
		*g = 0; 

		return( -1 );
	}

	/* The usual ratio. We do this in linear space before we gamma.
	 */
	Y = 0.2 * R + 0.7 * G + 0.1 * B;

	/* Look up with a float index: interpolate between the nearest two
	 * points.
	 *
	 * The +1 on the index is safe, see above.
	 */

	og = 0;

	Yf = Y * maxval;
	CLIP( 0, Yf, maxval );
	Yi = (int) Yf;
	v = lut[Yi] + (lut[Yi + 1] - lut[Yi]) * (Yf - Yi);
	*g = VIPS_RINT( v );

	if( og_ret )
		*og_ret = og; 

	return( 0 ); 
} 

int
vips_col_scRGB2BW_16( float R, float G, float B, int *g, int *og )
{
	vips_col_make_tables_RGB_16();

	return( vips_col_scRGB2BW( 65536, vips_Y2v_16, R, G, B, g, og ) ); 
}

int
vips_col_scRGB2BW_8( float R, float G, float B, int *g, int *og )
{
	vips_col_make_tables_RGB_8();

	return( vips_col_scRGB2BW( 256, vips_Y2v_8, R, G, B, g, og ) ); 
}

/* Build Lab->disp dither tables. 
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
                                float Rf, Gf, Bf;
                                int rb, gb, bb;
                                int oflow;
 
                                vips_col_Lab2XYZ( L, A, B, &X, &Y, &Z );
                                vips_col_XYZ2scRGB( X, Y, Z, &Rf, &Gf, &Bf );
                                vips_col_scRGB2sRGB_8( Rf, Gf, Bf,
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

	vips_col_make_tables_LabQ2sRGB();

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
	object_class->description = _( "convert a LabQ image to sRGB" );

	colour_class->process_line = vips_LabQ2sRGB_line;
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
 * @...: %NULL-terminated list of optional named arguments
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
