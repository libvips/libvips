/* Turn CMC to LCh
 *
 * 15/11/94 JC
 *	- error messages added
 *	- memory leak fixed
 * 16/11/94 JC
 *	- uses im_wrap_oneonebuf() now
 * 2/11/09
 * 	- gtkdoc
 * 30/11/09
 * 	- argh, im_col_make_tables_CMC(); missing, thanks Peter
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

#include "pcolour.h"

/* Arrays for lookup tables for the inverse function.
 */
static float LI[1001];
static float CI[3001];
static float hI[101][361];

typedef VipsColourTransform VipsCMC2LCh;
typedef VipsColourTransformClass VipsCMC2LChClass;

G_DEFINE_TYPE( VipsCMC2LCh, vips_CMC2LCh, VIPS_TYPE_COLOUR_TRANSFORM );

/* Generate LI (inverse) tables. 
 */
static void
make_LI( void )
{
	int i;
	float Ll[1001];

	for( i = 0; i < 1001; i++ ) 
		Ll[i] = vips_col_L2Lcmc( i / 10.0 ); 

	for( i = 0; i < 1001; i++ ) {
		int j;

		/* Must be 1000, since j will be +1 on exit.
		 */
		for( j = 0; j < 1000 && Ll[j] <= i / 10.0; j++ ) 
			;

		LI[i] = (j - 1) / 10.0 + 
			(i / 10.0 - Ll[j - 1]) / ((Ll[j] - Ll[j - 1]) * 10.0);
	}
}

/* Generate Ccmc table. 
 */
static void
make_CI( void )
{
	int i;
	float Cl[3001];

	for( i = 0; i < 3001; i++ ) 
		Cl[i] = vips_col_C2Ccmc( i / 10.0 ); 

	for( i = 0; i < 3001; i++ ) {
		int j;

		/* Must be 3000, since j will be +1 on exit.
		 */
		for( j = 0; j < 3000 && Cl[j] <= i / 10.0; j++ )
			;

		CI[i] = (j - 1) / 10.0 + 
			(i / 10.0 - Cl[j - 1]) / ((Cl[j] - Cl[j - 1]) * 10.0);
	}
}

/* The difficult one: hcmc. 
 */
static void
make_hI( void )
{
	int i, j;
	float hl[101][361];

	for( i = 0; i < 361; i++ ) 
		for( j = 0; j < 101; j++ ) 
			hl[j][i] = vips_col_Ch2hcmc( j * 2.0, i );

	for( j = 0; j < 101; j++ ) {
		for( i = 0; i < 361; i++ ) {
			int k;

			for( k = 0; k < 360 && hl[j][k] <= i; k++ ) 
				;

			hI[j][i] = k - 1 + (i - hl[j][k - 1]) / 
				(hl[j][k] - hl[j][k - 1]);
		}
	}
}

/**
 * vips_col_Lcmc2L:
 * @Lcmc: L cmc
 *
 * Calculate L from Lcmc using a table. Call vips_col_make_tables_CMC() at
 * least once before using this function.
 *
 * Returns: L*
 */
float
vips_col_Lcmc2L( float Lcmc )
{	
	int known;

	known = floor( Lcmc * 10.0 );
	known = VIPS_CLIP( 0, known, 1000 );

	return( LI[known] + 
		(LI[known + 1] - LI[known]) * (Lcmc * 10.0 - known) );
}

/**
 * vips_col_Ccmc2C:
 * @Ccmc: Ccmc
 *
 * Calculate C from Ccmc using a table. 
 * Call vips_col_make_tables_CMC() at
 * least once before using this function.
 *
 * Returns: C.
 */
float
vips_col_Ccmc2C( float Ccmc )
{	
	int known;

	known = floor( Ccmc * 10.0 );
	known = VIPS_CLIP( 0, known, 3000 );

	return( CI[known] + 
		(CI[known + 1] - CI[known]) * (Ccmc * 10.0 - known) );
}

/**
 * vips_col_Chcmc2h:
 * @C: Chroma
 * @hcmc: Hue cmc (degrees)
 *
 * Calculate h from C and hcmc, using a table.
 * Call vips_col_make_tables_CMC() at
 * least once before using this function.
 *
 * Returns: h.
 */
float
vips_col_Chcmc2h( float C, float hcmc )
{	
	int r;
	int known;

	/* Which row of the table?
	 */
	r = (int) ((C + 1.0) / 2.0);
	r = VIPS_CLIP( 0, r, 100 ); 

	known = floor( hcmc );
	known = VIPS_CLIP( 0, known, 360 ); 

	return( hI[r][known] + 
		(hI[r][(known + 1) % 360] - hI[r][known]) * (hcmc - known) );
}

static void *
tables_init( void *client )
{	
	make_LI();
	make_CI();
	make_hI();

	return( NULL );
}

/**
 * vips_col_make_tables_CMC:
 * 
 * Make the lookup tables for cmc.
 */
void
vips_col_make_tables_CMC( void )
{
	static GOnce once = G_ONCE_INIT;

	(void) g_once( &once, tables_init, NULL );
}

/* Process a buffer of data.
 */
void
vips_CMC2LCh_line( VipsColour *colour, VipsPel *out, VipsPel **in, int width )
{
	float *p = (float *) in[0];
	float *q = (float *) out;

	int x;

	for( x = 0; x < width; x++ ) {
		float Lcmc = p[0];
		float Ccmc = p[1];
		float hcmc = p[2];

		/* Turn from CMC.
		 */
		float C = vips_col_Ccmc2C( Ccmc );
		float h = vips_col_Chcmc2h( C, hcmc );
		float L = vips_col_Lcmc2L( Lcmc );

		p += 3;

		q[0] = L;
		q[1] = C;
		q[2] = h;

		q += 3;
	}
}

static void
vips_CMC2LCh_class_init( VipsCMC2LChClass *class )
{
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsColourClass *colour_class = VIPS_COLOUR_CLASS( class );

	object_class->nickname = "CMC2LCh";
	object_class->description = _( "transform LCh to CMC" );

	colour_class->process_line = vips_CMC2LCh_line;
}

static void
vips_CMC2LCh_init( VipsCMC2LCh *CMC2LCh )
{
	VipsColour *colour = VIPS_COLOUR( CMC2LCh );

	vips_col_make_tables_CMC();
	colour->interpretation = VIPS_INTERPRETATION_LCH;
}

/**
 * vips_CMC2LCh:
 * @in: input image
 * @out: output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Turn LCh to CMC.
 *
 * See also: vips_LCh2CMC(). 
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_CMC2LCh( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "CMC2LCh", ap, in, out );
	va_end( ap );

	return( result );
}

