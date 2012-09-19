/* Turn UCS to LCh
 *
 * 15/11/94 JC
 *	- error messages added
 *	- memory leak fixed
 * 16/11/94 JC
 *	- uses im_wrap_oneonebuf() now
 * 2/11/09
 * 	- gtkdoc
 * 30/11/09
 * 	- argh, im_col_make_tables_UCS(); missing, thanks Peter
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

/* Arrays for lookup tables for the inverse function.
 */
static float LI[1001];
static float CI[3001];
static float hI[101][361];

typedef VipsColorimetric VipsUCS2LCh;
typedef VipsColorimetricClass VipsUCS2LChClass;

G_DEFINE_TYPE( VipsUCS2LCh, vips_UCS2LCh, VIPS_TYPE_COLORIMETRIC );

/* Generate LI (inverse) tables. 
 */
static void
make_LI( void )
{
	int i;
	float Ll[1001];

	for( i = 0; i < 1001; i++ ) 
		Ll[i] = vips_col_L2Lucs( i / 10.0 ); 

	for( i = 0; i < 1001; i++ ) {
		int j;

		for( j = 0; j < 1001 && Ll[j] <= i / 10.0; j++ ) 
			;

		LI[i] = (j - 1) / 10.0 + 
			(i / 10.0 - Ll[j - 1]) / ((Ll[j] - Ll[j - 1]) * 10.0);
	}
}

/* Generate Cucs table. 
 */
static void
make_CI( void )
{
	int i;
	float Cl[3001];

	for( i = 0; i < 3001; i++ ) 
		Cl[i] = vips_col_C2Cucs( i / 10.0 ); 

	for( i = 0; i < 3001; i++ ) {
		int j;

		for( j = 0; j < 3001 && Cl[j] <= i / 10.0; j++ )
			;
		CI[i] = (j - 1) / 10.0 + 
			(i / 10.0 - Cl[j - 1]) / ((Cl[j] - Cl[j - 1]) * 10.0);
	}
}

/* The difficult one: hucs. 
 */
static void
make_hI( void )
{
	int i, j;
	float hl[101][361];

	for( i = 0; i < 361; i++ ) 
		for( j = 0; j < 101; j++ ) 
			hl[j][i] = vips_col_Ch2hucs( j * 2.0, i );

	for( j = 0; j < 101; j++ ) {
		for( i = 0; i < 361; i++ ) {
			int k;

			for( k = 0; k < 361 && hl[j][k] <= i; k++ ) 
				;
			hI[j][i] = k - 1 + (i - hl[j][k - 1]) / 
				(hl[j][k] - hl[j][k - 1]);
		}
	}
}

/**
 * vips_col_Lucs2L:
 * @Lucs: L ucs
 *
 * Calculate L from Lucs using a table. Call vips_col_make_tables_UCS() at
 * least once before using this function.
 *
 * Returns: L*
 */
float
vips_col_Lucs2L( float Lucs )
{	
	int known;

	known = floor( Lucs * 10.0 );
	known = VIPS_CLIP( 0, known, 1000 );

	return( LI[known] + 
		(LI[known + 1] - LI[known]) * (Lucs * 10.0 - known) );
}

/**
 * vips_col_Cucs2C:
 * @Cucs: Cucs
 *
 * Calculate C from Cucs using a table. 
 * Call vips_col_make_tables_UCS() at
 * least once before using this function.
 *
 * Returns: C.
 */
float
vips_col_Cucs2C( float Cucs )
{	
	int known;

	known = floor( Cucs * 10.0 );
	known = VIPS_CLIP( 0, known, 3000 );

	return( CI[known] + 
		(CI[known + 1] - CI[known]) * (Cucs * 10.0 - known) );
}

/**
 * vips_col_Chucs2h:
 * @C: Chroma
 * @hucs: Hue ucs (degrees)
 *
 * Calculate h from C and hucs, using a table.
 * Call vips_col_make_tables_UCS() at
 * least once before using this function.
 *
 * Returns: h.
 */
float
vips_col_Chucs2h( float C, float hucs )
{	
	int r;
	int known;

	/* Which row of the table?
	 */
	r = (int) ((C + 1.0) / 2.0);
	r = VIPS_CLIP( 0, r, 100 ); 

	known = floor( hucs );
	known = VIPS_CLIP( 0, known, 360 ); 

	return( hI[r][known] + 
		(hI[r][(known + 1) % 360] - hI[r][known]) * (hucs - known) );
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
 * vips_col_make_tables_UCS:
 * 
 * Make the lookup tables for ucs.
 */
void
vips_col_make_tables_UCS( void )
{
	static GOnce once = G_ONCE_INIT;

	(void) g_once( &once, tables_init, NULL );
}

/* Process a buffer of data.
 */
void
vips_UCS2LCh_line( VipsColour *colour, VipsPel *out, VipsPel **in, int width )
{
	float *p = (float *) in[0];
	float *q = (float *) out;

	int x;

	for( x = 0; x < width; x++ ) {
		float Lucs = p[0];
		float Cucs = p[1];
		float hucs = p[2];

		/* Turn from UCS.
		 */
		float C = vips_col_Cucs2C( Cucs );
		float h = vips_col_Chucs2h( C, hucs );
		float L = vips_col_Lucs2L( Lucs );

		p += 3;

		q[0] = L;
		q[1] = C;
		q[2] = h;

		q += 3;
	}
}

static void
vips_UCS2LCh_class_init( VipsUCS2LChClass *class )
{
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsColourClass *colour_class = VIPS_COLOUR_CLASS( class );

	object_class->nickname = "UCS2LCh";
	object_class->description = _( "transform LCh to UCS" );

	colour_class->process_line = vips_UCS2LCh_line;
	colour_class->interpretation = VIPS_INTERPRETATION_LCH;
}

static void
vips_UCS2LCh_init( VipsUCS2LCh *UCS2LCh )
{
	vips_col_make_tables_UCS();
}

/**
 * vips_UCS2LCh:
 * @in: input image
 * @out: output image
 *
 * Turn LCh to UCS.
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_UCS2LCh( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "UCS2LCh", ap, in, out );
	va_end( ap );

	return( result );
}

