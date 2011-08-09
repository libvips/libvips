/* Turn XYZ to Lab colourspace. 
 *
 * Modifed:
 * 16/11/94 JC
 *	- uses im_wrapone()
 *	- in-line conversion
 * 27/1/03 JC
 *	- swapped cbrt() for pow(), more portable
 * 12/11/04
 * 	- swapped pow() for cbrt() again, pow() is insanely slow on win32
 * 	- added a configure test for cbrt().
 * 23/11/04
 *	- use a large LUT instead, about 5x faster
 * 23/11/06
 *	- ahem, build the LUT outside the eval thread
 * 2/11/09
 * 	- gtkdoc
 * 3/8/11
 * 	- fix a race in the table build
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
#include <vips/thread.h>
#include <vips/internal.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

#ifndef HAVE_CBRT
#define cbrt( X ) pow( (X), 1.0 / 3.0 )
#endif /*!HAVE_CBRT*/

/* Lookup table size.
 */
#define QUANT_ELEMENTS (100000)

float cbrt_table[QUANT_ELEMENTS];

static void
imb_XYZ2Lab_tables( void )
{
	static int built_tables = 0;

	int i;

	g_mutex_lock( im__global_lock );

	if( built_tables ) {
		g_mutex_unlock( im__global_lock );
		return;
	}

	for( i = 0; i < QUANT_ELEMENTS; i++ ) {
		float Y = (double) i / QUANT_ELEMENTS;

		if( Y < 0.008856 ) 
			cbrt_table[i] = 7.787 * Y + (16.0 / 116.0);
		else 
			cbrt_table[i] = cbrt( Y );
	}

	built_tables = 1;

	g_mutex_unlock( im__global_lock );
}

/* Process a buffer of data.
 */
void
imb_XYZ2Lab( float *p, float *q, int n, im_colour_temperature *temp )
{
	int x;

        imb_XYZ2Lab_tables();

	for( x = 0; x < n; x++ ) {
		float nX, nY, nZ;
		int i;
		float f;
		float cbx, cby, cbz;

		nX = QUANT_ELEMENTS * p[0] / temp->X0;
		nY = QUANT_ELEMENTS * p[1] / temp->Y0;
		nZ = QUANT_ELEMENTS * p[2] / temp->Z0;
		p += 3;

		i = (int) nX;
		if( i < 0 )
			i = 0;
		if( i > QUANT_ELEMENTS - 2 )
			i = QUANT_ELEMENTS - 2;
		f = nX - i;
		cbx = cbrt_table[i] + f * (cbrt_table[i + 1] - cbrt_table[i]);

		i = (int) nY;
		if( i < 0 )
			i = 0;
		if( i > QUANT_ELEMENTS - 2 )
			i = QUANT_ELEMENTS - 2;
		f = nY - i;
		cby = cbrt_table[i] + f * (cbrt_table[i + 1] - cbrt_table[i]);

		i = (int) nZ;
		if( i < 0 )
			i = 0;
		if( i > QUANT_ELEMENTS - 2 )
			i = QUANT_ELEMENTS - 2;
		f = nZ - i;
		cbz = cbrt_table[i] + f * (cbrt_table[i + 1] - cbrt_table[i]);

		q[0] = 116.0 * cby - 16.0;
		q[1] = 500.0 * (cbx - cby);
		q[2] = 200.0 * (cby - cbz);
		q += 3;
	}
}

/**
 * im_XYZ2Lab_temp:
 * @in: input image
 * @out: output image
 * @X0: colour temperature
 * @Y0: colour temperature
 * @Z0: colour temperature
 *
 * Turn XYZ to Lab. @X0, @y0, @Z0 give the Lab colour temperature.
 *
 * Returns: 0 on success, -1 on error.
 */
int 
im_XYZ2Lab_temp( IMAGE *in, IMAGE *out, double X0, double Y0, double Z0 )
{
	im_colour_temperature *temp;

	if( !(temp = IM_NEW( out, im_colour_temperature )) )
		return( -1 );
	temp->X0 = X0;
	temp->Y0 = Y0;
	temp->Z0 = Z0;

	return( im__colour_unary( "im_XYZ2Lab", in, out, IM_TYPE_LAB,
		(im_wrapone_fn) imb_XYZ2Lab, temp, NULL ) );
}

/**
 * im_XYZ2Lab:
 * @in: input image
 * @out: output image
 *
 * Turn XYZ to D65 Lab.
 *
 * Returns: 0 on success, -1 on error.
 */
int 
im_XYZ2Lab( IMAGE *in, IMAGE *out )
{	
	return( im_XYZ2Lab_temp( in, out, IM_D65_X0, IM_D65_Y0, IM_D65_Z0 ) );
}
