/* @(#) Turn XYZ files into displayable rgb.
 * @(#) 
 * @(#) Usage: 	
 * @(#)   int im_XYZ2disp( IMAGE *in, IMAGE *out, struct im_col_display *d )
 * @(#) 
 * @(#) Returns: -1 on error, else 0
 *
 * Author: J-P. Laurent
 * Modified:
 * 15/11/94 JC
 *	- error message added
 *	- out->Type set to IM_TYPE_RGB
 *	- memory leak fixed
 * 16/11/94 JC
 *	- uses im_wrapone()
 * 15/2/95 JC
 *	- oops! now uses PEL, not float for output pointer
 * 2/1/96 JC
 *	- sometimes produced incorrect result at extrema
 *	- reformatted
 *	- now uses IM_RINT() and clip()
 * 18/9/96 JC
 *	- some speed-ups ... 3x faster
 *	- slightly less accurate, but who cares
 *	- added out-of-mem check for table build
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

/* Process a buffer of data.
 */
void
imb_XYZ2disp( float *p, PEL *q, int n, struct im_col_display *d )
{
	struct im_col_tab_disp *table = im_col_display_get_table( d );
	float rstep = (d->d_YCR - d->d_Y0R) / 1500.0;
	float gstep = (d->d_YCG - d->d_Y0G) / 1500.0;
	float bstep = (d->d_YCB - d->d_Y0B) / 1500.0;

	int x;

	for( x = 0; x < n; x++ ) {
		float Yr, Yg, Yb;
		int i;
		int r, g, b;

		float X = p[0];
		float Y = p[1];
		float Z = p[2];

		p += 3;

		/* Multiply through the matrix to get luminosity values. 
		 */
		Yr =  table->mat_XYZ2lum[0][0] * X 
		    + table->mat_XYZ2lum[0][1] * Y 
		    + table->mat_XYZ2lum[0][2] * Z;
		Yg =  table->mat_XYZ2lum[1][0] * X 
		    + table->mat_XYZ2lum[1][1] * Y 
		    + table->mat_XYZ2lum[1][2] * Z;
		Yb =  table->mat_XYZ2lum[2][0] * X 
		    + table->mat_XYZ2lum[2][1] * Y 
		    + table->mat_XYZ2lum[2][2] * Z;

		/* Clip -ves.
		 */
		Yr = IM_MAX( Yr, d->d_Y0R );
		Yg = IM_MAX( Yg, d->d_Y0G );
		Yb = IM_MAX( Yb, d->d_Y0B );

		/* Turn luminosity to colour value.
		 */
		i = IM_MIN( 1500, (Yr - d->d_Y0R) / rstep );
		r = table->t_Yr2r[i];

		i = IM_MIN( 1500, (Yg - d->d_Y0G) / gstep );
		g = table->t_Yg2g[i];

		i = IM_MIN( 1500, (Yb - d->d_Y0B) / bstep );
		b = table->t_Yb2b[i];

		/* Clip output.
		 */
		r = IM_MIN( r, d->d_Vrwr );
		g = IM_MIN( g, d->d_Vrwg );
		b = IM_MIN( b, d->d_Vrwb );

		q[0] = r;
		q[1] = g;
		q[2] = b;

		q += 3;
	}
}

int 
im_XYZ2disp( IMAGE *in, IMAGE *out, struct im_col_display *d )
{	
	/* Check input image.
	 */
	if( in->Bands != 3 || in->BandFmt != IM_BANDFMT_FLOAT || 
		in->Coding != IM_CODING_NONE ) {
		im_error( "im_XYZ2disp", 
			"%s", _( "3-band uncoded float only" ) );
		return( -1 );
	}

	if( im_cp_desc( out, in ) )
		return( -1 );
	out->BandFmt = IM_BANDFMT_UCHAR;
	out->Type = IM_TYPE_RGB;

	/* Do the processing.
	 */
	if( im_wrapone( in, out, 
		(im_wrapone_fn) imb_XYZ2disp, d, NULL ) )
		return( -1 );

	return( 0 );
}
