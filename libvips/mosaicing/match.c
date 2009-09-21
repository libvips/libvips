/* Match images.
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

#include "mosaic.h"

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* Given a pair of points, return scale, angle, dx, dy to resample the 2nd
 * image with.
 */
int 
im__coeff( int xr1, int yr1, int xs1, int ys1, 
	int xr2, int yr2, int xs2, int ys2, 
	double *a, double *b, double *dx, double *dy )
{	
	DOUBLEMASK *in, *out;

	if( !(in = im_create_dmask( "in", 4, 4 )) ) 
		return( -1 );

	in->coeff[0] = (double)xs1;
	in->coeff[1] = (double)-ys1;
	in->coeff[2] = 1.0;
	in->coeff[3] = 0.0;
	in->coeff[4] = (double)ys1;
	in->coeff[5] = (double)xs1;
	in->coeff[6] = 0.0;
	in->coeff[7] = 1.0;
	in->coeff[8] = (double)xs2;
	in->coeff[9] = (double)-ys2;
	in->coeff[10] = 1.0;
	in->coeff[11] = 0.0;
	in->coeff[12] = (double)ys2;
	in->coeff[13] = (double)xs2;
	in->coeff[14] = 0.0;
	in->coeff[15] = 1.0;

	if( !(out = im_matinv( in, "out" )) ) {
		im_free_dmask( in );
		return( -1 );
	}

	*a = out->coeff[0]*xr1 + out->coeff[1]*yr1 + 
		out->coeff[2]*xr2 + out->coeff[3]*yr2;
	*b = out->coeff[4]*xr1 + out->coeff[5]*yr1 + 
		out->coeff[6]*xr2 + out->coeff[7]*yr2;
	*dx= out->coeff[8]*xr1 + out->coeff[9]*yr1 + 	
		out->coeff[10]*xr2 + out->coeff[11]*yr2;
	*dy= out->coeff[12]*xr1 + out->coeff[13]*yr1 + 
		out->coeff[14]*xr2 + out->coeff[15]*yr2;

	im_free_dmask( in );
	im_free_dmask( out );

	return( 0 );
}

int
im_match_linear( IMAGE *ref, IMAGE *sec, IMAGE *out,
	int xr1, int yr1, int xs1, int ys1, 
	int xr2, int yr2, int xs2, int ys2 )
{ 
	double a, b, dx, dy;
	int w, h, x, y;

	/* Solve to get scale + rot + disp to obtain match.
	 */
	if( im__coeff( xr1, yr1, xs1, ys1, xr2, yr2, xs2, ys2, 
		&a, &b, &dx, &dy ) )
		return( -1 );

	/* Output area of ref image.
	 */
	x = 0;
	y = 0;
	w = ref->Xsize;
	h = ref->Ysize;

	/* Transform image!
	 */
	if( im_affinei( sec, out, vips_interpolate_bilinear_static(), 
		a, -b, b, a, dx, dy, x, y, w, h ) )
		return( -1 );

	return( 0 );
}

int
im_match_linear_search( IMAGE *ref, IMAGE *sec, IMAGE *out,
	int xr1, int yr1, int xs1, int ys1, 
	int xr2, int yr2, int xs2, int ys2,
	int hwindowsize, int hsearchsize )
{
	int xs3, ys3;
	int xs4, ys4;
	double cor1, cor2;

	/* Search for new tie-points.
	 */
	if( im_correl( ref, sec, xr1, yr1, xs1, ys1,
		hwindowsize, hsearchsize, &cor1, &xs3, &ys3 ) )
		return( -1 );
	if( im_correl( ref, sec, xr2, yr2, xs2, ys2,
		hwindowsize, hsearchsize, &cor2, &xs4, &ys4 ) )
		return( -1 );

	/* ... and match_linear.
	 */
	if( im_match_linear( ref, sec, out, 
		xr1, yr1, xs3, ys3, xr2, yr2, xs4, ys4 ) )
		return( -1 );

	return( 0 );
}
