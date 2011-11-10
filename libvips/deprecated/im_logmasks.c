/* laplacian of gaussian
 *
 * Written on: 30/11/1989
 * Updated on: 6/12/1991
 * 7/8/96 JC
 *	- ansified, mem leaks plugged
 * 20/11/98 JC
 *	- mask too large check added
 * 26/3/02 JC
 *	- ahem, was broken since '96, thanks matt
 * 16/7/03 JC
 *	- makes mask out to zero, not out to minimum, thanks again matt
 * 22/10/10
 * 	- gtkdoc
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

/*
#define PIM_RINT 1
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <math.h>

#include <vips/vips.h>
#include <vips/util.h>

#define IM_MAXMASK 256

/**
 * im_log_dmask:
 * @filename: the returned mask has this set as the filename
 * @sigma: standard deviation of mask
 * @min_ampl: minimum amplitude
 *
 * im_log_dmask() creates a circularly symmetric Laplacian of Gaussian mask 
 * of radius 
 * @sigma.  The size of the mask is determined by the variable @min_ampl; 
 * if for instance the value .1 is entered this means that the produced mask 
 * is clipped at values within 10 persent of zero, and where the change 
 * between mask elements is less than 10%.
 *
 * The program uses the following equation: (from Handbook of Pattern 
 * Recognition and image processing by Young and Fu, AP 1986 pages 220-221):
 *
 *  H(r) = (1 / (2 * M_PI * s4)) *
 * 	(2 - (r2 / s2)) * 
 * 	exp(-r2 / (2 * s2))
 *
 * where s2 = sigma * sigma, s4 = s2 * s2, r2 = r * r.  
 *
 * The generated mask has odd size and its maximum value is normalised to 1.0.
 *
 * See also: im_log_imask(), im_gauss_dmask(), im_conv().
 *
 * Returns: the calculated mask on success, or NULL on error.
 */
DOUBLEMASK *
im_log_dmask( const char *filename, double sigma, double min_ampl )
{
	const double sig2 = sigma * sigma;

	double last;
	int x, y, k;

	double *pt1, *pt2, *pt3, *pt4;
	int xm, ym;
	int xm2, ym2; /* xm2 = xm/2 */
	int offset;
	double *cf, *cfs, *mc;
	DOUBLEMASK *m;
	double sum;

	/* Find the size of the mask depending on the entered data. We want to
	 * eval the mask out to the flat zero part, ie. beyond the minimum and
	 * to the point where it comes back up towards zero.
	 */
	last = 0.0;
	for( x = 0; x < IM_MAXMASK; x++ ) {
		const double distance = x * x;
		double val;

		/* Handbook of Pattern Recognition and image processing
		 * by Young and Fu AP 1986 pp 220-221
		 * temp =  (1.0 / (2.0 * IM_PI * sig4)) *
			(2.0 - (distance / sig2)) * 
			exp( (-1.0) * distance / (2.0 * sig2) )

		   .. use 0.5 to normalise
		 */
		val = 0.5 * 
			(2.0 - (distance / sig2)) * 
			exp( -distance / (2.0 * sig2) );

		/* Stop when change in value (ie. difference from the last
		 * point) is positive (ie. we are going up) and absolute value 
		 * is less than the min.
		 */
		if( val - last >= 0 &&
			fabs( val ) < min_ampl )
			break;

		last = val;
	}
	if( x == IM_MAXMASK ) {
		im_error( "im_log_dmask", "%s", _( "mask too large" ) );
		return( NULL );
	}

	xm2 = x; 
	ym2 = x;
	xm = xm2 * 2 + 1; 
	ym = ym2 * 2 + 1;

	if( !(cfs = IM_ARRAY( NULL, (xm2 + 1) * (ym2 + 1), double )) )
		return( NULL );

	/* Make 1/4 of the mask.
	 */
	for( k = 0, y = 0; y <= ym2; y++ )
		for( x = 0; x <= xm2; x++, k++ ) {
			const double distance = x * x + y * y;

			cfs[k] = 0.5 *
				(2.0 - (distance / sig2)) *
				exp( -distance / (2.0 * sig2) );
		}

#ifdef PIM_RINT
	for( k = 0, y = 0; y <= ym2; y++ ) {
		for( x = 0; x <= xm2; x++, k++ )
			fprintf( stderr, "%3.2f ", cfs[k] );
		fprintf( stderr, "\n" );
	}
#endif

	if( !(m = im_create_dmask( filename, xm, ym )) ) {
		im_free( cfs ); 
		return( NULL );
	}

	/* Copy the 1/4 cfs into the m 
	 */
	cf = cfs;
	offset = xm2 * (xm + 1);
	mc = m->coeff + offset;
	for( y = 0; y <= ym2; y++ ) {
		for( x = 0; x <= xm2; x++ ) {
			pt1 = mc + (y * xm) + x; 
			pt2 = mc - (y * xm) + x;
			pt3 = mc + (y * xm) - x; 
			pt4 = mc - (y * xm) - x;

			*pt1 = cf[x];
			*pt2 = cf[x];
			*pt3 = cf[x];
			*pt4 = cf[x];
		}

		cf += (xm2 + 1);
	}
	im_free( cfs );

	sum = 0.0;
	for( k = 0, y = 0; y < m->ysize; y++ )
		for( x = 0; x < m->xsize; x++, k++ )
			sum += m->coeff[k];
	m->scale = sum;
	m->offset = 0.0;

#ifdef PIM_RINT
	im_print_dmask( m );
#endif

	return( m );
}

/**
 * im_log_imask:
 * @filename: the returned mask has this set as the filename
 * @sigma: standard deviation of mask
 * @min_ampl: minimum amplitude
 *
 * im_log_imask() works exactly as im_log_dmask(), but the returned mask
 * is scaled so that it's maximum value it set to 100.
 *
 * See also: im_log_dmask(), im_gauss_imask(), im_conv().
 *
 * Returns: the calculated mask on success, or NULL on error.
 */
INTMASK *
im_log_imask( const char *filename, double sigma, double min_ampl )
{
	DOUBLEMASK *dm;
	INTMASK *im;

	if( !(dm = im_log_dmask( filename, sigma, min_ampl )) )
		return( NULL );

	if( !(im = im_scale_dmask( dm, dm->filename )) ) {
		im_free_dmask( dm );
		return( NULL );
	}
	im_free_dmask( dm );

	return( im ) ;
}
