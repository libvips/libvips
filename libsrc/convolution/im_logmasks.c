/* @(#) Returns a circularly symmetric difference of Gaussian mask
 * @(#) min_amplitude should be greater than 0.0 and less than 1.0
 * @(#) min_amplitude determines the size of the mask; if for instance
 * @(#) the value .1 is entered this means that the produced mask is clipped
 * @(#) at values less than 10 percent of the minimum negative amplitude.
 * @(#) If the value of min_amplitude is too small, then the filter coefficients
 * @(#) are calculated for masksize equal to the min of 8 * sigma or 256.
 * @(#) The mask can be directly used with the vasari convolution programs,
 * @(#) the default offset set is 0
 * @(#) 
 * @(#) DOUBLEMASK *im_log_dmask( filename, sigma, min_amplitude )
 * @(#) char *filename;
 * @(#) double sigma, min_amplitude;
 * @(#) 
 * @(#) Returns a laplacian of Gaussian square double mask or NULL on error
 * @(#) 
 * @(#) DOUBLEMASK *im_log_imask( filename, sigma, min_amplitude )
 * @(#) char *filename;
 * @(#) double sigma, min_amplitude;
 * @(#) 
 * @(#) Returns a laplacian of Gaussian square int mask or NULL on error
 */

/* Written on: 30/11/1989
 * Updated on: 6/12/1991
 * 7/8/96 JC
 *	- ansified, mem leaks plugged
 * 20/11/98 JC
 *	- mask too large check added
 * 26/3/02 JC
 *	- ahem, was broken since '96, thanks matt
 * 16/7/03 JC
 *	- makes mask out to zero, not out to minimum, thanks again matt
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

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

#define IM_MAXMASK 256

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

	/* Stop used-before-set warnings.
	 */
	last = 0.0;

	/* Find the size of the mask depending on the entered data. We want to
	 * eval the mask out to the flat zero part, ie. beyond the minimum and
	 * to the point where it comes back up towards zero.
	 */
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

		/* Stop when change in temp (ie. difference from the last
		 * point) and absolute value are both less than the min.
		 */
		if( x > 0 && 
			fabs( val ) < min_ampl && 
			fabs( val - last ) < min_ampl ) 
			break;

		last = val;
	}
	if( x == IM_MAXMASK ) {
		im_errormsg( "im_log_dmask: mask too large" );
		return( NULL );
	}

	xm2 = x; ym2 = x;
	xm = xm2 * 2 + 1; ym = ym2 * 2 + 1;

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
