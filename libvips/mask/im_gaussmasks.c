/* @(#) Returns a circularly symmetric Gaussian mask
 * @(#) min_amplitude should be greater than 0.0 and less than 1.0
 * @(#) min_amplitude determines the size of the mask; if for instance
 * @(#) the value .1 is entered this means that the produced mask is clipped
 * @(#) at values less than 10 percent of the minimum negative amplitude.
 * @(#) If the value of min_amplitude is too small, then the filter coefficients
 * @(#) are calculated for masksize equal to the min of 8 * sigma or 256.
 * @(#) The mask can be directly used with the vasari convolution programs,
 * @(#) the default offset set is 0
 * @(#) 
 * @(#) DOUBLEMASK *im_gauss_dmask( filename, sigma, min_amplitude )
 * @(#) char *filename;
 * @(#) double sigma, min_amplitude;
 * @(#) 
 * @(#) Returns a laplacian of Gaussian square double mask or NULL on error
 * @(#) 
 * @(#) DOUBLEMASK *im_gauss_imask( filename, sigma, min_amplitude )
 * @(#) char *filename;
 * @(#) double sigma, min_amplitude;
 * @(#) 
 * @(#) Returns a laplacian of Gaussian square int mask or NULL on error
 */

/* Written on: 30/11/1989 by Nicos
 * Updated on: 6/12/1991
 * 7/8/96 JC
 *	- ansified, mem leaks plugged
 * 20/11/98 JC
 *	- mask too large check added
 * 18/3/09
 * 	- bumped max mask size *40
 * 	- added _sep variant
 * 30/3/09
 * 	- set scale in _sep variant, why not
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

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

#define IM_MAXMASK 5000

DOUBLEMASK *
im_gauss_dmask( const char *filename, double sigma, double min_ampl )
{
	int x, y, k;
	double distance;
	double temp;
	double *pt1, *pt2, *pt3, *pt4;
	int max_x;
	int xm, ym;
	int xm2, ym2; /* xm2 = xm/2 */
	int offset;
	double *cf, *cfs, *mc;
	DOUBLEMASK *m;
	double sig2, sum; /* sig2 = 2. * sigma * sigma */

	/* Find the size of the mask depending on the entered data 
	 */
	sig2 =  2. * sigma * sigma;
	max_x =  8 * sigma > IM_MAXMASK ? IM_MAXMASK : 8 * sigma ;
	for( x = 0; x < max_x; x++ ) {
		temp = exp( - ((double)(x * x))/sig2 );
		if( temp < min_ampl ) 
			break;
	}
	if( x == max_x ) {
		im_error( "im_gauss_dmask", "%s", _( "mask too large" ) );
		return( NULL );
	}

	xm2 = x; 
	ym2 = x;
	xm = xm2 * 2 + 1; 
	ym = ym2 * 2 + 1;

	if( !(cfs = IM_ARRAY( NULL, (xm2+1)*(ym2+1), double )) )
		return( NULL );

	for( k = 0, y = 0; y <= ym2; y++ ) {
		for( x = 0; x <= xm2; x++, k++ ) {
			distance = x*x + y*y;
			cfs[k] = exp( -distance / sig2 );
		}
	}

#ifdef PIM_RINT
	for( k = 0, y = 0; y <= ymask_2; y++ ) {
		for( x = 0; x <= xmask_2; x++, k++ )
			fprintf(stderr, "%3.2f ", cfs[k] );
		fprintf(stderr, "\n");
	}
#endif

	if( !(m = im_create_dmask( filename, xm, ym )) ) {
		im_free( cfs ); 
		return( NULL );
	}

	/* copy the 1/4 cfs into the m 
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
im_gauss_imask( const char *filename, double sigma, double min_amplitude )
{
	DOUBLEMASK *dm;
	INTMASK *im;

	if( !(dm = im_gauss_dmask( filename, sigma, min_amplitude )) )
		return( NULL );

	if( !(im = im_scale_dmask( dm, dm->filename )) ) {
		im_free_dmask( dm );
		return( NULL );
	}
	im_free_dmask( dm );

	return( im ) ;
}

/* Just return the central line of the mask. This helps nip, which really
 * struggles with large matrix manipulations.
 */
INTMASK *
im_gauss_imask_sep( const char *filename, double sigma, double min_amplitude )
{
	INTMASK *im;
	INTMASK *im2;
	int i;
	int sum;

	if( !(im = im_gauss_imask( filename, sigma, min_amplitude )) )
		return( NULL );
	if( !(im2 = im_create_imask( filename, im->xsize, 1 )) ) {
		im_free_imask( im );
		return( NULL );
	}

	sum = 0;
	for( i = 0; i < im->xsize; i++ ) {
		im2->coeff[i] = im->coeff[i + im->xsize * (im->ysize / 2)];
		sum += im2->coeff[i];
	}
	im2->scale = sum;

	im_free_imask( im );

	return( im2 ) ;
}
