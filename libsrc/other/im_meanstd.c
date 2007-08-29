/* @(#)  Calculates the mean and the standard deviation (std) of
 * @(#) an int or double buffer of size size.
 * @(#)
 * @(#) Usage:
 * @(#) int im__mean_std_double_buffer(buffer, size, pmean, pstd)
 * @(#) double *buffer;	
 * @(#) int size;
 * @(#) double *pmean, *pstd;
 * @(#)
 * @(#) int im__mean_std_int_buffer(buffer, size, pmean, pstd)
 * @(#) int *buffer;	
 * @(#) int size;
 * @(#) double *pmean, *pstd;
 * @(#)
 * @(#) Both functions return 0 on success and -1 on error
 *
 * Copyright: N. Dessipris 1991
 * Written on: 2/12/1991
 * Updated on: 2/12/1991
 * 22/7/93 JC
 *	- externs removed
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
#include <stdlib.h>
#include <math.h>

#include <vips/vips.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

int 
im__mean_std_double_buffer( double *buffer, int size, 
	double *pmean, double *pstd )
{
	double mean, std;
	register int i;
	double sumf;	
	double temp;
	double *pbuffer;
	double sumf2;
	double correction; /* calulates the correction term for the variance */
	double variance;	/* = (sumf2 - correction)/n */
	
	if (size <= 0) {
		im_errormsg("im_mean_std_double_buffer: wrong args");
		return(-1);
	}
	mean = 0.0; std = 0.0;
	sumf = 0.0; sumf2 = 0.0;
	pbuffer = buffer;
	for (i=0; i<size; i++) {
		temp = *pbuffer++;
		sumf += temp;
		sumf2 += (temp*temp);
	}

	correction = (sumf * sumf)/((double)size);
	mean = sumf/((double)size);
	variance = ( sumf2 - correction)/((double)size);
	std = sqrt(variance);
	*pmean = mean;
	*pstd = std;

	return( 0 );
}

int 
im__mean_std_int_buffer( int *buffer, int size, 
	double *pmean, double *pstd )
{
	double mean, std;
	register int i;
	int sumf;	
	int temp;
	int *pbuffer;
	int sumf2;
	double correction; /* calulates the correction term for the variance */
	double variance;	/* = (sumf2 - correction)/n */
	
	if (size <= 0) {
		im_errormsg("im_mean_std_int_buffer: wrong args");
		return(-1);
	}

	mean = 0.0; std = 0.0;
	sumf = 0; sumf2 = 0;
	pbuffer = buffer;
	for (i=0; i<size; i++) {
		temp = *pbuffer++;
		sumf += temp;
		sumf2 += (temp*temp);
	}

	correction = ((double)(sumf * sumf))/((double)size);
	mean = ((double)sumf)/((double)size);
	variance = ( sumf2 - correction)/((double)size);
	std = sqrt(variance);
	*pmean = mean;
	*pstd = std;

	return(0);
}
