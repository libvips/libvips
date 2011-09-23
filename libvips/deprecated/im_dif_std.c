/* @(#)  Program to calculate the stdev of the differnce image
 * @(#) at a given displacement vector
 *
 * Written : 25/11/1987
 * Author : N. Dessipris
 * Updated : 2/12/1991
 * 22/7/93 JC
 *	- im_incheck() added
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
#include <vips/internal.h>

static int 
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
		im_error( "im_mean_std_int_buffer", "%s", _( "wrong args") );
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

int im_dif_std(im, xpos, ypos, xsize, ysize, dx, dy, pmean, pstd)
IMAGE *im;
int xpos, ypos, xsize, ysize; /* location of the box within im */
int dx, dy; /* displacements */
double *pmean, *pstd;
{
	PEL *input, *cpinput;
	double m, s;
	int *buf, *pbuf;
	int x, y;
	int ofst, bufsize;


	if( im_incheck( im ) )
		return( -1 );

	if ((im->Bands != 1)||(im->BandFmt != IM_BANDFMT_UCHAR)) {
		im_error( "im_dif_std", "%s", _( "Unable to accept input") ); 
		return(-1);}
	if ( (xpos + xsize + dx > im->Xsize)|| (ypos + ysize + dy > im->Ysize) ) { 
		im_error( "im_dif_std", "%s", _( "wrong args") ); 
		return(-1); }

	bufsize = xsize * ysize;
	buf = (int *)calloc( (unsigned)bufsize, sizeof(int) );
	if ( buf == NULL ) { 
		im_error( "im_dif_std", "%s", _( "calloc failed") ); 
		return(-1); }
	input = (PEL*)im->data;
	input += ( ypos * im->Xsize + xpos );
	ofst = dy * im->Xsize + dx;
	pbuf = buf;
	for ( y=0; y<ysize; y++ )
		{
		cpinput = input;
		input += im->Xsize;
		for ( x=0; x<xsize; x++ )
			{
			*pbuf++ = ((int)(*cpinput))-((int)(*(cpinput + ofst)));
			cpinput++;
			}
		}

	m = 0.0; s = 0.0;
	if( im__mean_std_int_buffer( buf, bufsize, &m, &s ) )
		return(-1);
	*pmean = m;
	*pstd = s;
	free((char*)buf);

	return(0);
}
