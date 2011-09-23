/* @(#)  Calculates the spatial grey level differnce
 * @(#)  matrix of an image and some of its
 * @(#) features.  The 256x1 difference matrix of im is held by m
 * @(#) There should be enough margin around the box so the (dx,dy) can
 * @(#) access neighbouring pixels outside the box
 * @(#)
 * @(#) Usage:
 * @(#) int im_glds_matrix(im, m, xpos, ypos, xsize, ysize, dx, dy)
 * @(#) IMAGE *im, *m;
 * @(#) int xpos, ypos, xsize, ysize;  location of the box within im
 * @(#) int dx, dy;    displacements
 * @(#)
 * @(#) int im_glds_asm(m, asmoment)
 * @(#) IMAGE *m;
 * @(#) double *asmoment;
 * @(#)
 * @(#) int im_glds_contrast(m, contrast)
 * @(#) IMAGE *m;
 * @(#) double *contrast;
 * @(#)
 * @(#) int im_glds_entropy(m, entropy)
 * @(#) IMAGE *m;
 * @(#) double *entropy;
 * @(#)
 * @(#) int im_glds_mean(m, mean)
 * @(#) IMAGE *m;
 * @(#) double *mean;
 * @(#)
 * @(#) All functions return 0 on success and -1 on error
 *
 * Copyright:  N. Dessipris, 1991
 * Written on: 2/12/1991
 * Modified on:
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

/* Keep the greylevel difference matrix as a 256x1 double image */

int 
im_glds_matrix( IMAGE *im, IMAGE *m, 
	int xpos, int ypos, int xsize, int ysize, int dx, int dy )
{
	PEL *in, *cpin;
	int *b, *pb;
	double *l, *pl;
	int x, y;
	int ofs;
	int tmp;
	int norm;

	if (im_iocheck(im, m) == -1)
		return( -1 );

	if ((im->Bands != 1)||(im->BandFmt != IM_BANDFMT_UCHAR)) { 
		im_error( "im_glds_matrix", "%s", _( "Wrong input") ); 
		return(-1); }

	if ( (xpos + xsize + dx > im->Xsize)|| (ypos + ysize + dy > im->Ysize) ) { 
		im_error( "im_glds_matrix", "%s", _( "wrong args") ); 
		return(-1); }

	if (im_cp_desc(m, im) == -1)
		return( -1 );
	m->Xsize = 256; 
	m->Ysize = 1;
	m->BandFmt = IM_BANDFMT_DOUBLE;
	m->Type = IM_TYPE_B_W;

	if (im_setupout(m) == -1)
		return( -1 );

	b = (int *)calloc( (unsigned)m->Xsize, sizeof(int) );
	l = (double *)calloc( (unsigned)m->Xsize, sizeof(double));
	if ( (b == NULL) || (l == NULL) ) { 
		im_error( "im_glds_matrix", "%s", _( "calloc failed") ); 
		return(-1); }

	in = (PEL*)im->data;
	in += ( ypos * im->Xsize + xpos );
	ofs = dy * im->Xsize + dx;
	for ( y=0; y<ysize; y++ )
		{
		cpin = in;
		in += im->Xsize;
		for ( x=0; x<xsize; x++ )
			{
			tmp = abs((int)*cpin - (int)(*(cpin+ofs)));
			pb = (b + tmp);
			(*pb)++;
			cpin++;
			}
		}

	norm = xsize * ysize;
	pb = b;
	pl = l;
	for (x=0; x<m->Xsize; x++)
		*pl++ = ((double)(*pb++))/(double)norm;
	if (im_writeline( 0, m, (PEL *) l ) == -1) 
		return( -1 );

	free((char*)b); free((char*)l);
	return(0);
}

/* @(#)  Calculates the asmoment of the sglds matrix held by m
 */
int 
im_glds_asm( IMAGE *m, double *asmoment )
{
	double temp, tmpasm, *in;
        int i;

	if( im_incheck( m ) )
		return( -1 );

        if (m->Xsize != 256 || m->Ysize != 1 ||
		 m->Bands != 1 || m->BandFmt != IM_BANDFMT_DOUBLE) {
		im_error( "im_glds_asm", "%s", _( "unable to accept input") );
		return(-1);}
	tmpasm = 0.0;
	in = (double*)m->data;
	for(i=0; i<m->Xsize; i++)
		{
		temp = *in++;
		tmpasm += (temp*temp);
		}
	*asmoment = tmpasm;
	return(0);
}

/* @(#)     Calculates the contrast of the coocurence matrix passed in buffer
 */
int 
im_glds_contrast( IMAGE *m, double *contrast )
{
	double tmpcon, *in;
        int i;

	if( im_incheck( m ) )
		return( -1 );

        if (m->Xsize != 256 || m->Ysize != 1 ||
                m->Bands != 1 || m->BandFmt != IM_BANDFMT_DOUBLE) { 
		im_error( "im_glds_contrast", "%s", _( "wrong input") ); 
		return(-1); }
	tmpcon = 0.0;
	in = (double*)m->data;
	for(i=0; i<m->Xsize; i++)
		{
		tmpcon += ( ((double)i)*((double)i)*(*in) );
		in++;
		}
	*contrast = tmpcon;
	return(0);
}

/* @(#)     Calculates the entropy of the glds vector passed in buffer
 * @(#) Function returns the entropy based on log base 2.
 */
int 
im_glds_entropy( IMAGE *m, double *entropy )
{
	double tmpent, dtemp, *in;
        int i;

	if( im_incheck( m ) )
		return( -1 );

        if (m->Xsize != 256 || m->Ysize != 1 ||
                m->Bands != 1 || m->BandFmt != IM_BANDFMT_DOUBLE) { 
		im_error( "im_glds_entropy", "%s", _( "wrong input") ); 
		return(-1); }
	tmpent = 0.0;
	in = (double*)m->data;
	for(i=0; i<m->Xsize; i++)
		{
		if(*in != 0)
                        {
                        dtemp = *in;
                        tmpent += (dtemp*log10(dtemp));
                        }
                in++;
		}
	*entropy = ((-1)*tmpent/log10(2.0));
	return(0);
}

/* @(#)     Calculates the mean of the sglds matrix passed in m
 */
int 
im_glds_mean( IMAGE *m, double *mean )
{
	double tmpmean, *in;
        int i;

	if( im_incheck( m ) )
		return( -1 );

        if (m->Xsize != 256 || m->Ysize != 1 ||
                m->Bands != 1 || m->BandFmt != IM_BANDFMT_DOUBLE) { 
		im_error( "im_glds_mean", "%s", _( "wrong input") ); 
		return(-1); }
	tmpmean = 0.0;
	in = (double*)m->data;
	for(i=0; i<m->Xsize; i++)
		{
		tmpmean += ( ((double)i)*(*in) );
		in++;
		}
	tmpmean = tmpmean/((double)m->Xsize);
	*mean = tmpmean;
	return(0);
}
