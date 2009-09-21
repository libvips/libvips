/* @(#)  Calculates the cooccurrence matrix of an image and some of its
 * @(#) features.  The 256x256 cooccurrence matrix of im is held by m
 * @(#) There should be enough margin around the box so the (dx,dy) can
 * @(#) access neighbouring pixels outside the box
 * @(#)
 * @(#) Usage:
 * @(#) int im_cooc_matrix(im, m, xpos, ypos, xsize, ysize, dx, dy, sym_flag)
 * @(#) IMAGE *im, *m;
 * @(#) int xpos, ypos, xsize, ysize;  location of the box within im 
 * @(#) int dx, dy;    displacements 
 * @(#) int sym_flag;
 * @(#)
 * @(#) int im_cooc_asm(m, asmoment)
 * @(#) IMAGE *m;
 * @(#) double *asmoment;
 * @(#)
 * @(#) int im_cooc_contrast(m, contrast)
 * @(#) IMAGE *m;
 * @(#) double *contrast;
 * @(#)
 * @(#) int im_cooc_correlation(m, correlation)
 * @(#) IMAGE *m;
 * @(#) double *correlation;
 * @(#)
 * @(#) int im_cooc_entropy(m, entropy)
 * @(#) IMAGE *m;
 * @(#) double *entropy;
 * @(#)
 * @(#) All functions return 0 on success and -1 on error
 *
 * Copyright: N. Dessipris 1991
 * Written on: 2/12/1991
 * Updated on: 2/12/1991
 * 22/7/93 JC
 *	- extern decls removed
 *	- im_incheck() calls added
 * 28/5/97 JC
 *	- protos added :( 
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

static
int im_cooc_sym(im, m, xpos, ypos, xsize, ysize, dx, dy)
IMAGE *im, *m;
int xpos, ypos, xsize, ysize; /* location of the box within im */
int dx, dy; /* displacements */
{
	PEL *input, *cpinput;
	int *buf, *pnt, *cpnt;
	double *line, *cpline;
	int x, y;
	int offset;
	int bufofst;
	int tempA, tempB;
	int norm;

	if (im_iocheck(im, m) == -1)
		return( -1 );
	if ((im->Bands != 1)||(im->Bbits != IM_BBITS_BYTE)||(im->BandFmt != IM_BANDFMT_UCHAR)) {
		im_error( "im_cooc_sym", "%s", _( "Unable to accept input") );
		return(-1);
		}
	if ( (xpos + xsize + dx > im->Xsize)|| (ypos + ysize + dy > im->Ysize) ) { 
		im_error( "im_cooc_sym", "%s", _( "wrong args") ); 
		return(-1); }
	if (im_cp_desc(m, im) == -1)
		return( -1 );
	m->Xsize = 256;
	m->Ysize = 256;
	m->Bbits = IM_BBITS_DOUBLE;
	m->BandFmt = IM_BANDFMT_DOUBLE;
	m->Type = IM_TYPE_B_W;
	if (im_setupout(m) == -1)
		return( -1 );
/* malloc space to keep the read values */
	buf = (int *)calloc( (unsigned)m->Xsize*m->Ysize, sizeof(int) );
	line = (double *)calloc( (unsigned)m->Xsize * m->Bands, sizeof(double));
	if ( (buf == NULL) || (line == NULL) ) { 
		im_error( "im_cooc_sym", "%s", _( "calloc failed") ); 
		return(-1); }
	input = (PEL*)im->data;
	input += ( ypos * im->Xsize + xpos );
	offset = dy * im->Xsize + dx;
	for ( y=0; y<ysize; y++ )
		{
		cpinput = input;
		input += im->Xsize;
		for ( x=0; x<xsize; x++ )
			{
			tempA = (int)(*cpinput);
			tempB = (int)(*(cpinput + offset));
			bufofst = tempA + m->Xsize * tempB;
			(*(buf + bufofst))++;
			bufofst = tempB + m->Xsize * tempA;
			(*(buf + bufofst))++;
			cpinput++;
			}
		}

	norm = xsize * ysize * 2;
	pnt = buf;
	for ( y=0; y<m->Ysize; y++ )
		{
		cpnt = pnt;
		pnt += m->Xsize;
		cpline = line;
		for (x=0; x<m->Xsize; x++)
			*cpline++ = (double)(*cpnt++)/(double)norm;
		if (im_writeline( y, m, (PEL *) line ) == -1) 
			{
			im_error( "im_cooc_sym", "%s", _( "unable to im_writeline") );
			return(-1);
			}
		}
	free((char*)buf);
	free((char*)line);
	return(0);
}

static
int im_cooc_ord(im, m, xpos, ypos, xsize, ysize, dx, dy)
IMAGE *im, *m;
int xpos, ypos, xsize, ysize; /* location of the box within im */
int dx, dy; /* displacements */
{
	PEL *input, *cpinput;
	int *buf, *pnt, *cpnt;
	double *line, *cpline;
	int x, y;
	int offset;
	int bufofst;
	int tempA, tempB;
	int norm;

	if (im_iocheck(im, m) == -1)
		return( -1 );
	if ((im->Bands != 1)||(im->Bbits != IM_BBITS_BYTE)||(im->BandFmt != IM_BANDFMT_UCHAR))
		{
		im_error( "im_cooc_ord", "%s", _( "Unable to accept input") );
		return(-1);
		}
	if ( (xpos + xsize + dx > im->Xsize)|| (ypos + ysize + dy > im->Ysize) ) { 
		im_error( "im_cooc_ord", "%s", _( "wrong args") ); 
		return(-1); }
	if (im_cp_desc(m, im) == -1)
		return( -1 );
	m->Xsize = 256;
	m->Ysize = 256;
	m->Bbits = IM_BBITS_DOUBLE;
	m->BandFmt = IM_BANDFMT_DOUBLE;
	if (im_setupout(m) == -1)
		return( -1 );
/* malloc space to keep the read values */
	buf = (int *)calloc( (unsigned)m->Xsize*m->Ysize, sizeof(int) );
	line = (double *)calloc( (unsigned)m->Xsize * m->Bands, sizeof(double));
	if ( (buf == NULL) || (line == NULL) ) { 
		im_error( "im_cooc_ord", "%s", _( "calloc failed") ); 
		return(-1); }
	input = (PEL*)im->data;
	input += ( ypos * im->Xsize + xpos );
	offset = dy * im->Xsize + dx;
	for ( y=0; y<ysize; y++ )
		{
		cpinput = input;
		input += im->Xsize;
		for ( x=0; x<xsize; x++ )
			{
			tempA = (int)(*cpinput);
			tempB = (int)(*(cpinput + offset));
			bufofst = tempA + m->Xsize * tempB;
			(*(buf + bufofst))++;
			cpinput++;
			}
		}

	norm = xsize * ysize;
	pnt = buf;
	for ( y=0; y<m->Ysize; y++ )
		{
		cpnt = pnt;
		pnt += m->Xsize;
		cpline = line;
		for (x=0; x<m->Xsize; x++)
			*cpline++ = (double)(*cpnt++)/(double)norm;
		if (im_writeline( y, m, (PEL *) line ) == -1) 
			{
			im_error( "im_cooc_ord", "%s", _( "unable to im_writeline") );
			return(-1);
			}
		}
	free((char*)buf);
	free((char*)line);
	return(0);
}

/* Keep the coocurrence matrix as a 256x256x1 double image */

int 
im_cooc_matrix( IMAGE *im, IMAGE *m, 
	int xp, int yp, int xs, int ys, int dx, int dy, int flag )
{
	if (flag == 0)
		return( im_cooc_ord(im, m, xp, yp, xs, ys, dx, dy) );
	else if (flag == 1)	/* symmetrical cooc */
		return( im_cooc_sym(im, m, xp, yp, xs, ys, dx, dy) );
	else { 
		im_error( "im_cooc_matrix", "%s", _( "wrong flag!") ); 
		return(-1); }
}

/* Calculate contrast, asmoment, entropy and correlation
 */
int 
im_cooc_asm( IMAGE *m, double *asmoment )
{
	double temp, tmpasm, *pnt;
	int i;

	if( im_incheck( m ) )
		return( -1 );

	if (m->Xsize != 256 || m->Ysize != 256 || 
		m->Bands != 1 || m->BandFmt != IM_BANDFMT_DOUBLE)
		{
		im_error( "im_cooc_asm", "%s", _( "unable to accept input") );
		return(-1);
		}
	tmpasm = 0.0;
	pnt = (double*)m->data;
	for(i=0; i<m->Xsize * m->Ysize; i++)
		{
		temp = *pnt++;
		tmpasm += temp * temp;
		}
	*asmoment = tmpasm;
	return(0);
}

int 
im_cooc_contrast( IMAGE *m, double *contrast )
{
	double dtemp, tmpcon, *pnt, *cpnt;
	int x, y;

	if( im_incheck( m ) )
		return( -1 );

	if (m->Xsize != 256 || m->Ysize != 256 || 
		m->Bands != 1 || m->BandFmt != IM_BANDFMT_DOUBLE)
		{
		im_error( "im_cooc_contrast", "%s", _( "unable to accept input") );
		return(-1);
		}
	tmpcon = 0.0;
	pnt = (double*)m->data;
	for(y=0; y<m->Ysize; y++)
		{
		cpnt = pnt;
		pnt += m->Xsize;
		for(x=0; x<m->Xsize; x++)
			{
			dtemp = (double)( (y-x)*(y-x) );
			tmpcon += dtemp * (*cpnt);
			cpnt++;
			}
		}

	*contrast = tmpcon;
	return(0);
}

static void 
stats(buffer, size, pmean, pstd)
double *buffer;		/* buffer contains the frequency distributions f[i] */
int size;		/*  Note that sum(f[i]) = 1.0 and that the */
			/* cooccurence matrix is symmetrical */
double *pmean, *pstd;
{
	double mean, std;
	register int i;
	double sumf;	/* calculates the sum of f[i] */
	double temp;	/* temporary variable */
	double *pbuffer;
	double sumf2;	/* calculates the sum of f[i]^2 */
	double correction; /* calulates the correction term for the variance */
	double variance;	/* = (sumf2 - correction)/n, n=sum(f[i]) = 1 */
	
	mean = 0.0; std = 0.0;
	sumf = 0.0; sumf2 = 0.0;
	pbuffer = buffer;
	for (i=0; i<size; i++)
		{
		temp = *pbuffer++;
		sumf += (temp*i);
		sumf2 += (temp*i*i);
		}
	correction = sumf*sumf;
	mean = sumf;
	variance = sumf2-correction;
	std = sqrt(variance);
	*pmean = mean;
	*pstd = std;
}

int 
im_cooc_correlation( IMAGE *m, double *correlation )
{
	double mcol, stdcol, mrow, stdrow; /* mean and std of cols and rows */
	double *pbuf;
	double *cpbuf;
	double dtemp;
	register int i,j;
	double *row;	/* Keeps the sum of rows entries as double */
	double *col;	/* Keeps the sum of cols entries as double */
	double tmpcor=0.0;
	double sum = 0.0;

	if( im_incheck( m ) )
		return( -1 );

	if (m->Xsize != 256 || m->Ysize != 256 || 
		m->Bands != 1 || m->BandFmt != IM_BANDFMT_DOUBLE)
		{
		im_error( "im_cooc_correlation", "%s", _( "unable to accept input") );
		return(-1);
		}
	row = (double*)calloc( (unsigned)m->Ysize, sizeof(double));
	col = (double*)calloc( (unsigned)m->Xsize, sizeof(double));
	if ( row == NULL || col == NULL )
		{
		im_error( "im_cooc_correlation", "%s", _( "unable to calloc") );
		return(-1);
		}
	pbuf = (double*)m->data;
	for(j=0; j<m->Ysize; j++)
		{
		cpbuf = pbuf;
		pbuf += m->Xsize;
		sum=0.0;
		for(i=0; i<m->Xsize; i++)
			sum += *cpbuf++;
		*(row+j) = sum;
		}

	pbuf = (double*)m->data;
	for(j=0; j<m->Ysize; j++)
		{
		cpbuf = pbuf;
		pbuf++;
		sum=0.0;
		for(i=0; i<m->Xsize; i++)
			{
			sum += *cpbuf;
			cpbuf += m->Xsize;
			}
		*(col+j) = sum;
		}

	stats(row, m->Ysize, &mrow, &stdrow);

	stats(col, m->Ysize ,&mcol, &stdcol);
#ifdef DEBUG
	fprintf(stderr, "rows: mean=%f std=%f\ncols: mean=%f std=%f\n",
mrow, stdrow, mcol, stdcol);
#endif
	tmpcor = 0.0;
	pbuf = (double*)m->data;
	for(j=0; j<m->Ysize; j++)
		{
		cpbuf = pbuf;
		pbuf += m->Xsize;
		for(i=0; i<m->Xsize; i++)
			{
			dtemp = *cpbuf;
			tmpcor += ( ((double)i)*((double)j)*dtemp);
			cpbuf++;
			}
		}
#ifdef DEBUG
	fprintf(stderr, "tmpcor=%f\n", tmpcor);
#endif
	if ( (stdcol==0.0)||(stdrow==0) )
		{
		im_error( "im_cooc_correlation", "%s", _( "zero std") );
		return(-1);
		}
	tmpcor = (tmpcor-(mcol*mrow))/(stdcol*stdrow);
	*correlation = tmpcor;
	free((char*)row); free((char*)col);
	return(0);
}

int 
im_cooc_entropy( IMAGE *m, double *entropy )
{
	double *pbuf, *pbufstart;
	double *cpbuf;
	register int i,j;
	double tmpent, dtemp;
	double val;

	if( im_incheck( m ) )
		return( -1 );

	if (m->Xsize != 256 || m->Ysize != 256 || 
		m->Bands != 1 || m->BandFmt != IM_BANDFMT_DOUBLE)
		{
		im_error( "im_cooc_entropy", "%s", _( "unable to accept input") );
		return(-1);
		}
	pbufstart = (double*)m->data;

	tmpent = 0.0;
	pbuf = pbufstart;
	for(j=0; j<m->Ysize; j++)
		{
		cpbuf = pbuf;
		pbuf += m->Xsize;
		for(i=0; i<m->Xsize; i++)
			{
			if(*cpbuf != 0)
				{
				dtemp = *cpbuf;
				tmpent += (dtemp*log10(dtemp));
				}
			cpbuf++;
			}
		}
	val = tmpent*(-1);

#ifdef DEBUG
	fprintf(stderr,"ENT=%f\nwhich is %f bits\n", val, val/log10(2.0) );
#endif
	*entropy = (val/log10(2.0));
	return(0);
}
