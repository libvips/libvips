/* @(#) Function which convolves and subsamples VASARI format picture
 * @(#) with a mask stored in a file argument.
 * @(#)
 * @(#) int im_convsub( in, out, mask, xskip, yskip )
 * @(#) IMAGE *in, *out;
 * @(#) INTMASK *mask;  details in vips.h
 * @(#) int xskip, yskip;  is the subsamping factor along both directions
 * @(#)
 * @(#) Returns either 0 (sucess) or -1 (fail)
 * @(#)
 * @(#) Picture can have any number of channels (max 64).
 * @(#) It is assummed that the output picture is subsampled on
 * @(#) both directions by a factor of xskip horizontally and yskip vertically.
 *
 * Copyright: 1990, N. Dessipris.
 *
 * Author: Nicos Dessipris
 * Written on: 29/04/1991
 * Modified on: 
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

#include <vips/vips.h>
#include <vips/internal.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/


int im_convsub( in, out, m, xskip, yskip )
IMAGE *in, *out;
INTMASK *m;
int xskip, yskip;
{


	int x;		/* horizontal direction */
	int y;		/* vertical direction */
	int n_clipped = 0;
	int p_clipped = 0;
	int i, b;
	PEL **pnts, **cpnt1s, **cpnt2s;	/* to keep pointers to data */
	PEL **pnt, **cpnt1, **cpnt2;	/* to keep pointers to data */
	PEL *input, *line, *cpline;
	int *pm; /* pointer to mask coefficients */
	int count; /* no of non zero elms of the original mask */
	int *newm, *pnewm; /* pointer to non zero mask coefficients */
	int os; /* size of an input line of data */
	int ms; /*  is m->xsize * m->ysize */
	int **lut_orig, **lut;
	int lutcnt = 0;
	int rounding, sum;
	int tempsize;

/* Check input, output and vars */
	if ((xskip < 1)||(yskip < 1))
                {
                im_error( "im_convsub", "%s", _( "xskip and yskip must be >= 1") );
                return(-1);
                }
	if (im_iocheck(in, out) == -1)
		return( -1 );
	
	if ( (in->Coding != IM_CODING_NONE)||(in->Bbits != IM_BBITS_BYTE)
	    ||(in->BandFmt != IM_BANDFMT_UCHAR) )
		{
		im_error( "im_convsub", "%s", _( "nput should be unsigned char uncoded") );
		return(-1);
		}

/* Prepare output */
	if (im_cp_desc(out, in) == -1)
		return( -1 );
	tempsize = in->Xsize/xskip;
	while ( 1 )
		{
		if ( tempsize * xskip + m->xsize < in->Xsize )
			break;
		else
			tempsize--;
		if ( tempsize < 0 )
			break;
		}
        out->Xsize = tempsize;
	tempsize = in->Ysize/yskip;
	while ( 1 ) 
		{
		if ( tempsize * yskip + m->ysize < in->Ysize )
			break;
		else
			tempsize--;
		if ( tempsize < 0 )
			break;
		}
        out->Ysize = tempsize;
	if ( ( out->Xsize < 2 )||( out->Ysize < 2 ) ) {
		im_error( "im_convsub", "%s", _( "too small output sizes") );
		return(-1); 
	}

	if( im_setupout(out) == -1)
		return(-1); 

/* Malloc one line of output data */
	os = out->Xsize * out->Bands;
	if ( (line=(PEL*)calloc( (unsigned)os, sizeof(char))) == NULL) { 
		im_error( "im_convsub", "%s", _( "unable to calloc(1)") );
		return(-1); 
	}
	
/* Malloc pointers and put them at correct location */
	ms = m->xsize * m->ysize;
	count = 0;	/* exclude the non-zero elms */
	pm = m->coeff;
	for ( i=0; i<ms; i++)
		{
		if ( *pm++ != 0 )
			count++; 
		}

	if (((newm = (int*)calloc((unsigned)count, sizeof(int))) == NULL )||
	    ((pnts = (PEL**)calloc((unsigned)count, sizeof(char *))) == NULL)||
	    ((cpnt1s=(PEL**)calloc((unsigned)count, sizeof(char *))) == NULL)||
	    ((cpnt2s=(PEL**)calloc((unsigned)count, sizeof(char *))) ==NULL ) )
		{ 
		im_error( "im_convsub", "%s", _( "unable to calloc(2)") );
		return(-1); 
	}
	
	pnt = pnts;
	cpnt1 = cpnt1s;
	cpnt2 = cpnt2s;

/* copy the non-zero elms of the original mask and set pointers */
	i=0;
	input = (PEL*)in->data;
	pm = m->coeff;
	pnewm = newm;
	for (y=0; y<m->ysize; y++)
		{
		for (x=0; x<m->xsize; x++)
			{
			if ( *pm != 0 )
				{
				*pnewm++ = *pm;
				pnt[i] = (input +(x + y*in->Xsize) * in->Bands);
				i++;
				}
			pm++;
			}
		}

	if ( i != count ) { 
		im_error( "im_convsub", "%s", _( "impossible state") ); 
		return(-1); }

/* Malloc pointers; not all lut_orig are used necessarily */
        lut_orig = (int**)calloc((unsigned)count, sizeof(int**) );
        lut = (int**)calloc((unsigned)count, sizeof(int**) );
        if ( (lut == NULL) || (lut_orig == NULL) ) { 
		im_error( "im_conv", "%s", _( "unable to calloc(1)") ); 
		return(-1); }

/* Create luts; count is needed for freeing pointers. Not all lut_orig are used
 * if zero elms are detected.
 */
        if ( im__create_int_luts(newm, count, lut_orig, lut, &lutcnt ) == -1 )
		{
		im_error( "im_convsub", "%s", _( "im_create_int_luts failed") );
                return(-1);
		}

	rounding = m->scale/2;

/* Output out->Ysize processed lines */
	for(y=0; y < out->Ysize; y++)
		{
		cpline = line;
		for (i=0; i<count; i++)
			{
			cpnt1[i] = pnt[i];
				/* skip yskip input lines */
			pnt[i] += ( in->Xsize * in->Bands * yskip );
			}

		/* process out->Xsize points */
		for( x = 0; x < out->Xsize; x++ )
			{
			for (i=0; i<count; i++)
				{ /* skip xskip elms */
				cpnt2[i] = cpnt1[i];
				cpnt1[i] += xskip * in->Bands;
				}
			for ( b=0; b<out->Bands; b++ )
				{
				sum = 0;
				for (i=0; i<count; i++)
					{	/* core of convolution */
					sum += *( lut[i] + (*cpnt2[i]) );
					cpnt2[i]++;
					}
				sum = ( (sum+rounding)/m->scale ) + m->offset;

				if ( sum < (int)0 )
					{ n_clipped++; sum = (int)0; }
				else if ( sum > (int)255)
					{ p_clipped++; sum = (int)255; }
				*cpline++ = (unsigned char)sum;
				}
			}

		/* Output the calculated line */
		if ( im_writeline(y, out, (PEL*)line) == -1 )
			{
			free((char*)line); free((char*)newm);
			free((char*)pnts);
			free((char*)cpnt1s); free((char*)cpnt2s);
			for ( i=0; i<lutcnt; i++)
				free( (char*)lut_orig[i] );
			free( (char*)lut_orig ); free( (char*)lut );
			return(-1);
			}
		}		/* end of the for (..y..) loop */
	
	if (n_clipped || p_clipped)
               fprintf(stderr,
               "im_convsub: %d pels over 255 and %d under 0 clipped\n",
                p_clipped, n_clipped);

	free((char*)line); free((char*)newm);
	free((char*)pnts);
	free((char*)cpnt1s); free((char*)cpnt2s);
	for ( i=0; i<lutcnt; i++)
		free( (char*)lut_orig[i] );
	free( (char*)lut_orig ); free( (char*)lut );

	return(0);
}
