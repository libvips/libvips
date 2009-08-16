/*	Copyright (c) 1982 Michael Landy, Yoav Cohen, and George Sperling

Disclaimer:  No guarantees of performance accompany this software,
nor is any responsibility assumed on the part of the authors.  All the
software has been tested extensively and every effort has been made to
insure its reliability.   */

/* 1991 Modified by N. Dessipris to return a valid code on error */

/* fft -- fast fourier transform, adapted from 
** Gonzalez & Wintz p.87.
**
** No division by N is performed.
**
** Timing: rough estimates:
**   two-dimensional arrays, (including copying columns
**	 back and forth):
**	 for arrays up to 16X16: less than 1 sec.
**	 for 32X32 arrays: about 3.0 sec.
**	 for 64X64 arrays: about 9.0 sec.
**	 for 128X128 arrays: about 31.0 sec.
**
** Calling sequence:
**
** float *rvec,*ivec;
** int loglen,skip;
**
** fft_2d(rvec,ivec,loglen)
** performs a 2-dimensional fft where loglen is the log of the length of
** a side of the array
**
** fft_2dgen(rvec,ivec,logrows,logcols)
** performs a 2-dimensional fft where logrows is the log of the number of
** rows, and logcols is the log of the number of columns
**
** fftn(rvec,ivec,loglen,skip)
** performs a 1-dimensional fft on every skip-th entry
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

/* Only compile this if we're missing the fftw library.
 */
#if !HAVE_FFTW && !HAVE_FFTW3

#include <stdio.h>
#include <stdlib.h>
#include <math.h>

#include <vips/vips.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

static float *Const = NULL, *iConst = NULL;
static int storesize = 0, Constsize = 0;

static int 
fftn(rvec,ivec,loglen,nskip)

float *rvec,*ivec;
int loglen,nskip;

{
	int n,nv2,nm1,i,j,k,l,le,le1,c,nle;
	float	*rveci , *rvecj , *iveci , *ivecj ;
	float	t,wr,wi,tr,ti ;

	if(loglen==0)
		return(-1);
	n=1<<loglen ;
	nv2=n >> 1 ; nm1=n-1 ; j=0 ;
	if (storesize<nv2) {
		if ((0==(Const=(float *)calloc((unsigned)nv2,sizeof(float)))) ||
		    (0==(iConst=(float *)calloc((unsigned)nv2,sizeof(float))))){
			im_errormsg( "Not enough core for fftn" );
			return(-1);
		}
		storesize = nv2;
	}
	if (Constsize!=nv2) {
		Constsize = nv2;
		wr =  cos(2*IM_PI/n);
		wi = -sin(2*IM_PI/n);
		Const[0] = 1.;
		iConst[0] = 0.;
		for (i=1;i<nv2;i++) {
			Const[i] = wr*Const[i-1] - wi*iConst[i-1];
			iConst[i] = wr*iConst[i-1] + wi*Const[i-1];
		}
	}
	for (i=0;i<nm1;i++) {
		if(i<j) {
			rveci=rvec+i*nskip ; rvecj=rvec+j*nskip ;
			t=(*rvecj) ; *rvecj=(*rveci) ; *rveci=t ; 
			iveci=ivec+i*nskip ; ivecj=ivec+j*nskip ;
			t=(*ivecj) ; *ivecj=(*iveci) ; *iveci=t ;
		}
		k=nv2 ;
		while (k<=j) {
			j-=k ; k>>=1 ;
		}
		j+=k ;
	}
	le=1 ;
	for (l=0;l<loglen;l++) {
		le1=le ; le+=le ; c = 0; nle = n/le;
		for (j=0;j<le1;j++) {
			for (i=j;i<n;i+=le) {
				if(i+le1>=n) {
					im_warning("index=%d\n",i+le1);
					return(-1);
				}
				rveci=rvec+i*nskip ; rvecj=rvec+(i+le1)*nskip;
			  	iveci=ivec+i*nskip ; ivecj=ivec+(i+le1)*nskip;

			  	if (c==0) {
					tr = *rvecj;
					ti = *ivecj;
				}
				else {
					tr = *rvecj*Const[c] - *ivecj*iConst[c];
					ti = *rvecj*iConst[c] + *ivecj*Const[c];
				}
				*rvecj = *rveci - tr;
				*ivecj = *iveci - ti;

				*rveci += tr;
				*iveci += ti;
			}
			c += nle;
		}
	}
/* Division by n
	for(i=0;i<n;i++)
		{rvec[i*nskip]/=n ; ivec[i*nskip]/=n ;}
*/
	return(0);
}


static void
free_store( void )
{
	if( Const ) {
		free( Const );
		Const = NULL;
	}
	if( iConst ) {
		free( iConst );
		iConst = NULL;
	}

	storesize = 0;
	Constsize = 0;
}

int
im__fft_sp( float *rvec, float *ivec, int logrows, int logcols )
{
	int i,rows,cols,size;

	rows = 1<<logrows;
	cols = 1<<logcols;
	size = rows * cols;

	for (i=0;i<size;i+=cols)
		if ( fftn(rvec+i,ivec+i,logcols,1) == -1) {
			free_store();
			return(-1);
		}

	for (i=0;i<cols;i++)
		if ( fftn(rvec+i,ivec+i,logrows,cols) == -1) {
			free_store();
			return(-1);
		}

	free_store();
	return(0);
}

#endif /*HAVE_FFTW*/
