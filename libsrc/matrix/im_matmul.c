/* @(#) Multiplies two DOUBLEMASKs. Result matrix is made and returned.
 * @(#) Pass the filename to set for the output.
 * @(#)  
 * @(#) DOUBLEMASK *
 * @(#) im_matmul( in1, in2, name )
 * @(#) DOUBLEMASK *in1, *in2;
 * @(#) char *name;
 * @(#)  
 * @(#) NULL for error.
 *
 * Copyright: 1990, K. Martinez and J. Cupitt
 *
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

#include <vips/vips.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* MATRIX MULTIPLY?
 */
DOUBLEMASK *
im_matmul( DOUBLEMASK *in1, DOUBLEMASK *in2, const char *name )
{	
	int xc, yc, col;
	double sum;
	DOUBLEMASK *mat;
	double *out, *a, *b;
	double *s1, *s2;

	/* Check matrix sizes.
	 */
	if( in1->xsize != in2->ysize ) {
		im_errormsg( "im_matmul: bad sizes" );
		return( NULL );
	}

	/* Allocate output matrix.
	 */
	if( !(mat = im_create_dmask( name, in2->xsize, in1->ysize )) ) {
		im_errormsg( "im_matmul: unable to allocate output mask" );
		return( NULL );
	}

	/* Multiply.
	 */
	out = mat->coeff;
	s1 = in1->coeff;

	for( yc = 0; yc < in1->ysize; yc++ ) {
		s2 = in2->coeff;

		for( col = 0; col < in2->xsize; col++ ) {
			/* Get ready to sweep a row.
			 */
			sum = 0.0;
			a = s1;
			b = s2;

			for( sum = 0.0, xc = 0; xc < in1->xsize; xc++ ) {
				sum += *a++ * *b;
				b += in2->xsize;
			}

			*out++ = sum;
			s2++;
		}

		s1 += in1->xsize;
	}

	return( mat );
}
