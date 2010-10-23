/* matrix transpose
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

/**
 * im_mattrn:
 * @in: input matrix 
 * @filename: name for output matrix
 *
 * Transposes the input matrix.
 * Pass the filename to set for the output.
 *
 * See also: im_matmul(), im_matinv().
 *
 * Returns: the result matrix on success, or %NULL on error.
 */
DOUBLEMASK *
im_mattrn( DOUBLEMASK *in, const char *name )
{	
	int xc, yc;
	DOUBLEMASK *mat;
	double *out, *a, *b;

	/* Allocate output matrix.
	 */
	if( !(mat = im_create_dmask( name, in->ysize, in->xsize )) ) 
		return( NULL );
	mat->scale = in->scale;
	mat->offset = in->offset;

	/* Transpose.
	 */
	out = mat->coeff;
	a = in->coeff;

	for( yc = 0; yc < mat->ysize; yc++ ) {
		b = a;

		for( xc = 0; xc < mat->xsize; xc++ ) {
			*out++ = *b;
			b += in->xsize;
		}

		a++;
	}

	return( mat );
}
