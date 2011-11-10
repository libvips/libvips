/* matrix catenate
 *
 * 1994, K. Martinez
 *
 * 22/10/10
 * 	- gtk-doc
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
#include <string.h>

#include <vips/vips.h>

/**
 * im_matcat:
 * @top: input matrix
 * @bottom: input matrix
 * @filename: filename for output
 *
 * Matrix catenations. Returns a new matrix which is the two source matrices
 * joined together top-bottom. They must be the same width.
 *
 * See also: im_mattrn(), im_matmul(), im_matinv().
 *
 * Returns: the joined mask on success, or NULL on error.
 */
DOUBLEMASK *
im_matcat( DOUBLEMASK *top, DOUBLEMASK *bottom, const char *filename )
{
	int newxsize, newysize;
	DOUBLEMASK *mat;
	double *out;

	/* matrices must be same width
	 */
	if( top->xsize != bottom->xsize ) {
		im_error( "im_matcat", "%s", 
			_( "matrices must be same width" ) );
		return( NULL );
	}

	newxsize = top->xsize;
	newysize = top->ysize + bottom->ysize;

	/* Allocate output matrix.
	 */
	if( !(mat = im_create_dmask( filename, newxsize, newysize )) ) 
		return( NULL );

	/* copy first matrix then add second on the end
	 */
	memcpy( mat->coeff, top->coeff, 
		top->xsize * top->ysize * sizeof( double ) );
	out = mat->coeff + top->xsize * top->ysize;
	memcpy( out, bottom->coeff, 
		bottom->xsize * bottom->ysize * sizeof( double ) );

	return( mat );
}
