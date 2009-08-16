/* @(#) combine two masks. Result mask is made and returned. 
 * @(#) Pass in the name to set in the creation of the mask.
 * @(#) DOUBLEMASK *
 * @(#) im_matcat( in1, in2, name );
 * @(#) DOUBLEMASK *in1, *in2;
 * @(#) char *name;
 * @(#)  
 * @(#) return NULL for error.
 *
 * 1994, K. Martinez
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

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* MATRIX concatenate (join columns ie add mask to bottom of another)
 */
DOUBLEMASK *
im_matcat( DOUBLEMASK *in1, DOUBLEMASK *in2, const char *name )
{
	int newxsize, newysize;
	DOUBLEMASK *mat;
	double *out;
	
	/* matrices must be same width
	 */
	if( in1->xsize != in2->xsize ) {
		im_errormsg( "im_matcat: matrices must be same width" );
		return( NULL );
	}

	newxsize = in1->xsize;
	newysize = in1->ysize + in2->ysize;

	/* Allocate output matrix.
	 */
	if( !(mat = im_create_dmask( name, newxsize, newysize )) ) {
		im_errormsg( "im_matcat: unable to allocate output matrix" );
		return( NULL );
	}

	/* copy first matrix then add second on the end
	 */
	memcpy( mat->coeff, in1->coeff, 
		in1->xsize * in1->ysize * sizeof( double ) );
	out = mat->coeff + in1->xsize * in1->ysize;
	memcpy( out, in2->coeff, 
		in2->xsize * in2->ysize * sizeof( double ) );

	return( mat );
}
