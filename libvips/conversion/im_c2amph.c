/* im_c2amph.c ... convert to polar
 *
 * Copyright: 1990, N. Dessipris.
 *
 * Author: Nicos Dessipris
 * Written on: 12/02/1990
 * Modified on : 09/05/1990
 * 15/6/93 JC
 *	- stupid stupid includes and externs fixed
 *	- I have been editing for 1 1/2 hours and I'm still drowning in
 *	  rubbish extetrnshh
 * 13/12/94 JC
 *	- modernised
 * 9/7/02 JC
 *	- degree output, for consistency
 *	- slightly better behaviour in edge cases
 * 27/1/10
 * 	- modernised
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
#include <stdlib.h>
#include <math.h>

#include <vips/vips.h>

#define loop(TYPE) { \
	TYPE *p = (TYPE *) in; \
	TYPE *q = (TYPE *) out; \
	int x; \
	\
	for( x = 0; x < n; x++ ) { \
		double re = p[0]; \
		double im = p[1]; \
		double am, ph; \
		\
		am = sqrt( re * re + im * im ); \
		ph = im_col_ab2h( re, im ); \
		\
		q[0] = am; \
		q[1] = ph; \
 		\
		p += 2; \
		q += 2; \
	} \
}

/* c2amph buffer processor.
 */
static void
buffer_c2amph( void *in, void *out, int w, IMAGE *im )
{
	int n = w * im->Bands;

	switch( im->BandFmt ) {
		case IM_BANDFMT_DPCOMPLEX:      loop(double); break; 
		case IM_BANDFMT_COMPLEX:        loop(float); break;
		default:
			g_assert( 0 );
	}
}

/**
 * im_c2amph:
 * @in: input image
 * @out: output image
 *
 * Convert a complex image from rectangular to polar coordinates. Angles are
 * expressed in degrees.
 *
 * See also: im_c2rect(), im_abs().
 *
 * Returns: 0 on success, -1 on error
 */
int 
im_c2amph( IMAGE *in, IMAGE *out )
{
	if( im_check_uncoded( "im_c2amph", in ) ||
		im_check_complex( "im_c2amph", in ) ||
		im_cp_desc( out, in ) )
                return( -1 );

        if( im_wrapone( in, out,
                (im_wrapone_fn) buffer_c2amph, in, NULL ) )
                return( -1 );

	return( 0 );
}
