/* @(#)  Functions which transforms the real and the imaginary parts of
 * @(#) a complex image into amplitude and phase.
 * @(#) Input image is either memory mapped or in a buffer.
 * @(#) Used to display an inverse complex Fourier transform
 * @(#)
 * @(#) int im_c2amph(in, out)
 * @(#) IMAGE *in, *out;
 * @(#)
 * @(#) All functions return 0 on success and -1 on error
 * @(#)
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

#define loop(TYPE) \
{\
	TYPE *p = (TYPE *) in;\
	TYPE *q = (TYPE *) out;\
	int x;\
	\
	for( x = 0; x < n; x++ ) {\
		double re = p[0];\
		double im = p[1];\
		double am, ph;\
		\
		am = sqrt( re * re + im * im );\
		\
		if( re == 0 ) { \
			if( im < 0.0 ) \
				ph = 270; \
			else if( im == 0.0 ) \
				ph = 0; \
			else \
				ph = 90; \
		} \
		else { \
			double t = atan( im / re ); \
 			\
			if( re > 0.0 ) \
				if( im < 0.0 ) \
					ph = IM_DEG( t + IM_PI * 2.0 ); \
				else \
					ph = IM_DEG( t ); \
			else \
				ph = IM_DEG( t + IM_PI ); \
		} \
 		\
		q[0] = am; \
		q[1] = ph; \
 		\
		p += 2; \
		q += 2; \
	}\
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
			error_exit( "buffer_c2amph: internal error" );	
	}
}

int 
im_c2amph( IMAGE *in, IMAGE *out )
{
	if( in->Coding != IM_CODING_NONE || 
		!vips_bandfmt_iscomplex( in->BandFmt ) ) {
		im_error( "im_c2amph", "%s", 
			_( "input should be uncoded complex" ) );
		return( -1 );
	}
        if( im_cp_desc( out, in ) )
                return( -1 );

        /* Do the processing.
         */
        if( im_wrapone( in, out,
                (im_wrapone_fn) buffer_c2amph, in, NULL ) )
                return( -1 );

	return( 0 );
}
