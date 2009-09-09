/* im_sign.c
 *
 * 9/7/02 JC
 *	- from im_cmulnorm
 * 9/9/09
 * 	- gtkdoc, tidies
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
#include <assert.h>

#include <vips/vips.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

#define CSIGN( IN, OUT ) { \
	IN *p = (IN *) in; \
	OUT *q = (OUT *) out; \
	int x; \
	\
	for( x = 0; x < n; x++ ) { \
		IN re = p[0]; \
		IN im = p[1]; \
		double fac = sqrt( re * re + im * im ); \
		\
		p += 2; \
		\
		if( fac == 0.0 ) { \
			q[0] = 0.0; \
			q[1] = 0.0; \
		} \
		else { \
			q[0] = re / fac; \
			q[1] = im / fac; \
		} \
		\
		q += 2; \
	} \
}

#define SIGN( IN, OUT ) { \
	IN *p = (IN *) in; \
	OUT *q = (OUT *) out; \
	int x; \
	\
	for( x = 0; x < n; x++ ) { \
		IN v = p[x]; \
 		\
		if( v > 0 ) \
			q[x] = 1; \
		else if( v == 0 ) \
			q[x] = 0; \
		else \
			q[x] = -1; \
	} \
}

/* sign buffer processor.
 */
static void
sign_gen( void *in, void *out, int w, IMAGE *im )
{
	int n = w * im->Bands;

	switch( im->BandFmt ) {
        case IM_BANDFMT_UCHAR: 	SIGN( unsigned char, signed char ); break;
        case IM_BANDFMT_CHAR: 	SIGN( signed char, signed char ); break; 
        case IM_BANDFMT_USHORT: SIGN( unsigned short, signed char ); break; 
        case IM_BANDFMT_SHORT: 	SIGN( signed short, signed char ); break; 
        case IM_BANDFMT_UINT: 	SIGN( unsigned int, signed char ); break; 
        case IM_BANDFMT_INT: 	SIGN( signed int, signed char );  break; 
        case IM_BANDFMT_FLOAT: 	SIGN( float, signed char ); break; 
        case IM_BANDFMT_DOUBLE:	SIGN( double, signed char ); break; 
	case IM_BANDFMT_COMPLEX:	CSIGN( float, float ); break;
	case IM_BANDFMT_DPCOMPLEX:	CSIGN( double, double ); break; 

	default:
		g_assert( 0 );
	}
}

/**
 * im_sign:
 * @in: input image
 * @out: output image
 *
 * Finds the unit vector in the direction of the pixel value. For non-complex
 * images, it returns a signed char image with values -1, 0, and 1 for negative,
 * zero and positive pixels. For complex images, it returns a
 * complex normalised to length 1.
 *
 * See also: im_abs(), im_cmulnorm(), im_c2amph().
 *
 * Returns: 0 on success, -1 on error
 */
int 
im_sign( IMAGE *in, IMAGE *out )
{
	if( im_piocheck( in, out ) ||
		im_check_uncoded( "im_sign", in ) || 
		im_cp_desc( out, in ) )
                return( -1 );

	if( !im_iscomplex( in ) ) {
		out->Bbits = IM_BBITS_BYTE;
		out->BandFmt = IM_BANDFMT_CHAR;
	}

        if( im_wrapone( in, out, (im_wrapone_fn) sign_gen, in, NULL ) )
                return( -1 );

	return( 0 );
}
