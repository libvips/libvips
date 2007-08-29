/* @(#) Find the unit vector in the direction of the pixel.
 * @(#)
 * @(#) int im_sign(in, out)
 * @(#) IMAGE *in, *out;
 * @(#)
 * @(#) Returns 0 on success and -1 on error
 * @(#)
 *
 * 9/7/02 JC
 *	- from im_cmulnorm
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

#define sign_complex( IN, OUT ) \
{ \
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

#define sign( IN, OUT ) \
{ \
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
buffer_sign( void *in, void *out, int w, IMAGE *im )
{
	int n = w * im->Bands;

	switch( im->BandFmt ) {
        case IM_BANDFMT_UCHAR: 	
		sign( unsigned char, signed char ); 
		break;
        case IM_BANDFMT_CHAR: 		
		sign( signed char, signed char ); 
		break; 
        case IM_BANDFMT_USHORT: 	
		sign( unsigned short, signed char ); 
		break; 
        case IM_BANDFMT_SHORT: 		
		sign( signed short, signed char ); 
		break; 
        case IM_BANDFMT_UINT: 		
		sign( unsigned int, signed char ); 
		break; 
        case IM_BANDFMT_INT: 		
		sign( signed int, signed char );  
		break; 
        case IM_BANDFMT_FLOAT: 		
		sign( float, signed char ); 
		break; 
        case IM_BANDFMT_DOUBLE:		
		sign( double, signed char ); 
		break; 
	case IM_BANDFMT_COMPLEX:        
		sign_complex( float, float ); 
		break;
	case IM_BANDFMT_DPCOMPLEX:      
		sign_complex( double, double ); 
		break; 
	default:
		assert( 0 );
	}
}

int 
im_sign( IMAGE *in, IMAGE *out )
{
	if( in->Coding != IM_CODING_NONE ) {
		im_error( "im_sign", _( "not uncoded" ) );
		return( -1 );
	}
        if( im_cp_desc( out, in ) )
                return( -1 );
	if( !im_iscomplex( in ) ) {
		out->Bbits = IM_BBITS_BYTE;
		out->BandFmt = IM_BANDFMT_CHAR;
	}

        /* Do the processing.
         */
        if( im_wrapone( in, out, (im_wrapone_fn) buffer_sign, in, NULL ) )
                return( -1 );

	return( 0 );
}
