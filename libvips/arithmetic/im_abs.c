/* im_abs()
 *
 * Copyright: 1990, N. Dessipris, based on im_powtra()
 * Author: Nicos Dessipris
 * Written on: 02/05/1990
 * Modified on: 
 * 5/5/93 J.Cupitt
 *	- adapted from im_lintra to work with partial images
 *	- complex and signed support added
 * 30/6/93 JC
 *	- adapted for partial v2
 *	- ANSI conversion
 *	- spe29873r6k3h()**!@lling errors removed
 * 9/2/95 JC
 *	- adapted for im_wrap...
 * 20/6/02 JC
 *	- tiny speed up
 * 8/12/06
 * 	- add liboil support
 * 28/8/09
 * 	- gtkdoc
 * 	- tiny polish
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
#include <vips/internal.h>

#ifdef HAVE_LIBOIL
#include <liboil/liboil.h>
#endif /*HAVE_LIBOIL*/

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* Integer abs operation: just test and negate.
 */
#define intabs(TYPE) { \
	TYPE *p = (TYPE *) in; \
	TYPE *q = (TYPE *) out; \
	int x; \
	\
	for( x = 0; x < sz; x++ ) { \
		TYPE v = p[x]; \
		\
		if( v < 0 ) \
			q[x] = 0 - v; \
		else \
			q[x] = v; \
	} \
}

/* Float abs operation: call fabs().
 */
#define floatabs(TYPE) { \
	TYPE *p = (TYPE *) in; \
	TYPE *q = (TYPE *) out; \
	int x; \
	\
	for( x = 0; x < sz; x++ ) \
		q[x] = fabs( p[x] ); \
}

/* Complex abs operation: calculate modulus.
 */

#ifdef HAVE_HYPOT

#define complexabs(TYPE) { \
	TYPE *p = (TYPE *) in; \
	TYPE *q = (TYPE *) out; \
	int x; \
	\
	for( x = 0; x < sz; x++ ) { \
		q[x] = hypot( p[0], p[1] ); \
		p += 2; \
	} \
}

#else /*HAVE_HYPOT*/

#define complexabs(TYPE) { \
	TYPE *p = (TYPE *) in; \
	TYPE *q = (TYPE *) out; \
	int x; \
	\
	for( x = 0; x < sz; x++ ) { \
		double rp = p[0]; \
		double ip = p[1]; \
		double abs_rp = fabs( rp ); \
		double abs_ip = fabs( ip ); \
		\
		if( abs_rp > abs_ip ) { \
			double temp = ip / rp; \
			\
			q[x]= abs_rp * sqrt( 1.0 + temp * temp ); \
		} \
		else { \
			double temp = rp / ip; \
			\
			q[x]= abs_ip * sqrt( 1.0 + temp * temp ); \
		} \
		\
		p += 2; \
	} \
}

#endif /*HAVE_HYPOT*/

/* Abs a buffer of PELs.
 */
static void
abs_gen( PEL *in, PEL *out, int width, IMAGE *im )
{
	int sz = width * im->Bands;

	/* Abs all input types.
         */
        switch( im->BandFmt ) {
        case IM_BANDFMT_CHAR: 		
#ifdef HAVE_LIBOIL
		oil_abs_u8_s8( (uint8_t *) out, sizeof( uint8_t ), 
			(int8_t *) in, sizeof( int8_t ), sz );
#else /*!HAVE_LIBOIL*/
		intabs( signed char ); 
#endif /*HAVE_LIBOIL*/
		break; 

        case IM_BANDFMT_SHORT: 		
#ifdef HAVE_LIBOIL
		oil_abs_u16_s16( (uint16_t *) out, sizeof( uint16_t ), 
			(int16_t *) in, sizeof( int16_t ), sz );
#else /*!HAVE_LIBOIL*/
		intabs( signed short ); 
#endif /*HAVE_LIBOIL*/
		break; 

        case IM_BANDFMT_INT: 
#ifdef HAVE_LIBOIL
		oil_abs_u32_s32( (uint32_t *) out, sizeof( uint32_t ), 
			(int32_t *) in, sizeof( int32_t ), sz );
#else /*!HAVE_LIBOIL*/
		intabs( signed int ); 
#endif /*HAVE_LIBOIL*/
		break; 

        case IM_BANDFMT_FLOAT: 
#ifdef HAVE_LIBOIL
		oil_abs_f32_f32( (float *) out, sizeof( float ), 
			(float *) in, sizeof( float ), sz );
#else /*!HAVE_LIBOIL*/
		floatabs( float ); 
#endif /*HAVE_LIBOIL*/
		break; 

        case IM_BANDFMT_DOUBLE:		
#ifdef HAVE_LIBOIL
		oil_abs_f64_f64( (double *) out, sizeof( double ), 
			(double *) in, sizeof( double ), sz );
#else /*!HAVE_LIBOIL*/
		floatabs( float ); 
#endif /*HAVE_LIBOIL*/
		break; 

        case IM_BANDFMT_COMPLEX:	complexabs( float ); break;
        case IM_BANDFMT_DPCOMPLEX:	complexabs( double ); break;

        default:
		assert( 0 );
        }
}

/** 
 * im_abs:
 * @in: input #IMAGE
 * @out: output #IMAGE
 *
 * This operation finds the absolute value of an image. It does a copy for 
 * unsigned integer types, negate for negative values in 
 * signed integer types, <function>fabs(3)</function> for 
 * float types, and calculate modulus for complex 
 * types. 
 *
 * See also: im_exp10tra(), im_sign().
 *
 * Returns: 0 on success, -1 on error
 */
int 
im_abs( IMAGE *in, IMAGE *out )
{	
	if( im_check_uncoded( "im_abs", in ) ) 
		return( -1 );

	/* Is this one of the unsigned types? Degenerate to im_copy() if it
	 * is.
	 */
	if( im_isuint( in ) )
		return( im_copy( in, out ) );

	/* Prepare output header. Output type == input type, except for
	 * complex.
	 */
	if( im_cp_desc( out, in ) )
		return( -1 );
	switch( in->BandFmt ) {
                case IM_BANDFMT_CHAR:
                case IM_BANDFMT_SHORT:
                case IM_BANDFMT_INT:
		case IM_BANDFMT_FLOAT:
		case IM_BANDFMT_DOUBLE:
			/* No action.
			 */
			break;

		case IM_BANDFMT_COMPLEX:
			out->Bbits = IM_BBITS_FLOAT;
			out->BandFmt = IM_BANDFMT_FLOAT;
			break;

		case IM_BANDFMT_DPCOMPLEX:
			out->Bbits = IM_BBITS_DOUBLE;
			out->BandFmt = IM_BANDFMT_DOUBLE;
			break;

		default:
			im_error( "im_abs", "%s", _( "unknown input type" ) );
                        return( -1 );
	}

	/* Generate!
	 */
	if( im_wrapone( in, out, 
		(im_wrapone_fn) abs_gen, in, NULL ) )
		return( -1 );

	return( 0 );
}
