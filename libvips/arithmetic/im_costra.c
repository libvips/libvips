/* @(#) Find cos of any non-complex image. Output is always float for integer 
 * @(#) input and double for double input. All angles in degrees.
 * @(#)
 * @(#) int 
 * @(#) im_costra( in, out )
 * @(#) IMAGE *in, *out;
 * @(#)
 * @(#) Returns 0 on success and -1 on error
 * @(#)
 *
 * Copyright: 1990, N. Dessipris, based on im_powtra()
 * Author: Nicos Dessipris
 * Written on: 02/05/1990
 * Modified on: 
 * 5/5/93 JC
 *	- adapted from im_lintra to work with partial images
 *	- incorrect implementation of complex logs removed
 * 1/7/93 JC
 *	- adapted for partial v2
 *	- ANSIfied
 * 24/2/95 JC
 *	- im_logtra() adapted to make im_costra()
 *	- adapted for im_wrapone()
 * 26/1/96 JC
 *	- im_acostra() added
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

/* Define what we do for each band element type. Non-complex input, any
 * output.
 */
#define loop( IN, OUT ) { \
	IN *p = (IN *) in; \
	OUT *q = (OUT *) out; \
	\
	for( x = 0; x < sz; x++ ) \
		q[x] = cos( IM_RAD( (double) p[x] ) ); \
}

/* cos a buffer of PELs.
 */
static void
costra_gen( PEL *in, PEL *out, int width, IMAGE *im )
{	
	int x;
	int sz = width * im->Bands;

	/* Switch for all input types.
         */
        switch( im->BandFmt ) {
        case IM_BANDFMT_UCHAR: 	loop( unsigned char, float ); break; 
        case IM_BANDFMT_CHAR: 	loop( signed char, float ); break; 
        case IM_BANDFMT_USHORT: loop( unsigned short, float ); break; 
        case IM_BANDFMT_SHORT: 	loop( signed short, float ); break; 
        case IM_BANDFMT_UINT: 	loop( unsigned int, float ); break; 
        case IM_BANDFMT_INT: 	loop( signed int, float );  break; 
        case IM_BANDFMT_FLOAT: 	loop( float, float ); break; 
        case IM_BANDFMT_DOUBLE:	loop( double, double ); break; 

        default:
		assert( 0 );
        }
}

/* Cos transform.
 */
int 
im_costra( IMAGE *in, IMAGE *out )
{	
	if( im_piocheck( in, out ) ||
		im_check_uncoded( "im_costra", in ) ||
		im_check_noncomplex( "im_costra", in ) )
		return( -1 );

	/* Prepare output header.
	 */
	if( im_cp_desc( out, in ) )
		return( -1 );
	switch( in->BandFmt ) {
		case IM_BANDFMT_UCHAR:
                case IM_BANDFMT_CHAR:
                case IM_BANDFMT_USHORT:
                case IM_BANDFMT_SHORT:
                case IM_BANDFMT_UINT:
                case IM_BANDFMT_INT:
			out->Bbits = IM_BBITS_FLOAT;
			out->BandFmt = IM_BANDFMT_FLOAT;
			break;

		case IM_BANDFMT_FLOAT:
		case IM_BANDFMT_DOUBLE:
			break;

		default:
			assert( 0 );
	}

	/* Generate!
	 */
	if( im_wrapone( in, out, (im_wrapone_fn) costra_gen, in, NULL ) )
		return( -1 );

	return( 0 );
}

/* And acos().
 */
#define aloop( IN, OUT ) { \
	IN *p = (IN *) in; \
	OUT *q = (OUT *) out; \
	\
	for( x = 0; x < sz; x++ ) \
		q[x] = IM_DEG( acos( (double) p[x] ) ); \
}

/* acos a buffer of PELs.
 */
static void
acostra_gen( PEL *in, PEL *out, int width, IMAGE *im )
{	
	int x;
	int sz = width * im->Bands;

	/* Switch for all input types.
         */
        switch( im->BandFmt ) {
        case IM_BANDFMT_UCHAR: 	aloop( unsigned char, float ); break; 
        case IM_BANDFMT_CHAR: 	aloop( signed char, float ); break; 
        case IM_BANDFMT_USHORT: aloop( unsigned short, float ); break; 
        case IM_BANDFMT_SHORT: 	aloop( signed short, float ); break; 
        case IM_BANDFMT_UINT: 	aloop( unsigned int, float ); break; 
        case IM_BANDFMT_INT: 	aloop( signed int, float );  break; 
        case IM_BANDFMT_FLOAT: 	aloop( float, float ); break; 
        case IM_BANDFMT_DOUBLE:	aloop( double, double ); break; 

        default:
		assert( 0 );
        }
}

/* Acos transform.
 */
int 
im_acostra( IMAGE *in, IMAGE *out )
{
	if( im_piocheck( in, out ) ||
		im_check_uncoded( "im_acostra", in ) ||
		im_check_noncomplex( "im_acostra", in ) )
		return( -1 );

	/* Prepare output header.
	 */
	if( im_cp_desc( out, in ) )
		return( -1 );
	switch( in->BandFmt ) {
		case IM_BANDFMT_UCHAR:
                case IM_BANDFMT_CHAR:
                case IM_BANDFMT_USHORT:
                case IM_BANDFMT_SHORT:
                case IM_BANDFMT_UINT:
                case IM_BANDFMT_INT:
			out->Bbits = IM_BBITS_FLOAT;
			out->BandFmt = IM_BANDFMT_FLOAT;
			break;

		case IM_BANDFMT_FLOAT:
		case IM_BANDFMT_DOUBLE:
			break;

		default:
			assert( 0 );
	}

	/* Generate!
	 */
	if( im_wrapone( in, out, (im_wrapone_fn) acostra_gen, in, NULL ) )
		return( -1 );

	return( 0 );
}
