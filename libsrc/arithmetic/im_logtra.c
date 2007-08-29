/* @(#) Find natural log of any non-complex image. Output
 * @(#) is always float for integer input and double for double input.
 * @(#)
 * @(#) int 
 * @(#) im_logtra( in, out )
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
#define loop(IN, OUT)\
	for( y = to; y < bo; y++ ) {\
		IN *p = (IN *) IM_REGION_ADDR( ir, le, y );\
		OUT *q = (OUT *) IM_REGION_ADDR( or, le, y );\
		\
		for( x = 0; x < sz; x++ )\
			*q++ = log( *p++ );\
	}

/* logtra a small area.
 */
static int
logtra_gen( REGION *or, REGION *ir )
{	
	Rect *r = &or->valid;
	int le = r->left;
	int to = r->top;
	int bo = IM_RECT_BOTTOM(r);
	int sz = IM_REGION_N_ELEMENTS( or );
	int x, y;

	/* Ask for input we need.
	 */
	if( im_prepare( ir, r ) )
		return( -1 );

	/* logtra all input types.
         */
        switch( ir->im->BandFmt ) {
        case IM_BANDFMT_UCHAR: 		loop(unsigned char, float); break; 
        case IM_BANDFMT_CHAR: 		loop(signed char, float); break; 
        case IM_BANDFMT_USHORT: 	loop(unsigned short, float); break; 
        case IM_BANDFMT_SHORT: 		loop(signed short, float); break; 
        case IM_BANDFMT_UINT: 		loop(unsigned int, float); break; 
        case IM_BANDFMT_INT: 		loop(signed int, float);  break; 
        case IM_BANDFMT_FLOAT: 		loop(float, float); break; 
        case IM_BANDFMT_DOUBLE:		loop(double, double); break; 

        default:
		assert( 0 );
        }
 
	return( 0 );
}

/* Log transform.
 */
int 
im_logtra( IMAGE *in, IMAGE *out )
{	
	/* Check args.
	 */
        if( im_piocheck( in, out ) )
		return( -1 );
	if( in->Coding != IM_CODING_NONE ) {
		im_error( "im_logtra", _( "not uncoded" ) );
		return( -1 );
	}
	if( im_iscomplex( in ) ) {
		im_error( "im_logtra", _( "not non-complex" ) );
		return( -1 );
	}

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

	/* Set demand hints.
	 */
	if( im_demand_hint( out, IM_THINSTRIP, in, NULL ) )
		 return( -1 );

	/* Generate!
	 */
	if( im_generate( out, 
		im_start_one, logtra_gen, im_stop_one, in, NULL ) )
		return( -1 );

	return( 0 );
}
