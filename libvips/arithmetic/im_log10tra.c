/* @(#) Find base 10 log of any non-complex image. Output
 * @(#) is always float for integer input and double for double input.
 * @(#)
 * @(#) int 
 * @(#) im_log10tra( in, out )
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
 * 30/8/09
 * 	- gtkdoc
 * 	- tiny cleanups
 * 	- use im__math()
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
#include <vips/internal.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* Define what we do for each band element type. Non-complex input, any
 * output.
 */
#define LOG10( IN, OUT ) { \
	IN *p = (IN *) in; \
	OUT *q = (OUT *) out; \
	\
	for( x = 0; x < sz; x++ ) \
		q[x] = log10( p[x] ); \
}

/* log10() a buffer of PELs.
 */
static void
log10tra_gen( PEL *in, PEL *out, int width, IMAGE *im )
{	
	const int sz = width * im->Bands;

	int x;

	/* Switch for all input types.
         */
        switch( im->BandFmt ) {
        case IM_BANDFMT_UCHAR: 	LOG10( unsigned char, float ); break; 
        case IM_BANDFMT_CHAR: 	LOG10( signed char, float ); break; 
        case IM_BANDFMT_USHORT: LOG10( unsigned short, float ); break; 
        case IM_BANDFMT_SHORT: 	LOG10( signed short, float ); break; 
        case IM_BANDFMT_UINT: 	LOG10( unsigned int, float ); break; 
        case IM_BANDFMT_INT: 	LOG10( signed int, float );  break; 
        case IM_BANDFMT_FLOAT: 	LOG10( float, float ); break; 
        case IM_BANDFMT_DOUBLE:	LOG10( double, double ); break; 

        default:
		g_assert( 0 );
        }
}

/**
 * im_log10tra
 * @in: input #IMAGE
 * @out: output #IMAGE
 *
 * For each pixel, call <function>log10(3)</function> (base 10 logarithm). 
 * The output type is float, unless the input is 
 * double, in which case the output is double.  Non-complex images only.
 *
 * See also: im_exp10tra(), im_logntra(), im_sintra().
 *
 * Returns: 0 on success, -1 on error
 */
int 
im_log10tra( IMAGE *in, IMAGE *out )
{
	return( im__math( "im_log10tra", in, out, 
		(im_wrapone_fn) log10tra_gen ) );
}
