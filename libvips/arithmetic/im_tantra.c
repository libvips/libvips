/* @(#) Find tan of any non-complex image. Output is always float for integer 
 * @(#) input and double for double input. All angles in degrees.
 * @(#)
 * @(#) int 
 * @(#) im_tantra( in, out )
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
 *	- im_logtra() adapted to make im_tantra()
 *	- adapted for im_wrapone()
 * 26/1/96 JC
 * 	- atan() added
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
#define TAN( IN, OUT ) { \
	IN *p = (IN *) in; \
	OUT *q = (OUT *) out; \
	\
	for( x = 0; x < sz; x++ ) \
		q[x] = tan( IM_RAD( (double) p[x] ) ); \
}

/* tan a buffer of PELs.
 */
static void
tantra_gen( PEL *in, PEL *out, int width, IMAGE *im )
{	
	const int sz = width * im->Bands;

	int x;

	/* Switch for all input types.
         */
        switch( im->BandFmt ) {
        case IM_BANDFMT_UCHAR: 	TAN( unsigned char, float ); break; 
        case IM_BANDFMT_CHAR: 	TAN( signed char, float ); break; 
        case IM_BANDFMT_USHORT: TAN( unsigned short, float ); break; 
        case IM_BANDFMT_SHORT: 	TAN( signed short, float ); break; 
        case IM_BANDFMT_UINT: 	TAN( unsigned int, float ); break; 
        case IM_BANDFMT_INT: 	TAN( signed int, float );  break; 
        case IM_BANDFMT_FLOAT: 	TAN( float, float ); break; 
        case IM_BANDFMT_DOUBLE:	TAN( double, double ); break; 

        default:
		g_assert( 0 );
        }
}

/**
 * im_tantra
 * @in: input #IMAGE
 * @out: output #IMAGE
 *
 * For each pixel, call <function>tan(3)</function> (tangent). Angles are 
 * expressed in degrees. The output type is float, unless the input is 
 * double, in which case the output is double.  Non-complex images only.
 *
 * See also: im_atantra(), im_sintra().
 *
 * Returns: 0 on success, -1 on error
 */
int 
im_tantra( IMAGE *in, IMAGE *out )
{
	return( im__math( "im_tantra", in, out, (im_wrapone_fn) tantra_gen ) );
}

/* Define what we do for each band element type. Non-complex input, any
 * output.
 */
#define ATAN( IN, OUT ) { \
	IN *p = (IN *) in; \
	OUT *q = (OUT *) out; \
	\
	for( x = 0; x < sz; x++ ) \
		q[x] = IM_DEG( atan( (double) p[x] ) ); \
}

/* atan a buffer of PELs.
 */
static void
atantra_gen( PEL *in, PEL *out, int width, IMAGE *im )
{	
	const int sz = width * im->Bands;

	int x;

	/* Switch for all input types.
         */
        switch( im->BandFmt ) {
        case IM_BANDFMT_UCHAR: 	ATAN( unsigned char, float ); break; 
        case IM_BANDFMT_CHAR: 	ATAN( signed char, float ); break; 
        case IM_BANDFMT_USHORT: ATAN( unsigned short, float ); break; 
        case IM_BANDFMT_SHORT: 	ATAN( signed short, float ); break; 
        case IM_BANDFMT_UINT: 	ATAN( unsigned int, float ); break; 
        case IM_BANDFMT_INT: 	ATAN( signed int, float );  break; 
        case IM_BANDFMT_FLOAT: 	ATAN( float, float ); break; 
        case IM_BANDFMT_DOUBLE:	ATAN( double, double ); break; 

        default:
		g_assert( 0 );
        }
}

/**
 * im_atantra
 * @in: input #IMAGE
 * @out: output #IMAGE
 *
 * For each pixel, call <function>atan(3)</function> (arc or inverse tangent). 
 * Angles are 
 * expressed in degrees. The output type is float, unless the input is 
 * double, in which case the output is double.  Non-complex images only.
 *
 * See also: im_tantra(), im_sintra().
 *
 * Returns: 0 on success, -1 on error
 */
int 
im_atantra( IMAGE *in, IMAGE *out )
{
	return( im__math( "im_atantra", in, out, 
		(im_wrapone_fn) atantra_gen ) );
}

