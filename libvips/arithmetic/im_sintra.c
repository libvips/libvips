/* im_sintra.c
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
 *	- im_logtra() adapted to make im_sintra()
 *	- adapted for im_wrapone()
 * 26/1/96 JC
 *	- im_asintra() added
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
#define SIN( IN, OUT ) { \
	IN *p = (IN *) in; \
	OUT *q = (OUT *) out; \
	\
	for( x = 0; x < sz; x++ ) \
		q[x] = sin( IM_RAD( (double) p[x] ) ); \
}

/* sin() a buffer of PELs.
 */
static void
sintra_gen( PEL *in, PEL *out, int width, IMAGE *im )
{	
	const int sz = width * im->Bands;

	int x;

	/* Switch for all input types.
         */
        switch( im->BandFmt ) {
        case IM_BANDFMT_UCHAR: 	SIN( unsigned char, float ); break; 
        case IM_BANDFMT_CHAR: 	SIN( signed char, float ); break; 
        case IM_BANDFMT_USHORT: SIN( unsigned short, float ); break; 
        case IM_BANDFMT_SHORT: 	SIN( signed short, float ); break; 
        case IM_BANDFMT_UINT: 	SIN( unsigned int, float ); break; 
        case IM_BANDFMT_INT: 	SIN( signed int, float );  break; 
        case IM_BANDFMT_FLOAT: 	SIN( float, float ); break; 
        case IM_BANDFMT_DOUBLE:	SIN( double, double ); break; 

        default:
		g_assert( 0 );
        }
}

/**
 * im_sintra
 * @in: input #IMAGE
 * @out: output #IMAGE
 *
 * For each pixel, call <function>sin(3)</function> (sine). Angles are 
 * expressed in degrees. The output type is float, unless the input is 
 * double, in which case the output is double.  Non-complex images only.
 *
 * See also: im_asintra(), im_costra(), im_tantra().
 *
 * Returns: 0 on success, -1 on error
 */
int 
im_sintra( IMAGE *in, IMAGE *out )
{
	return( im__math( "im_sintra", in, out, (im_wrapone_fn) sintra_gen ) );
}

/* And asin().
 */
#define ASIN( IN, OUT ) { \
	IN *p = (IN *) in; \
	OUT *q = (OUT *) out; \
	\
	for( x = 0; x < sz; x++ ) \
		q[x] = IM_DEG( asin( (double) p[x] ) ); \
}

/* asin a buffer of PELs.
 */
static void
asintra_gen( PEL *in, PEL *out, int width, IMAGE *im )
{	
	const int sz = width * im->Bands;

	int x;

	/* Switch for all input types.
         */
        switch( im->BandFmt ) {
        case IM_BANDFMT_UCHAR: 	ASIN( unsigned char, float ); break; 
        case IM_BANDFMT_CHAR: 	ASIN( signed char, float ); break; 
        case IM_BANDFMT_USHORT: ASIN( unsigned short, float ); break; 
        case IM_BANDFMT_SHORT: 	ASIN( signed short, float ); break; 
        case IM_BANDFMT_UINT: 	ASIN( unsigned int, float ); break; 
        case IM_BANDFMT_INT: 	ASIN( signed int, float );  break; 
        case IM_BANDFMT_FLOAT: 	ASIN( float, float ); break; 
        case IM_BANDFMT_DOUBLE:	ASIN( double, double ); break; 

        default:
		g_assert( 0 );
        }
}

/**
 * im_asintra
 * @in: input #IMAGE
 * @out: output #IMAGE
 *
 * For each pixel, call <function>asin(3)</function> (arc, or inverse sine). 
 * Angles are 
 * expressed in degrees. The output type is float, unless the input is 
 * double, in which case the output is double.  Non-complex images only.
 *
 * See also: im_asintra(), im_costra(), im_tantra().
 *
 * Returns: 0 on success, -1 on error
 */
int 
im_asintra( IMAGE *in, IMAGE *out )
{
	return( im__math( "im_asintra", in, out, 
		(im_wrapone_fn) asintra_gen ) );
}
