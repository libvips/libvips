/* im_costra
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
 * 30/8/09
 * 	- gtkdoc
 * 	- tiny cleanups
 * 	- make im__math(), share with other math-style functions
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

/* Define what we do for each band element type. Non-complex input, any
 * output.
 */
#define COS( IN, OUT ) { \
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
	const int sz = width * im->Bands;

	int x;

	/* Switch for all input types.
         */
        switch( im->BandFmt ) {
        case IM_BANDFMT_UCHAR: 	COS( unsigned char, float ); break; 
        case IM_BANDFMT_CHAR: 	COS( signed char, float ); break; 
        case IM_BANDFMT_USHORT: COS( unsigned short, float ); break; 
        case IM_BANDFMT_SHORT: 	COS( signed short, float ); break; 
        case IM_BANDFMT_UINT: 	COS( unsigned int, float ); break; 
        case IM_BANDFMT_INT: 	COS( signed int, float );  break; 
        case IM_BANDFMT_FLOAT: 	COS( float, float ); break; 
        case IM_BANDFMT_DOUBLE:	COS( double, double ); break; 

        default:
		g_assert( 0 );
        }
}

/**
 * im_costra
 * @in: input #IMAGE
 * @out: output #IMAGE
 *
 * For each pixel, call <function>cos(3)</function> (cosine). Angles are 
 * expressed in degrees. The output type is float, unless the input is 
 * double, in which case the output is double.  Non-complex images only.
 *
 * See also: im_acostra(), im_sintra(), im_tantra().
 *
 * Returns: 0 on success, -1 on error
 */
int 
im_costra( IMAGE *in, IMAGE *out )
{
	return( im__math( "im_costra", in, out, (im_wrapone_fn) costra_gen ) );
}

/* And acos().
 */
#define ACOS( IN, OUT ) { \
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
	const int sz = width * im->Bands;

	int x;

	/* Switch for all input types.
         */
        switch( im->BandFmt ) {
        case IM_BANDFMT_UCHAR: 	ACOS( unsigned char, float ); break; 
        case IM_BANDFMT_CHAR: 	ACOS( signed char, float ); break; 
        case IM_BANDFMT_USHORT: ACOS( unsigned short, float ); break; 
        case IM_BANDFMT_SHORT: 	ACOS( signed short, float ); break; 
        case IM_BANDFMT_UINT: 	ACOS( unsigned int, float ); break; 
        case IM_BANDFMT_INT: 	ACOS( signed int, float );  break; 
        case IM_BANDFMT_FLOAT: 	ACOS( float, float ); break; 
        case IM_BANDFMT_DOUBLE:	ACOS( double, double ); break; 

        default:
		g_assert( 0 );
        }
}


/**
 * im_acostra
 * @in: input #IMAGE
 * @out: output #IMAGE
 *
 * For each pixel, call <function>acos(3)</function> (arc or inverse cosine). 
 * Angles are expressed in
 * degrees. The output type is float, unless the input is double, in which 
 * case the output is double.  Non-complex images only.
 *
 * See also: im_costra(), im_asintra(), im_atantra().
 *
 * Returns: 0 on success, -1 on error
 */
int 
im_acostra( IMAGE *in, IMAGE *out )
{
	return( im__math( "im_acostra", in, out, 
		(im_wrapone_fn) acostra_gen ) );
}
