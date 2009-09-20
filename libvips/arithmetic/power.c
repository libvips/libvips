/* power.c --- various power functions
 *
 * Copyright: 1990, N. Dessipris
 *
 * Author: Nicos Dessipris
 * Written on: 02/05/1990
 * Modified on: 
 * 10/12/93 JC
 *	- now reports total number of x/0, rather than each one.
 * 1/2/95 JC
 *	- rewritten for PIO with im_wrapone()
 *	- incorrect complex code removed
 *	- /0 reporting removed for ease of programming
 * 15/4/97 JC
 *	- return( 0 ) missing, oops!
 * 6/7/98 JC
 *	- _vec form added
 * 30/8/09
 * 	- gtkdoc
 * 	- tiny cleanups
 * 20/9/09
 * 	- im_powtra() adapated to make power.c
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
#include <math.h>

#include <vips/vips.h>
#include <vips/internal.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* Operator with a single constant.
 */
#define CONST1( IN, OUT, FUN ) { \
	OUT *tq = (OUT *) q; \
	OUT tc = *((OUT *) vector); \
	IN *tp = (IN *) p; \
 	\
	for( i = 0; i < ne; i++ ) \
		 FUN( tq[i], tp[i], tc ); \
}

/* Operator with a single constant on a buffer.
 */
#define CONST1_BUFFER( FUN ) \
static void \
FUN ## 1_buffer( PEL *p, PEL *q, int n, PEL *vector, IMAGE *im ) \
{ \
	/* Complex just doubles the size. \
	 */ \
	const int ne = n * im->Bands * (im_iscomplex( im ) ? 2 : 1); \
	\
	int i; \
	\
        switch( im->BandFmt ) { \
        case IM_BANDFMT_CHAR: \
		CONST1( signed char, float, FUN ); break; \
        case IM_BANDFMT_UCHAR:  \
		CONST1( unsigned char, float, FUN ); break; \
        case IM_BANDFMT_SHORT:  \
		CONST1( signed short, float, FUN ); break; \
        case IM_BANDFMT_USHORT: \
		CONST1( unsigned short, float, FUN ); break; \
        case IM_BANDFMT_INT: \
		CONST1( signed int, float, FUN ); break; \
        case IM_BANDFMT_UINT: \
		CONST1( unsigned int, float, FUN ); break; \
        case IM_BANDFMT_FLOAT: \
		CONST1( float, float, FUN ); break; \
        case IM_BANDFMT_COMPLEX: \
		CONST1( float, float, FUN ); break; \
        case IM_BANDFMT_DOUBLE: \
		CONST1( double, double, FUN ); break; \
        case IM_BANDFMT_DPCOMPLEX: \
		CONST1( double, double, FUN ); break; \
	\
        default: \
                g_assert( 0 ); \
        } \
}

/* Operator with one constant per band.
 */
#define CONSTN( IN, OUT, FUN ) { \
	OUT *tq = (OUT *) q; \
	IN *tp = (IN *) p; \
	OUT *tc = (OUT *) vector; \
 	\
	for( i = 0, x = 0; x < n; x++ ) \
		for( b = 0; b < bands; b++, i++ ) \
			FUN( tq[i], tp[i], tc[b] ); \
}

/* Operator with one constant per band on a buffer.
 */
#define CONSTN_BUFFER( FUN ) \
static void \
FUN ## n_buffer( PEL *p, PEL *q, int n, PEL *vector, IMAGE *im ) \
{ \
	const int bands = im->Bands; \
	\
	int i, x, b; \
	\
        switch( im->BandFmt ) { \
        case IM_BANDFMT_CHAR: \
		CONSTN( signed char, float, FUN ); break; \
        case IM_BANDFMT_UCHAR:  \
		CONSTN( unsigned char, float, FUN ); break; \
        case IM_BANDFMT_SHORT:  \
		CONSTN( signed short, float, FUN ); break; \
        case IM_BANDFMT_USHORT: \
		CONSTN( unsigned short, float, FUN ); break; \
        case IM_BANDFMT_INT: \
		CONSTN( signed int, float, FUN ); break; \
        case IM_BANDFMT_UINT: \
		CONSTN( unsigned int, float, FUN ); break; \
        case IM_BANDFMT_FLOAT: \
		CONSTN( float, float, FUN ); break; \
        case IM_BANDFMT_COMPLEX: \
		CONSTN( float, float, FUN ); break; \
        case IM_BANDFMT_DOUBLE: \
		CONSTN( double, double, FUN ); break; \
        case IM_BANDFMT_DPCOMPLEX: \
		CONSTN( double, double, FUN ); break; \
	\
        default: \
                g_assert( 0 ); \
        } \
}

#define POW( Y, X, E ) { \
	double x = (double) (X); \
	double e = (double) (E); \
	\
	if( x == 0.0 && e < 0.0 ) \
		/* Division by zero! Difficult to report tho' \
		 */ \
		(Y) = 0.0; \
	else \
		(Y) = pow( x, e ); \
}

CONST1_BUFFER( POW )

CONSTN_BUFFER( POW )

/* Save a bit of typing.
 */
#define F IM_BANDFMT_FLOAT
#define X IM_BANDFMT_COMPLEX
#define D IM_BANDFMT_DOUBLE
#define DX IM_BANDFMT_DPCOMPLEX

/* Type conversions for boolean. 
 */
static int bandfmt_power[10] = {
/* UC  C   US  S   UI  I   F   X   D   DX */
   F,  F,  F,  F,  F,  F,  F,  X,  D,  DX,
};

/**
 * im_powtra_vec:
 * @in: input #IMAGE 
 * @out: output #IMAGE
 * @n: number of elements in array
 * @e: array of constants
 *
 * im_powtra_vec() transforms element x of input to 
 * <function>pow</function>(x, @b) in output. 
 * It detects division by zero, setting those pixels to zero in the output. 
 * Beware: it does this silently!
 *
 * If the array of constants has one element, that constant is used for each
 * image band. If the array has more than one element, it must have the same
 * number of elements as there are bands in the image, and one array element
 * is used for each band.
 *
 * See also: im_logtra(), im_expntra_vec()
 *
 * Returns: 0 on success, -1 on error
 */
int 
im_powtra_vec( IMAGE *in, IMAGE *out, int n, double *c )
{
	if( im_check_noncomplex( "im_powtra_vec", in ) )
		return( -1 );

	return( im__arith_binary_const( "im_powtra_vec", 
		in, out, n, c, 
		bandfmt_power,
		(im_wrapone_fn) POW1_buffer, 
		(im_wrapone_fn) POWn_buffer ) );
}

/**
 * im_powtra:
 * @in: input #IMAGE 
 * @out: output #IMAGE
 * @e: exponent
 *
 * im_powtra() transforms element x of input to 
 * <function>pow</function>(x, @e) in output. 
 * It detects division by zero, setting those pixels to zero in the output. 
 * Beware: it does this silently!
 *
 * See also: im_logtra(), im_powntra_vec()
 *
 * Returns: 0 on success, -1 on error
 */
int 
im_powtra( IMAGE *in, IMAGE *out, double e )
{
	return( im_powtra_vec( in, out, 1, &e ) );
}

/* Converse of POW() above.
 */
#define POWC( Y, X, E ) POW( Y, E, X )

CONST1_BUFFER( POWC )

CONSTN_BUFFER( POWC )

/**
 * im_expntra_vec:
 * @in: input #IMAGE 
 * @out: output #IMAGE
 * @n: number of elements in array
 * @e: array of constants
 *
 * im_expntra_vec() transforms element x of input to 
 * <function>pow</function>(@b, x) in output. 
 * It detects division by zero, setting those pixels to zero in the output. 
 * Beware: it does this silently!
 *
 * If the array of constants has one element, that constant is used for each
 * image band. If the array has more than one element, it must have the same
 * number of elements as there are bands in the image, and one array element
 * is used for each band.
 *
 * See also: im_logtra(), im_powtra()
 *
 * Returns: 0 on success, -1 on error
 */
int 
im_expntra_vec( IMAGE *in, IMAGE *out, int n, double *c )
{
	if( im_check_noncomplex( "im_expntra_vec", in ) )
		return( -1 );

	return( im__arith_binary_const( "im_expntra_vec", 
		in, out, n, c, 
		bandfmt_power,
		(im_wrapone_fn) POWC1_buffer, 
		(im_wrapone_fn) POWCn_buffer ) );
}

/**
 * im_expntra:
 * @in: input #IMAGE 
 * @out: output #IMAGE
 * @e: base
 *
 * im_expntra() transforms element x of input to 
 * <function>pow</function>(@e, x) in output. 
 * It detects division by zero, setting those pixels to zero in the output. 
 * Beware: it does this silently!
 *
 * See also: im_logtra(), im_powtra()
 *
 * Returns: 0 on success, -1 on error
 */
int 
im_expntra( IMAGE *in, IMAGE *out, double e )
{
	return( im_expntra_vec( in, out, 1, &e ) );
}

/**
 * im_exptra:
 * @in: input #IMAGE 
 * @out: output #IMAGE
 *
 * im_exptra() transforms element x of input to 
 * <function>pow</function>(e, x) in output. 
 * It detects division by zero, setting those pixels to zero in the output. 
 * Beware: it does this silently!
 *
 * See also: im_logtra(), im_powtra()
 *
 * Returns: 0 on success, -1 on error
 */
int
im_exptra( IMAGE *in, IMAGE *out )
{
	return( im_expntra( in, out, 2.7182818284590452354 ) );
}

/**
 * im_exp10tra:
 * @in: input #IMAGE 
 * @out: output #IMAGE
 *
 * im_exptra() transforms element x of input to 
 * <function>pow</function>(10, x) in output. 
 * It detects division by zero, setting those pixels to zero in the output. 
 * Beware: it does this silently!
 *
 * See also: im_logtra(), im_powtra()
 *
 * Returns: 0 on success, -1 on error
 */
int
im_exp10tra( IMAGE *in, IMAGE *out )
{
	return( im_expntra( in, out, 10.0 ) );
}

