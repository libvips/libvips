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

/* Cast a vector of double to a vector of TYPE, clipping to a range.
 */
#define CAST_CLIP( TYPE, N, X ) { \
	TYPE *tq = (TYPE *) q; \
	\
	for( i = 0; i < n; i++ ) \
		tq[i] = (TYPE) IM_CLIP( N, p[i], X ); \
}

/* Cast a vector of double to a vector of TYPE.
 */
#define CAST( TYPE ) { \
	TYPE *tq = (TYPE *) q; \
	\
	for( i = 0; i < n; i++ ) \
		tq[i] = (TYPE) p[i]; \
}

/* Cast a vector of double to a complex vector of TYPE.
 */
#define CASTC( TYPE ) { \
	TYPE *tq = (TYPE *) q; \
	\
	for( i = 0; i < n; i++ ) { \
		tq[0] = (TYPE) p[i]; \
		tq[1] = 0; \
		tq += 2; \
	} \
}

/* Cast a vector of double to a passed format.
 */
static PEL *
make_pixel( IMAGE *out, VipsBandFmt fmt, int n, double *p )
{
	PEL *q;
	int i;

	if( !(q = IM_ARRAY( out, n * (im_bits_of_fmt( fmt ) >> 3), PEL )) )
		return( NULL );

        switch( fmt ) {
        case IM_BANDFMT_CHAR:		
		CAST_CLIP( signed char, SCHAR_MIN, SCHAR_MAX ); 
		break;

        case IM_BANDFMT_UCHAR:  	
		CAST_CLIP( unsigned char, 0, UCHAR_MAX ); 
		break;

        case IM_BANDFMT_SHORT:  	
		CAST_CLIP( signed short, SCHAR_MIN, SCHAR_MAX ); 
		break;

        case IM_BANDFMT_USHORT: 	
		CAST_CLIP( unsigned short, 0, USHRT_MAX ); 
		break;

        case IM_BANDFMT_INT:    	
		CAST_CLIP( signed int, INT_MIN, INT_MAX ); 
		break;

        case IM_BANDFMT_UINT:   	
		CAST_CLIP( unsigned int, 0, UINT_MAX ); 
		break;

        case IM_BANDFMT_FLOAT: 		
		CAST( float ); 
		break; 

        case IM_BANDFMT_DOUBLE:		
		CAST( double ); 
		break;

        case IM_BANDFMT_COMPLEX: 	
		CASTC( float ); 
		break; 

        case IM_BANDFMT_DPCOMPLEX:	
		CASTC( double ); 
		break;

        default:
                g_assert( 0 );
        }

	return( q );
}

int 
im__arith_binary_const( const char *domain,
	IMAGE *in, IMAGE *out, 
	int n, double *c, VipsBandFmt vfmt,
	int format_table[10], 
	im_wrapone_fn fn1, im_wrapone_fn fnn )
{
	PEL *vector;

	if( im_piocheck( in, out ) ||
		im_check_vector( domain, n, in ) ||
		im_check_uncoded( domain, in ) )
		return( -1 );
	if( im_cp_desc( out, in ) )
		return( -1 );
	out->BandFmt = format_table[in->BandFmt];

	/* Some operations need the vector in the input type (eg.
	 * im_equal_vec() where the output type is always uchar and is useless
	 * for comparisons), some need it in the output type (eg.
	 * im_andimage_vec() where we want to get the double to an int so we
	 * can do bitwise-and without having to cast for each pixel), some
	 * need a fixed type (eg. im_powtra_vec(), where we want to keep it as
	 * double).
	 *
	 * Therefore pass in the desired vector type as a param.
	 */
	if( !(vector = make_pixel( out, vfmt, n, c )) )
		return( -1 );

	/* Band-up the input image if we have a >1 vector and
	 * a 1-band image.
	 */
	if( n > 1 && out->Bands == 1 ) {
		IMAGE *t;

		if( !(t = im_open_local( out, domain, "p" )) ||
			im__bandup( domain, in, t, n ) )
			return( -1 );

		in = t;
	}

	if( n == 1 ) {
		if( im_wrapone( in, out, fn1, vector, in ) )
			return( -1 );
	}
	else {
		if( im_wrapone( in, out, fnn, vector, in ) )
			return( -1 );
	}

	return( 0 );
}

/* Operator with a single constant.
 */
#define CONST1( IN, OUT, FUN ) { \
	OUT *tq = (OUT *) q; \
	IN *tp = (IN *) p; \
 	\
	for( i = 0; i < ne; i++ ) \
		 FUN( tq[i], tp[i], c ); \
}

/* Operator with a single constant on a buffer.
 */
#define CONST1_BUFFER( FUN ) \
static void \
FUN ## 1_buffer( PEL *p, PEL *q, int n, double *tc, IMAGE *im ) \
{ \
	/* Complex just doubles the size. \
	 */ \
	const int ne = n * im->Bands * \
		(vips_bandfmt_iscomplex( im->BandFmt ) ? 2 : 1); \
	const double c = tc[0]; \
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
 	\
	for( i = 0, x = 0; x < n; x++ ) \
		for( b = 0; b < bands; b++, i++ ) \
			FUN( tq[i], tp[i], tc[b] ); \
}

/* Operator with one constant per band on a buffer.
 */
#define CONSTN_BUFFER( FUN ) \
static void \
FUN ## n_buffer( PEL *p, PEL *q, int n, double *tc, IMAGE *im ) \
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
		in, out, n, c, IM_BANDFMT_DOUBLE,
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
		in, out, n, c, IM_BANDFMT_DOUBLE,
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
