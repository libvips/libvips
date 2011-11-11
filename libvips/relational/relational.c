/* relational.c --- various relational operation
 *
 * Modified:
 * 26/7/93 JC
 *	- >,<,>=,<= tests now as (double) to prevent compiler warnings. Should
 *	  split into int/float cases really for speed.
 * 25/1/95 JC
 * 	- partialized
 * 	- updated
 * 7/2/95 JC
 *	- oops! bug with doubles fixed
 * 3/7/98 JC
 *	- vector versions added ... im_equal_vec(), im_lesseq_vec() etc
 * 	- small tidies
 *	- should be a bit faster, lots of *q++ changed to q[x]
 * 10/3/03 JC
 *	- reworked to remove nested #defines: a bit slower, but much smaller
 *	- all except _vec forms now work on complex
 * 31/7/03 JC
 *	- oops, relational_format was broken for some combinations
 * 23/9/09
 * 	- gtkdoc
 * 	- use new im__arith_binary*() functions
 * 	- more meta-programming
 * 23/6/10
 * 	- oops, moreconst and moreeqconst were the same
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

#define UC IM_BANDFMT_UCHAR

/* Type conversions for relational: everything goes to uchar. 
 */
static int bandfmt_relational[10] = {
/* UC  C   US   S  UI  I   F   X   D   DX */
   UC, UC, UC, UC, UC, UC, UC, UC, UC, UC,
};

#define EQUAL_REAL( Q, A, B ) { \
	if( (A) == (B) ) \
		Q = 255; \
	else \
		Q = 0; \
}

#define EQUAL_COMPLEX( Q, A, B ) { \
	if( (A)[0] == (B)[0] && (A)[1] == (B)[1] ) \
		Q = 255; \
	else \
		Q = 0; \
}

#define NOTEQUAL_REAL( Q, A, B ) { \
	if( (A) != (B) ) \
		Q = 255; \
	else \
		Q = 0; \
}

#define NOTEQUAL_COMPLEX( Q, A, B ) { \
	if( (A)[0] != (B)[0] || (A)[1] != (B)[1] ) \
		Q = 255; \
	else \
		Q = 0; \
}

#define LESS_REAL( Q, A, B ) { \
	if( (A) < (B) ) \
		Q = 255; \
	else \
		Q = 0; \
}

#define LESS_COMPLEX( Q, A, B ) { \
	double m1 = (A)[0] * (A)[0] + (A)[1] * (A)[1]; \
	double m2 = (B)[0] * (B)[0] + (B)[1] * (B)[1]; \
	\
	if( m1 < m2 ) \
		Q = 255; \
	else \
		Q = 0; \
}

#define LESSEQ_REAL( Q, A, B ) { \
	if( (A) <= (B) ) \
		Q = 255; \
	else \
		Q = 0; \
}

#define LESSEQ_COMPLEX( Q, A, B ) { \
	double m1 = (A)[0] * (A)[0] + (A)[1] * (A)[1]; \
	double m2 = (B)[0] * (B)[0] + (B)[1] * (B)[1]; \
	\
	if( m1 <= m2 ) \
		Q = 255; \
	else \
		Q = 0; \
}

#define RCONST1( IN, FUN ) { \
	IN *tp = (IN *) p; \
	IN tc = *((IN *) vector); \
 	\
	for( i = 0; i < ne; i++ ) \
		FUN( q[i], tp[i], tc ); \
}

#define CCONST1( IN, FUN ) { \
	IN *tp = (IN *) p; \
	IN *tc = ((IN *) vector); \
 	\
	for( i = 0; i < ne; i++ ) { \
		FUN( q[i], tp, tc ); \
		\
		tp += 2; \
	} \
}

#define CONST1_BUFFER( NAME, RFUN, CFUN ) \
static void \
NAME ## 1_buffer( PEL *p, PEL *q, int n, PEL *vector, IMAGE *im ) \
{ \
	const int ne = n * im->Bands; \
	\
	int i; \
	\
        switch( im->BandFmt ) { \
        case IM_BANDFMT_CHAR: 	RCONST1( signed char, RFUN ); break; \
        case IM_BANDFMT_UCHAR:  RCONST1( unsigned char, RFUN ); break; \
        case IM_BANDFMT_SHORT:  RCONST1( signed short, RFUN ); break; \
        case IM_BANDFMT_USHORT: RCONST1( unsigned short, RFUN ); break; \
        case IM_BANDFMT_INT: 	RCONST1( signed int, RFUN ); break; \
        case IM_BANDFMT_UINT: 	RCONST1( unsigned int, RFUN ); break; \
        case IM_BANDFMT_FLOAT: 	RCONST1( float, RFUN ); break; \
        case IM_BANDFMT_COMPLEX: CCONST1( float, CFUN ); break; \
        case IM_BANDFMT_DOUBLE: RCONST1( double, RFUN ); break; \
        case IM_BANDFMT_DPCOMPLEX: CCONST1( double, CFUN ); break; \
	\
        default: \
                g_assert( 0 ); \
        } \
}

#define RCONSTN( IN, FUN ) { \
	IN *tp = (IN *) p; \
	IN *tc = (IN *) vector; \
 	\
	for( i = 0, x = 0; x < n; x++ ) \
		for( b = 0; b < bands; b++, i++ ) \
			FUN( q[i], tp[i], tc[b] ); \
}

#define CCONSTN( IN, FUN ) { \
	IN *tp = (IN *) p; \
 	\
	for( i = 0, x = 0; x < n; x++ ) { \
		IN *tc = ((IN *) vector); \
		\
		for( b = 0; b < bands; b++, i++ ) { \
			FUN( q[i], tp, tc ); \
			\
			tp += 2; \
			tc += 2; \
		} \
	} \
}

#define CONSTN_BUFFER( NAME, RFUN, CFUN ) \
static void \
NAME ## n_buffer( PEL *p, PEL *q, int n, PEL *vector, IMAGE *im ) \
{ \
	const int bands = im->Bands; \
	\
	int i, x, b; \
	\
        switch( im->BandFmt ) { \
        case IM_BANDFMT_CHAR: 	RCONSTN( signed char, RFUN ); break; \
        case IM_BANDFMT_UCHAR:  RCONSTN( unsigned char, RFUN ); break; \
        case IM_BANDFMT_SHORT:  RCONSTN( signed short, RFUN ); break; \
        case IM_BANDFMT_USHORT: RCONSTN( unsigned short, RFUN ); break; \
        case IM_BANDFMT_INT: 	RCONSTN( signed int, RFUN ); break; \
        case IM_BANDFMT_UINT: 	RCONSTN( unsigned int, RFUN ); break; \
        case IM_BANDFMT_FLOAT: 	RCONSTN( float, RFUN ); break; \
        case IM_BANDFMT_COMPLEX: CCONSTN( float, CFUN ); break; \
        case IM_BANDFMT_DOUBLE: RCONSTN( double, RFUN ); break; \
        case IM_BANDFMT_DPCOMPLEX: CCONSTN( double, CFUN ); break; \
	\
        default: \
                g_assert( 0 ); \
        } \
}

CONST1_BUFFER( EQUAL, EQUAL_REAL, EQUAL_COMPLEX )

CONSTN_BUFFER( EQUAL, EQUAL_REAL, EQUAL_COMPLEX )

/**
 * im_equal_vec:
 * @in: input #IMAGE 
 * @out: output #IMAGE
 * @n: array length
 * @c: array of constants
 *
 * This operation calculates @in == @c (image element equals constant array
 * @c) and writes the result to @out. 
 *
 * See also: im_equal(), im_equalconst().
 *
 * Returns: 0 on success, -1 on error
 */
int 
im_equal_vec( IMAGE *in, IMAGE *out, int n, double *c )
{
	return( im__arith_binary_const( "im_equal", 
		in, out, n, c, in->BandFmt,
		bandfmt_relational,
		(im_wrapone_fn) EQUAL1_buffer, 
		(im_wrapone_fn) EQUALn_buffer ) );
}

CONST1_BUFFER( NOTEQUAL, NOTEQUAL_REAL, NOTEQUAL_COMPLEX )

CONSTN_BUFFER( NOTEQUAL, NOTEQUAL_REAL, NOTEQUAL_COMPLEX )

/**
 * im_notequal_vec:
 * @in: input #IMAGE 
 * @out: output #IMAGE
 * @n: array length
 * @c: array of constants
 *
 * This operation calculates @in != @c (image element is not equal to constant 
 * array @c) and writes the result to @out. 
 *
 * See also: im_equal(), im_equal_vec().
 *
 * Returns: 0 on success, -1 on error
 */
int 
im_notequal_vec( IMAGE *in, IMAGE *out, int n, double *c )
{
	return( im__arith_binary_const( "im_notequal", 
		in, out, n, c, in->BandFmt,
		bandfmt_relational,
		(im_wrapone_fn) NOTEQUAL1_buffer, 
		(im_wrapone_fn) NOTEQUALn_buffer ) );
}

CONST1_BUFFER( LESS, LESS_REAL, LESS_COMPLEX )

CONSTN_BUFFER( LESS, LESS_REAL, LESS_COMPLEX )

/**
 * im_less_vec:
 * @in: input #IMAGE 
 * @out: output #IMAGE
 * @n: array length
 * @c: array of constants
 *
 * This operation calculates @in < @c (image element is less than constant 
 * array @c) and writes the result to @out. 
 *
 * See also: im_less(), im_lessconst().
 *
 * Returns: 0 on success, -1 on error
 */
int 
im_less_vec( IMAGE *in, IMAGE *out, int n, double *c )
{
	return( im__arith_binary_const( "im_less", 
		in, out, n, c, in->BandFmt,
		bandfmt_relational,
		(im_wrapone_fn) LESS1_buffer, 
		(im_wrapone_fn) LESSn_buffer ) );
}

CONST1_BUFFER( LESSEQ, LESSEQ_REAL, LESSEQ_COMPLEX )

CONSTN_BUFFER( LESSEQ, LESSEQ_REAL, LESSEQ_COMPLEX )

/**
 * im_lesseq_vec:
 * @in: input #IMAGE 
 * @out: output #IMAGE
 * @n: array length
 * @c: array of constants
 *
 * This operation calculates @in <= @c (image element is less than or equal to 
 * constant array @c) and writes the result to @out. 
 *
 * See also: im_lesseq(), im_lesseqconst().
 *
 * Returns: 0 on success, -1 on error
 */
int 
im_lesseq_vec( IMAGE *in, IMAGE *out, int n, double *c )
{
	return( im__arith_binary_const( "im_lesseq", 
		in, out, n, c, in->BandFmt,
		bandfmt_relational,
		(im_wrapone_fn) LESSEQ1_buffer, 
		(im_wrapone_fn) LESSEQn_buffer ) );
}

#define MORE_REAL( Q, A, B ) { \
	if( (A) > (B) ) \
		Q = 255; \
	else \
		Q = 0; \
}

#define MORE_COMPLEX( Q, A, B ) { \
	double m1 = (A)[0] * (A)[0] + (A)[1] * (A)[1]; \
	double m2 = (B)[0] * (B)[0] + (B)[1] * (B)[1]; \
	\
	if( m1 > m2 ) \
		Q = 255; \
	else \
		Q = 0; \
}

CONST1_BUFFER( MORE, MORE_REAL, MORE_COMPLEX )

CONSTN_BUFFER( MORE, MORE_REAL, MORE_COMPLEX )

/**
 * im_more_vec:
 * @in: input #IMAGE 
 * @out: output #IMAGE
 * @n: array length
 * @c: array of constants
 *
 * This operation calculates @in > @c (image element is greater than 
 * constant array @c) and writes the result to @out. 
 *
 * See also: im_lesseq(), im_lesseqconst().
 *
 * Returns: 0 on success, -1 on error
 */
int 
im_more_vec( IMAGE *in, IMAGE *out, int n, double *c )
{
	return( im__arith_binary_const( "im_more", 
		in, out, n, c, in->BandFmt,
		bandfmt_relational,
		(im_wrapone_fn) MORE1_buffer, 
		(im_wrapone_fn) MOREn_buffer ) );
}

#define MOREEQ_REAL( Q, A, B ) { \
	if( (A) >= (B) ) \
		Q = 255; \
	else \
		Q = 0; \
}

#define MOREEQ_COMPLEX( Q, A, B ) { \
	double m1 = (A)[0] * (A)[0] + (A)[1] * (A)[1]; \
	double m2 = (B)[0] * (B)[0] + (B)[1] * (B)[1]; \
	\
	if( m1 >= m2 ) \
		Q = 255; \
	else \
		Q = 0; \
}

CONST1_BUFFER( MOREEQ, MOREEQ_REAL, MOREEQ_COMPLEX )

CONSTN_BUFFER( MOREEQ, MOREEQ_REAL, MOREEQ_COMPLEX )

/**
 * im_moreeq_vec:
 * @in: input #IMAGE 
 * @out: output #IMAGE
 * @n: array length
 * @c: array of constants
 *
 * This operation calculates @in >= @c (image element is greater than or 
 * equal to 
 * constant array @c) and writes the result to @out. 
 *
 * See also: im_lesseq(), im_lesseqconst().
 *
 * Returns: 0 on success, -1 on error
 */
int 
im_moreeq_vec( IMAGE *in, IMAGE *out, int n, double *c )
{
	return( im__arith_binary_const( "im_moreeq", 
		in, out, n, c, in->BandFmt,
		bandfmt_relational,
		(im_wrapone_fn) MOREEQ1_buffer, 
		(im_wrapone_fn) MOREEQn_buffer ) );
}

/**
 * im_equalconst:
 * @in: input #IMAGE 
 * @out: output #IMAGE
 * @c: constant
 *
 * This operation calculates @in == @c (image element is 
 * equal to constant @c) and writes the result to @out. 
 *
 * See also: im_lesseq(), im_lesseqconst().
 *
 * Returns: 0 on success, -1 on error
 */
int 
im_equalconst( IMAGE *in, IMAGE *out, double c )
{
	return( im_equal_vec( in, out, 1, &c ) );
}

/**
 * im_notequalconst:
 * @in: input #IMAGE 
 * @out: output #IMAGE
 * @c: constant
 *
 * This operation calculates @in != @c (image element is not equal to 
 * constant @c) and writes the result to @out. 
 *
 * See also: im_lesseq(), im_lesseqconst().
 *
 * Returns: 0 on success, -1 on error
 */
int
im_notequalconst( IMAGE *in, IMAGE *out, double c )
{
	return( im_notequal_vec( in, out, 1, &c ) );
}

/**
 * im_lessconst:
 * @in: input #IMAGE 
 * @out: output #IMAGE
 * @c: constant
 *
 * This operation calculates @in < @c (image element is less than 
 * constant @c) and writes the result to @out. 
 *
 * See also: im_lesseq(), im_lesseqconst().
 *
 * Returns: 0 on success, -1 on error
 */
int
im_lessconst( IMAGE *in, IMAGE *out, double c )
{
	return( im_less_vec( in, out, 1, &c ) );
}

/**
 * im_lesseqconst:
 * @in: input #IMAGE 
 * @out: output #IMAGE
 * @c: constant
 *
 * This operation calculates @in = @c (image element is less than 
 * or equal to
 * constant @c) and writes the result to @out. 
 *
 * See also: im_lesseq(), im_lesseqconst().
 *
 * Returns: 0 on success, -1 on error
 */
int
im_lesseqconst( IMAGE *in, IMAGE *out, double c )
{
	return( im_lesseq_vec( in, out, 1, &c ) );
}

/**
 * im_moreconst:
 * @in: input #IMAGE 
 * @out: output #IMAGE
 * @c: constant
 *
 * This operation calculates @in = @c (image element is more than 
 * constant @c) and writes the result to @out. 
 *
 * See also: im_lesseq(), im_lesseqconst().
 *
 * Returns: 0 on success, -1 on error
 */
int
im_moreconst( IMAGE *in, IMAGE *out, double c )
{
	return( im_more_vec( in, out, 1, &c ) );
}

/**
 * im_moreeqconst:
 * @in: input #IMAGE 
 * @out: output #IMAGE
 * @c: constant
 *
 * This operation calculates @in = @c (image element is more than 
 * or equal to
 * constant @c) and writes the result to @out. 
 *
 * See also: im_lesseq(), im_lesseqconst().
 *
 * Returns: 0 on success, -1 on error
 */
int
im_moreeqconst( IMAGE *in, IMAGE *out, double c )
{
	return( im_moreeq_vec( in, out, 1, &c ) );
}

