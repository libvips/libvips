/* boolean.c --- various bit operations
 *
 * Modified: 
 * 15/12/94 JC
 * 	- ANSIfied
 * 	- adapted to partials with im_wrap...
 * 25/1/95 JC
 *	- added check1ary(), check2ary()
 * 8/2/95 JC
 *	- new im_wrapmany
 * 19/7/95 JC
 *	- added im_shiftleft() and im_shiftright()
 * 6/7/98 JC
 *	- added _vec forms
 * 	- removed *p++ stuff
 * 10/9/99 JC
 *	- and/or/eor now do all int types
 * 10/10/02 JC
 *	- renamed im_and() etc. as im_andimage() to remove breakage in the C++
 *	  layer if operator names are turned on
 * 30/6/04
 *	- now cast float/complex args to int
 * 11/9/09
 * 	- use new im__cast_and__call()
 * 	- therefore now supports 1-band $op n-band 
 * 17/9/09
 * 	- moved to im__arith_binary*()
 * 	- renamed im_eor_vec() as im_eorimage_vec() for C++ sanity
 * 21/11/10
 * 	- oop, constants are always (int) now, so (^-1) works for unsigned
 * 	  types
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

/* Save a bit of typing.
 */
#define UC IM_BANDFMT_UCHAR
#define C IM_BANDFMT_CHAR
#define US IM_BANDFMT_USHORT
#define S IM_BANDFMT_SHORT
#define UI IM_BANDFMT_UINT
#define I IM_BANDFMT_INT

/* Type conversions for boolean. 
 */
static int bandfmt_bool[10] = {
/* UC  C   US  S   UI  I   F   X   D   DX */
   UC, C,  US, S,  UI, I,  I,  I,  I,  I,
};

#define BINARY( IN, OUT, OP ) { \
	OUT *tq = (OUT *) q; \
	IN *tp1 = (IN *) p[0]; \
	IN *tp2 = (IN *) p[1]; \
 	\
	for( i = 0; i < ne; i++ )  \
		tq[i] = (OUT) tp1[i] OP (OUT) tp2[i]; \
}

#define BINARY_BUFFER( NAME, OP ) \
static void \
NAME ## _buffer( PEL **p, PEL *q, int n, IMAGE *im ) \
{ \
	/* Complex just doubles the size. \
	 */ \
	const int ne = n * im->Bands * \
		(vips_bandfmt_iscomplex( im->BandFmt ) ? 2 : 1); \
	\
	int i; \
	\
        switch( im->BandFmt ) { \
        case IM_BANDFMT_CHAR:	\
		BINARY( signed char, signed char, OP ); break; \
        case IM_BANDFMT_UCHAR:  \
		BINARY( unsigned char, unsigned char, OP ); break; \
        case IM_BANDFMT_SHORT:  \
		BINARY( signed short, signed short, OP ); break; \
        case IM_BANDFMT_USHORT: \
		BINARY( unsigned short, unsigned short, OP ); break; \
        case IM_BANDFMT_INT:    \
		BINARY( signed int, signed int, OP ); break; \
        case IM_BANDFMT_UINT:   \
		BINARY( unsigned int, unsigned int, OP ); break; \
        case IM_BANDFMT_FLOAT:  \
		BINARY( float, signed int, OP ); break; \
        case IM_BANDFMT_COMPLEX: \
		BINARY( float, signed int, OP ); break; \
        case IM_BANDFMT_DOUBLE: \
		BINARY( double, signed int, OP ); break; \
        case IM_BANDFMT_DPCOMPLEX: \
		BINARY( double, signed int, OP ); break; \
	\
        default: \
                g_assert( 0 ); \
        } \
}

BINARY_BUFFER( AND, & )

/**
 * im_andimage:
 * @in1: input #IMAGE 1
 * @in2: input #IMAGE 2
 * @out: output #IMAGE
 *
 * This operation calculates @in1 & @in2 and writes the result to @out. 
 * The images must be the same size. They may have any format. They may differ
 * in their number of bands, see above.
 *
 * See also: im_orimage().
 *
 * Returns: 0 on success, -1 on error
 */
int 
im_andimage( IMAGE *in1, IMAGE *in2, IMAGE *out )
{
	return( im__arith_binary( "im_andimage",
		in1, in2, out, 
		bandfmt_bool,
		(im_wrapmany_fn) AND_buffer, NULL ) );
}

BINARY_BUFFER( OR, | )

/**
 * im_orimage:
 * @in1: input #IMAGE 1
 * @in2: input #IMAGE 2
 * @out: output #IMAGE
 *
 * This operation calculates @in1 | @in2 and writes the result to @out. 
 * The images must be the same size. They may have any format. They may differ
 * in their number of bands, see above.
 *
 * See also: im_eorimage().
 *
 * Returns: 0 on success, -1 on error
 */
int 
im_orimage( IMAGE *in1, IMAGE *in2, IMAGE *out )
{
	return( im__arith_binary( "im_orimage",
		in1, in2, out, 
		bandfmt_bool,
		(im_wrapmany_fn) OR_buffer, NULL ) );
}

BINARY_BUFFER( EOR, ^ )

/**
 * im_eorimage:
 * @in1: input #IMAGE 1
 * @in2: input #IMAGE 2
 * @out: output #IMAGE
 *
 * This operation calculates @in1 ^ @in2 and writes the result to @out. 
 * The images must be the same size. They may have any format. They may differ
 * in their number of bands, see above.
 *
 * See also: im_eorimage_vec(), im_andimage().
 *
 * Returns: 0 on success, -1 on error
 */
int 
im_eorimage( IMAGE *in1, IMAGE *in2, IMAGE *out )
{
	return( im__arith_binary( "im_eorimage",
		in1, in2, out, 
		bandfmt_bool,
		(im_wrapmany_fn) EOR_buffer, NULL ) );
}

#define CONST1( IN, OUT, OP ) { \
	OUT *tq = (OUT *) q; \
	IN *tp = (IN *) p; \
	int tc = *((int *) vector); \
 	\
	for( i = 0; i < ne; i++ ) \
		tq[i] = (OUT) tp[i] OP (OUT) tc; \
}

#define CONST1_BUFFER( NAME, OP ) \
static void \
NAME ## 1_buffer( PEL *p, PEL *q, int n, PEL *vector, IMAGE *im ) \
{ \
	/* Complex just doubles the size. \
	 */ \
	const int ne = n * im->Bands * \
		(vips_bandfmt_iscomplex( im->BandFmt ) ? 2 : 1); \
	\
	int i; \
	\
        switch( im->BandFmt ) { \
        case IM_BANDFMT_CHAR: \
		CONST1( signed char, signed char, OP ); break; \
        case IM_BANDFMT_UCHAR:  \
		CONST1( unsigned char, unsigned char, OP ); break; \
        case IM_BANDFMT_SHORT:  \
		CONST1( signed short, signed short, OP ); break; \
        case IM_BANDFMT_USHORT: \
		CONST1( unsigned short, unsigned short, OP ); break; \
        case IM_BANDFMT_INT: \
		CONST1( signed int, signed int, OP ); break; \
        case IM_BANDFMT_UINT: \
		CONST1( unsigned int, unsigned int, OP ); break; \
        case IM_BANDFMT_FLOAT: \
		CONST1( float, signed int, OP ); break; \
        case IM_BANDFMT_COMPLEX: \
		CONST1( float, signed int, OP ); break; \
        case IM_BANDFMT_DOUBLE: \
		CONST1( double, signed int, OP ); break; \
        case IM_BANDFMT_DPCOMPLEX: \
		CONST1( double, signed int, OP ); break; \
	\
        default: \
                g_assert( 0 ); \
        } \
}

#define CONSTN( IN, OUT, OP ) { \
	OUT *tq = (OUT *) q; \
	IN *tp = (IN *) p; \
	int *tc = (int *) vector; \
 	\
	for( i = 0, x = 0; x < n; x++ ) \
		for( b = 0; b < bands; b++, i++ ) \
			tq[i] = (OUT) tp[i] OP (OUT) tc[b]; \
}

#define CONSTN_BUFFER( NAME, OP ) \
static void \
NAME ## n_buffer( PEL *p, PEL *q, int n, PEL *vector, IMAGE *im ) \
{ \
	const int bands = im->Bands; \
	\
	int i, x, b; \
	\
        switch( im->BandFmt ) { \
        case IM_BANDFMT_CHAR: \
		CONSTN( signed char, signed char, OP ); break; \
        case IM_BANDFMT_UCHAR:  \
		CONSTN( unsigned char, unsigned char, OP ); break; \
        case IM_BANDFMT_SHORT:  \
		CONSTN( signed short, signed short, OP ); break; \
        case IM_BANDFMT_USHORT: \
		CONSTN( unsigned short, unsigned short, OP ); break; \
        case IM_BANDFMT_INT: \
		CONSTN( signed int, signed int, OP ); break; \
        case IM_BANDFMT_UINT: \
		CONSTN( unsigned int, unsigned int, OP ); break; \
        case IM_BANDFMT_FLOAT: \
		CONSTN( float, signed int, OP ); break; \
        case IM_BANDFMT_COMPLEX: \
		CONSTN( float, signed int, OP ); break; \
        case IM_BANDFMT_DOUBLE: \
		CONSTN( double, signed int, OP ); break; \
        case IM_BANDFMT_DPCOMPLEX: \
		CONSTN( double, signed int, OP ); break; \
	\
        default: \
                g_assert( 0 ); \
        } \
}

CONST1_BUFFER( AND, & )

CONSTN_BUFFER( AND, & )

/**
 * im_andimage_vec:
 * @in: input #IMAGE 1
 * @out: output #IMAGE
 * @n: array length
 * @c: array of constants
 *
 * This operation calculates @in & @c (bitwise and of image pixels with array
 * @c) and writes the result to @out. 
 *
 * See also: im_andimage(), im_orimage_vec().
 *
 * Returns: 0 on success, -1 on error
 */
int 
im_andimage_vec( IMAGE *in, IMAGE *out, int n, double *c )
{
	return( im__arith_binary_const( "im_andimage", 
		in, out, n, c, IM_BANDFMT_INT,
		bandfmt_bool,
		(im_wrapone_fn) AND1_buffer, 
		(im_wrapone_fn) ANDn_buffer ) );
}

/**
 * im_andimageconst:
 * @in: input #IMAGE 1
 * @out: output #IMAGE
 * @c: constant
 *
 * This operation calculates @in & @c (bitwise and of image pixels with
 * constant
 * @c) and writes the result to @out. 
 *
 * See also: im_andimage(), im_orimage_vec().
 *
 * Returns: 0 on success, -1 on error
 */
int 
im_andimageconst( IMAGE *in, IMAGE *out, double c )
{
	return( im_andimage_vec( in, out, 1, &c ) ); 
}

CONST1_BUFFER( OR, | )

CONSTN_BUFFER( OR, | )

/**
 * im_orimage_vec:
 * @in: input #IMAGE 1
 * @out: output #IMAGE
 * @n: array length
 * @c: array of constants
 *
 * This operation calculates @in | @c (bitwise or of image pixels with array
 * @c) and writes the result to @out. 
 *
 * See also: im_andimage(), im_orimageconst().
 *
 * Returns: 0 on success, -1 on error
 */
int 
im_orimage_vec( IMAGE *in, IMAGE *out, int n, double *c )
{
	return( im__arith_binary_const( "im_orimage", 
		in, out, n, c, IM_BANDFMT_INT,
		bandfmt_bool,
		(im_wrapone_fn) OR1_buffer, 
		(im_wrapone_fn) ORn_buffer ) );
}

/**
 * im_orimageconst:
 * @in: input #IMAGE 1
 * @out: output #IMAGE
 * @c: constant
 *
 * This operation calculates @in | @c (bitwise or of image pixels with
 * constant
 * @c) and writes the result to @out. 
 *
 * See also: im_andimage(), im_orimage_vec().
 *
 * Returns: 0 on success, -1 on error
 */
int 
im_orimageconst( IMAGE *in, IMAGE *out, double c )
{
	return( im_orimage_vec( in, out, 1, &c ) );
}

CONST1_BUFFER( EOR, ^ )

CONSTN_BUFFER( EOR, ^ )

/**
 * im_eorimage_vec:
 * @in: input #IMAGE 1
 * @out: output #IMAGE
 * @n: array length
 * @c: array of constants
 *
 * This operation calculates @in ^ @c (bitwise exclusive-or of image pixels 
 * with array
 * @c) and writes the result to @out. 
 *
 * See also: im_andimage(), im_orimageconst().
 *
 * Returns: 0 on success, -1 on error
 */
int 
im_eorimage_vec( IMAGE *in, IMAGE *out, int n, double *c )
{
	return( im__arith_binary_const( "im_eorimage", 
		in, out, n, c, IM_BANDFMT_INT,
		bandfmt_bool,
		(im_wrapone_fn) EOR1_buffer, 
		(im_wrapone_fn) EORn_buffer ) );
}

/**
 * im_eorimageconst:
 * @in: input #IMAGE 1
 * @out: output #IMAGE
 * @c: constant
 *
 * This operation calculates @in ^ @c (bitwise exclusive-or of image pixels 
 * with
 * constant
 * @c) and writes the result to @out. 
 *
 * See also: im_andimage(), im_orimage_vec().
 *
 * Returns: 0 on success, -1 on error
 */
int 
im_eorimageconst( IMAGE *in, IMAGE *out, double c )
{
	return( im_eorimage_vec( in, out, 1, &c ) );
}

CONST1_BUFFER( SHIFTL, << )

CONSTN_BUFFER( SHIFTL, << )

/**
 * im_shiftleft_vec:
 * @in: input #IMAGE 
 * @out: output #IMAGE
 * @n: array length
 * @c: array of constants
 *
 * This operation calculates @in << @c (left-shift by @c bits
 * with array
 * @c) and writes the result to @out. 
 *
 * See also: im_andimage(), im_orimageconst().
 *
 * Returns: 0 on success, -1 on error
 */
int 
im_shiftleft_vec( IMAGE *in, IMAGE *out, int n, double *c )
{
	return( im__arith_binary_const( "im_shiftleft", 
		in, out, n, c, IM_BANDFMT_INT,
		bandfmt_bool,
		(im_wrapone_fn) SHIFTL1_buffer, 
		(im_wrapone_fn) SHIFTLn_buffer ) );
}

/**
 * im_shiftleft:
 * @in: input #IMAGE 
 * @out: output #IMAGE
 * @n: constant
 *
 * This operation calculates @in << @n (left-shift by @n bits)
 * and writes the result to @out. 
 *
 * See also: im_andimage(), im_orimageconst().
 *
 * Returns: 0 on success, -1 on error
 */
int 
im_shiftleft( IMAGE *in, IMAGE *out, int n )
{
	double c = n;

	return( im_shiftleft_vec( in, out, 1, &c ) );
}

CONST1_BUFFER( SHIFTR, >> )

CONSTN_BUFFER( SHIFTR, >> )

/**
 * im_shiftright_vec:
 * @in: input #IMAGE 
 * @out: output #IMAGE
 * @n: array length
 * @c: array of constants
 *
 * This operation calculates @in << @c (right-shift by @c bits
 * with array
 * @c) and writes the result to @out. 
 *
 * See also: im_andimage(), im_orimageconst().
 *
 * Returns: 0 on success, -1 on error
 */
int 
im_shiftright_vec( IMAGE *in, IMAGE *out, int n, double *c )
{
	return( im__arith_binary_const( "im_shiftright", 
		in, out, n, c, IM_BANDFMT_INT,
		bandfmt_bool,
		(im_wrapone_fn) SHIFTR1_buffer, 
		(im_wrapone_fn) SHIFTRn_buffer ) );
}

/**
 * im_shiftright:
 * @in: input #IMAGE 
 * @out: output #IMAGE
 * @n: constant
 *
 * This operation calculates @in >> @n (right-shift by @n bits)
 * and writes the result to @out. 
 *
 * See also: im_andimage(), im_orimageconst().
 *
 * Returns: 0 on success, -1 on error
 */
int 
im_shiftright( IMAGE *in, IMAGE *out, int n )
{
	double c = n;

	return( im_shiftright_vec( in, out, 1, &c ) );
}

