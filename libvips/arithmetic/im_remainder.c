/* im_remainder.c
 *
 * 2/8/99 JC
 *	- im_divide adapted to make im_remainder
 * 8/5/02 JC
 *	- im_remainderconst added
 *	- im_remainderconst_vec added
 * 27/9/04
 *	- updated for 1 band $op n band image -> n band image case
 * 26/2/07
 * 	- oop, broken for _vec case :-(
 * 14/5/08
 * 	- better /0 test
 * 27/8/08
 * 	- revise upcasting system
 * 	- add gtkdoc comments
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

/* Integer remainder-after-division.
 */
#define IREMAINDER( TYPE ) { \
	TYPE *p1 = (TYPE *) in[0]; \
	TYPE *p2 = (TYPE *) in[1]; \
	TYPE *q = (TYPE *) out; \
	\
	for( x = 0; x < ne; x++ ) \
		if( p2[x] ) \
			q[x] = p1[x] % p2[x]; \
		else \
			q[x] = -1; \
}

/* Float remainder-after-division.
 */
#define FREMAINDER( TYPE ) { \
	TYPE *p1 = (TYPE *) in[0]; \
	TYPE *p2 = (TYPE *) in[1]; \
	TYPE *q = (TYPE *) out; \
	\
	for( x = 0; x < ne; x++ ) { \
		double a = p1[x]; \
		double b = p2[x]; \
		\
		if( b ) \
			q[x] = a - b * floor (a / b); \
		else \
			q[x] = -1; \
	} \
}

static void
remainder_buffer( PEL **in, PEL *out, int width, IMAGE *im )
{
	const int ne = width * im->Bands;

	int x;

        switch( im->BandFmt ) {
        case IM_BANDFMT_CHAR: 	IREMAINDER( signed char ); break; 
        case IM_BANDFMT_UCHAR: 	IREMAINDER( unsigned char ); break; 
        case IM_BANDFMT_SHORT: 	IREMAINDER( signed short ); break; 
        case IM_BANDFMT_USHORT:	IREMAINDER( unsigned short ); break; 
        case IM_BANDFMT_INT: 	IREMAINDER( signed int ); break; 
        case IM_BANDFMT_UINT: 	IREMAINDER( unsigned int ); break; 
        case IM_BANDFMT_FLOAT: 	FREMAINDER( float ); break; 
        case IM_BANDFMT_DOUBLE:	FREMAINDER( double ); break;

        default:
		g_assert( 0 );
        }
}

/* Save a bit of typing.
 */
#define UC IM_BANDFMT_UCHAR
#define C IM_BANDFMT_CHAR
#define US IM_BANDFMT_USHORT
#define S IM_BANDFMT_SHORT
#define UI IM_BANDFMT_UINT
#define I IM_BANDFMT_INT
#define F IM_BANDFMT_FLOAT
#define X IM_BANDFMT_COMPLEX
#define D IM_BANDFMT_DOUBLE
#define DX IM_BANDFMT_DPCOMPLEX

/* Type promotion for remainder. Keep in sync with remainder_buffer() above.
 */
static int bandfmt_remainder[10] = {
/* UC  C   US  S   UI  I  F  X  D  DX */
   UC, C,  US, S,  UI, I, F, X, D, DX
};

/**
 * im_remainder:
 * @in1: input #IMAGE 1
 * @in2: input #IMAGE 2
 * @out: output #IMAGE
 *
 * This operation calculates @in1 % @in2 (remainder after division) and writes 
 * the result to @out. The images must be the same size. They may have any 
 * non-complex format. For float formats, im_remainder() calculates @in1 -
 * @in2 * floor (@in1 / @in2).
 *
 * If the number of bands differs, one of the images 
 * must have one band. In this case, an n-band image is formed from the 
 * one-band image by joining n copies of the one-band image together, and then
 * the two n-band images are operated upon.
 *
 * The two input images are cast up to the smallest common type (see table 
 * Smallest common format in 
 * <link linkend="VIPS-arithmetic">arithmetic</link>), and that format is the
 * result type.
 *
 * See also: im_remainderconst(), im_divide().
 *
 * Returns: 0 on success, -1 on error
 */
int 
im_remainder( IMAGE *in1, IMAGE *in2, IMAGE *out )
{
	if( im_check_noncomplex( "im_remainder", in1 ) ||
		im_check_noncomplex( "im_remainder", in2 ) )
		return( -1 );

	return( im__arith_binary( "im_remainder", 
		in1, in2, out, 
		bandfmt_remainder,
		(im_wrapmany_fn) remainder_buffer, NULL ) );
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

/* Cast a vector of double to the type of IMAGE.
 */
static PEL *
make_pixel( IMAGE *out, int n, double *p )
{
	PEL *q;
	int i;

	if( !(q = IM_ARRAY( out, n * IM_IMAGE_SIZEOF_ELEMENT( out ), PEL )) )
		return( NULL );

        switch( out->BandFmt ) {
        case IM_BANDFMT_CHAR:	CAST( signed char ); break;
        case IM_BANDFMT_UCHAR:  CAST( unsigned char ); break;
        case IM_BANDFMT_SHORT:  CAST( signed short ); break;
        case IM_BANDFMT_USHORT: CAST( unsigned short ); break;
        case IM_BANDFMT_INT:    CAST( signed int ); break;
        case IM_BANDFMT_UINT:   CAST( unsigned int ); break;
        case IM_BANDFMT_FLOAT: 	CAST( float ); break; 
        case IM_BANDFMT_DOUBLE:	CAST( double ); break;
        case IM_BANDFMT_COMPLEX: 	CASTC( float ); break; 
        case IM_BANDFMT_DPCOMPLEX:	CASTC( double ); break;

        default:
                g_assert( 0 );
        }

	return( q );
}

int 
im__arith_binary_const( const char *name,
	IMAGE *in, IMAGE *out, int n, double *c,
	int format_table[10], 
	im_wrapone_fn fn1, im_wrapone_fn fnn )
{
	PEL *vector;

	if( im_piocheck( in, out ) ||
		im_check_vector( name, n, in ) ||
		im_check_uncoded( name, in ) )
		return( -1 );
	if( im_cp_desc( out, in ) )
		return( -1 );
	out->BandFmt = format_table[in->BandFmt];
	out->Bbits = im_bits_of_fmt( out->BandFmt );

	/* Cast vector to output type.
	 */
	if( !(vector = make_pixel( out, n, c )) )
		return( -1 );

	/* Band-up the input image if we have a >1 vector and
	 * a 1-band image.
	 */
	if( n > 1 && out->Bands == 1 ) {
		IMAGE *t;

		if( !(t = im_open_local( out, "arith_binary_const", "p" )) ||
			im__bandup( in, t, n ) )
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

/* Integer remainder-after-divide, single constant.
 */
#define IREMAINDERCONST1( TYPE ) { \
	TYPE *p = (TYPE *) in; \
	TYPE *q = (TYPE *) out; \
	TYPE c = *((TYPE *) vector); \
	\
	for( x = 0; x < ne; x++ ) \
		q[x] = p[x] % c; \
}

/* Float remainder-after-divide, single constant.
 */
#define FREMAINDERCONST1( TYPE ) { \
	TYPE *p = (TYPE *) in; \
	TYPE *q = (TYPE *) out; \
	TYPE c = *((TYPE *) vector); \
	\
	for( x = 0; x < ne; x++ ) { \
		double a = p[x]; \
		\
		if( c ) \
			q[x] = a - c * floor (a / c); \
		else \
			q[x] = -1; \
	} \
}

static void
remainderconst1_buffer( PEL *in, PEL *out, int width, PEL *vector, IMAGE *im )
{
	const int ne = width * im->Bands;

	int x;

        switch( im->BandFmt ) {
        case IM_BANDFMT_CHAR: 	IREMAINDERCONST1( signed char ); break; 
        case IM_BANDFMT_UCHAR: 	IREMAINDERCONST1( unsigned char ); break; 
        case IM_BANDFMT_SHORT: 	IREMAINDERCONST1( signed short ); break; 
        case IM_BANDFMT_USHORT:	IREMAINDERCONST1( unsigned short ); break; 
        case IM_BANDFMT_INT: 	IREMAINDERCONST1( signed int ); break; 
        case IM_BANDFMT_UINT: 	IREMAINDERCONST1( unsigned int ); break; 
        case IM_BANDFMT_FLOAT: 	FREMAINDERCONST1( float ); break; 
        case IM_BANDFMT_DOUBLE:	FREMAINDERCONST1( double ); break;

        default:
		g_assert( 0 );
        }
}

/* Integer remainder-after-divide, per-band constant.
 */
#define IREMAINDERCONSTN( TYPE ) { \
	TYPE *p = (TYPE *) in; \
	TYPE *q = (TYPE *) out; \
	TYPE *c = (TYPE *) vector; \
	\
	for( i = 0, x = 0; x < width; x++ ) \
		for( k = 0; k < b; k++, i++ ) \
			q[i] = p[i] % c[k]; \
}

/* Float remainder-after-divide, per-band constant.
 */
#define FREMAINDERCONSTN( TYPE ) { \
	TYPE *p = (TYPE *) in; \
	TYPE *q = (TYPE *) out; \
	TYPE *c = (TYPE *) vector; \
	\
	for( i = 0, x = 0; x < width; x++ ) \
		for( k = 0; k < b; k++, i++ ) { \
			double a = p[i]; \
			double b = c[k]; \
			\
			if( b ) \
				q[i] = a - b * floor (a / b); \
			else \
				q[i] = -1; \
		} \
}

static void
remainderconst_buffer( PEL *in, PEL *out, int width, PEL *vector, IMAGE *im )
{
	int b = im->Bands;
	int i, x, k; 

        switch( im->BandFmt ) {
        case IM_BANDFMT_CHAR: 	IREMAINDERCONSTN( signed char ); break; 
        case IM_BANDFMT_UCHAR: 	IREMAINDERCONSTN( unsigned char ); break; 
        case IM_BANDFMT_SHORT: 	IREMAINDERCONSTN( signed short ); break; 
        case IM_BANDFMT_USHORT:	IREMAINDERCONSTN( unsigned short ); break; 
        case IM_BANDFMT_INT: 	IREMAINDERCONSTN( signed int ); break; 
        case IM_BANDFMT_UINT: 	IREMAINDERCONSTN( unsigned int ); break; 
        case IM_BANDFMT_FLOAT: 	FREMAINDERCONSTN( float ); break; 
        case IM_BANDFMT_DOUBLE:	FREMAINDERCONSTN( double ); break;

        default:
		g_assert( 0 );
        }
}

/**
 * im_remainder_vec:
 * @in: input #IMAGE 
 * @out: output #IMAGE
 * @n: number of elements in array
 * @c: array of constants
 *
 * This operation calculates @in % @c (remainder after division by constant) 
 * and writes the result to @out. 
 * The image may have any 
 * non-complex format. For float formats, im_remainder() calculates @in -
 * @c * floor (@in / @c).
 *
 * If the number of image bands end array elements differs, one of them
 * must have one band. Either the image is up-banded by joining n copies of
 * the one-band image together, or the array is upbanded by copying the single
 * element n times.
 *
 * See also: im_remainder(), im_remainderconst(), im_divide().
 *
 * Returns: 0 on success, -1 on error
 */
int 
im_remainder_vec( IMAGE *in, IMAGE *out, int n, double *c )
{
	if( im_check_noncomplex( "im_remainder", in ) )
		return( -1 );

	return( im__arith_binary_const( "im_remainder", 
		in, out, n, c, 
		bandfmt_remainder,
		(im_wrapone_fn) remainderconst1_buffer, 
		(im_wrapone_fn) remainderconst_buffer ) );
}

/**
 * im_remainderconst:
 * @in: input #IMAGE 
 * @out: output #IMAGE
 * @c: constant
 *
 * This operation calculates @in % @c (remainder after division by constant) 
 * and writes the result to @out. The image must be one of the integer types. 
 *
 * See also: im_remainder_vec(), im_divide().
 *
 * Returns: 0 on success, -1 on error
 */
int 
im_remainderconst( IMAGE *in, IMAGE *out, double c )
{
	return( im_remainder_vec( in, out, 1, &c ) );
}
