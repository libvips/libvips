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
#include <assert.h>

#include <vips/vips.h>
#include <vips/internal.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* Integer remainder-after-division.
 */
#define ILOOP( IN, OUT ) { \
	IN *p1 = (IN *) in[0]; \
	IN *p2 = (IN *) in[1]; \
	OUT *q = (OUT *) out; \
	\
	for( x = 0; x < sz; x++ ) \
		if( p2[x] ) \
			q[x] = (int) p1[x] % (int) p2[x]; \
		else \
			q[x] = -1; \
}

/* Float remainder-after-division.
 */
#define FLOOP( IN, OUT ) { \
	IN *p1 = (IN *) in[0]; \
	IN *p2 = (IN *) in[1]; \
	OUT *q = (OUT *) out; \
	\
	for( x = 0; x < sz; x++ ) { \
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
	int x;
	int sz = width * im->Bands;

        switch( im->BandFmt ) {
        case IM_BANDFMT_CHAR: 	ILOOP( signed char, signed char ); break; 
        case IM_BANDFMT_UCHAR: 	ILOOP( unsigned char, unsigned char ); break; 
        case IM_BANDFMT_SHORT: 	ILOOP( signed short, signed short ); break; 
        case IM_BANDFMT_USHORT:	ILOOP( unsigned short, unsigned short ); break; 
        case IM_BANDFMT_INT: 	ILOOP( signed int, signed int ); break; 
        case IM_BANDFMT_UINT: 	ILOOP( unsigned int, unsigned int ); break; 
        case IM_BANDFMT_FLOAT: 	FLOOP( float, float ); break; 
        case IM_BANDFMT_DOUBLE:	FLOOP( double, double ); break;

        default:
		assert( 0 );
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

/* Type promotion for remainder. Same as input, except float/complex which are
 * signed int. Keep in sync with remainder_buffer() above.
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
 * non-complex format. For float types, im_remainder() calculates a - b * 
 * floor (a / b).
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
	if( im_piocheck( in1, out ) || 
		im_pincheck( in2 ) ||
		im_check_bands_1orn( "im_remainder", in1, in2 ) ||
		im_check_uncoded( "im_remainder", in1 ) ||
		im_check_uncoded( "im_remainder", in2 ) ||
		im_check_noncomplex( "im_remainder", in1 ) ||
		im_check_noncomplex( "im_remainder", in2 ) )
		return( -1 );

	if( im_cp_descv( out, in1, in2, NULL ) )
		return( -1 );

	/* What number of bands will we write?
	 */
	out->Bands = IM_MAX( in1->Bands, in2->Bands );

	/* What output type will we write? Same as LHS type.
	 */
	out->BandFmt = bandfmt_remainder[im__format_common( in1, in2 )];
	out->Bbits = im_bits_of_fmt( out->BandFmt );

	/* And process!
	 */
	if( im__cast_and_call( in1, in2, out, 
		(im_wrapmany_fn) remainder_buffer, NULL ) )
		return( -1 );

	/* Success!
	 */
	return( 0 );
}

/* Parameters saved here.
 */
typedef struct _Remainderconst {
	IMAGE *in;
	IMAGE *out;
	int n;	
	int *c;
} Remainderconst;

/* Integer remainder-after-divide.
 */
#define ICONST1LOOP( TYPE ) { \
	TYPE *p = (TYPE *) in; \
	TYPE *q = (TYPE *) out; \
	\
	for( x = 0; x < sz; x++ ) \
		q[x] = p[x] % c; \
}

static void
remainderconst1_buffer( PEL *in, PEL *out, int width, Remainderconst *rc )
{
	IMAGE *im = rc->in;
	int sz = width * im->Bands;
	int c = rc->c[0];
	int x;

        switch( im->BandFmt ) {
        case IM_BANDFMT_CHAR: 	ICONST1LOOP( signed char ); break; 
        case IM_BANDFMT_UCHAR: 	ICONST1LOOP( unsigned char ); break; 
        case IM_BANDFMT_SHORT: 	ICONST1LOOP( signed short ); break; 
        case IM_BANDFMT_USHORT:	ICONST1LOOP( unsigned short ); break; 
        case IM_BANDFMT_INT: 	ICONST1LOOP( signed int ); break; 
        case IM_BANDFMT_UINT: 	ICONST1LOOP( unsigned int ); break; 

        default:
		assert( 0 );
        }
}

#define ICONSTLOOP( TYPE ) { \
	TYPE *p = (TYPE *) in; \
	TYPE *q = (TYPE *) out; \
	\
	for( i = 0, x = 0; x < width; x++ ) \
		for( k = 0; k < b; k++, i++ ) \
			q[i] = p[i] % c[k]; \
}

static void
remainderconst_buffer( PEL *in, PEL *out, int width, Remainderconst *rc )
{
	IMAGE *im = rc->in;
	int b = im->Bands;
	int *c = rc->c;
	int i, x, k; 

        switch( im->BandFmt ) {
        case IM_BANDFMT_CHAR: 	ICONSTLOOP( signed char ); break; 
        case IM_BANDFMT_UCHAR: 	ICONSTLOOP( unsigned char ); break; 
        case IM_BANDFMT_SHORT: 	ICONSTLOOP( signed short ); break; 
        case IM_BANDFMT_USHORT:	ICONSTLOOP( unsigned short ); break; 
        case IM_BANDFMT_INT: 	ICONSTLOOP( signed int ); break; 
        case IM_BANDFMT_UINT: 	ICONSTLOOP( unsigned int ); break; 

        default:
		assert( 0 );
        }
}

/**
 * im_remainderconst_vec:
 * @in: input #IMAGE 
 * @out: output #IMAGE
 * @n: number of elements in array
 * @c: array of constants
 *
 * This operation calculates @in % @c (remainder after division by constant) 
 * and writes the result to @out. The image must be one of the integer types. 
 *
 * If the array of constants has one element, that constant is used for each
 * image band. If the array has more than one element, it must have the same
 * number of elements as there are bands in the image, and one array element
 * is used for each band.
 *
 * See also: im_remainder(), im_divide().
 *
 * Returns: 0 on success, -1 on error
 */
int 
im_remainderconst_vec( IMAGE *in, IMAGE *out, int n, double *c )
{
	Remainderconst *rc;
	int i;

	/* Basic checks.
	 */
	if( im_piocheck( in, out ) ||
		im_check_vector( "im_remainder", n, in ) ||
		im_check_uncoded( "im_remainder", in ) ||
		im_check_int( "im_remainder", in ) )
		return( -1 );
	if( im_cp_desc( out, in ) )
		return( -1 );

	/* Take a copy of the parameters.
	 */
	if( !(rc = IM_NEW( out, Remainderconst )) ||
		!(rc->c = IM_ARRAY( out, n, int )) )
		return( -1 );
	rc->in = in;
	rc->out = out;
	rc->n = n;
	for( i = 0; i < n; i++ ) {
		/* Cast down to int ... we pass in double for consistency with
		 * the other _vec functions.
		 */
		if( c[i] != (int) c[i] )
			im_warn( "im_remainderconst_vec", 
				_( "float constant %g truncated to integer" ), 
				c[i] );
		rc->c[i] = c[i];

		if( rc->c[i] == 0 ) {
			im_error( "im_remainderconst_vec",
				"%s", _( "division by zero" ) );
			return( -1 );
		}
	}

	if( n == 1 ) {
		if( im_wrapone( in, out, 
			(im_wrapone_fn) remainderconst1_buffer, rc, NULL ) )
			return( -1 );
	}
	else {
		if( im_wrapone( in, out, 
			(im_wrapone_fn) remainderconst_buffer, rc, NULL ) )
			return( -1 );
	}

	return( 0 );
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
 * See also: im_remainderconst_vec(), im_divide().
 *
 * Returns: 0 on success, -1 on error
 */
int 
im_remainderconst( IMAGE *in, IMAGE *out, double c )
{
	return( im_remainderconst_vec( in, out, 1, &c ) );
}
