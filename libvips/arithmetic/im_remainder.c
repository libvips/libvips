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

#define RLOOP( IN, OUT ) { \
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

#define CLOOP( IN ) { \
	IN *p1 = (IN *) in[0]; \
	IN *p2 = (IN *) in[1]; \
	signed int *q = (signed int *) out; \
	\
	for( x = 0; x < sz; x++ ) { \
		if( p2[0] ) \
			q[x] = (int) p1[0] % (int) p2[0]; \
		else \
			q[x] = -1; \
		\
		p1 += 2; \
		p2 += 2; \
	} \
}

static void
remainder_buffer( PEL **in, PEL *out, int width, IMAGE *im )
{
	int x;
	int sz = width * im->Bands;

        switch( im->BandFmt ) {
        case IM_BANDFMT_CHAR: 	RLOOP( signed char, signed char ); break; 
        case IM_BANDFMT_UCHAR: 	RLOOP( unsigned char, unsigned char ); break; 
        case IM_BANDFMT_SHORT: 	RLOOP( signed short, signed short ); break; 
        case IM_BANDFMT_USHORT:	RLOOP( unsigned short, unsigned short ); break; 
        case IM_BANDFMT_INT: 	RLOOP( signed int, signed int ); break; 
        case IM_BANDFMT_UINT: 	RLOOP( unsigned int, unsigned int ); break; 
        case IM_BANDFMT_FLOAT: 	RLOOP( float, signed int ); break; 
        case IM_BANDFMT_COMPLEX:CLOOP( float ); break; 
        case IM_BANDFMT_DOUBLE:	RLOOP( double, signed int ); break;
        case IM_BANDFMT_DPCOMPLEX: CLOOP( double ); break;

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
   UC, C,  US, S,  UI, I, I, I, I, I
};

/*
.B im_remainder(3)
calculates the remainder after integer division of two images. The output
type is the same as the type of
.B in1
unless
.B in1
is float or complex, in which
case the output type is signed integer.
 */
int 
im_remainder( IMAGE *in1, IMAGE *in2, IMAGE *out )
{	
	if( im_piocheck( in1, out ) || 
		im_pincheck( in2 ) ||
		im_check_bands_1orn( "im_remainder", in1, in2 ) ||
		im_check_uncoded( "im_remainder", in1 ) ||
		im_check_uncoded( "im_remainder", in2 ) )
		return( -1 );

	if( im_cp_descv( out, in1, in2, NULL ) )
		return( -1 );

	/* What number of bands will we write?
	 */
	out->Bands = IM_MAX( in1->Bands, in2->Bands );

	/* What output type will we write? Same as LHS type, except float
	 * and double become signed int.
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

#define const1_loop(TYPE) {\
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
        case IM_BANDFMT_CHAR: 	const1_loop( signed char ); break; 
        case IM_BANDFMT_UCHAR: 	const1_loop( unsigned char ); break; 
        case IM_BANDFMT_SHORT: 	const1_loop( signed short ); break; 
        case IM_BANDFMT_USHORT:	const1_loop( unsigned short ); break; 
        case IM_BANDFMT_INT: 	const1_loop( signed int ); break; 
        case IM_BANDFMT_UINT: 	const1_loop( unsigned int ); break; 

        default:
		assert( 0 );
        }
}

#define const_loop(TYPE) {\
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
        case IM_BANDFMT_CHAR: 	const_loop( signed char ); break; 
        case IM_BANDFMT_UCHAR: 	const_loop( unsigned char ); break; 
        case IM_BANDFMT_SHORT: 	const_loop( signed short ); break; 
        case IM_BANDFMT_USHORT:	const_loop( unsigned short ); break; 
        case IM_BANDFMT_INT: 	const_loop( signed int ); break; 
        case IM_BANDFMT_UINT: 	const_loop( unsigned int ); break; 

        default:
		assert( 0 );
        }
}

int 
im_remainderconst_vec( IMAGE *in, IMAGE *out, int n, double *c )
{
	Remainderconst *rc;
	int i;

	/* Basic checks.
	 */
	if( im_piocheck( in, out ) )
		return( -1 );
	if( in->Coding != IM_CODING_NONE ) {
		im_error( "im_remainderconst_vec", "%s", _( "not uncoded" ) );
		return( -1 );
	}
	if( n != 1 && n != in->Bands ) {
		im_error( "im_remainderconst_vec",
			_( "not 1 or %d elements in vector" ), in->Bands );
		return( -1 );
	}
	if( im_cp_desc( out, in ) )
		return( -1 );

	/* Make space for a little buffer.
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
		rc->c[i] = c[i];

		if( rc->c[i] == 0 ) {
			im_error( "im_remainderconst_vec",
				"%s", _( "division by zero" ) );
			return( -1 );
		}
	}

	/* What output type will we write? Same as input type, except float
	 * and double become signed int.
	 */
	if( im_isfloat( in ) || im_iscomplex( in ) ) {
		IMAGE *t = im_open_local( out, "im_remainderconst:1", "p" );

		out->BandFmt = IM_BANDFMT_INT;
		out->Bbits = IM_BBITS_INT;
		if( !t || im_clip2fmt( in, t, out->BandFmt ) )
			return( -1 );

		rc->in = in = t;
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

int 
im_remainderconst( IMAGE *in, IMAGE *out, double c )
{
	return( im_remainderconst_vec( in, out, 1, &c ) );
}
