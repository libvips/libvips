/* @(#) Bitwise operations on VASARI images. Inputs must be some 
 * @(#) integer type and have the same size and number of bands. Use
 * @(#) im_eorconst( in, out, -1 ) for im_not.
 * @(#)
 * @(#) int im_andimage( a, b, out )	int im_andconst( a, out, c )
 * @(#) IMAGE *a, *b, *out;		IMAGE *a, *out;
 * @(#)					unsigned char c;
 * @(#)
 * @(#) int im_orimage( a, b, out )	int im_orconst( a, out, c )
 * @(#) IMAGE *a, *b, *out;		IMAGE *a, *out;
 * @(#)					unsigned char c;
 * @(#)
 * @(#) int im_eorimage( a, b, out )	int im_eorconst( a, out, c )
 * @(#) IMAGE *a, *b, *out;		IMAGE *a, *out;
 * @(#)					unsigned char c;
 * @(#)
 * @(#) int im_shiftleft( in, out, n )	int im_shiftright( in, out, n )
 * @(#) IMAGE *in, *out;		IMAGE *in, *out;
 * @(#)	int n;				int n;
 * @(#)
 * @(#) Returns either 0 (success) or -1 (fail).
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

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* A selection of main loops. Only implement monotype operations, ie. input 
 * type == output type. Float types are cast to int before we come here.
 */
#define AND2( TYPE ) { \
	TYPE *tq = (TYPE *) q; \
	TYPE *tp1 = (TYPE *) p[0]; \
	TYPE *tp2 = (TYPE *) p[1]; \
 	\
	for( x = 0; x < ne; x++ )  \
		tq[x] = tp1[x] & tp2[x]; \
}

#define OR2( TYPE ) { \
	TYPE *tq = (TYPE *) q; \
	TYPE *tp1 = (TYPE *) p[0]; \
	TYPE *tp2 = (TYPE *) p[1]; \
 	\
	for( x = 0; x < ne; x++ )  \
		tq[x] = tp1[x] | tp2[x]; \
}

#define EOR2( TYPE ) { \
	TYPE *tq = (TYPE *) q; \
	TYPE *tp1 = (TYPE *) p[0]; \
	TYPE *tp2 = (TYPE *) p[1]; \
 	\
	for( x = 0; x < ne; x++ )  \
		tq[x] = tp1[x] ^ tp2[x]; \
}

#define ANDCONST( TYPE ) { \
	TYPE *tq = (TYPE *) q; \
	TYPE *tp = (TYPE *) p; \
	TYPE *tc = (TYPE *) c; \
 	\
	for( i = 0, x = 0; x < n; x++ ) \
		for( b = 0; b < bands; b++, i++ ) \
			tq[i] = tp[i] & tc[b]; \
}

#define ORCONST( TYPE ) { \
	TYPE *tq = (TYPE *) q; \
	TYPE *tp = (TYPE *) p; \
	TYPE *tc = (TYPE *) c; \
 	\
	for( i = 0, x = 0; x < n; x++ ) \
		for( b = 0; b < bands; b++, i++ ) \
			tq[i] = tp[i] | tc[b]; \
}

#define EORCONST( TYPE ) { \
	TYPE *tq = (TYPE *) q; \
	TYPE *tp = (TYPE *) p; \
	TYPE *tc = (TYPE *) c; \
 	\
	for( i = 0, x = 0; x < n; x++ ) \
		for( b = 0; b < bands; b++, i++ ) \
			tq[i] = tp[i] ^ tc[b]; \
}

/* The above, wrapped up as buffer processing functions.
 */
static void
and_buffer( PEL **p, PEL *q, int n, IMAGE *im )
{
	const int ne = n * im->Bands;

	int x;

        switch( im->BandFmt ) {
        case IM_BANDFMT_CHAR:	AND2( signed char ); break;
        case IM_BANDFMT_UCHAR:  AND2( unsigned char ); break;
        case IM_BANDFMT_SHORT:  AND2( signed short ); break;
        case IM_BANDFMT_USHORT: AND2( unsigned short ); break;
        case IM_BANDFMT_INT:    AND2( signed int ); break;
        case IM_BANDFMT_UINT:   AND2( unsigned int ); break;

        default:
                g_assert( 0 );
        }
}

static void
or_buffer( PEL **p, PEL *q, int n, IMAGE *im )
{
	const int ne = n * im->Bands;

	int x;

        switch( im->BandFmt ) {
        case IM_BANDFMT_CHAR:	OR2( signed char ); break;
        case IM_BANDFMT_UCHAR:  OR2( unsigned char ); break;
        case IM_BANDFMT_SHORT:  OR2( signed short ); break;
        case IM_BANDFMT_USHORT: OR2( unsigned short ); break;
        case IM_BANDFMT_INT:    OR2( signed int ); break;
        case IM_BANDFMT_UINT:   OR2( unsigned int ); break;

        default:
                g_assert( 0 );
        }
}

static void
eor_buffer( PEL **p, PEL *q, int n, IMAGE *in1 )
{
	const int ne = n * im->Bands;

	int x;

        switch( im->BandFmt ) {
        case IM_BANDFMT_CHAR:	EOR2( signed char ); break;
        case IM_BANDFMT_UCHAR:  EOR2( unsigned char ); break;
        case IM_BANDFMT_SHORT:  EOR2( signed short ); break;
        case IM_BANDFMT_USHORT: EOR2( unsigned short ); break;
        case IM_BANDFMT_INT:    EOR2( signed int ); break;
        case IM_BANDFMT_UINT:   EOR2( unsigned int ); break;

        default:
                g_assert( 0 );
        }
}

static void
andconst_buffer( PEL *p, PEL *q, int n, IMAGE *in, PEL *c )
{
	int x, i, b;
	int bands = in->Bands;

        switch( in->BandFmt ) {
        case IM_BANDFMT_CHAR:	ANDCONST( signed char ); break;
        case IM_BANDFMT_UCHAR:  ANDCONST( unsigned char ); break;
        case IM_BANDFMT_SHORT:  ANDCONST( signed short ); break;
        case IM_BANDFMT_USHORT: ANDCONST( unsigned short ); break;
        case IM_BANDFMT_INT:    ANDCONST( signed int ); break;
        case IM_BANDFMT_UINT:   ANDCONST( unsigned int ); break;

        default:
                g_assert( 0 );
        }
}

static void
orconst_buffer( PEL *p, PEL *q, int n, IMAGE *in, PEL *c )
{
	int x, i, b;
	int bands = in->Bands;

        switch( in->BandFmt ) {
        case IM_BANDFMT_CHAR:	ORCONST( signed char ); break;
        case IM_BANDFMT_UCHAR:  ORCONST( unsigned char ); break;
        case IM_BANDFMT_SHORT:  ORCONST( signed short ); break;
        case IM_BANDFMT_USHORT: ORCONST( unsigned short ); break;
        case IM_BANDFMT_INT:    ORCONST( signed int ); break;
        case IM_BANDFMT_UINT:   ORCONST( unsigned int ); break;

        default:
                g_assert( 0 );
        }
}

static void
eorconst_buffer( PEL *p, PEL *q, int n, IMAGE *in, PEL *c )
{
	int x, i, b;
	int bands = in->Bands;

        switch( in->BandFmt ) {
        case IM_BANDFMT_CHAR:	EORCONST( signed char ); break;
        case IM_BANDFMT_UCHAR:  EORCONST( unsigned char ); break;
        case IM_BANDFMT_SHORT:  EORCONST( signed short ); break;
        case IM_BANDFMT_USHORT: EORCONST( unsigned short ); break;
        case IM_BANDFMT_INT:    EORCONST( signed int ); break;
        case IM_BANDFMT_UINT:   EORCONST( unsigned int ); break;

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

/* Type conversions for boolean. 
 */
static int bandfmt_bool[10] = {
/* UC  C   US  S   UI  I   F   X   D   DX */
   UC, C,  US, S,  UI, I,  I,  I,  I,  I },
};

/* The above, wrapped up as im_*() functions.
 */
int 
im_andimage( IMAGE *in1, IMAGE *in2, IMAGE *out )
{
	return( im__arith_binary( "im_andimage",
		in1, in2, out, 
		bandfmt_bool,
		(im_wrapmany_fn) and_buffer, NULL ) );
}

int 
im_orimage( IMAGE *in1, IMAGE *in2, IMAGE *out )
{
	return( im__arith_binary( "im_orimage",
		in1, in2, out, 
		bandfmt_bool,
		(im_wrapmany_fn) or_buffer, NULL ) );
}

int 
im_eorimage( IMAGE *in1, IMAGE *in2, IMAGE *out )
{
	return( im__arith_binary( "im_eorimage",
		in1, in2, out, 
		bandfmt_bool,
		(im_wrapmany_fn) eor_buffer, NULL ) );
}

int 
im_and_vec( IMAGE *in, IMAGE *out, int n, double *c )
{
	IMAGE *invec[2];
	PEL *cb;

	invec[0] = in; invec[1] = NULL;
	if( check( invec, out ) )
		return( -1 );
	in = invec[0];
	if( n != in->Bands ) {
		im_error( "im_and_vec", 
			"%s", _( "vec size does not match bands" ) );
		return( -1 );
	}
	if( !(cb = make_pixel( out, in->BandFmt, c )) )
		return( -1 );

	if( im_wrapone( in, out, 
		(im_wrapone_fn) andconst_buffer, (void *) in, (void *) cb ) )
		return( -1 );

	return( 0 );
}

int 
im_or_vec( IMAGE *in, IMAGE *out, int n, double *c )
{
	IMAGE *invec[2];
	PEL *cb;

	invec[0] = in; invec[1] = NULL;
	if( check( invec, out ) )
		return( -1 );
	in = invec[0];
	if( n != in->Bands ) {
		im_error( "im_or_vec", 
			"%s", _( "vec size does not match bands" ) );
		return( -1 );
	}
	if( !(cb = make_pixel( out, in->BandFmt, c )) )
		return( -1 );

	if( im_wrapone( in, out, 
		(im_wrapone_fn) orconst_buffer, (void *) in, (void *) cb ) )
		return( -1 );

	return( 0 );
}

int 
im_eor_vec( IMAGE *in, IMAGE *out, int n, double *c )
{
	IMAGE *invec[2];
	PEL *cb;

	invec[0] = in; invec[1] = NULL;
	if( check( invec, out ) )
		return( -1 );
	in = invec[0];
	if( n != in->Bands ) {
		im_error( "im_eor_vec", 
			"%s", _( "vec size does not match bands" ) );
		return( -1 );
	}
	if( !(cb = make_pixel( out, in->BandFmt, c )) )
		return( -1 );

	if( im_wrapone( in, out, 
		(im_wrapone_fn) eorconst_buffer, (void *) in, (void *) cb ) )
		return( -1 );

	return( 0 );
}

/* Cast a double to a vector of TYPE.
 */
#define CCAST( TYPE ) { \
	TYPE *tq = (TYPE *) q; \
	\
	for( i = 0; i < in->Bands; i++ ) \
		tq[i] = (TYPE) p; \
}

/* Make a pixel of output type from a single double.
 */
static double *
make_pixel_const( IMAGE *in, IMAGE *out, double p )
{
	double *q;
	int i;

	if( !(q = IM_ARRAY( out, in->Bands, double )) )
		return( NULL );
	for( i = 0; i < in->Bands; i++ ) 
		q[i] = p; 

	return( q );
}

int 
im_andconst( IMAGE *in, IMAGE *out, double c )
{
	double *v = make_pixel_const( in, out, c );

	return( !v || im_and_vec( in, out, in->Bands, v ) ); 
}

int 
im_orconst( IMAGE *in, IMAGE *out, double c )
{
	double *v = make_pixel_const( in, out, c );

	return( !v || im_or_vec( in, out, in->Bands, v ) );
}

int 
im_eorconst( IMAGE *in, IMAGE *out, double c )
{
	double *v = make_pixel_const( in, out, c );

	return( !v || im_eor_vec( in, out, in->Bands, v ) );
}

/* Assorted shift operations.
 */
#define SHIFTL( TYPE ) { \
	TYPE *pt = (TYPE *) p;\
	TYPE *qt = (TYPE *) q;\
	\
	for( x = 0; x < ne; x++ )\
		qt[x] = pt[x] << n;\
}

/* The above as buffer ops.
 */
static void
shiftleft_buffer( PEL *p, PEL *q, int len, IMAGE *in, int n )
{
	int x;
	int ne = len * in->Bands;

        switch( in->BandFmt ) {
        case IM_BANDFMT_UCHAR: 	SHIFTL( unsigned char ); break;
        case IM_BANDFMT_CHAR: 	SHIFTL( signed char ); break; 
        case IM_BANDFMT_USHORT:	SHIFTL( unsigned short ); break; 
        case IM_BANDFMT_SHORT: 	SHIFTL( signed short ); break; 
        case IM_BANDFMT_UINT: 	SHIFTL( unsigned int ); break; 
        case IM_BANDFMT_INT: 	SHIFTL( signed int );  break; 

	default:
                g_assert( 0 );
	}
}

/* The above as im_*() functions.
 */
int 
im_shiftleft( IMAGE *in, IMAGE *out, int n )
{
	IMAGE *invec[2];

	invec[0] = in; invec[1] = NULL;
	if( check( invec, out ) )
		return( -1 );
	in = invec[0];

	if( im_wrapone( in, out, 
		(im_wrapone_fn) shiftleft_buffer, in, GINT_TO_POINTER( n ) ) )
		return( -1 );

	return( 0 );
}

#define SHIFTR( TYPE ) { \
	TYPE *pt = (TYPE *) p; \
	TYPE *qt = (TYPE *) q; \
	\
	for( x = 0; x < ne; x++ ) \
		qt[x] = pt[x] >> n; \
}

static void
shiftright_buffer( PEL *p, PEL *q, int len, IMAGE *in, int n )
{
	int x;
	int ne = len * in->Bands;

        switch( in->BandFmt ) {
        case IM_BANDFMT_UCHAR: 	SHIFTR( unsigned char ); break;
        case IM_BANDFMT_CHAR: 	SHIFTR( signed char ); break; 
        case IM_BANDFMT_USHORT:	SHIFTR( unsigned short ); break; 
        case IM_BANDFMT_SHORT: 	SHIFTR( signed short ); break; 
        case IM_BANDFMT_UINT: 	SHIFTR( unsigned int ); break; 
        case IM_BANDFMT_INT: 	SHIFTR( signed int );  break; 

	default:
                g_assert( 0 );
	}
}

int 
im_shiftright( IMAGE *in, IMAGE *out, int n )
{
	IMAGE *invec[2];

	invec[0] = in; invec[1] = NULL;
	if( check( invec, out ) )
		return( -1 );
	in = invec[0];

	if( im_wrapone( in, out, 
		(im_wrapone_fn) shiftright_buffer, in, GINT_TO_POINTER( n ) ) )
		return( -1 );

	return( 0 );
}
