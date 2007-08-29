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
#include <assert.h>

#include <vips/vips.h>

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
#define F IM_BANDFMT_FLOAT
#define M IM_BANDFMT_COMPLEX
#define D IM_BANDFMT_DOUBLE
#define DM IM_BANDFMT_DPCOMPLEX

/* Type conversions for boolean.
 */
static int iformat[10][10] = {
        /* UC  C   US  S   UI  I   F   M   D   DM */
/* UC */ { UC, C,  US, S,  UI, I,  I,  I,  I,  I },
/* C */  { C,  C,  S,  S,  I,  I,  I,  I,  I,  I },
/* US */ { US, S,  US, S,  UI, I,  I,  I,  I,  I },
/* S */  { S,  S,  S,  S,  I,  I,  I,  I,  I,  I },
/* UI */ { UI, I,  UI, I,  UI, I,  I,  I,  I,  I },
/* I */  { I,  I,  I,  I,  I,  I,  I,  I,  I,  I },
/* F */  { I,  I,  I,  I,  I,  I,  I,  I,  I,  I },
/* M */  { I,  I,  I,  I,  I,  I,  I,  I,  I,  I },
/* D */  { I,  I,  I,  I,  I,  I,  I,  I,  I,  I },
/* DM */ { I,  I,  I,  I,  I,  I,  I,  I,  I,  I }
};

/* Check args. Cast inputs to matching integer format.
 */
static int
check( char *name, IMAGE **in, IMAGE *out )
{
	int i, n;

	/* Count args.
	 */
	for( n = 0; in[n]; n++ ) {
		if( in[n]->Coding != IM_CODING_NONE ) {
			im_errormsg( "%s: uncoded images only", name );
			return( -1 );
		}
	}

	/* Check sizes match.
	 */
	for( i = 1; i < n; i++ )
		if( in[0]->Bands != in[i]->Bands ||
			in[0]->Xsize != in[i]->Xsize ||
			in[0]->Ysize != in[i]->Ysize ) {
			im_errormsg( "%s: images differ in size", name );
			return( -1 );
		}

	/* Prepare the output image.
	 */
	if( im_cp_desc_array( out, in ) )
		return( -1 );

	/* Calculate type conversion ... just 1ary and 2ary.
	 */
	switch( n ) {
	case 1:
		out->BandFmt = iformat[0][in[0]->BandFmt];
		break;

	case 2:
		out->BandFmt = iformat[in[1]->BandFmt][in[0]->BandFmt];
		break;

	default:
		assert( FALSE );
	}

	for( i = 0; i < n; i++ ) {
		IMAGE *t = im_open_local( out, name, "p" );

		if( !t || im_clip2fmt( in[i], t, out->BandFmt ) )
			return( -1 );
		in[i] = t;
	}

	return( 0 );
}

/* A selection of main loops. As with im_add(), only implement monotype
 * operations. TYPE is some integer type, signed or unsigned.
 */
#define AND2( TYPE ) \
{ \
	TYPE *tq = (TYPE *) q; \
	TYPE *tp1 = (TYPE *) p1; \
	TYPE *tp2 = (TYPE *) p2; \
 	\
	for( x = 0; x < ne; x++ )  \
		tq[x] = tp1[x] & tp2[x]; \
}

#define OR2( TYPE ) \
{ \
	TYPE *tq = (TYPE *) q; \
	TYPE *tp1 = (TYPE *) p1; \
	TYPE *tp2 = (TYPE *) p2; \
 	\
	for( x = 0; x < ne; x++ )  \
		tq[x] = tp1[x] | tp2[x]; \
}

#define EOR2( TYPE ) \
{ \
	TYPE *tq = (TYPE *) q; \
	TYPE *tp1 = (TYPE *) p1; \
	TYPE *tp2 = (TYPE *) p2; \
 	\
	for( x = 0; x < ne; x++ )  \
		tq[x] = tp1[x] ^ tp2[x]; \
}

#define ANDCONST( TYPE ) \
{ \
	TYPE *tq = (TYPE *) q; \
	TYPE *tp = (TYPE *) p; \
	TYPE *tc = (TYPE *) c; \
 	\
	for( i = 0, x = 0; x < n; x++ ) \
		for( b = 0; b < bands; b++, i++ ) \
			tq[i] = tp[i] & tc[b]; \
}

#define ORCONST( TYPE ) \
{ \
	TYPE *tq = (TYPE *) q; \
	TYPE *tp = (TYPE *) p; \
	TYPE *tc = (TYPE *) c; \
 	\
	for( i = 0, x = 0; x < n; x++ ) \
		for( b = 0; b < bands; b++, i++ ) \
			tq[i] = tp[i] | tc[b]; \
}

#define EORCONST( TYPE ) \
{ \
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
	int x;
	int bands = im->Bands;
	int ne = n * bands;
	PEL *p1 = p[0];
	PEL *p2 = p[1];

        switch( im->BandFmt ) {
        case IM_BANDFMT_CHAR:	AND2( signed char ); break;
        case IM_BANDFMT_UCHAR:  AND2( unsigned char ); break;
        case IM_BANDFMT_SHORT:  AND2( signed short ); break;
        case IM_BANDFMT_USHORT: AND2( unsigned short ); break;
        case IM_BANDFMT_INT:    AND2( signed int ); break;
        case IM_BANDFMT_UINT:   AND2( unsigned int ); break;

        default:
                error_exit( "im_and: internal error" );
        }
}

static void
or_buffer( PEL **p, PEL *q, int n, IMAGE *in1 )
{
	int x;
	int bands = in1->Bands;
	int ne = n * bands;
	PEL *p1 = p[0];
	PEL *p2 = p[1];

        switch( in1->BandFmt ) {
        case IM_BANDFMT_CHAR:	OR2( signed char ); break;
        case IM_BANDFMT_UCHAR:  OR2( unsigned char ); break;
        case IM_BANDFMT_SHORT:  OR2( signed short ); break;
        case IM_BANDFMT_USHORT: OR2( unsigned short ); break;
        case IM_BANDFMT_INT:    OR2( signed int ); break;
        case IM_BANDFMT_UINT:   OR2( unsigned int ); break;

        default:
                error_exit( "im_or: internal error" );
        }
}

static void
eor_buffer( PEL **p, PEL *q, int n, IMAGE *in1 )
{
	int x;
	int bands = in1->Bands;
	int ne = n * bands;
	PEL *p1 = p[0];
	PEL *p2 = p[1];

        switch( in1->BandFmt ) {
        case IM_BANDFMT_CHAR:	EOR2( signed char ); break;
        case IM_BANDFMT_UCHAR:  EOR2( unsigned char ); break;
        case IM_BANDFMT_SHORT:  EOR2( signed short ); break;
        case IM_BANDFMT_USHORT: EOR2( unsigned short ); break;
        case IM_BANDFMT_INT:    EOR2( signed int ); break;
        case IM_BANDFMT_UINT:   EOR2( unsigned int ); break;

        default:
                error_exit( "im_eor: internal error" );
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
                error_exit( "im_andconst: internal error" );
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
                error_exit( "im_orconst: internal error" );
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
                error_exit( "im_eorconst: internal error" );
        }
}

/* The above, wrapped up as im_*() functions.
 */
int 
im_andimage( IMAGE *in1, IMAGE *in2, IMAGE *out )
{
	IMAGE *invec[3];

	/* Check images.
	 */
	invec[0] = in1; invec[1] = in2; invec[2] = NULL;
	if( check( "im_andimage", invec, out ) )
		return( -1 );

	/* Process!
	 */
	if( im_wrapmany( invec, out, (im_wrapmany_fn) and_buffer, out, NULL ) )
		return( -1 );

	return( 0 );
}

int 
im_orimage( IMAGE *in1, IMAGE *in2, IMAGE *out )
{	
	IMAGE *invec[3];

	invec[0] = in1; invec[1] = in2; invec[2] = NULL;
	if( check( "im_orimage", invec, out ) )
		return( -1 );

	if( im_wrapmany( invec, out, (im_wrapmany_fn) or_buffer, out, NULL ) )
		return( -1 );

	return( 0 );
}

int 
im_eorimage( IMAGE *in1, IMAGE *in2, IMAGE *out )
{	
	IMAGE *invec[3];

	invec[0] = in1; invec[1] = in2; invec[2] = NULL;
	if( check( "im_eorimage", invec, out ) )
		return( -1 );

	if( im_wrapmany( invec, out, (im_wrapmany_fn) eor_buffer, out, NULL ) )
		return( -1 );

	return( 0 );
}

/* Cast a vector of double to a vector of TYPE.
 */
#define CAST( TYPE ) \
{ \
	TYPE *tq = (TYPE *) q; \
	\
	for( i = 0; i < out->Bands; i++ ) \
		tq[i] = (TYPE) p[i]; \
}

/* Make a pixel of output type from a realvec.
 */
static PEL *
make_pixel( IMAGE *out, double *p )
{
	PEL *q;
	int i;

	if( !(q = IM_ARRAY( out, IM_IMAGE_SIZEOF_PEL( out ), PEL )) )
		return( NULL );

        switch( out->BandFmt ) {
        case IM_BANDFMT_CHAR:	CAST( signed char ); break;
        case IM_BANDFMT_UCHAR:  CAST( unsigned char ); break;
        case IM_BANDFMT_SHORT:  CAST( signed short ); break;
        case IM_BANDFMT_USHORT: CAST( unsigned short ); break;
        case IM_BANDFMT_INT:    CAST( signed int ); break;
        case IM_BANDFMT_UINT:   CAST( unsigned int ); break;

        default:
                error_exit( "make_pixel: internal error" );
        }

	return( q );
}

int 
im_and_vec( IMAGE *in, IMAGE *out, int n, double *c )
{
	IMAGE *invec[2];
	PEL *cb;

	invec[0] = in; invec[1] = NULL;
	if( check( "im_andconst", invec, out ) )
		return( -1 );
	in = invec[0];
	if( n != in->Bands ) {
		im_errormsg( "im_and_vec: vec size does not match bands" );
		return( -1 );
	}
	if( !(cb = make_pixel( out, c )) )
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
	if( check( "im_orconst", invec, out ) )
		return( -1 );
	in = invec[0];
	if( n != in->Bands ) {
		im_errormsg( "im_or_vec: vec size does not match bands" );
		return( -1 );
	}
	if( !(cb = make_pixel( out, c )) )
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
	if( check( "im_eorconst", invec, out ) )
		return( -1 );
	in = invec[0];
	if( n != in->Bands ) {
		im_errormsg( "im_eor_vec: vec size does not match bands" );
		return( -1 );
	}
	if( !(cb = make_pixel( out, c )) )
		return( -1 );

	if( im_wrapone( in, out, 
		(im_wrapone_fn) eorconst_buffer, (void *) in, (void *) cb ) )
		return( -1 );

	return( 0 );
}

/* Cast a double to a vector of TYPE.
 */
#define CCAST( TYPE ) \
{ \
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
#define SHIFTL( TYPE ) \
{\
	TYPE *pt = (TYPE *) p;\
	TYPE *qt = (TYPE *) q;\
	\
	for( x = 0; x < ne; x++ )\
		qt[x] = pt[x] << n;\
}

#define SHIFTR( TYPE ) \
{\
	TYPE *pt = (TYPE *) p;\
	TYPE *qt = (TYPE *) q;\
	\
	for( x = 0; x < ne; x++ )\
		qt[x] = pt[x] >> n;\
}

/* The above as buffer ops.
 */
static void
shiftleft_buffer( PEL *p, PEL *q, int len, IMAGE *in, int n )
{
	int x;
	int ne = len * in->Bands;

        switch( in->BandFmt ) {
        case IM_BANDFMT_UCHAR: 	SHIFTL(unsigned char); break;
        case IM_BANDFMT_CHAR: 	SHIFTL(signed char); break; 
        case IM_BANDFMT_USHORT:	SHIFTL(unsigned short); break; 
        case IM_BANDFMT_SHORT: 	SHIFTL(signed short); break; 
        case IM_BANDFMT_UINT: 	SHIFTL(unsigned int); break; 
        case IM_BANDFMT_INT: 	SHIFTL(signed int);  break; 

	default:
		error_exit( "im_shiftleft: internal error" );
		/*NOTREACHED*/
	}
}

static void
shiftright_buffer( PEL *p, PEL *q, int len, IMAGE *in, int n )
{
	int x;
	int ne = len * in->Bands;

        switch( in->BandFmt ) {
        case IM_BANDFMT_UCHAR: 	SHIFTR(unsigned char); break;
        case IM_BANDFMT_CHAR: 	SHIFTR(signed char); break; 
        case IM_BANDFMT_USHORT:	SHIFTR(unsigned short); break; 
        case IM_BANDFMT_SHORT: 	SHIFTR(signed short); break; 
        case IM_BANDFMT_UINT: 	SHIFTR(unsigned int); break; 
        case IM_BANDFMT_INT: 	SHIFTR(signed int);  break; 

	default:
		error_exit( "im_shiftright: internal error" );
		/*NOTREACHED*/
	}
}

/* The above as im_*() functions.
 */
int 
im_shiftleft( IMAGE *in, IMAGE *out, int n )
{
	IMAGE *invec[2];

	invec[0] = in; invec[1] = NULL;
	if( check( "im_shiftleft", invec, out ) )
		return( -1 );
	in = invec[0];

	if( im_wrapone( in, out, 
		(im_wrapone_fn) shiftleft_buffer, in, GINT_TO_POINTER( n ) ) )
		return( -1 );

	return( 0 );
}

int 
im_shiftright( IMAGE *in, IMAGE *out, int n )
{
	IMAGE *invec[2];

	invec[0] = in; invec[1] = NULL;
	if( check( "im_shiftleft", invec, out ) )
		return( -1 );
	in = invec[0];

	if( im_wrapone( in, out, 
		(im_wrapone_fn) shiftright_buffer, in, GINT_TO_POINTER( n ) ) )
		return( -1 );

	return( 0 );
}
