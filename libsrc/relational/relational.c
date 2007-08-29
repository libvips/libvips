/* @(#) Relational operations on VASARI images. All return a unsigned
 * @(#) char image with the same number of bands as the input images. 255
 * @(#) for true, 0 for false. All work with mixed images types: eg. 
 * @(#) comparing float and byte.
 * @(#)
 * @(#) int im_equal( a, b, out )	int im_notequal( a, b, out )
 * @(#) IMAGE *a, *b, *out;		IMAGE *a, *b, *out;
 * @(#)
 * @(#)
 * @(#) int im_equalconst( a, out, c )	int im_notequalconst( a, out, c )
 * @(#) IMAGE *a, *out;			IMAGE *a, *out;
 * @(#) double c;			double c;
 * @(#)
 * @(#) int im_less( a, b, out )	int im_lessconst( a, out, c )
 * @(#) IMAGE *a, *b, *out;		IMAGE *a, *out;
 * @(#)					double c;
 * @(#)
 * @(#) int im_more( a, b, out )	int im_moreconst( a, out, c )
 * @(#) IMAGE *a, *b, *out;		IMAGE *a, *out;
 * @(#)					double c;
 * @(#)
 * @(#) int im_lesseq( a, b, out )	int im_lesseqconst( a, out, c )
 * @(#) IMAGE *a, *b, *out;		IMAGE *a, *out;
 * @(#)					double c;
 * @(#)
 * @(#) int im_moreeq( a, b, out )	int im_moreeqconst( a, out, c )
 * @(#) IMAGE *a, *b, *out;		IMAGE *a, *out;
 * @(#)					double c;
 * @(#)
 * @(#) Returns either 0 (success) or -1 (fail).
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
#include <assert.h>
#include <math.h>

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

/* Type conversions for relational operators. For two input types, give the
 * smallest common type, that is, the smallest type which can completely
 * express the range of each.
 */
static int relational_format[10][10] = {
	/* UC  C   US  S   UI  I   F   M   D   DM */
/* UC */ { UC, S,  US, S,  UI, I,  F,  M,  D,  DM },
/* C  */ { S,  C,  I,  S,  D,  I,  F,  M,  D,  DM },
/* US */ { US, I,  US, I,  UI, I,  F,  M,  D,  DM },
/* S  */ { S,  S,  I,  S,  D,  I,  F,  M,  D,  DM },
/* UI */ { UI, D,  UI, D,  UI, D,  F,  M,  D,  DM },
/* I  */ { I,  I,  I,  I,  D,  I,  F,  M,  D,  DM },
/* F  */ { F,  F,  F,  F,  F,  F,  F,  M,  D,  DM },
/* M  */ { M,  M,  M,  M,  M,  M,  M,  M,  DM, DM },
/* D  */ { D,  D,  D,  D,  D,  D,  D,  DM, D,  DM },
/* DM */ { DM, DM, DM, DM, DM, DM, DM, DM, DM, DM }
};

/* Check input images, cast both up to the smallest common type, and invoke
 * the process function.
 */
static int
relational_process( char *name, IMAGE **in, IMAGE *out, 
	im_wrapmany_fn fn, void *b )
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

	/* Check sizes match. We don't need to check xsize/ysize, as wrapmany
	 * does this for us.
	 */
	for( i = 1; i < n; i++ )
		if( in[0]->Bands != in[i]->Bands ) {
			im_errormsg( "%s: images differ in numbers of bands", 
				name );
			return( -1 );
		}

	/* Prepare the output image.
	 */
	if( im_cp_desc_array( out, in ) )
		return( -1 );
	out->BandFmt = IM_BANDFMT_UCHAR;
	out->Bbits = IM_BBITS_BYTE;

	/* For binary ops, cast inputs up to a common format.
	 */
	if( n == 2 ) {
		int fmt = relational_format[in[0]->BandFmt][in[1]->BandFmt];
		IMAGE *t[3];

		if( im_open_local_array( out, t, 2, "relational-1", "p" ) )
			return( -1 );
		t[2] = NULL;

		for( i = 0; i < n; i++ )
			if( im_clip2fmt( in[i], t[i], fmt ) )
				return( -1 );

		if( im_wrapmany( t, out, fn, t[0], b ) )
			return( -1 );
	}
	else
		if( im_wrapmany( in, out, fn, in[0], b ) )
			return( -1 );

	return( 0 );
}

/* Switch over bandfmt, calling a complexd and a non-complex processor.
 */
#define SWITCH( T, P_REAL, P_COMPLEX ) \
        switch( T ) {\
	case IM_BANDFMT_UCHAR: \
		P_REAL( unsigned char ); \
		break; \
	case IM_BANDFMT_CHAR: \
		P_REAL( char ); \
		break; \
	case IM_BANDFMT_USHORT: \
		P_REAL( unsigned short ); \
		break; \
	case IM_BANDFMT_SHORT: \
		P_REAL( short ); \
		break; \
	case IM_BANDFMT_UINT: \
		P_REAL( unsigned int ); \
		break; \
	case IM_BANDFMT_INT: \
		P_REAL( int ); \
		break; \
	case IM_BANDFMT_FLOAT: \
		P_REAL( float ); \
		break; \
	case IM_BANDFMT_DOUBLE: \
		P_REAL( double ); \
		break; \
	case IM_BANDFMT_COMPLEX: \
		P_COMPLEX( float ); \
		break; \
	case IM_BANDFMT_DPCOMPLEX: \
		P_COMPLEX( double ); \
		break; \
	default:\
		error_exit( "relational: internal error" );\
	}

static void
equal_buffer( PEL **p, PEL *q, int n, IMAGE *a )
{
	int ne = n * a->Bands;
	PEL *p1 = p[0];
	PEL *p2 = p[1];
	int x;

#define EQUAL_REAL( TYPE ) { \
	TYPE *i = (TYPE *) p1; \
	TYPE *j = (TYPE *) p2; \
	\
	for( x = 0; x < ne; x++ ) \
		if( i[x] == j[x] ) \
			q[x] = 255; \
		else \
			q[x] = 0; \
}

#define EQUAL_COMPLEX( TYPE ) { \
	TYPE *i = (TYPE *) p1; \
	TYPE *j = (TYPE *) p2; \
	\
	for( x = 0; x < ne; x++ ) { \
		if( i[0] == j[0] && i[1] == j[1] ) \
			q[x] = 255; \
		else \
			q[x] = 0; \
		\
		i += 2; \
		j += 2; \
	} \
}

	SWITCH( a->BandFmt, EQUAL_REAL, EQUAL_COMPLEX );
}

int 
im_equal( IMAGE *in1, IMAGE *in2, IMAGE *out )
{
	IMAGE *invec[3];

	invec[0] = in1; invec[1] = in2; invec[2] = NULL;
	if( relational_process( "im_equal", invec, out, 
		(im_wrapmany_fn) equal_buffer, NULL ) )
		return( -1 );

	return( 0 );
}

static void
notequal_buffer( PEL **p, PEL *q, int n, IMAGE *a )
{
	int ne = n * a->Bands;
	PEL *p1 = p[0];
	PEL *p2 = p[1];
	int x;

#define NOTEQUAL_REAL( TYPE ) { \
	TYPE *i = (TYPE *) p1; \
	TYPE *j = (TYPE *) p2; \
	\
	for( x = 0; x < ne; x++ ) \
		if( i[x] != j[x] ) \
			q[x] = 255; \
		else \
			q[x] = 0; \
}

#define NOTEQUAL_COMPLEX( TYPE ) { \
	TYPE *i = (TYPE *) p1; \
	TYPE *j = (TYPE *) p2; \
	\
	for( x = 0; x < ne; x++ ) { \
		if( i[0] != j[0] || i[1] != j[1] ) \
			q[x] = 255; \
		else \
			q[x] = 0; \
		\
		i += 2; \
		j += 2; \
	} \
}

	SWITCH( a->BandFmt, NOTEQUAL_REAL, NOTEQUAL_COMPLEX );
}

int 
im_notequal( IMAGE *in1, IMAGE *in2, IMAGE *out )
{
	IMAGE *invec[3];

	invec[0] = in1; invec[1] = in2; invec[2] = NULL;
	if( relational_process( "im_equal", invec, out, 
		(im_wrapmany_fn) notequal_buffer, NULL ) )
		return( -1 );

	return( 0 );
}

/* strdup a vector of doubles.
 */
static double *
numdup( IMAGE *out, int n, double *c )
{
	double *p = IM_ARRAY( out, n, double );
	int i;

	if( !p )
		return( NULL );

	for( i = 0; i < n; i++ )
		p[i] = c[i];

	return( p );
}

static void
equalvec_buffer( PEL **in, PEL *out, int n, IMAGE *a, double *c )
{
	int x, b, i;

#define EQUALVEC_REAL( TYPE ) { \
	TYPE *p = (TYPE *) in[0]; \
	\
	for( i = 0, x = 0; x < n; x++ ) \
		for( b = 0; b < a->Bands; b++, i++ ) \
			if( p[i] == c[b] ) \
				out[i] = 255; \
			else \
				out[i] = 0; \
}

/* Sanity failure! 
 */
#define EQUALVEC_COMPLEX( TYPE ) assert( 0 );

	SWITCH( a->BandFmt, EQUALVEC_REAL, EQUALVEC_COMPLEX );
}

int 
im_equal_vec( IMAGE *in, IMAGE *out, int n, double *c )
{
	IMAGE *invec[2];
	double *p;

	if( n != in->Bands ) {
		im_errormsg( "im_equal_vec: vec size does not match bands" );
		return( -1 );
	}
	if( im_iscomplex( in ) ) {
		im_errormsg( "im_equal_vec: not implemented for complex" );
		return( -1 );
	}

	invec[0] = in; invec[1] = NULL;
	if( !(p = numdup( out, n, c )) || 
		relational_process( "im_equal_vec", invec, out, 
			(im_wrapmany_fn) equalvec_buffer, (void *) p ) )
		return( -1 );

	return( 0 );
}

static double *
mkvec( IMAGE *in, IMAGE *out, double c )
{
	double *v;
	int i;

	if( !(v = IM_ARRAY( out, in->Bands, double )) )
		return( NULL );
	for( i = 0; i < in->Bands; i++ )
		v[i] = c;
	
	return( v );
}

int 
im_equalconst( IMAGE *in, IMAGE *out, double c )
{
	double *v;

	return( !(v = mkvec( in, out, c )) || 
		im_equal_vec( in, out, in->Bands, v ) );
}

static void
notequalvec_buffer( PEL **in, PEL *out, int n, IMAGE *a, double *c )
{
	int x, b, i;

#define NOTEQUALVEC_REAL( TYPE ) { \
	TYPE *p = (TYPE *) in[0]; \
	\
	for( i = 0, x = 0; x < n; x++ ) \
		for( b = 0; b < a->Bands; b++, i++ ) \
			if( p[i] != c[b] ) \
				out[i] = 255; \
			else \
				out[i] = 0; \
}

#define NOTEQUALVEC_COMPLEX( TYPE ) assert( 0 );

	SWITCH( a->BandFmt, NOTEQUALVEC_REAL, NOTEQUALVEC_COMPLEX );
}

int 
im_notequal_vec( IMAGE *in, IMAGE *out, int n, double *c )
{
	IMAGE *invec[2];
	double *p;

	if( n != in->Bands ) {
		im_errormsg( "im_notequal_vec: vec size does not match bands" );
		return( -1 );
	}
	if( im_iscomplex( in ) ) {
		im_errormsg( "im_notequal_vec: not implemented for complex" );
		return( -1 );
	}

	invec[0] = in; invec[1] = NULL;
	if( !(p = numdup( out, n, c )) || 
		relational_process( "im_notequal_vec", invec, out, 
			(im_wrapmany_fn) notequalvec_buffer, (void *) p ) )
		return( -1 );

	return( 0 );
}

int
im_notequalconst( IMAGE *in, IMAGE *out, double c )
{
	double *v;

	return( !(v = mkvec( in, out, c )) || 
		im_notequal_vec( in, out, in->Bands, v ) );
}

static void
less_buffer( PEL **p, PEL *q, int n, IMAGE *a, IMAGE *b )
{
	int ne = n * a->Bands;
	PEL *p1 = p[0];
	PEL *p2 = p[1];
	int x;

#define LESS_REAL( TYPE ) { \
	TYPE *i = (TYPE *) p1; \
	TYPE *j = (TYPE *) p2; \
	\
	for( x = 0; x < ne; x++ ) \
		if( i[x] < j[x] ) \
			q[x] = 255; \
		else \
			q[x] = 0; \
}

/* Take the mod and compare that.
 */
#define LESS_COMPLEX( TYPE ) { \
	TYPE *i = (TYPE *) p1; \
	TYPE *j = (TYPE *) p2; \
	\
	for( x = 0; x < ne; x++ ) { \
		double m1 = sqrt( i[0] * i[0] + i[1] * i[1] ); \
		double m2 = sqrt( j[0] * j[0] + j[1] * j[1] ); \
		\
		if( m1 < m2 ) \
			q[x] = 255; \
		else \
			q[x] = 0; \
		\
		i += 2; \
		j += 2; \
	} \
}

	SWITCH( a->BandFmt, LESS_REAL, LESS_COMPLEX );
}

int 
im_less( IMAGE *in1, IMAGE *in2, IMAGE *out )
{
	IMAGE *invec[3];

	invec[0] = in1; invec[1] = in2; invec[2] = NULL;
	if( relational_process( "im_less", invec, out, 
		(im_wrapmany_fn) less_buffer, NULL ) )
		return( -1 );

	return( 0 );
}

static void
lessvec_buffer( PEL **in, PEL *out, int n, IMAGE *a, double *c )
{
	int x, b, i;

#define LESSVEC_REAL( TYPE ) { \
	TYPE *p = (TYPE *) in[0]; \
	\
	for( i = 0, x = 0; x < n; x++ ) \
		for( b = 0; b < a->Bands; b++, i++ ) \
			if( p[i] < c[b] ) \
				out[i] = 255; \
			else \
				out[i] = 0; \
}

#define LESSVEC_COMPLEX( TYPE ) assert( 0 );

	SWITCH( a->BandFmt, LESSVEC_REAL, LESSVEC_COMPLEX );
}

int 
im_less_vec( IMAGE *in, IMAGE *out, int n, double *c )
{
	IMAGE *invec[2];
	double *p;

	if( n != in->Bands ) {
		im_errormsg( "im_less_vec: vec size does not match bands" );
		return( -1 );
	}
	if( im_iscomplex( in ) ) {
		im_errormsg( "im_less_vec: not implemented for complex" );
		return( -1 );
	}

	invec[0] = in; invec[1] = NULL;
	if( !(p = numdup( out, n, c )) || 
		relational_process( "im_less_vec", invec, out, 
			(im_wrapmany_fn) lessvec_buffer, (void *) p ) )
		return( -1 );

	return( 0 );
}

int 
im_lessconst( IMAGE *in, IMAGE *out, double c )
{	
	double *v;

	return( !(v = mkvec( in, out, c )) || 
		im_less_vec( in, out, in->Bands, v ) );
}

static void
lesseq_buffer( PEL **p, PEL *q, int n, IMAGE *a, IMAGE *b )
{
	int ne = n * a->Bands;
	PEL *p1 = p[0];
	PEL *p2 = p[1];
	int x;

#define LESSEQ_REAL( TYPE ) { \
	TYPE *i = (TYPE *) p1; \
	TYPE *j = (TYPE *) p2; \
	\
	for( x = 0; x < ne; x++ ) \
		if( i[x] <= j[x] ) \
			q[x] = 255; \
		else \
			q[x] = 0; \
}

/* Take the mod and compare that.
 */
#define LESSEQ_COMPLEX( TYPE ) { \
	TYPE *i = (TYPE *) p1; \
	TYPE *j = (TYPE *) p2; \
	\
	for( x = 0; x < ne; x++ ) { \
		double m1 = sqrt( i[0] * i[0] + i[1] * i[1] ); \
		double m2 = sqrt( j[0] * j[0] + j[1] * j[1] ); \
		\
		if( m1 <= m2 ) \
			q[x] = 255; \
		else \
			q[x] = 0; \
		\
		i += 2; \
		j += 2; \
	} \
}

	SWITCH( a->BandFmt, LESSEQ_REAL, LESSEQ_COMPLEX );
}

int 
im_lesseq( IMAGE *in1, IMAGE *in2, IMAGE *out )
{
	IMAGE *invec[3];

	invec[0] = in1; invec[1] = in2; invec[2] = NULL;
	if( relational_process( "im_lesseq", invec, out, 
		(im_wrapmany_fn) lesseq_buffer, NULL ) )
		return( -1 );

	return( 0 );
}

static void
lesseqvec_buffer( PEL **in, PEL *out, int n, IMAGE *a, double *c )
{
	int x, b, i;

#define LESSEQVEC_REAL( TYPE ) { \
	TYPE *p = (TYPE *) in[0]; \
	\
	for( i = 0, x = 0; x < n; x++ ) \
		for( b = 0; b < a->Bands; b++, i++ ) \
			if( p[i] <= c[b] ) \
				out[i] = 255; \
			else \
				out[i] = 0; \
}

#define LESSEQVEC_COMPLEX( TYPE ) assert( 0 );

	SWITCH( a->BandFmt, LESSEQVEC_REAL, LESSEQVEC_COMPLEX );
}

int 
im_lesseq_vec( IMAGE *in, IMAGE *out, int n, double *c )
{
	IMAGE *invec[2];
	double *p;

	if( n != in->Bands ) {
		im_errormsg( "im_lesseq_vec: vec size does not match bands" );
		return( -1 );
	}
	if( im_iscomplex( in ) ) {
		im_errormsg( "im_lesseq_vec: not implemented for complex" );
		return( -1 );
	}

	invec[0] = in; invec[1] = NULL;
	if( !(p = numdup( out, n, c )) || 
		relational_process( "im_lesseq_vec", invec, out, 
			(im_wrapmany_fn) lesseqvec_buffer, (void *) p ) )
		return( -1 );

	return( 0 );
}

int 
im_lesseqconst( IMAGE *in, IMAGE *out, double c )
{	
	double *v;

	return( !(v = mkvec( in, out, c )) || 
		im_lesseq_vec( in, out, in->Bands, v ) );
}

int 
im_more( IMAGE *in1, IMAGE *in2, IMAGE *out )
{
	return( im_less( in2, in1, out ) );
}

int 
im_more_vec( IMAGE *in, IMAGE *out, int n, double *c )
{
	IMAGE *t;
	
	/* Same as not (lesseq x).
	 */
	if( !(t = im_open_local( out, "im_more_vec-1", "p" )) ||
		im_lesseq_vec( in, t, n, c ) ||
		im_eorconst( t, out, 255 ) )
		return( -1 );

	return( 0 );
}

int 
im_moreconst( IMAGE *in, IMAGE *out, double c )
{
	double *v;

	return( !(v = mkvec( in, out, c )) || 
		im_more_vec( in, out, in->Bands, v ) );
}

int 
im_moreeq( IMAGE *in1, IMAGE *in2, IMAGE *out )
{
	return( im_lesseq( in2, in1, out ) );
}

int 
im_moreeq_vec( IMAGE *in, IMAGE *out, int n, double *c )
{
	IMAGE *t;
	
	/* Same as not (less x).
	 */
	if( !(t = im_open_local( out, "im_moreeq_vec-1", "p" )) ||
		im_less_vec( in, t, n, c ) ||
		im_eorconst( t, out, 255 ) )
		return( -1 );

	return( 0 );
}

int 
im_moreeqconst( IMAGE *in, IMAGE *out, double c )
{	
	double *v;

	return( !(v = mkvec( in, out, c )) || 
		im_moreeq_vec( in, out, in->Bands, v ) );
}
