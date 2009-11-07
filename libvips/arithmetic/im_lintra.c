/* @(#) Pass an image through a linear transform - ie. out = in*a + b. Output
 * @(#) is always float for integer input, double for double input, complex for
 * @(#) complex input and double complex for double complex input.
 * @(#)
 * @(#) int 
 * @(#) im_lintra( a, in, b, out )
 * @(#) IMAGE *in, *out;
 * @(#) double a, b;
 * @(#)
 * @(#) Returns 0 on success and -1 on error
 * @(#)
 *
 * Copyright: 1990, N. Dessipris, based on im_powtra()
 * Author: Nicos Dessipris
 * Written on: 02/05/1990
 * Modified on: 
 * 23/4/93 JC
 *	- adapted to work with partial images
 * 1/7/93 JC
 *	- adapted for partial v2
 * 7/10/94 JC
 *	- new IM_NEW()
 *	- more typedefs 
 * 9/2/95 JC
 *	- adapted for im_wrap...
 *	- operations on complex images now just transform the real channel
 * 29/9/95 JC
 *	- complex was broken
 * 15/4/97 JC
 *	- return(0) missing from generate, arrgh!
 * 1/7/98 JC
 *	- im_lintra_vec added
 * 3/8/02 JC
 *	- fall back to im_copy() for a == 1, b == 0
 * 10/10/02 JC
 *	- auug, failing to multiply imag for complex! (thanks matt)
 * 10/12/02 JC
 *	- removed im_copy() fallback ... meant that output format could change
 *	  with value :-( very confusing
 * 30/6/04
 *	- added 1 band image * n band vector case
 * 8/12/06
 * 	- add liboil support
 * 9/9/09
 * 	- gtkdoc comment, minor reformat
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

#ifdef HAVE_LIBOIL
#include <liboil/liboil.h>
#endif /*HAVE_LIBOIL*/

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* Struct we need for im_generate().
 */
typedef struct {
	int n;			/* Number of bands of constants */
	double *a, *b;
} LintraInfo;

/* Define what we do for each band element type. Non-complex input, any
 * output.
 */
#define LOOP( IN, OUT ) { \
	IN *p = (IN *) in; \
	OUT *q = (OUT *) out; \
	\
	for( x = 0; x < sz; x++ ) \
		q[x] = a * (OUT) p[x] + b; \
}

/* Complex input, complex output. 
 */
#define LOOPCMPLX( IN, OUT ) { \
	IN *p = (IN *) in; \
	OUT *q = (OUT *) out; \
	\
	for( x = 0; x < sz; x++ ) { \
		q[0] = a * p[0] + b; \
		q[1] = a * p[1]; \
		q += 2; \
		p += 2; \
	} \
}

#ifdef HAVE_LIBOIL
/* Process granularity.
 */
#define CHUNKS (1000)

/* d[] = s[] * b + c, with liboil
 */
static void
lintra_f32( float *d, float *s, int n, float b, float c )
{
	float buf[CHUNKS];
	int i;

	for( i = 0; i < n; i += CHUNKS ) {
		oil_scalarmultiply_f32_ns( buf, s, 
			&b, IM_MIN( CHUNKS, n - i ) );
		oil_scalaradd_f32_ns( d, buf, 
			&c, IM_MIN( CHUNKS, n - i ) );

		s += CHUNKS;
		d += CHUNKS;
	}
}
#endif /*HAVE_LIBOIL*/

/* Lintra a buffer, 1 set of scale/offset.
 */
static int
lintra1_gen( PEL *in, PEL *out, int width, IMAGE *im, LintraInfo *inf )
{	
	double a = inf->a[0];
	double b = inf->b[0];
	int sz = width * im->Bands;
	int x;

	/* Lintra all input types.
         */
        switch( im->BandFmt ) {
        case IM_BANDFMT_UCHAR: 		LOOP( unsigned char, float ); break;
        case IM_BANDFMT_CHAR: 		LOOP( signed char, float ); break; 
        case IM_BANDFMT_USHORT: 	LOOP( unsigned short, float ); break; 
        case IM_BANDFMT_SHORT: 		LOOP( signed short, float ); break; 
        case IM_BANDFMT_UINT: 		LOOP( unsigned int, float ); break; 
        case IM_BANDFMT_INT: 		LOOP( signed int, float );  break; 
        case IM_BANDFMT_FLOAT: 		
#ifdef HAVE_LIBOIL
		lintra_f32( (float *) out, (float *) in, sz, a, b );
#else /*!HAVE_LIBOIL*/
		LOOP( float, float ); 
#endif /*HAVE_LIBOIL*/
		break; 

        case IM_BANDFMT_DOUBLE:		LOOP( double, double ); break; 
        case IM_BANDFMT_COMPLEX:	LOOPCMPLX( float, float ); break; 
        case IM_BANDFMT_DPCOMPLEX:	LOOPCMPLX( double, double ); break;

        default:
		assert( 0 );
        }

	return( 0 );
}

/* Define what we do for each band element type. Non-complex input, any
 * output.
 */
#define LOOPN( IN, OUT ) {\
	IN *p = (IN *) in;\
	OUT *q = (OUT *) out;\
	\
	for( i = 0, x = 0; x < width; x++ )\
		for( k = 0; k < nb; k++, i++ )\
			q[i] = a[k] * (OUT) p[i] + b[k];\
}

/* Complex input, complex output. 
 */
#define LOOPCMPLXN( IN, OUT ) {\
	IN *p = (IN *) in;\
	OUT *q = (OUT *) out;\
	\
	for( x = 0; x < width; x++ ) \
		for( k = 0; k < nb; k++ ) {\
			q[0] = a[k] * p[0] + b[k];\
			q[1] = a[k] * p[1];\
			q += 2;\
			p += 2;\
		}\
}

/* Lintra a buffer, n set of scale/offset.
 */
static int
lintran_gen( PEL *in, PEL *out, int width, IMAGE *im, LintraInfo *inf )
{
	double *a = inf->a;
	double *b = inf->b;
	int nb = im->Bands;
	int i, x, k;

	/* Lintra all input types.
         */
        switch( im->BandFmt ) {
        case IM_BANDFMT_UCHAR: 		LOOPN( unsigned char, float ); break;
        case IM_BANDFMT_CHAR: 		LOOPN( signed char, float ); break; 
        case IM_BANDFMT_USHORT: 	LOOPN( unsigned short, float ); break; 
        case IM_BANDFMT_SHORT: 		LOOPN( signed short, float ); break; 
        case IM_BANDFMT_UINT: 		LOOPN( unsigned int, float ); break; 
        case IM_BANDFMT_INT: 		LOOPN( signed int, float );  break; 
        case IM_BANDFMT_FLOAT: 		LOOPN( float, float ); break; 
        case IM_BANDFMT_DOUBLE:		LOOPN( double, double ); break; 
        case IM_BANDFMT_COMPLEX:	LOOPCMPLXN( float, float ); break; 
        case IM_BANDFMT_DPCOMPLEX:	LOOPCMPLXN( double, double ); break;

        default:
		assert( 0 );
        }

	return( 0 );
}

/* 1 band image, n band vector.
 */
#define LOOPNV( IN, OUT ) { \
	IN *p = (IN *) in; \
	OUT *q = (OUT *) out; \
	\
	for( i = 0, x = 0; x < width; x++ ) { \
		OUT v = p[x]; \
		\
		for( k = 0; k < nb; k++, i++ ) \
			q[i] = a[k] * v + b[k]; \
	} \
}

#define LOOPCMPLXNV( IN, OUT ) { \
	IN *p = (IN *) in; \
	OUT *q = (OUT *) out; \
	\
	for( x = 0; x < width; x++ ) { \
		OUT p0 = p[0]; \
		OUT p1 = p[1]; \
		\
		for( k = 0; k < nb; k++ ) { \
			q[0] = a[k] * p0 + b[k]; \
			q[1] = a[k] * p1; \
			q += 2; \
		} \
		\
		p += 2; \
	} \
}

static int
lintranv_gen( PEL *in, PEL *out, int width, IMAGE *im, LintraInfo *inf )
{
	double *a = inf->a;
	double *b = inf->b;
	int nb = inf->n;
	int i, x, k;

	/* Lintra all input types.
         */
        switch( im->BandFmt ) {
        case IM_BANDFMT_UCHAR: 		LOOPNV( unsigned char, float ); break;
        case IM_BANDFMT_CHAR: 		LOOPNV( signed char, float ); break; 
        case IM_BANDFMT_USHORT: 	LOOPNV( unsigned short, float ); break; 
        case IM_BANDFMT_SHORT: 		LOOPNV( signed short, float ); break; 
        case IM_BANDFMT_UINT: 		LOOPNV( unsigned int, float ); break; 
        case IM_BANDFMT_INT: 		LOOPNV( signed int, float );  break; 
        case IM_BANDFMT_FLOAT: 		LOOPNV( float, float ); break; 
        case IM_BANDFMT_DOUBLE:		LOOPNV( double, double ); break; 
        case IM_BANDFMT_COMPLEX:	LOOPCMPLXNV( float, float ); break; 
        case IM_BANDFMT_DPCOMPLEX:	LOOPCMPLXNV( double, double ); break;

        default:
		assert( 0 );
        }

	return( 0 );
}

/**
 * im_lintra_vec:
 * @n: array size
 * @a: array of constants for multiplication
 * @in: image to transform
 * @b: array of constants for addition
 * @out: output image
 *
 * Pass an image through a linear transform - ie. @out = @in * @a + @b. Output
 * is always float for integer input, double for double input, complex for
 * complex input and double complex for double complex input.
 *
 * If the arrays of constants have just one element, that constant are used for 
 * all image bands. If the arrays have more than one element and they have 
 * the same number of elements as there are bands in the image, then 
 * one array element is used for each band. If the arrays have more than one
 * element and the image only has a single band, the result is a many-band
 * image where each band corresponds to one array element.
 *
 * See also: im_add(), im_lintra().
 *
 * Returns: 0 on success, -1 on error
 */
int 
im_lintra_vec( int n, double *a, IMAGE *in, double *b, IMAGE *out )
{	
	LintraInfo *inf;
	int i;

	if( im_piocheck( in, out ) ||
		im_check_vector( "im_lintra_vec", n, in ) ||
		im_check_uncoded( "lintra_vec", in ) )
		return( -1 );

	/* Prepare output header.
	 */
	if( im_cp_desc( out, in ) )
		return( -1 );
	if( im_isint( in ) ) 
		out->BandFmt = IM_BANDFMT_FLOAT;
	if( in->Bands == 1 )
		out->Bands = n;

	/* Make space for a little buffer.
	 */
	if( !(inf = IM_NEW( out, LintraInfo )) || 
		!(inf->a = IM_ARRAY( out, n, double )) ||
		!(inf->b = IM_ARRAY( out, n, double )) )
		return( -1 );
	inf->n = n;
	for( i = 0; i < n; i++ ) {
		inf->a[i] = a[i];
		inf->b[i] = b[i];
	}

	/* Generate!
	 */
	if( n == 1 ) {
		if( im_wrapone( in, out, 
			(im_wrapone_fn) lintra1_gen, in, inf ) )
			return( -1 );
	}
	else if( in->Bands == 1 ) {
		if( im_wrapone( in, out, 
			(im_wrapone_fn) lintranv_gen, in, inf ) )
			return( -1 );
	}
	else {
		if( im_wrapone( in, out, 
			(im_wrapone_fn) lintran_gen, in, inf ) )
			return( -1 );
	}

	return( 0 );
}

/**
 * im_lintra:
 * @a: constant for multiplication
 * @in: image to transform
 * @b: constant for addition
 * @out: output image
 *
 * Pass an image through a linear transform - ie. @out = @in * @a + @b. Output
 * is always float for integer input, double for double input, complex for
 * complex input and double complex for double complex input.
 *
 * See also: im_add(), im_lintra_vec().
 *
 * Returns: 0 on success, -1 on error
 */
int 
im_lintra( double a, IMAGE *in, double b, IMAGE *out )
{	
	return( im_lintra_vec( 1, &a, in, &b, out ) );
}
