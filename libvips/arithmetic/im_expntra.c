/* @(#) Calculates n^pel, with n as a parameter. 
 * @(#) If input is up to float, output is float, else input is the same as 
 * @(#) output. Does not work for complex input.
 * @(#)
 * @(#) int 
 * @(#) im_expntra( in, out, e )
 * @(#) IMAGE *in, *out;
 * @(#) double e;
 * @(#)
 * @(#) Returns 0 on success and -1 on error
 * @(#)
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
 * 8/5/95 JC
 *	- im_expntra() adapted to make this
 * 15/4/97 JC
 *	- oops, return(0) missing
 *	- M_E removed, as not everywhere
 * 6/7/98 JC
 *	- _vec version added
 * 30/8/09
 * 	- gtkdoc
 * 	- tiny cleanups
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

/* Parameters saved here.
 */
typedef struct {
	int n;			/* Number of bands of constants */
	double *e;		/* Exponent values, one per band */
} ExpntraInfo;

/* Define what we do for each band element type. Single constant.
 */
#define POW1( IN, OUT ) { \
	IN *p = (IN *) in; \
	OUT *q = (OUT *) out; \
	\
	for( x = 0; x < sz; x++ ) { \
		double f = (double) p[x]; \
		\
		if( e == 0.0 && f < 0.0 ) \
			/* Division by zero! Difficult to report tho' \
			 */ \
			q[x] = 0.0; \
		else \
			q[x] = pow( e, f ); \
	} \
}

/* Expntra a buffer.
 */
static int
expntra1_gen( PEL *in, PEL *out, int width, IMAGE *im, ExpntraInfo *inf )
{
	const int sz = width * im->Bands;
	const double e = inf->e[0];

	int x;

	/* Expntra all non-complex input types.
         */
        switch( im->BandFmt ) {
        case IM_BANDFMT_UCHAR: 	POW1( unsigned char, float ); break;
        case IM_BANDFMT_CHAR: 	POW1( signed char, float ); break; 
        case IM_BANDFMT_USHORT:	POW1( unsigned short, float ); break; 
        case IM_BANDFMT_SHORT: 	POW1( signed short, float ); break; 
        case IM_BANDFMT_UINT: 	POW1( unsigned int, float ); break; 
        case IM_BANDFMT_INT: 	POW1( signed int, float );  break; 
        case IM_BANDFMT_FLOAT: 	POW1( float, float ); break; 
        case IM_BANDFMT_DOUBLE:	POW1( double, double ); break; 

        default:
		g_assert( 0 );
        }

	return( 0 );
}

/* Define what we do for each band element type. One constant per band.
 */
#define POWN( IN, OUT ) { \
	IN *p = (IN *) in; \
	OUT *q = (OUT *) out; \
	\
	for( i = 0, x = 0; x < width; x++ ) \
		for( k = 0; k < im->Bands; k++, i++ ) { \
			double e = inf->e[k]; \
			double f = (double) p[i]; \
			\
			if( e == 0.0 && f < 0.0 ) \
				q[i] = 0.0; \
			else \
				q[i] = pow( e, f ); \
		} \
}

/* Expntra a buffer.
 */
static int
expntran_gen( PEL *in, PEL *out, int width, IMAGE *im, ExpntraInfo *inf )
{
	int x, k, i;

	/* Expntra all non-complex input types.
         */
        switch( im->BandFmt ) {
        case IM_BANDFMT_UCHAR:	POWN( unsigned char, float ); break;
        case IM_BANDFMT_CHAR: 	POWN( signed char, float ); break; 
        case IM_BANDFMT_USHORT:	POWN( unsigned short, float ); break; 
        case IM_BANDFMT_SHORT: 	POWN( signed short, float ); break; 
        case IM_BANDFMT_UINT: 	POWN( unsigned int, float ); break; 
        case IM_BANDFMT_INT: 	POWN( signed int, float );  break; 
        case IM_BANDFMT_FLOAT: 	POWN( float, float ); break; 
        case IM_BANDFMT_DOUBLE:	POWN( double, double ); break; 

        default:
		g_assert( 0 );
        }

	return( 0 );
}

/**
 * im_expntra_vec:
 * @in: input #IMAGE 
 * @out: output #IMAGE
 * @n: number of elements in array
 * @b: array of constants
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
im_expntra_vec( IMAGE *in, IMAGE *out, int n, double *e )
{
	ExpntraInfo *inf;
	int i;

	if( im_piocheck( in, out ) ||
		im_check_uncoded( "im_expntra_vec", in ) ||
		im_check_noncomplex( "im_expntra_vec", in ) ||
		im_check_vector( "im_expntra_vec", n, in ) )
		return( -1 );

	/* Prepare output header.
	 */
	if( im_cp_desc( out, in ) )
		return( -1 );
	if( im_isint( in ) ) {
		out->Bbits = IM_BBITS_FLOAT;
		out->BandFmt = IM_BANDFMT_FLOAT;
	}

	/* Make space for a little buffer.
	 */
	if( !(inf = IM_NEW( out, ExpntraInfo )) ||
		!(inf->e = IM_ARRAY( out, n, double )) )
		return( -1 );
	for( i = 0; i < n; i++ ) 
		inf->e[i] = e[i];
	inf->n = n;

	/* Generate!
	 */
	if( n == 1 ) {
		if( im_wrapone( in, out, 
			(im_wrapone_fn) expntra1_gen, in, inf ) )
			return( -1 );
	}
	else {
		if( im_wrapone( in, out, 
			(im_wrapone_fn) expntran_gen, in, inf ) )
			return( -1 );
	}

	return( 0 );
}

/**
 * im_expntra:
 * @in: input #IMAGE 
 * @out: output #IMAGE
 * @b: base
 *
 * im_expntra() transforms element x of input to 
 * <function>pow</function>(@b, x) in output. 
 * It detects division by zero, setting those pixels to zero in the output. 
 * Beware: it does this silently!
 *
 * See also: im_logtra(), im_powtra()
 *
 * Returns: 0 on success, -1 on error
 */
int 
im_expntra( IMAGE *in, IMAGE *out, double b )
{
	return( im_expntra_vec( in, out, 1, &b ) );
}

/**
 * im_exptra:
 * @in: input #IMAGE 
 * @out: output #IMAGE
 *
 * im_exptra() transforms element x of input to 
 * <function>pow</function>(e, x) in output. 
 * It detects division by zero, setting those pixels to zero in the output. 
 * Beware: it does this silently!
 *
 * See also: im_logtra(), im_powtra()
 *
 * Returns: 0 on success, -1 on error
 */
int
im_exptra( IMAGE *in, IMAGE *out )
{
	return( im_expntra( in, out, 2.7182818284590452354 ) );
}

/**
 * im_exp10tra:
 * @in: input #IMAGE 
 * @out: output #IMAGE
 *
 * im_exptra() transforms element x of input to 
 * <function>pow</function>(10, x) in output. 
 * It detects division by zero, setting those pixels to zero in the output. 
 * Beware: it does this silently!
 *
 * See also: im_logtra(), im_powtra()
 *
 * Returns: 0 on success, -1 on error
 */
int
im_exp10tra( IMAGE *in, IMAGE *out )
{
	return( im_expntra( in, out, 10.0 ) );
}
