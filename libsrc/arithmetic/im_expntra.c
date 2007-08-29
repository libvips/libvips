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

/* Parameters saved here.
 */
typedef struct {
	int n;			/* Number of bands of constants */
	double *e;		/* Exponent values, one per band */
} ExpntraInfo;

/* Define what we do for each band element type. Single constant.
 */
#define loop1(IN, OUT)\
{\
	IN *p = (IN *) in;\
	OUT *q = (OUT *) out;\
	\
	for( x = 0; x < sz; x++ ) {\
		double f = (double) p[x];\
		\
		if( e == 0.0 && f < 0.0 ) {\
			/* Division by zero! Difficult to report tho'\
			 */\
			q[x] = 0.0;\
		}\
		else\
			q[x] = pow( e, f );\
	}\
}

/* Expntra a buffer.
 */
static int
expntra1_gen( PEL *in, PEL *out, int width, IMAGE *im, ExpntraInfo *inf )
{
	int sz = width * im->Bands;
	double e = inf->e[0];
	int x;

	/* Expntra all non-complex input types.
         */
        switch( im->BandFmt ) {
        case IM_BANDFMT_UCHAR: 		loop1(unsigned char, float); break;
        case IM_BANDFMT_CHAR: 		loop1(signed char, float); break; 
        case IM_BANDFMT_USHORT: 	loop1(unsigned short, float); break; 
        case IM_BANDFMT_SHORT: 		loop1(signed short, float); break; 
        case IM_BANDFMT_UINT: 		loop1(unsigned int, float); break; 
        case IM_BANDFMT_INT: 		loop1(signed int, float);  break; 
        case IM_BANDFMT_FLOAT: 		loop1(float, float); break; 
        case IM_BANDFMT_DOUBLE:		loop1(double, double); break; 

        default:
		assert( 0 );
        }

	return( 0 );
}

/* Define what we do for each band element type. One constant per band.
 */
#define loopn(IN, OUT)\
{\
	IN *p = (IN *) in;\
	OUT *q = (OUT *) out;\
	\
	for( i = 0, x = 0; x < width; x++ )\
		for( k = 0; k < im->Bands; k++, i++ ) {\
			double e = inf->e[k];\
			double f = (double) p[i];\
			\
			if( e == 0.0 && f < 0.0 ) {\
				q[i] = 0.0;\
			}\
			else\
				q[i] = pow( e, f );\
		}\
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
        case IM_BANDFMT_UCHAR: 		loopn(unsigned char, float); break;
        case IM_BANDFMT_CHAR: 		loopn(signed char, float); break; 
        case IM_BANDFMT_USHORT: 	loopn(unsigned short, float); break; 
        case IM_BANDFMT_SHORT: 		loopn(signed short, float); break; 
        case IM_BANDFMT_UINT: 		loopn(unsigned int, float); break; 
        case IM_BANDFMT_INT: 		loopn(signed int, float);  break; 
        case IM_BANDFMT_FLOAT: 		loopn(float, float); break; 
        case IM_BANDFMT_DOUBLE:		loopn(double, double); break; 

        default:
		assert( 0 );
        }

	return( 0 );
}

int 
im_expntra_vec( IMAGE *in, IMAGE *out, int n, double *e )
{
	ExpntraInfo *inf;
	int i;

	/* Check args.
	 */
	if( in->Coding != IM_CODING_NONE ) {
		im_error( "im_expntra_vec", _( "not uncoded" ) );
		return( -1 );
	}
	if( im_iscomplex( in ) ) {
		im_error( "im_expntra_vec", _( "not non-complex" ) );
		return( -1 );
	}
	if( n != 1 && n != in->Bands ) {
		im_error( "im_expntra_vec", 
			_( "not 1 or %d elements in vector" ), in->Bands );
		return( -1 );
	}

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

int 
im_expntra( IMAGE *in, IMAGE *out, double e )
{
	return( im_expntra_vec( in, out, 1, &e ) );
}

/* Define im_exptra() and im_exp10tra() in terms of im_expntra().
 */
int
im_exptra( IMAGE *in, IMAGE *out )
{
	return( im_expntra( in, out, 2.7182818284590452354 ) );
}

int
im_exp10tra( IMAGE *in, IMAGE *out )
{
	return( im_expntra( in, out, 10.0 ) );
}
