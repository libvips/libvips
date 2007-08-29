/* @(#) Join two images to make a complex. If one of the inputs
 * @(#) is a double, the output is IM_BANDFMT_DPCOMPLEX, otherwise it is IM_BANDFMT_COMPLEX.
 * @(#) 
 * @(#) im_ri2c( IMAGE *in1, IMAGE *in2, IMAGE *out )
 * @(#) 
 * @(#) Returns: -1 on error, else 0
 * Author: Nicos Dessipris
 * Written on: 12/02/1990
 * Modified on : 10/04/1990
 * 16/11/94 JC
 *	- rewritten with partials
 *	- more general
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

/* Join two float buffers to make a complex.
 */
static void
join_float( float **p, float *q, int n, IMAGE *im )
{
	int x;
	int len = n * im->Bands;
	float *p1 = p[0];
	float *p2 = p[1];

	for( x = 0; x < len; x++ ) {
		q[0] = *p1++;
		q[1] = *p2++;

		q += 2;
	}
}

/* Join two double buffers to make a complex.
 */
static void
join_double( double **p, double *q, int n, IMAGE *im )
{
	int x;
	int len = n * im->Bands;
	double *p1 = p[0];
	double *p2 = p[1];

	for( x = 0; x < len; x++ ) {
		q[0] = *p1++;
		q[1] = *p2++;

		q += 2;
	}
}

/* Type conversion.
 */
static IMAGE *
convert( IMAGE *out, IMAGE *in, int (*cvt_fn)( IMAGE *, IMAGE * ) )
{
	IMAGE *t1 = im_open_local( out, "Type conversion", "p" );

	if( !t1 )
		return( NULL );
	
	if( cvt_fn( in, t1 ) )
		return( NULL );
	
	return( t1 );
}

int 
im_ri2c( IMAGE *in1, IMAGE *in2, IMAGE *out )
{
	IMAGE *invec[3];
	extern int im_clip2f( IMAGE *, IMAGE * );
	extern int im_clip2d( IMAGE *, IMAGE * );

	/* Check input image. We don't need to check that sizes match --
	 * im_wrapmany does this for us.
	 */
	if( in1->Coding != IM_CODING_NONE || in2->Coding != IM_CODING_NONE ) {
		im_errormsg( "im_ri2c: inputs should be uncoded" );
		return( -1 );
	}
	if( im_iscomplex( in1 ) || im_iscomplex( in2 ) ) {
		im_errormsg( "im_ri2c: inputs already complex" );
		return( -1 );
	}

	/* Prepare the output image. If either of the inputs is DOUBLE, we are
	 * DPCOMPLEX; otherwise we are COMPLEX.
	 */
	if( im_cp_descv( out, in1, in2, NULL ) )
		return( -1 );
	if( in1->BandFmt == IM_BANDFMT_DOUBLE || 
		in2->BandFmt == IM_BANDFMT_DOUBLE ) {
		out->Bbits = IM_BBITS_DPCOMPLEX;
		out->BandFmt = IM_BANDFMT_DPCOMPLEX;
	}
	else {
		out->Bbits = IM_BBITS_COMPLEX;
		out->BandFmt = IM_BANDFMT_COMPLEX;
	}

	/* Float inputs up to correct type. Note that if they are already the
	 * right type, this operation becomes a NOOP.
	 */
	if( out->BandFmt == IM_BANDFMT_COMPLEX ) {
		in1 = convert( out, in1, im_clip2f );
		in2 = convert( out, in2, im_clip2f );
	}
	else {
		in1 = convert( out, in1, im_clip2d );
		in2 = convert( out, in2, im_clip2d );
	}
	if( !in1 || !in2 )
		return( -1 );

	/* Process!
	 */
	invec[0] = in1; invec[1] = in2; invec[2] = NULL;
	if( out->BandFmt == IM_BANDFMT_COMPLEX ) {
		if( im_wrapmany( invec, out,
			(im_wrapmany_fn) join_float, out, NULL ) )
			return( -1 );
	}
	else {
		if( im_wrapmany( invec, out,
			(im_wrapmany_fn) join_double, out, NULL ) )
			return( -1 );
	}

	return( 0 );
}
