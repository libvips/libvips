/* @(#) Recombination of bands of image: perform a matrix mult of the form
 * @(#) 
 * @(#) 	a1		b11 b21 .. bm1		c1
 * @(#) 	a2		b12 b22 ..		c2
 * @(#) 	.	=	.   .		   x	.
 * @(#) 	.		.			.
 * @(#) 
 * @(#) 	an		b1n	   bmn		cm
 * @(#) 
 * @(#) Where A is an n band output image, C is an m band input image and B
 * @(#) is an mxn matrix of floats. Can be used with 3x3 matrix to perform
 * @(#) simple colour space transforms; 7x30 matrix to shrink 3rd order
 * @(#) development of 3 filter system to IM_TYPE_XYZ etc.
 * @(#) 
 * @(#) Output is always float, unless input is double, in which case output
 * @(#) is double. Does not work for complex images.
 * @(#) 
 * @(#) Usage: 	
 * @(#) 	im_recomb( imagein, imageout, mat )
 * @(#) 	IMAGE *imagein, *imageout;
 * @(#) 	DOUBLEMASK *mat;
 * @(#) 
 * @(#) Returns: -1 on error, else 0
 * 21/6/95 JC
 *	- mildly modernised
 * 14/3/96 JC
 *	- better error checks, partial
 *	- proper rounding behaviour for int types
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

#include <vips/vips.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* Inner loop.
 */
#define LOOP(INTYPE, OUTTYPE) \
{\
	INTYPE *p = (INTYPE *) bin;\
	OUTTYPE *q = (OUTTYPE *) bout;\
	\
	for( i = 0; i < width; i++ ) {\
		double *m = mat->coeff;\
		\
		for( v = 0; v < mat->ysize; v++ ) {\
			double t = 0.0;\
			\
			for( u = 0; u < mat->xsize; u++ )\
				t += *m++ * p[u];\
			\
			*q++ = (OUTTYPE) t;\
		}\
		\
		p += mat->xsize;\
	}\
}

/* Process a buffer of PELs.
 */
static int
recomb_buf( void *bin, void *bout, int width, IMAGE *in, DOUBLEMASK *mat )
{
	int i;
	int u, v;

	/* Do the processing.
	 */
	switch( in->BandFmt ) {
	case IM_BANDFMT_UCHAR:	LOOP( unsigned char, float );  break; 
	case IM_BANDFMT_CHAR:	LOOP( signed char, float );  break; 
	case IM_BANDFMT_USHORT:	LOOP( unsigned short, float );  break; 
	case IM_BANDFMT_SHORT:	LOOP( signed short, float );  break; 
	case IM_BANDFMT_UINT:	LOOP( unsigned int, float );  break; 
	case IM_BANDFMT_INT:	LOOP( signed int, float );  break; 
	case IM_BANDFMT_FLOAT:	LOOP( float, float );  break; 
	case IM_BANDFMT_DOUBLE:	LOOP( double, double );  break; 

	default:
		im_error( "im_recomb", "%s", _( "unsupported input type" ) );
		return( -1 );
	}

	return( 0 );
}

/* Start here.
 */
int 
im_recomb( IMAGE *in, IMAGE *out, DOUBLEMASK *mat )
{
	DOUBLEMASK *mcpy;

	/* Check input image.
	 */
	if( im_piocheck( in, out ) )
		return( -1 );
	if( in->Coding != IM_CODING_NONE || im_iscomplex( in ) ) {
		im_error( "im_recomb", "%s", 
			_( "uncoded non-complex only" ) );
		return( -1 );
	}
	if( in->Bands != mat->xsize ) {
		im_error( "im_recomb", "%s", 
			_( "bands in must equal matrix width" ) );
		return( -1 );
	}

	/* Prepare the output image 
	 */
	if( im_cp_desc( out, in ) )
		return( -1 );
	out->Bands = mat->ysize;
	if( im_isint( in ) ) {
		out->Bbits = IM_BBITS_FLOAT;
		out->BandFmt = IM_BANDFMT_FLOAT;
	}

	/* Take a copy of the matrix.
	 */
	if( !(mcpy = im_dup_dmask( mat, "conv_mask" )) )
		return( -1 );
	if( im_add_close_callback( out, 
		(im_callback_fn) im_free_dmask, mcpy, NULL ) ) {
		im_free_dmask( mcpy );
		return( -1 );
	}

	/* And process!
	 */
	if( im_wrapone( in, out, (im_wrapone_fn) recomb_buf, in, mcpy ) )
		return( -1 );

	return( 0 );
}
