/* im_recomb.c
 *
 * 21/6/95 JC
 *	- mildly modernised
 * 14/3/96 JC
 *	- better error checks, partial
 * 4/11/09
 * 	- gtkdoc
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

#include <vips/vips.h>

/* Inner loop.
 */
#define LOOP( IN, OUT ) { \
	IN *p = (IN *) bin; \
	OUT *q = (OUT *) bout; \
	\
	for( i = 0; i < width; i++ ) { \
		double *m = mat->coeff; \
		\
		for( v = 0; v < mat->ysize; v++ ) { \
			double t = 0.0; \
			\
			for( u = 0; u < mat->xsize; u++ ) \
				t += *m++ * p[u]; \
			\
			*q++ = (OUT) t; \
		} \
		\
		p += mat->xsize; \
	} \
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
		g_assert( 0 );
	}

	return( 0 );
}

/** 
 * im_recomb:
 * @in: input image
 * @out: output image
 * @recomb: recombination matrix
 *
 * This operation recombines an image's bands. Each pixel in @in is treated as 
 * an n-element vector, where n is the number of bands in @in, and multipled by
 * the n x m matrix @recomb to produce the m-band image @out.
 *
 * @out is always float, unless @in is double, in which case @out is double
 * too. No complex images allowed.
 *
 * It's useful for various sorts of colour space conversions.
 *
 * Returns: 0 on success, -1 on error.
 */
int 
im_recomb( IMAGE *in, IMAGE *out, DOUBLEMASK *recomb )
{
	DOUBLEMASK *mcpy;

	/* Check input image.
	 */
	if( im_piocheck( in, out ) ||
		im_check_uncoded( "im_recomb", in ) || 
		im_check_noncomplex( "im_recomb", in ) )
		return( -1 );
	if( in->Bands != recomb->xsize ) {
		im_error( "im_recomb", "%s", 
			_( "bands in must equal matrix width" ) );
		return( -1 );
	}

	/* Prepare the output image 
	 */
	if( im_cp_desc( out, in ) )
		return( -1 );
	out->Bands = recomb->ysize;
	if( vips_bandfmt_isint( in->BandFmt ) ) 
		out->BandFmt = IM_BANDFMT_FLOAT;

	/* Take a copy of the matrix.
	 */
	if( !(mcpy = im_dup_dmask( recomb, "conv_mask" )) )
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
