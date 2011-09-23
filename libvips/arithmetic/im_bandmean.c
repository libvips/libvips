/* im_bandmean.c
 *
 * Author: Simon Goodall
 * Written on: 17/7/07
 * 17/7/07 JC
 * 	- hacked about a bit
 * 18/8/09
 * 	- gtkdoc
 * 	- get rid of the complex case, just double the width
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

#include <assert.h>

#include <vips/vips.h>
#include <vips/internal.h>

/* Int types. Round, keep sum in a larger variable.
 */
#define ILOOP( TYPE, STYPE ) { \
	TYPE *p1 = (TYPE *) p; \
	TYPE *q1 = (TYPE *) q; \
	\
	for( i = 0; i < sz; i++ ) { \
		STYPE sum; \
		\
		sum = 0; \
		for( j = 0; j < b; j++ ) \
			sum += p1[j]; \
		q1[i] = sum > 0 ? (sum + b / 2) / b : (sum - b / 2) / b; \
		p1 += b; \
	} \
}

/* Float loop. No rounding, sum in same container.
 */
#define FLOOP( TYPE ) { \
	TYPE *p1 = (TYPE *) p; \
	TYPE *q1 = (TYPE *) q; \
	\
	for( i = 0; i < sz; i++ ) { \
		TYPE sum; \
		\
		sum = 0; \
		for( j = 0; j < b; j++ ) \
			sum += p1[j]; \
		q1[i] = sum / b; \
		p1 += b; \
	} \
}

static void
bandmean_buffer( PEL *p, PEL *q, int n, IMAGE *in )
{
	/* Complex just doubles the size.
	 */
	const int sz = n * (vips_bandfmt_iscomplex( in->BandFmt ) ? 2 : 1);
	const int b = in->Bands;

	int i, j;

        switch( in->BandFmt ) {
        case IM_BANDFMT_CHAR: 	ILOOP( signed char, int ); break; 
        case IM_BANDFMT_UCHAR:	ILOOP( unsigned char, unsigned int ); break; 
        case IM_BANDFMT_SHORT: 	ILOOP( signed short, int ); break; 
        case IM_BANDFMT_USHORT:	ILOOP( unsigned short, unsigned int ); break; 
        case IM_BANDFMT_INT: 	ILOOP( signed int, int ); break; 
        case IM_BANDFMT_UINT: 	ILOOP( unsigned int, unsigned int ); break; 
        case IM_BANDFMT_FLOAT: 	FLOOP( float ); break; 
        case IM_BANDFMT_DOUBLE:	FLOOP( double ); break; 
        case IM_BANDFMT_COMPLEX:FLOOP( float ); break;
        case IM_BANDFMT_DPCOMPLEX:FLOOP( double ); break;

        default:
		assert( 0 );
        }
}

/**
 * im_bandmean:
 * @in: input #IMAGE
 * @out: output #IMAGE
 *
 * im_bandmean() writes a one-band image where each pixel is the average of 
 * the bands for that pixel in the input image. The output band format is 
 * the same as the input band format. Integer types use round-to-nearest
 * averaging.
 *
 * See also: im_add(), im_avg(), im_recomb()
 *
 * Returns: 0 on success, -1 on error
 */
int
im_bandmean( IMAGE *in, IMAGE *out )
{
	/* Check input params 
	 */
	if( in->Bands == 1 ) 
		return( im_copy( in, out ) );
	if( im_check_uncoded( "im_bandmean", in ) ) 
		return( -1 );

	/* Prepare output image.
	 */
	if( im_cp_desc( out, in ) )
		return( -1 );
	out->Bands = 1;
	out->Type = IM_TYPE_B_W;

	/* And process!
	 */
	if( im_wrapone( in, out, 
		(im_wrapone_fn) bandmean_buffer, in, NULL ) )	
		return( -1 );

	return( 0 );
}

