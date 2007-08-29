/* @(#) Average the bands in an image.
 * @(#)
 * @(#) int 
 * @(#) im_bandmean(in, out)
 * @(#) IMAGE *in, *out;
 * @(#)
 * @(#) Returns 0 on success and -1 on error
 *
 * Author: Simon Goodall
 * Written on: 17/7/07
 * 17/7/07 JC
 * 	- hacked about a bit
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

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* Int types. Round, keep sum in a larger variable.
 */
#define ILOOP( TYPE, STYPE ) { \
	TYPE *p1 = (TYPE *) p; \
	TYPE *q1 = (TYPE *) q; \
	\
	for( i = 0; i < n; i++ ) { \
		STYPE sum; \
		\
		sum = 0; \
		for( j = 0; j < b; j++ ) \
			sum += p1[j]; \
		*q1++ = sum > 0 ? (sum + b / 2) / b : (sum - b / 2) / b; \
		p1 += b; \
	} \
}

/* Float loop. No rounding, sum in same container.
 */
#define FLOOP( TYPE ) { \
	TYPE *p1 = (TYPE *) p; \
	TYPE *q1 = (TYPE *) q; \
	\
	for( i = 0; i < n; i++ ) { \
		TYPE sum; \
		\
		sum = 0; \
		for( j = 0; j < b; j++ ) \
			sum += p1[j]; \
		*q1++ = sum / b; \
		p1 += b; \
	} \
}

/* Complex loop. Mean reals and imaginaries separately.
 */
#define CLOOP( TYPE ) { \
	TYPE *p1 = (TYPE *) p; \
	TYPE *q1 = (TYPE *) q; \
	\
	for( i = 0; i < n * 2; i += 2 ) { \
		TYPE sum; \
		\
		sum = 0; \
		for( j = 0; j < b; j++ ) \
			sum += p1[j * 2]; \
		q1[0] = sum / b; \
		sum = 0; \
		for( j = 0; j < b; j++ ) \
			sum += p1[j * 2 + 1]; \
		q1[1] = sum / b; \
		p1 += b; \
		q1 += 2; \
	} \
}

static void
bandmean_buffer( PEL *p, PEL *q, int n, IMAGE *in )
{
	int i, j;
	const int b = in->Bands;

        switch( in->BandFmt ) {
        case IM_BANDFMT_CHAR: 	ILOOP( signed char, int ); break; 
        case IM_BANDFMT_UCHAR:	ILOOP( unsigned char, unsigned int ); break; 
        case IM_BANDFMT_SHORT: 	ILOOP( signed short, int ); break; 
        case IM_BANDFMT_USHORT:	ILOOP( unsigned short, unsigned int ); break; 
        case IM_BANDFMT_INT: 	ILOOP( signed int, int ); break; 
        case IM_BANDFMT_UINT: 	ILOOP( unsigned int, unsigned int ); break; 
        case IM_BANDFMT_FLOAT: 	FLOOP( float ); break; 
        case IM_BANDFMT_DOUBLE:	FLOOP( double ); break; 
        case IM_BANDFMT_COMPLEX:	CLOOP( float ); break;
        case IM_BANDFMT_DPCOMPLEX:	CLOOP( double ); break;

        default:
		assert( 0 );
        }
}

int
im_bandmean( IMAGE *in, IMAGE *out )
{
	/* Check input params 
	 */
	if( in->Bands == 1 ) 
		return( im_copy( in, out ) );
	if( in->Coding != IM_CODING_NONE ) {
		im_error( "im_bandmean", _( "uncoded multiband only" ) );
		return( -1 );
	}

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

