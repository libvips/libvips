/* @(#) Takes as input a histogram and creates a lut which when applied
 * @(#) on the original image, histogram equilises it.
 * @(#) 
 * @(#) Histogram equalisation is carried out for each band of hist 
 * @(#) individually.
 * @(#) 
 * @(#) int im_histeq( IMAGE *hist, IMAGE *lut )
 * @(#)
 * @(#) Returns 0 on sucess and -1 on error
 *
 * Copyright: 1991, N. Dessipris
 *
 * Author: N. Dessipris
 * Written on: 02/08/1990
 * 24/5/95 JC
 *	- tidied up and ANSIfied
 * 20/7/95 JC
 *	- smartened up again
 *	- now works for hists >256 elements
 * 3/3/01 JC
 *	- broken into cum and norm ... helps im_histspec()
 *	- better behaviour for >8 bit hists
 * 31/10/05 JC
 * 	- was broken for vertical histograms, gah
 * 	- neater im_histnorm()
 * 23/7/07
 * 	- eek, off by 1 for more than 1 band hists
 * 12/5/08
 * 	- histcum works for signed hists now as well
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

#define ACCUMULATE( ITYPE, OTYPE ) { \
	for( b = 0; b < nb; b++ ) { \
		ITYPE *p = (ITYPE *) in->data; \
		OTYPE *q = (OTYPE *) outbuf; \
		OTYPE total; \
		\
		total = 0; \
		for( x = b; x < mx; x += nb ) { \
			total += p[x]; \
			q[x] = total; \
		} \
	} \
}

/* Form cumulative histogram.
 */
int 
im_histcum( IMAGE *in, IMAGE *out )
{
	const int px = in->Xsize * in->Ysize;
	const int nb = vips_bandfmt_iscomplex( in->BandFmt ) ? 
		in->Bands * 2 : in->Bands;
	const int mx = px * nb;

	PEL *outbuf;		
	int b, x;

	if( im_check_uncoded( "im_histcum", in ) ||
		im_check_hist( "im_histcum", in ) ||
		im_iocheck( in, out ) )
		return( -1 );

	if( im_cp_desc( out, in ) )
		return( -1 );
	out->Xsize = px;
	out->Ysize = 1;
	if( vips_bandfmt_isuint( in->BandFmt ) )
		out->BandFmt = IM_BANDFMT_UINT;
	else if( vips_bandfmt_isint( in->BandFmt ) )
		out->BandFmt = IM_BANDFMT_INT;
	if( im_setupout( out ) )
		return( -1 );

	if( !(outbuf = im_malloc( out, IM_IMAGE_SIZEOF_LINE( out ))) )
                return( -1 );

        switch( in->BandFmt ) {
        case IM_BANDFMT_CHAR: 		
		ACCUMULATE( signed char, signed int ); break; 
        case IM_BANDFMT_UCHAR: 		
		ACCUMULATE( unsigned char, unsigned int ); break; 
        case IM_BANDFMT_SHORT: 		
		ACCUMULATE( signed short, signed int ); break; 
        case IM_BANDFMT_USHORT: 	
		ACCUMULATE( unsigned short, unsigned int ); break; 
        case IM_BANDFMT_INT: 		
		ACCUMULATE( signed int, signed int ); break; 
        case IM_BANDFMT_UINT: 		
		ACCUMULATE( unsigned int, unsigned int ); break; 

        case IM_BANDFMT_FLOAT: 		
        case IM_BANDFMT_COMPLEX:	
		ACCUMULATE( float, float ); break;
        case IM_BANDFMT_DOUBLE:		
        case IM_BANDFMT_DPCOMPLEX:	
		ACCUMULATE( double, double ); break;

        default:
		g_assert( 0 );
        }

	if( im_writeline( 0, out, outbuf ) )
		return( -1 );

	return( 0 );
}

/* Normalise histogram ... normalise range to make it square (ie. max ==
 * number of elements). Normalise each band separately.
 */
int 
im_histnorm( IMAGE *in, IMAGE *out )
{
	const int px = in->Xsize * in->Ysize;
	DOUBLEMASK *stats;
	double *a, *b;
	int i;
	IMAGE *t1;
	int fmt;

	/* Need max for each channel.
	 */
	if( !(a = IM_ARRAY( out, in->Bands, double )) ||
		!(b = IM_ARRAY( out, in->Bands, double )) ||
		!(stats = im_stats( in )) )
		return( -1 );

	/* Scale each channel by px / channel max
	 */
	for( i = 0; i < in->Bands; i++ ) {
		a[i] = px / stats->coeff[6 + 1 + 6*i];
		b[i] = 0;
	}

	im_free_dmask( stats );

	if( !(t1 = im_open_local( out, "im_histnorm:2", "p" )) ||
		im_lintra_vec( in->Bands, a, in, b, t1 ) )
		return( -1 );

	/* Make output format as small as we can.
	 */
	if( px <= 256 ) 
		fmt = IM_BANDFMT_UCHAR;
	else if( px <= 65536 ) 
		fmt = IM_BANDFMT_USHORT;
	else 
		fmt = IM_BANDFMT_UINT;

	if( im_clip2fmt( t1, out, fmt ) )
		return( -1 );

	return( 0 );
}

/* Histogram equalisation. 
 */
int 
im_histeq( IMAGE *in, IMAGE *out )
{
	IMAGE *t1 = im_open_local( out, "im_histeq:1", "p" );

	/* Normalised cumulative.
	 */
	if( !t1 || im_histcum( in, t1 ) || im_histnorm( t1, out ) )
		return( -1 );

	return( 0 );
}
