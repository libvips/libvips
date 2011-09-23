/* match PDFs
 *
 * Copyright: 1991, N. Dessipris.
 *
 * Author: Nicos Dessipris
 * Written on: 19/07/1990
 * Modified on: 26/03/1991
 *
 * 1/3/01 JC
 * 	- bleurg! rewritten, now does 16 bits as well, bugs removed, faster,
 *     	  smaller
 * 24/3/10
 * 	- gtkdoc
 * 	- small cleanups
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
#include <assert.h>

#include <vips/vips.h>

/*
#define DEBUG
 */

/*
#define PIM_RINT 
 */

/* Match two normalised cumulative histograms.
 */
static int
match( IMAGE *in, IMAGE *ref, IMAGE *out )
{
	const int inpx = in->Xsize * in->Ysize;
	const int refpx = ref->Xsize * ref->Ysize;
	const int bands = in->Bands;	

	unsigned int *inbuf;		/* in and ref, padded to same size */
	unsigned int *refbuf;
	unsigned int *outbuf;		/* Always output as uint */

	int px;				/* Number of pixels */
	int max;			/* px * bands */

	int i, j;

	if( im_iocheck( in, out ) || 
		im_iocheck( ref, out ) ||
		im_check_uncoded( "im_histspec", in ) ||
		im_check_format( "im_histspec", in, IM_BANDFMT_UINT ) ||
		im_check_coding_same( "im_histspec", in, ref ) ||
		im_check_format_same( "im_histspec", in, ref ) ||
		im_check_bands_same( "im_histspec", in, ref ) ||
		im_check_hist( "im_histspec", in ) ||
		im_check_hist( "im_histspec", ref ) )
                return( -1 );

	/* How big?
	 */
	if( inpx <= 256 && refpx <= 256 )
		px = 256;
	else if( inpx <= 65536 && refpx <= 65536 )
		px = 65536;
	max = px * bands;

	/* Unpack to equal-sized buffers.
	 */
	inbuf = IM_ARRAY( out, max, unsigned int );
	refbuf = IM_ARRAY( out, max, unsigned int );
	outbuf = IM_ARRAY( out, max, unsigned int );
	if( !inbuf || !refbuf || !outbuf )
		return( -1 );
	for( i = 0; i < inpx * bands; i++ ) 
		inbuf[i] = ((unsigned int *)in->data)[i];
	for( ; i < max; i++ ) 
		inbuf[i] = 0;
	for( i = 0; i < refpx * bands; i++ ) 
		refbuf[i] = ((unsigned int *)ref->data)[i];
	for( ; i < max; i++ ) 
		refbuf[i] = 0;

	for( j = 0; j < bands; j++ ) {
		/* Track up refbuf[] with this.
		 */
		int ri = j;
		int limit = max - bands;

		for( i = j; i < max; i += bands ) {
			unsigned int inv = inbuf[i];

			for( ; ri < limit; ri += bands )
				if( inv <= refbuf[ri] )
					break;

			if( ri < limit ) {
				/* Simple rounding.
				 */
				double mid = refbuf[ri] + 
					refbuf[ri + bands] / 2.0;

				if( inv < mid )
					outbuf[i] = ri/bands;
				else
					outbuf[i] = ri/bands + 1;
			}
			else 
				outbuf[i] = refbuf[ri];
		}
	}

        if( im_cp_descv( out, in, ref, NULL ) )
		return( -1 );
	out->Xsize = px;
	out->Ysize = 1;
	out->Type = IM_TYPE_HISTOGRAM;
        if( im_setupout( out ) )
		return( -1 );

        if( im_writeline( 0, out, (PEL *) outbuf ) )
		return( -1 );

	return( 0 );
}

/**
 * im_histspec:
 * @in: input image
 * @ref: reference histogram 
 * @out: output image
 *
 * Creates a lut which, when applied to the image from which histogram @in was
 * formed, will produce an image whose PDF matches that of the image from 
 * which @ref was formed.
 *
 * See also: im_hsp(), im_histgr(), im_maplut().
 *
 * Returns: 0 on success, -1 on error
 */
int 
im_histspec( IMAGE *in, IMAGE *ref, IMAGE *out )
{
	IMAGE *t[5];
	int px;
	int fmt;

	if( im_check_uint( "im_histspec", in ) ||
		im_check_uint( "im_histspec", ref ) )
		return( -1 );

	/* Match hists.
	 */
	if( im_open_local_array( out, t, 5, "im_histspec", "p" ) ||
		im_histeq( in, t[0] ) || 
		im_clip2fmt( t[0], t[1], IM_BANDFMT_UINT ) ||
		im_histeq( ref, t[2] ) || 
		im_clip2fmt( t[2], t[3], IM_BANDFMT_UINT ) ||
		match( t[1], t[3], t[4] ) )
		return( -1 );

	/* Clip type down.
	 */
	px = t[4]->Xsize * t[4]->Ysize;
	if( px <= 256 ) 
		fmt = IM_BANDFMT_UCHAR;
	else if( px <= 65536 ) 
		fmt = IM_BANDFMT_USHORT;
	else 
		fmt = IM_BANDFMT_UINT;

	if( im_clip2fmt( t[4], out, fmt ) )
		return( -1 );

        return( 0 );
}

