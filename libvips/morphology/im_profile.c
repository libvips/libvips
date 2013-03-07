/* find image profiles 
 *
 * 11/8/99 JC
 *	- from im_cntlines()
 * 22/4/04
 *	- now outputs horizontal/vertical image
 * 9/11/10
 * 	- any image format, any number of bands
 * 	- gtk-doc
 */

/*

   	TODO

	- walk a region over the image and avoid wio

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
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
    02110-1301  USA

 */

/*

    These files are distributed with VIPS - http://www.vips.ecs.soton.ac.uk

 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <vips/vips.h>

/**
 * im_profile:
 * @in: input image
 * @out: output image
 * @dir: search direction
 *
 * im_profile() searches inward from the edge of @in and finds the 
 * first non-zero pixel. It outputs an image containing a list of the offsets 
 * for each row or column.
 *
 * If @dir == 0, then im_profile() searches down from the top edge, writing an 
 * image as wide as the input image, but only 1 pixel high, containing the 
 * number of pixels down to the first non-zero pixel for each column of input 
 * pixels.
 *
 * If @dir == 1, then im_profile() searches across from the left edge, 
 * writing an image as high as the input image, but only 1 pixel wide, 
 * containing the number of pixels across to the
 * first non-zero pixel for each row of input pixels.
 *
 * See also: im_cntlines().
 *
 * Returns: 0 on success, -1 on error
 */
int 
im_profile( IMAGE *in, IMAGE *out, int dir )
{
	int sz;
	unsigned short *buf;
	int x, y, b;

	/* If in is not uchar, do (!=0) to make a uchar image.
	 */
	if( in->BandFmt != IM_BANDFMT_UCHAR ) {
		IMAGE *t;

		if( !(t = im_open_local( out, "im_profile", "p" )) ||
			im_notequalconst( in, t, 0 ) )
			return( -1 );

		in = t;
	}

	/* Check im.
	 */
	if( im_iocheck( in, out ) ||
		im_check_uncoded( "im_profile", in ) ||
		im_check_format( "im_profile", in, IM_BANDFMT_UCHAR ) )
		return( -1 );
	if( dir != 0 && 
		dir != 1 ) {
		im_error( "im_profile", "%s", _( "dir not 0 or 1" ) );
		return( -1 ); 
	}

	if( im_cp_desc( out, in ) )
		return( -1 );
	out->Type = IM_TYPE_HISTOGRAM;
	if( dir == 0 ) {
		out->Xsize = in->Xsize;
		out->Ysize = 1;
	}
	else {
		out->Xsize = 1;
		out->Ysize = in->Ysize;
	}
	out->BandFmt = IM_BANDFMT_USHORT;
	if( im_setupout( out ) )
		return( -1 );
	sz = IM_IMAGE_N_ELEMENTS( out );
	if( !(buf = IM_ARRAY( out, sz, unsigned short )) )
		return( -1 );

	if( dir == 0 ) {
		/* Find vertical lines.
		 */
		for( x = 0; x < sz; x++ ) {
			VipsPel *p = IM_IMAGE_ADDR( in, 0, 0 ) + x;
			int lsk = IM_IMAGE_SIZEOF_LINE( in );

			for( y = 0; y < in->Ysize; y++ ) {
				if( *p )
					break;
				p += lsk;
			}

			buf[x] = y;
		}

		if( im_writeline( 0, out, (VipsPel *) buf ) )
			return( -1 );
	}
	else {
		/* Search horizontal lines.
		 */
		for( y = 0; y < in->Ysize; y++ ) {
			VipsPel *p = IM_IMAGE_ADDR( in, 0, y );

			for( b = 0; b < in->Bands; b++ ) {
				VipsPel *p1;

				p1 = p + b;
				for( x = 0; x < in->Xsize; x++ ) {
					if( *p1 )
						break;
					p1 += in->Bands;
				}

				buf[b] = x;
			}

			if( im_writeline( y, out, (VipsPel *) buf ) )
				return( -1 );
		}
	}

	return( 0 );
}
