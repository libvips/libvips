/* @(#) dir = 0:
 * @(#)		For each vertical line, find the position of the first 
 * @(#)		non-zero pixel from the top. Output is USHORT with 
 * @(#)		width = input width, height = 1.
 * @(#)
 * @(#) dir = 1:
 * @(#)		For each horizontal line, find the position of the first 
 * @(#)		non-zero pixel from the left. Output is USHORT with 
 * @(#)		width = 1, height = input height
 * @(#)
 * @(#) int im_profile( IMAGE *in, IMAGE *out, int dir )
 * @(#)
 * @(#) Returns 0 on success and non-zero on error
 *
 * 11/8/99 JC
 *	- from im_cntlines()
 * 22/4/04
 *	- now outputs horizontal/vertical image
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

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

int 
im_profile( IMAGE *in, IMAGE *out, int dir )
{
	int x, y;
	unsigned short *buf;

	/* Check im.
	 */
	if( im_iocheck( in, out ) )
		return( -1 );
	if( in->Coding != IM_CODING_NONE || in->BandFmt != IM_BANDFMT_UCHAR ||
		in->Bands != 1 ) {
		im_error( "im_profile", "%s", 
			_( "1-band uchar uncoded only" ) );
		return( -1 ); 
	}
	if( dir != 0 && dir != 1 ) {
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
	if( !(buf = IM_ARRAY( out, out->Xsize, unsigned short )) )
		return( -1 );

	if( dir == 0 ) {
		/* Find vertical lines.
		 */
		for( x = 0; x < in->Xsize; x++ ) {
			PEL *p = (PEL *) IM_IMAGE_ADDR( in, x, 0 );
			int lsk = IM_IMAGE_SIZEOF_LINE( in );

			for( y = 0; y < in->Ysize; y++ ) 
				if( p[y * lsk] )
					break;

			buf[x] = y;
		}

		if( im_writeline( 0, out, (PEL *) buf ) )
			return( -1 );
	}
	else {
		/* Count horizontal lines.
		 */
		for( y = 0; y < in->Ysize; y++ ) {
			PEL *p = (PEL *) IM_IMAGE_ADDR( in, 0, y );

			for( x = 0; x < in->Xsize; x++ ) 
				if( p[x] )
					break;

			buf[0] = x;

			if( im_writeline( y, out, (PEL *) buf ) )
				return( -1 );
		}
	}


	return( 0 );
}
