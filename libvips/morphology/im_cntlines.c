/* count lines 
 *
 * Copyright: 1990, N. Dessipris.
 *
 * Author: Nicos Dessipris
 * Written on: 02/05/1990
 * Modified on : 
 *
 * 19/9/95 JC
 *	- tidied up
 * 23/10/10
 * 	- gtk-doc
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

/**
 * im_cntlines:
 * @im: input #IMAGE
 * @nolines: output average number of lines
 * @flag: 0 horizontal, 1 vertical
 *
 * Function which calculates the number of transitions
 * between black and white for the horizontal or the vertical
 * direction of an image.  black<128 , white>=128
 * The function calculates the number of transitions for all
 * Xsize or Ysize and returns the mean of the result
 * Input should be one band, 8-bit.
 *
 * See also: im_erode(), im_zerox(), im_conv().
 *
 * Returns: 0 on success, -1 on error.
 */
int 
im_cntlines( IMAGE *im, double *nolines, int flag )
{
	int x, y;
	PEL *line;
	int cnt;

	if( im_incheck( im ) ||
		im_check_uncoded( "im_cntlines", im ) ||
		im_check_mono( "im_cntlines", im ) ||
		im_check_format( "im_cntlines", im, IM_BANDFMT_UCHAR ) )
		return( -1 );
	if( flag != 0 && flag != 1 ) {
		im_error( "im_cntlines", "%s", 
			_( "flag should be 0 (horizontal) or 1 (vertical)" ) );
		return( -1 ); 
	}

	line = (PEL *) im->data;
	if( flag == 1 ) {
		/* Count vertical lines.
		 */
		for( cnt = 0, y = 0; y < im->Ysize; y++ ) {
			PEL *p = line;
			
			for( x = 0; x < im->Xsize - 1; x++ ) {
				if( p[0] < 128 && p[1] >= 128 )
					cnt++;
				else if( p[0] >= 128 && p[1] < 128 )
					cnt++;
				
				p++;
			}

			line += im->Xsize;
		}

		*nolines = (float) cnt / (2.0 * im->Ysize);
	}
	else {
		/* Count horizontal lines.
		 */
		for( cnt = 0, y = 0; y < im->Ysize - 1; y++ ) {
			PEL *p1 = line;
			PEL *p2 = line + im->Xsize;
			
			for( x = 0; x < im->Xsize; x++ ) {
				if( *p1 < 128 && *p2 >= 128 )
					cnt++;
				else if( *p1 >= 128 && *p2 < 128 )
					cnt++;

				p1++;
				p2++;
			}

			line += im->Xsize;
		}

		*nolines = (float) cnt / (2.0 * im->Xsize);
	}

	return( 0 );
}
