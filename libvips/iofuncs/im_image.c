/* @(#) Make a memory area of pixels into a VIPS image ... we don't free() on
 * @(#) im_close(), that's up to the caller ... format is BandFmt
 * @(#)
 * @(#) Usage:
 * @(#)
 * @(#) IMAGE *
 * @(#) im_image( void *buffer, int width, int height, int bands, int format )
 * @(#)
 * @(#) The function returns NULL on error.
 * Written on: 11/7/00
 * Modified on:
 * 20/3/01 JC
 * - oops, broken for IM_BANDFMT_UCHAR
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

#include <vips/vips.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

IMAGE *
im_image( void *buffer, int width, int height, int bands, int format )
{
	IMAGE *im;

	if( width <= 0 || height <= 0 || bands <= 0 || 
		format < 0 || format > IM_BANDFMT_DPCOMPLEX ) {
		im_error( "im_image", "%s", _( "bad parameters" ) );
		return( NULL );
	}

	/* Make new output image for us.
	 */
	if( !(im = im_init( "untitled" )) )
		return( NULL );

	/* Set header fields.
	 */
	im->Xsize = width;
	im->Ysize = height;
	im->Bands = bands;
	im->BandFmt = format;
	im->Bbits = im_bits_of_fmt( format );
	im->Coding = IM_CODING_NONE;

	if( bands == 1 )
		im->Type = IM_TYPE_B_W;
	else if( bands == 3 )
		im->Type = IM_TYPE_RGB;
	else 
		im->Type = IM_TYPE_MULTIBAND;

	im->data = (char *) buffer;
	im->dtype = IM_SETBUF_FOREIGN;

	return( im );
}
