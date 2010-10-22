/* im_image.c ... area of memory as an image
 *
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
#include <vips/internal.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/**
 * im_image:
 * @buffer: start of memory area
 * @xsize: image width
 * @ysize: image height
 * @bands: image bands (or bytes per pixel)
 * @bandfmt: image format
 *
 * This function wraps an #IMAGE around a memory buffer. VIPS does not take
 * responsibility for the area of memory, it's up to you to make sure it's
 * freed when the image is closed. See for example im_add_close_callback().
 *
 * See also: im_binfile(), im_raw2vips(), im_open().
 *
 * Returns: the new #IMAGE, or %NULL on error.
 */
IMAGE *
im_image( void *buffer, int xsize, int ysize, int bands, VipsBandFmt bandfmt )
{
	IMAGE *im;

	if( xsize <= 0 || ysize <= 0 || bands <= 0 || 
		bandfmt < 0 || bandfmt > IM_BANDFMT_DPCOMPLEX ) {
		im_error( "im_image", "%s", _( "bad parameters" ) );
		return( NULL );
	}

	/* Make new output image for us.
	 */
	if( !(im = im_init( "untitled" )) )
		return( NULL );

	/* Set header fields.
	 */
	im->Xsize = xsize;
	im->Ysize = ysize;
	im->Bands = bands;
	im->BandFmt = bandfmt;
	im->Bbits = im_bits_of_fmt( bandfmt );
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
