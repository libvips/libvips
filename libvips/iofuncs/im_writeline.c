/* write a scanline
 *
 * Copyright: Nicos Dessipris
 * Written on: 04/04/1990
 * Modified on : 
 * 15/4/93 JC
 *	- support for partial images 
 * 13/12/93 JC
 *	- now triggers eval callbacks for the output image.
 * 26/3/02 JC
 *	- better error messages
 * 31/10/03 JC
 *	- stop early on kill
 * 7/11/07
 * 	- add eval start/stop
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
#include <string.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif /*HAVE_UNISTD_H*/
#include <errno.h>
#ifdef HAVE_IO_H
#include <io.h>
#endif /*HAVE_IO_H*/

#include <vips/vips.h>
#include <vips/internal.h>
#include <vips/debug.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/**
 * im_writeline:
 * @image: image to write to
 * @ypos: vertical position of scan-line to write
 * @linebuffer: scanline of pixels
 *
 * Write a line of pixels to an image. This function must be called repeatedly
 * with @ypos increasing from 0 to @YSize -
 * @linebuffer must be IM_IMAGE_SIZEOF_LINE() bytes long.
 *
 * See also: im_setupout(), im_generate().
 *
 * Returns: 0 on success, or -1 on error.
 */
int
vips_image_write_line( VipsImage *image, int ypos, PEL *linebuffer )
{	
	int linesize = VIPS_IMAGE_SIZEOF_LINE( image );

	/* Is this the start of eval?
	 */
	if( ypos == 0 )
		vips_image_preeval( image );

	/* Possible cases for output: FILE or SETBUF.
	 */
	switch( image->dtype ) {
	case VIPS_IMAGE_SETBUF:
	case VIPS_IMAGE_SETBUF_FOREIGN:
		memcpy( VIPS_IMAGE_ADDR( image, 0, ypos ), 
			linebuffer, linesize );
		break;

	case VIPS_IMAGE_OPENOUT:
		/* Don't use ypos for this.
		 */
		if( im__write( image->fd, linebuffer, linesize ) )
			return( -1 );
		break;

	default:
		vips_error( "im_writeline", 
			_( "unable to output to a %s image" ),
			VIPS_ENUM_STRING( VIPS_TYPE_DEMAND_STYLE, 
				image->dtype ) );
		return( -1 );
	}

	/* Trigger evaluation callbacks for this image.
	 */
	vips_image_eval( image, image->Xsize, 1 );
	if( im__test_kill( image ) )
		return( -1 );

	/* Is this the end of eval?
	 */
	if( ypos == image->Ysize - 1 ) {
		vips_image_posteval( image );
		vips_image_written( image );
	}

	return( 0 );
}
