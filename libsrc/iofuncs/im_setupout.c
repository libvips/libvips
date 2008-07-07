/* @(#)
 * @(#) Function which sets up the output as follows
 * @(#)  If the output is a buffer, it allocates memory according to image sizes
 * @(#)  If the output is a file, it write a header 
 * @(#) to the file pointed by image.fd
 * @(#)  If the output is a partial image, then `magically' turn this from an
 * @(#) im_partial() image into an im_setbuf() image. If im_setupout() is
 * @(#) called, we take it as a sign that we are dealing with pre-partial 
 * @(#) images code.
 * @(#)  When exiting, image.fd points at the end of the header info.
 * @(#) expecting raw image data.
 * @(#)  No description or history is involved
 * @(#) Called by all im_funcs
 * @(#)
 * @(#) int im_setupout(image)
 * @(#) IMAGE *image;
 * @(#)  Returns either 0 (success) or -1 (fail)
 * @(#)
 * Copyright: Nicos Dessipris
 * Written on: 16/01/1990
 * Modified on : 04/04/1990, 28/02/1991
 * 15/4/93 JC
 *	- partial image support added
 * 18/6/93 JC
 *	- ANSIfied
 * 4/7/01 JC
 *	- OPENOUT open delayed until here
 * 21/8/01 ruven
 *	- stat/file needed
 * 22/8/05
 * *	- less stupid header write
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

#include <sys/types.h>
#include <sys/stat.h>
#ifdef HAVE_SYS_FILE_H
#include <sys/file.h>
#endif /*HAVE_SYS_FILE_H*/
#include <fcntl.h>

#include <vips/vips.h>
#include <vips/internal.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* Open mode for write ... on some systems, have to set BINARY too.
 */
#ifdef BINARY_OPEN
#define MODE (O_WRONLY | O_CREAT | O_TRUNC | O_BINARY)
#else
#define MODE (O_WRONLY | O_CREAT | O_TRUNC)
#endif /*BINARY_OPEN*/

int
im_setupout( IMAGE *im )
{	
	im_image_sanity( im );

	if( im->Xsize <= 0 || im->Ysize <= 0 || im->Bands <= 0 ) {
		im_error( "im_setupout", _( "bad dimensions" ) );
		return( -1 );
	}

	if( im->dtype == IM_PARTIAL ) {
		/* Make it into a im_setbuf() image.
		 */
#ifdef DEBUG_IO
		printf( "im_setupout: old-style output for %s\n",
			im->filename );
#endif /*DEBUG_IO*/

		im->dtype = IM_SETBUF;
	}

	switch( im->dtype ) {
	case IM_MMAPINRW:
	case IM_SETBUF_FOREIGN:
		/* No action.
		 */
		break;

	case IM_SETBUF:
		/* Allocate memory.
		 */
		if( im->data ) {
			/* Sanity failure!
			 */
			im_error( "im_setupout", _( "called twice!" ) );
			return( -1 );
		}
		if( !(im->data = im_malloc( NULL, 
			IM_IMAGE_SIZEOF_LINE( im ) * im->Ysize )) ) 
			return( -1 );

		break;

	case IM_OPENOUT:
	{
		/* Don't use im->sizeof_header here, but we know we're 
		 * writing a VIPS image anyway.
		 */
		unsigned char header[IM_SIZEOF_HEADER];

		if( (im->fd = open( im->filename, MODE, 0666 )) < 0 ) {
	                im_error( "im_setupout", 
				_( "unable to write to \"%s\"" ),
				im->filename );
			return( -1 );
		}
		if( im__write_header_bytes( im, header ) ||
			im__write( im->fd, header, IM_SIZEOF_HEADER ) )
			return( -1 );

		break;
	}

	default:
		im_error( "im_setupout", _( "bad image descriptor" ) );
		return( -1 );
	}

	return( 0 );
}
