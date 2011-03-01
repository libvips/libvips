/* get an image ready for im_writeline()
 *
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
#include <vips/debug.h>

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

/**
 * im_setupout:
 * @im: image to prepare for writing
 *
 * This call gets the #IMAGE ready for scanline-based writing with 
 * im_writeline(). You need to have set all the image fields, such as @Xsize
 * and @BandFmt, before calling this. 
 *
 * See also: im_writeline(), im_generate(), im_initdesc(), im_cp_desc().
 *
 * Returns: 0 on success, or -1 on error.
 */
int
im_setupout( IMAGE *im )
{	
	g_assert( !im_image_sanity( im ) );

	if( im->Xsize <= 0 || im->Ysize <= 0 || im->Bands <= 0 ) {
		vips_error( "im_setupout", 
			"%s", _( "bad dimensions" ) );
		return( -1 );
	}

	/* We don't use this, but make sure it's set in case any old binaries
	 * are expectiing it.
	 */
	im->Bbits = im_bits_of_fmt( im->BandFmt );
 
	if( im->dtype == VIPS_IMAGE_PARTIAL ) {
		/* Make it into a im_setbuf() image.
		 */
#ifdef DEBUG_IO
		printf( "im_setupout: old-style output for %s\n",
			im->filename );
#endif /*DEBUG_IO*/

		im->dtype = VIPS_IMAGE_SETBUF;
	}

	switch( im->dtype ) {
	case VIPS_IMAGE_MMAPINRW:
	case VIPS_IMAGE_SETBUF_FOREIGN:
		/* No action.
		 */
		break;

	case VIPS_IMAGE_SETBUF:
		/* Allocate memory.
		 */
		if( im->data ) {
			/* Sanity failure!
			 */
			vips_error( "im_setupout", 
				"%s", _( "called twice!" ) );
			return( -1 );
		}
		if( !(im->data = im_malloc( NULL, 
			VIPS_IMAGE_SIZEOF_LINE( im ) * im->Ysize )) ) 
			return( -1 );

		break;

	case VIPS_IMAGE_OPENOUT:
	{
		/* Don't use im->sizeof_header here, but we know we're 
		 * writing a VIPS image anyway.
		 */
		unsigned char header[IM_SIZEOF_HEADER];

		if( (im->fd = open( im->filename, MODE, 0666 )) < 0 ) {
	                vips_error( "im_setupout", 
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
		vips_error( "im_setupout", 
			"%s", _( "bad image descriptor" ) );
		return( -1 );
	}

	return( 0 );
}
