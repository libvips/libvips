/* @(#)  Functions which writes the yth buffer line to either the output file
 * @(#) or the output buffer.
 * @(#)  It is the responsibility of the user to create a buffer line 
 * @(#) and write the data to it before calling this function.
 * @(#)  No checking is carried out for image
 * @(#)
 * @(#) int im_writeline(ypos, image, linebuffer)
 * @(#) int ypos;
 * @(#) IMAGE *image;
 * @(#) char *linebuffer;
 * @(#)
 * @(#) Returns 0 on success and -1 on error
 * @(#)
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

int
im_writeline( int ypos, IMAGE *im, PEL *linebuffer )
{	
	int linesize = IM_IMAGE_SIZEOF_LINE( im );
	char *tmp;

	/* Is this the start of eval?
	 */
	if( ypos == 0 )
		im__start_eval( im );

	/* Possible cases for output: FILE or SETBUF.
	 */
	switch( im->dtype ) {
	case IM_SETBUF:
	case IM_SETBUF_FOREIGN:
		tmp = im->data + ypos * linesize;
		memcpy( tmp, linebuffer, linesize );

		break;

	case IM_OPENOUT:
		/* Don't use ypos for this.
		 */
		if( im__write( im->fd, linebuffer, linesize ) )
			return( -1 );

		break;

	default:
		im_error( "im_writeline", 
			_( "unable to output to a %s image" ),
			im_dtype2char( im->dtype ) );
		return( -1 );
	}

	/* Trigger evaluation callbacks for this image.
	 */
	if( im__handle_eval( im, im->Xsize, 1 ) )
		return( -1 );
	if( im__test_kill( im ) )
		return( -1 );

	/* Is this the end of eval?
	 */
	if( ypos == im->Ysize - 1 )
		im__end_eval( im );

	return( 0 );
}
