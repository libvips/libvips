/* copy an image to a file and then copy that to the output ... a disc cache
 *
 * 16/10/09
 * 	- from im_system()
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

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif /*HAVE_UNISTD_H*/
#include <stdarg.h>
#include <string.h>
#include <errno.h>

#include <vips/vips.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* Copy an image to a disc file, then copy again to output. If the image is
 * already a disc file, just copy straight through.
 */
int
im_copy_file( IMAGE *in, IMAGE *out )
{
	if( !im_isfile( in ) ) {
		IMAGE *disc;

		if( !(disc = im__open_temp( "%s.v" )) )
			return( -1 );
		if( im_add_close_callback( out, 
			(im_callback_fn) im_close, disc, NULL ) ) {
			im_close( disc );
			return( -1 );
		}

		if( im_copy( in, disc ) ||
			im_copy( disc, out ) )
			return( -1 );
	}
	else {
		if( im_copy( in, out ) )
			return( -1 );
	}

	return( 0 );
}
