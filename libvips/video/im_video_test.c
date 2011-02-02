/* test video grabber ... just generates noise and optional errors
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

/**
 * im_video_test:
 * @im: write image here
 * @brightness: brightness setting
 * @error: set this to make the function return an error
 *
 * Make a test video image. Set @error to trigger an error.
 *
 * Returns: 0 on success, -1 on error
 */
int
im_video_test( IMAGE *im, int brightness, int error )
{
	if( error ) {
		im_error( "im_video_test", "%s", _( "error requested" ) );
		return( -1 );
	}
	else
		return( im_gaussnoise( im, 720, 576, brightness, 20 ) );
}

