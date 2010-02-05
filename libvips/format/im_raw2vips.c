/* Read raw image. Just a wrapper over im_binfile().
 * 
 * 3/8/05
 * 4/2/10
 * 	- gtkdoc
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

/*
#define DEBUG
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
 * im_raw2vips:
 * @filename: file to read
 * @out: image to write to
 * @width: image width in pixels
 * @height: image height in pixels
 * @bpp: bytes per pixel 
 * @offset: skip this many bytes at the start of the file
 *
 * This operation mmaps the file, setting @out so that access to that 
 * image will read from the file.
 *
 * Use functions like im_copy_morph() to set the pixel type, byte ordering 
 * and so on.
 *
 * See also: #VipsFormat, im_vips2raw().
 *
 * Returns: 0 on success, -1 on error.
 */
int
im_raw2vips( const char *filename, IMAGE *out, 
	int width, int height, int bpp, int offset )
{
	IMAGE *t;

	if( !(t = im_binfile( filename, width, height, bpp, offset )) )
		return( -1 );
	if( im_add_close_callback( out, 
		(im_callback_fn) im_close, t, NULL ) ) {
		im_close( t );
		return( -1 );
	}
	if( im_copy( t, out ) )
		return( -1 );

	return( 0 );
}
