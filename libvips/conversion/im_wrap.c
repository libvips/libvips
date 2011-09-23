/* im_wrap
 *
 * Copyright: 2008, Nottingham Trent University
 * Author: Tom Vajzovic
 * Written on: 2008-01-15
 * 2/2/10
 * 	- rewritten in terms of im_replicate()/im_extract_area()
 * 	- gtkdoc
 * 	- allows any x/y 
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

/**
 * im_wrap:
 * @in: input image
 * @out: output image
 * @x: horizontal displacement
 * @y: vertical displacement
 *
 * Slice an image up and move the segments about so that the pixel that was
 * at 0, 0 is now at @x, @y.
 *
 * See also: im_embed(), im_replicate(), im_rotquad().
 *
 * Returns: 0 on success, -1 on error
 */
int
im_wrap( IMAGE *in, IMAGE *out, int x, int y )
{
	IMAGE *t;

	/* Clock arithmetic: we want negative x/y to wrap around
	 * nicely.
	 */
	x = x < 0 ? -x % in->Xsize : in->Xsize - x % in->Xsize;
	y = y < 0 ? -y % in->Ysize : in->Ysize - y % in->Ysize;

	if( !(t = im_open_local( out, "im_wrap", "p" )) ||
		im_replicate( in, t, 2, 2 ) ||
		im_extract_area( t, out, x, y, in->Xsize, in->Ysize ) )
		return( -1 );

	out->Xoffset = x;
	out->Yoffset = y;

	return( 0 );
}
