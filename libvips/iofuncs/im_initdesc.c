/* @(#)  Initialises an image descriptor to entered values
 * @(#)  fd, baseaddr, data and filename are not handled by this function
 * @(#)  The order of the args is the same as in vips/vips.h
 * 
 * @(#) Right call:
 * @(#) void im_initdesc(image, xsize, ysize, bands, bandbits, bandfmt,
		      coding, type, xres, yres)
 * @(#) IMAGE *image;
 * @(#) int xsize, ysize, bands, bandbits, bandfmt, coding, type;
 * @(#) float xres, yres;
 * HANDLESHEADER
 * Copyright: Nicos Dessipris, 1991
 * Written on: 02/04/1991
 * Modified on : 3/6/92 Kirk Martinez 
 * 23/2/94 JC
 *	- ANSIfied
 * 2/6/07
 * 	- ignore bandbits
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

#include <vips/vips.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

void 
im_initdesc( IMAGE *image, 
	int xsize, int ysize, 
	int bands, int bandbits, int bandfmt,
	int coding, int type, 
	float xres, float yres,
	int xo, int yo )
{
	image->Xsize = xsize;
	image->Ysize = ysize;
	image->Bands = bands;
	/* bandbits is deprecated ... set to whatever the format requires.
	 */
	image->Bbits = im_bits_of_fmt( bandfmt );
	image->BandFmt = bandfmt;
	image->Coding = coding;
	image->Type = type;
	image->Xres = xres;
	image->Yres = yres;
	image->Xoffset = xo;
	image->Yoffset = yo;
}
