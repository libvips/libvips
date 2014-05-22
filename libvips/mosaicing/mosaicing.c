/* base class for all mosaicing operations
 *
 */

/*

    Copyright (C) 1991-2005 The National Gallery

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License as published by the Free Software Foundation; either
    version 2.1 of the License, or (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU 
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this library; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
    02110-1301  USA

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

#include <stdio.h>
#include <stdlib.h>
#include <math.h>

#include <vips/vips.h>
#include <vips/internal.h>

/** 
 * SECTION: mosaicing
 * @short_description: build image mosaics
 * @stability: Stable
 * @include: vips/vips.h
 *
 * These functions are useful for joining many small images together to make
 * one large image. They can cope with unstable contrast and arbitary sub-image
 * layout, but will not do any geometric correction. Geometric errors should
 * be removed before using these functions.
 *
 * The mosaicing functions can be grouped into layers:
 *
 * The lowest level functions are im_correl(), im_lrmerge() and im_tbmerge().
 * im_correl() 
 * searches a large image for a small sub-image, returning
 * the position of the best sub-image match. im_lrmerge() and im_tbmerge() 
 * join two images together
 * left-right or up-down with a smooth seam.
 *
 * Next, im_lrmosaic() and im_tbmosaic() use the
 * search function plus the two low-level merge operations to join two images 
 * given just an approximate overlap as a start point. 
 *
 * The functions im_lrmosaic1() and im_tbmosaic1() are
 * first-order
 * analogues of the basic mosaic functions: they take two approximate 
 * tie-points and use
 * them to rotate and scale the right-hand or bottom image before starting to
 * join.
 *
 * Finally, im_global_balance() can be used to remove contrast differences in 
 * a mosaic
 * which has been assembled with these functions. It takes the mosaic apart,
 * measures image contrast differences along the seams, finds a set of
 * correction factors which will minimise these differences, and reassembles
 * the mosaic.
 * im_remosaic() uses the
 * same
 * techniques, but will reassemble the image from a different set of source
 * images.
 *
 */

/* Called from iofuncs to init all operations in this dir. Use a plugin system
 * instead?
 */
void
vips_mosaicing_operation_init( void )
{
	extern int vips_merge_get_type( void ); 
	extern int vips_mosaic_get_type( void ); 

	vips_merge_get_type(); 
	vips_mosaic_get_type(); 
}
