/* @(#) Invert a UCHAR image. Very simple new-style VIPS routine. See
 * @(#) im_exptra() for the next level of complexity. This function is not
 * @(#) as quick as it could be - it is intended to be an example rather than
 * @(#) to be useful. This should really be written with im_wrapone().
 * @(#)
 * @(#) int
 * @(#) im_invert( IMAGE *in, IMAGE *out )
 * @(#)
 * @(#) All functions return 0 on success and -1 on error
 * @(#)
 *
 * Copyright: 1990, N. Dessipris.
 *
 * Author: Nicos Dessipris
 * Written on: 12/02/1990
 * Modified on :
 * 7/7/93 JC
 *      - memory leaks fixed
 *      - adapted for partial v2
 *      - ANSIfied
 * 22/2/95 JC
 *	- tidied up again
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

/* Invert a REGION. We are given the REGION we should write to, the REGION we
 * should use for input, and the IMAGE we are processing. On entry to
 * invert_gen(), or points to the memory we should write to and ir is blank.
 */
static int
invert_gen( REGION *or, void *seq, void *a, void *b )
{
	REGION *ir = (REGION *) seq;

	/* Left, right, top and bottom for the output region.
	 */
	int le = or->valid.left;
	int to = or->valid.top;
	int bo = IM_RECT_BOTTOM( &or->valid );

	int x, y;

	/* Ask for the section of the input image we need to produce this
	 * section of the output image.
	 */
	if( im_prepare( ir, &or->valid ) )
		return( -1 );
	
	/* Loop over output, writing input.
	 */
	for( y = to; y < bo; y++ ) {
		/* Point p and q at the start of the line of pels we must
		 * process this loop.
		 */
		PEL *p = (PEL *) IM_REGION_ADDR( ir, le, y );
		PEL *q = (PEL *) IM_REGION_ADDR( or, le, y );

		/* Loop along the line, processing pels. 
		 * IM_REGION_N_ELEMENTS(region) gives
		 * the number of band elements across a region. By looping to
		 * IM_REGION_N_ELEMENTS() rather than ir->valid.width, we work 
		 * for any number of bands.
		 */
		for( x = 0; x < IM_REGION_N_ELEMENTS( or ); x++ )
			q[x] = 255 - p[x];
	}

        return( 0 );
}

/* Invert IMAGE in to IMAGE out. Any number of bands, unsigned char pels
 * only. See im_exptra() for an example of a VIPS function which can process
 * any input image type.
 */
int
im_invert( IMAGE *in, IMAGE *out )
{
	/* Check args.
	 */
	if( in->Coding != IM_CODING_NONE ) {
		im_error( "im_invert", "%s", _( "not uncoded" ) );
		return( -1 );
	}
	if( in->BandFmt != IM_BANDFMT_UCHAR ) {
		im_error( "im_invert", "%s", _( "not UCHAR" ) );
		return( -1 );
	}
        if( im_piocheck( in, out ) )
		return( -1 );

	/* Prepare the output header.
	 */
        if( im_cp_desc( out, in ) ) 
		return( -1 );

	/* Set demand hints. Like most one-to-one operations, we work best
	 * with long, thin strips.
	 */
	if( im_demand_hint( out, IM_THINSTRIP, in, NULL ) )
		 return( -1 );

	/* Generate into out. im_start_one() and im_stop_one() are simple
	 * convenience functions provided by VIPS which do the necessary
	 * region creation and destruction for one-image-in
	 * style functions. See im_add(), im_start_many() and im_stop_many() 
	 * for convenience functions for multiple inputs.
	 */
	if( im_generate( out,
		im_start_one, invert_gen, im_stop_one, in, NULL ) )
		return( -1 );
	
	return( 0 );
}
