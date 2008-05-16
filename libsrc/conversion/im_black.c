/* @(#) Make a black uchar image of a specified size. Sometimes useful for
 * @(#) building masks.
 * @(#)  IMAGE out should nhave been set by the calling program
 * @(#)
 * @(#) int 
 * @(#) im_black(out, x, y, bands)
 * @(#) IMAGE *out;
 * @(#) int x, y;
 * @(#) int bands;
 * @(#)
 * @(#) Returns 0 on success and -1 on error.
 *
 * Copyright: 1990, J. Cupitt
 *
 * Author: J. Cupitt
 * Written on: 02/08/1990
 * Modified on : 16/04/1991 by N. Dessipris to work on a line by line basis
 * 15/8/94 JC
 *	- adapted for partials
 *	- ANSIfied
 * 	- memory leaks fixed!
 * 2/3/98 JC
 *	- IM_ANY added
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
#include <string.h>

#include <vips/vips.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* Generate function --- just black out the region.
 */
static int
black_gen( REGION *or, void *seq, void *a, void *b )
{
	im__black_region( or );

	return( 0 );
}

/* Make a one band black uchar image of a specified size.
 */
int
im_black( IMAGE *out, int x, int y, int bands )
{	
	int type;

	/* Check parameters.
	 */
	if( x < 0 || y < 0 || bands < 0 ) {
		im_errormsg( "im_black: bad parameter" );
		return( -1 );
	}

	/* Check descriptor.
	 */
	if( im_poutcheck( out ) )
		return( -1 );
	
	/* Set fields.
	 */
	if( bands == 1 )
		type = IM_TYPE_B_W;
	else
		type = IM_TYPE_MULTIBAND;
	im_initdesc( out, 
		x, y, bands, 
		IM_BBITS_BYTE, IM_BANDFMT_UCHAR, IM_CODING_NONE, type,
		1.0, 1.0, 0, 0 );

	/* Set hints - ANY is ok with us.
	 */
	if( im_demand_hint( out, IM_ANY, NULL ) )
		return( -1 );
	
	/* Generate image.
	 */
	if( im_generate( out, NULL, black_gen, NULL, NULL, NULL ) )
		return( -1 );
	
	return( 0 );
}
