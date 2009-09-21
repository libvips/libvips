/* @(#) Try to make an IMAGE writeable. im_mmapin files become im_mmapinrw
 * @(#) files, buffers are left alone and output files and partial images
 * @(#) generate an error.
 * @(#)
 * @(#) int im_makerw( im )
 * @(#) IMAGE *im;
 * @(#)
 * @(#) Returns non-zero on error.
 * @(#)
 * Copyright: John Cupitt
 * Written on: 17/6/92
 * Updated on:
 * 15/4/93
 *	- checks for partial images added
 *	- now uses type field
 * 31/8/93 JC
 *	- returns ok for IM_MMAPINRW type files now too
 *	- returns -1 rather than 1 on error
 *	- ANSIfied
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

int
im_makerw( IMAGE *im )
{	
	/* This will rewind im_openout() files, and generate im_partial() files.
	 */
	if( im_incheck( im ) ) {
		im_error( "im_makerw", "%s", _( "unable to rewind file" ) );
		return( -1 );
	}

	switch( im->dtype ) {
	case IM_SETBUF:
	case IM_SETBUF_FOREIGN:
	case IM_MMAPINRW:
		break;

	case IM_MMAPIN:
		if( im_remapfilerw( im ) ) 
			return( -1 );
		break;

	default:
		im_error( "im_makerw", "%s", _( "bad file type" ) );
		return( -1 );
	}

	return( 0 );
}
