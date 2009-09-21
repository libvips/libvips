/* @(#) Function which checks the structures imagein and imageout and gets
 * @(#) ready for partial input. If a function calls this in its setup stage,
 * @(#) we assume it is partial-ready. If it calls im_iocheck(), we fall back
 * @(#) to old-style behaviour.
 * @(#)
 * @(#) int 
 * @(#) im_piocheck( imagein, imageout )
 * @(#) IMAGE *imagein, *imageout;
 * @(#)
 * @(#) int 
 * @(#) im_pincheck( imagein )
 * @(#) IMAGE *imagein;
 * @(#)
 * @(#) int 
 * @(#) im_piocheck( imageout )
 * @(#) IMAGE *imageout;
 * @(#)
 * @(#) Returns -1 on fail
 * @(#) 
 *
 * Copyright: Nicos Dessipris
 * Written on: 12/02/1990
 * Modified on : 
 * 15/4/93 J.Cupitt
 *	- im_incheck(), im_outcheck() added.
 *	- type field now checked.
 * 10/6/93 J.Cupitt
 * 	- im_iocheck() adapted to make im_piocheck()
 * 	- auto-rewind feature added
 * 27/10/95 JC
 *	- im_pincheck() on a setbuf now zaps generate function so as not to
 *	  confuse any later calls to im_prepare() or im_prepare_inplace()
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
#include <vips/internal.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* Check that an image is readable. 
 */
int
im_pincheck( IMAGE *im )
{	
	g_assert( !im_image_sanity( im ) );

#ifdef DEBUG_IO
	printf( "im_pincheck: enabling partial input for %s\n", im->filename );
#endif /*DEBUG_IO*/

	switch( im->dtype ) {
	case IM_SETBUF:
	case IM_SETBUF_FOREIGN:
		/* Should have been written to.
		 */
		if( !im->data ) {
			im_error( "im_pincheck", "%s", _( "no image data" ) );
			return( -1 );
		}

		/* Should be no generate functions now.
		 */
		im->start = NULL;
		im->generate = NULL;
		im->stop = NULL;

		break;

	case IM_PARTIAL:
		/* Should have had generate functions attached.
		 */
		if( !im->generate ) {
			im_error( "im_pincheck", "%s", _( "no image data" ) );
			return( -1 );
		}

		break;

	case IM_MMAPIN:
	case IM_MMAPINRW:
	case IM_OPENIN:
		break;

	case IM_OPENOUT:
		/* Close file down and reopen as im_mmapin.
		 */
#ifdef DEBUG_IO
		printf( "im_pincheck: auto-rewind of %s\n", im->filename );
#endif/*DEBUG_IO*/
		if( im__close( im ) || im_openin( im ) ) {
			im_error( "im_pincheck", 
				_( "auto-rewind for %s failed" ),
				im->filename );
			return( -1 );
		}

		break;

	default:
		im_error( "im_pincheck", "%s", _( "image not readable" ) );
		return( -1 );
	}

	return( 0 );
}

/* Check that an image is writeable. 
 */
int 
im_poutcheck( IMAGE *im )
{
	if( !im ) {
		im_error( "im_poutcheck", "%s", _( "null image descriptor" ) );
		return( -1 );
	}

#ifdef DEBUG_IO
	printf( "im_pincheck: enabling partial output for %s\n", im->filename );
#endif /*DEBUG_IO*/

	switch( im->dtype ) {
	case IM_SETBUF:
		/* Check that it has not been im_setupout().
		 */
		if( im->data ) {
			im_error( "im_poutcheck", "%s", 
				_( "image already written" ) );
			return( -1 );
		}

		break;

	case IM_PARTIAL:
		/* Make sure nothing is attached.
		 */
		if( im->generate ) {
			im_error( "im_poutcheck", "%s", 
				_( "image already written" ) );
			return( -1 );
		}

		break;

	case IM_OPENOUT:
	case IM_SETBUF_FOREIGN:
		/* Okeydoke. Not much checking here.
		 */
		break;

	default:
		im_error( "im_poutcheck", "%s", _( "image not writeable" ) );
		return( -1 );
	}

	return( 0 );
}
 
/* Check a pair of fds for IO.
 */
int 
im_piocheck( IMAGE *in, IMAGE *out )
{	
	return( im_pincheck( in ) || im_poutcheck( out ) );
}
