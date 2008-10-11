/* @(#)  Function which checks the structures imagein and imageout
 * @(#)  It returns a valid value only if ip and op are set properly
 * @(#)  Cases of returned integer value
 * @(#)
 * @(#) int im_iocheck(imagein, imageout)
 * @(#) IMAGE *imagein, *imageout;
 * @(#)
 * @(#)  Returns -1 on fail
 * @(#) 
 *
 * Copyright: Nicos Dessipris
 * Written on: 12/02/1990
 * Modified on : 
 * 15/4/93 JC
 *	- im_incheck(), im_outcheck() added.
 *	- type field now checked.
 * 10/6/93 JC
 *	- auto-fallback to old-style input added
 * 6/6/95 JC
 *	- revised and improved fallback code
 */

/* @(#) Try to make an IMAGE writeable. im_mmapin files become im_mmapinrw
 * @(#) files, buffers are left alone and output files and partial images
 * @(#) generate an error.
 * @(#)
 * @(#) int im_rwcheck( im )
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
 * 1/10/97 JC
 *	- moved here, and renamed im_rwcheck()
 * 13/2/01 JC
 *	- im_image_sanity() checks added
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
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#ifdef HAVE_SYS_FILE_H
#include <sys/file.h>
#endif /*HAVE_SYS_FILE_H*/

#include <vips/vips.h>
#include <vips/internal.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* Convert a partial to a setbuf.
 */
static int
convert_ptob( IMAGE *im )
{
	IMAGE *t1;

	/* Change to IM_SETBUF. First, make a memory buffer and copy into that.
	 */
	if( !(t1 = im_open( "im_incheck:1", "t" )) ) 
		return( -1 );
	if( im_copy( im, t1 ) ) {
		im_close( t1 );
		return( -1 );
	}

	/* Copy new stuff in. We can't im__close( im ) and free stuff, as this
	 * would kill of lots of regions and cause dangling pointers
	 * elsewhere.
	 */
	im->dtype = IM_SETBUF;
	im->data = t1->data; 
	t1->data = NULL;

	/* Close temp image.
	 */
	if( im_close( t1 ) )
		return( -1 );

	return( 0 );
}

/* Convert an openin to a mmapin.
 */
static int
convert_otom( IMAGE *im )
{
	/* just mmap() the whole thing.
	 */
	if( im_mapfile( im ) ) 
		return( -1 );
	im->data = im->baseaddr + im->sizeof_header;
	im->dtype = IM_MMAPIN;

	return( 0 );
}

/* Check that an image is readable by old-style VIPS functions.
 */
int
im_incheck( IMAGE *im )
{	
	g_assert( !im_image_sanity( im ) );

#ifdef DEBUG_IO
	printf( "im_incheck: old-style input for %s\n", im->filename );
#endif/*DEBUG_IO*/

	switch( im->dtype ) {
	case IM_SETBUF:
	case IM_SETBUF_FOREIGN:
		/* Should have been written to.
		 */
		if( !im->data ) {
			im_error( "im_incheck", _( "no image data" ) );
			return( -1 );
		}

		break;

	case IM_MMAPIN:
	case IM_MMAPINRW:
		/* Can read from all these, in principle anyway.
		 */
		break;

	case IM_PARTIAL:
#ifdef DEBUG_IO
		printf( "im_incheck: converting partial image to WIO\n" );
#endif/*DEBUG_IO*/

		/* Change to a setbuf, so our caller can use it.
		 */
		if( convert_ptob( im ) )
			return( -1 );

		break;

	case IM_OPENIN:
#ifdef DEBUG_IO
		printf( "im_incheck: converting openin image for old-style input\n" );
#endif/*DEBUG_IO*/

		/* Change to a MMAPIN.
		 */
		if( convert_otom( im ) )
			return( -1 );

		break;

	case IM_OPENOUT:
		/* Close file down and reopen as im_mmapin.
		 */
#ifdef DEBUG_IO
		printf( "im_incheck: auto-rewind of %s\n", im->filename );
#endif/*DEBUG_IO*/
		if( im__close( im ) || im_openin( im ) ) {
			im_error( "im_incheck", 
				_( "auto-rewind for %s failed" ),
				im->filename );
			return( -1 );
		}

		break;

	default:
		im_error( "im_incheck", _( "image not readable" ) );
		return( -1 );
	}

	return( 0 );
}

/* Check that an image is writeable. 
 */
int 
im_outcheck( IMAGE *im )
{
#ifdef DEBUG_IO
	printf( "im_outcheck: old-style output for %s\n", im->filename );
#endif/*DEBUG_IO*/

	switch( im->dtype ) {
	case IM_PARTIAL:
		/* Make sure nothing is attached.
		 */
		if( im->generate ) {
			im_error( "im_outcheck", _( "image already written" ) );
			return( -1 );
		}

		/* Cannot do old-style write to PARTIAL. Turn to SETBUF.
		 */
		im->dtype = IM_SETBUF;

		/* Fall through to SETBUF case.
		 */

	case IM_SETBUF:
		/* Check that it has not been im_setupout().
		 */
		if( im->data ) {
			im_error( "im_outcheck", _( "image already written" ) );
			return( -1 );
		}

		break;

	case IM_OPENOUT:
	case IM_SETBUF_FOREIGN:
		/* Can write to this ok.
		 */
		break;

	default:
		im_error( "im_outcheck", _( "image not writeable" ) );
		return( -1 );
	}

	return( 0 );
}
 
/* Check a pair of fds for IO.
 */
int 
im_iocheck( IMAGE *in, IMAGE *out )
{	
	return( im_incheck( in ) || im_outcheck( out ) );
}

int
im_rwcheck( IMAGE *im )
{
	/* Do an im_incheck(). This will rewind im_openout() files, and
	 * generate im_partial() files.
	 */
	if( im_incheck( im ) ) {
		im_error( "im_rwcheck", _( "unable to rewind file" ) );
		return( -1 );
	}

	/* Look at the type.
	 */
	switch( im->dtype ) {
	case IM_SETBUF:
	case IM_SETBUF_FOREIGN:
	case IM_MMAPINRW:
		/* No action necessary.
		 */
		break;

	case IM_MMAPIN:
		/* Try to remap read-write.
		 */
		if( im_remapfilerw( im ) )
			return( -1 );

		break;

	default:
		im_error( "im_rwcheck", _( "bad file type" ) );
		return( -1 );
	}

	return( 0 );
}
