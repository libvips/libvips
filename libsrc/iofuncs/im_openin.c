/* @(#) Open a VIPS image file for reading. The IMAGE should be as made by
 * @(#) im_init(), or after im__close.
 * @(#)
 * @(#) If the file is small, we mmap() it
 * @(#) and make an image of type IM_MMAP. If the file is large, we don't
 * @(#) mmap(); instead we just open a file descriptor and wait for any regions
 * @(#) defined on the image to make small mmap() windows. Also read the
 * @(#) history.
 * @(#)
 * @(#) int
 * @(#) im_openin( IMAGE *image )
 * @(#)
 * @(#) As above, but always mmap() the whole file, and do it read/write.
 * @(#)
 * @(#) int
 * @(#) im_openinrw( IMAGE *image )
 *
 * Copyright: Nicos Dessipris
 * Written on: 13/02/1990
 * Modified on : 27/02/1991
 * 17/6/92 J.Cupitt
 *	- Now opens read-write if possible. This allows later calls to 
 *	  im_makerw. We mmap with PROT_READ, so there is no danger of 
 *	  scribbling over owned images.
 * 16/4/93 J.Cupitt
 *	- adapted to use type field
 * 10/5/93 J.Cupitt
 *	- split into im__mmapin() and im_mmapin() for im_openout() convenience
 *	- functions of im_mmapin.c and im_mmapinrw.c combined
 * 7/9/93 JC
 *	- now sets dhint field
 * 17/11/94 JC
 *	- checks length of compressed files too
 * 19/8/98 JC
 *	- uses strerror() to print system error messages
 * 28/10/98 JC
 *	- _INTEL and _SPARC auto byte-swap added
 * 6/8/02 JC
 *	- redone for mmap() window stuff
 * 13/3/06 JC
 * 	- don't abort load if we can't get the XML
 * 16/8/06
 *      - more O_BINARY nonsense to help cygwin
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif /*HAVE_UNISTD_H*/
#include <assert.h>
#ifdef HAVE_IO_H
#include <io.h>
#endif

/* Try to make an O_BINARY ... sometimes need the leading '_'.
 */
#ifdef BINARY_OPEN
#ifndef O_BINARY
#ifdef _O_BINARY
#define O_BINARY _O_BINARY
#endif /*_O_BINARY*/
#endif /*!O_BINARY*/
#endif /*BINARY_OPEN*/

#include <vips/vips.h> 
#include <vips/internal.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* mmap() whole vs. window threshold ... an int, so we can tune easily from a
 * debugger.
 */
#ifdef DEBUG
int im__mmap_limit = 1;
#else
int im__mmap_limit = IM__MMAP_LIMIT;
#endif /*DEBUG*/

/* Sort of open for read for image files.
 */
int
im__open_image_file( const char *filename )
{
	int fd;

	/* Try to open read-write, so that calls to im_makerw() will work.
	 * When we later mmap this file, we set read-only, so there 
	 * is little danger of scrubbing over files we own.
	 */
#ifdef BINARY_OPEN
	if( (fd = open( filename, O_RDWR | O_BINARY )) == -1 ) {
#else /*BINARY_OPEN*/
	if( (fd = open( filename, O_RDWR )) == -1 ) {
#endif /*BINARY_OPEN*/
		/* Open read-write failed. Fall back to open read-only.
		 */
#ifdef BINARY_OPEN
		if( (fd = open( filename, O_RDONLY | O_BINARY )) == -1 ) {
#else /*BINARY_OPEN*/
		if( (fd = open( filename, O_RDONLY )) == -1 ) {
#endif /*BINARY_OPEN*/
			im_error( "im__open_image_file", 
				_( "unable to open \"%s\", %s" ),
				filename, strerror( errno ) );
			return( -1 );
		}
	}

	return( fd );
}

/* Predict the size of the header plus pixel data. Don't use off_t,
 * it's sometimes only 32 bits (eg. on many windows build environments) and we
 * want to always be 64 bit.
 */
gint64
im__image_pixel_length( IMAGE *im )
{
	gint64 psize;

	switch( im->Coding ) {
	case IM_CODING_LABQ:
	case IM_CODING_NONE:
		psize = (gint64) IM_IMAGE_SIZEOF_LINE( im ) * im->Ysize;
		break;

	default:
		psize = im->Length;
		break;
	}

	return( psize + im->sizeof_header );
}

/* Open the filename, read the header, some sanity checking.
 */
int
im__read_header( IMAGE *image )
{
	/* We don't use im->sizeof_header here, but we know we're reading a
	 * VIPS image anyway.
	 */
	unsigned char header[IM_SIZEOF_HEADER];

	gint64 length;
	gint64 psize;

	image->dtype = IM_OPENIN;
	if( (image->fd = im__open_image_file( image->filename )) == -1 ) 
		return( -1 );
	if( read( image->fd, header, IM_SIZEOF_HEADER ) != IM_SIZEOF_HEADER ||
		im__read_header_bytes( image, header ) ) {
		im_error( "im_openin", 
			_( "unable to read header for \"%s\", %s" ),
			image->filename, strerror( errno ) );
		return( -1 );
	}

	/* Predict and check the file size.
	 */
	psize = im__image_pixel_length( image );
	if( (length = im_file_length( image->fd )) == -1 ) 
		return( -1 );
	if( psize > length ) {
		im_error( "im_openin", _( "unable to open \"%s\", %s" ),
			image->filename, _( "file has been truncated" ) );
		return( -1 );
	}

	/* Set demand style. Allow the most permissive sort.
	 */
	image->dhint = IM_THINSTRIP;

	/* Set the history part of im descriptor. Don't return an error if this
	 * fails (due to eg. corrupted XML) because it's probably mostly
	 * harmless.
	 */
	if( im__readhist( image ) ) {
		im_warn( "im_openin", _( "error reading XML: %s" ),
			im_error_buffer() );
		im_error_clear();
	}

	return( 0 );
}

/* Open, then mmap() small images, leave large images to have a rolling mmap()
 * window for each region.
 */
int
im_openin( IMAGE *image )
{
	gint64 size;

#ifdef DEBUG
	char *str;

	if( (str = g_getenv( "IM_MMAP_LIMIT" )) ) {
		im__mmap_limit = atoi( str );
		printf( "im_openin: setting maplimit to %d from environment\n",
			im__mmap_limit );
	}
#endif /*DEBUG*/

	if( im__read_header( image ) )
		return( -1 );

	size = (gint64) IM_IMAGE_SIZEOF_LINE( image ) * image->Ysize + 
		image->sizeof_header;
	if( size < im__mmap_limit ) {
		if( im_mapfile( image ) )
			return( -1 );
		image->data = image->baseaddr + image->sizeof_header;
		image->dtype = IM_MMAPIN;

#ifdef DEBUG
		printf( "im_openin: completely mmap()ing \"%s\": it's small\n",
			image->filename );
#endif /*DEBUG*/
	}
	else {
#ifdef DEBUG
		printf( "im_openin: delaying mmap() of \"%s\": it's big!\n",
			image->filename );
#endif /*DEBUG*/
	}

	return( 0 );
}

/* Open, then mmap() read/write.
 */
int
im_openinrw( IMAGE *image )
{
	if( im__read_header( image ) )
		return( -1 );

	if( im_mapfilerw( image ) ) 
		return( -1 );
	image->data = image->baseaddr + image->sizeof_header;
	image->dtype = IM_MMAPINRW;

#ifdef DEBUG
	printf( "im_openin: completely mmap()ing \"%s\" read-write\n",
		image->filename );
#endif /*DEBUG*/

	return( 0 );
}
