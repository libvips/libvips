/* im_close.c --- close an image
 *
 * Copyright: Nicos Dessipris
 * Written on: 12/04/1990
 * Modified on :  
 * 24/7/92 JC
 *	- im_update_descfile code tidied up
 *     	- free on NULL string when junking Hist fixed
 *     	- now calls im_unmapfile
 *     	- better behaviour if image has been opened and closed with 
 *	  no im_setupout call
 *      - better behaviour for half-made IMAGE descriptors
 * 15/4/93 JC
 *      - additions for freeing partial images
 * 29/4/93 JC
 *      - close callback list added
 * 10/5/93 JC
 *      - im__close() added
 * 9/11/93 JC
 *	- im_update_descfile -> write_descfile
 *	- if Hist is NULL, no longer makes up and writes .desc file
 * 16/8/94 JC
 *	- evalend callbacks added
 *	- ANSIfied
 * 24/10/95 JC
 *	- now tracks open images ... see also im_init() and debug.c
 * 11/7/00 JC
 *	- SETBUF_FOREIGN added
 * 16/1/04 JC
 *	- frees as much as possible on im_close() failure
 * 6/6/05 Markus Wollgarten
 *	- free Meta on close
 * 30/6/05 JC
 *	- actually, free Meta on final close, so we carry meta over on an
 *	  im__close()/im_openin() pair (eg. see im_pincheck())
 * 11/7/05
 *	- call im__writehist() to send history to XML after image data
 * 3/1/07
 * 	- free history_list 
 * 7/11/07
 * 	- added preclose, removed evalend triggers
 * 23/7/08
 * 	- im__close() will no longer free regions
 * 9/8/08
 * 	- lock global image list (thanks Lee)
 * 8/9/09
 * 	- move close callbacks *after* we have released resources --- we
 * 	  can now write close callbacks that unlink() temporary files
 * 	- use preclose callbacks if you want to run before resources are
 * 	  released
 * 6/10/09
 * 	- gtkdoc comment
 * 10/1/09
 * 	- added postclose
 * 14/1/09
 * 	- added written
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
#define DEBUG_IO
#define DEBUG_NEW
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif /*HAVE_UNISTD_H*/
#ifdef HAVE_IO_H
#include <io.h>
#endif /*HAVE_IO_H*/
#include <assert.h>

#include <vips/vips.h>
#include <vips/thread.h>
#include <vips/internal.h>
#include <vips/debug.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* Maximum file name length.
 */
#define NAMELEN 1024

/* Free any resources owned by this descriptor. The descriptor is left as if a
 * call to im_init had just happened - ie. the filename is set, but no other
 * resources are attached. Information is lost if this is a im_setbuf()
 * image! On an error, return non-zero and leave the image in an indeterminate
 * state. Too hard to recover gracefully.
 */
int 
im__close( IMAGE *im )
{
	int result;

	result = 0;

	/* No action for NULL image.
	 */
	if( !im )
		return( result );

#ifdef DEBUG_IO
	printf( "im__close: starting for %s ..\n", im->filename );
#endif /*DEBUG_IO*/

	/* Trigger all pre-close fns.
	 */
	result |= im__trigger_callbacks( im->preclosefns );
	IM_FREEF( im_slist_free_all, im->preclosefns );

	/* Should be no regions defined on the image. im_close() ought to put
	 * us into a zombie state if there are, im__close() should not be
	 * called on images with running regions.
	 */
	if( im->regions ) {
		GSList *p;

		printf( "** im__close: leaked regions!\n" );
		for( p = im->regions; p; p = p->next )
			im_region_print( (REGION *) p->data );
	}

	/* That should mean we have no windows.
	 */
	if( im->windows ) {
		GSList *p;

		printf( "** im__close: leaked windows!\n" );
		for( p = im->windows; p; p = p->next )
			im_window_print( (im_window_t *) p->data );
	}

	/* Junk generate functions. 
	 */
	im->start = NULL;
	im->generate = NULL;
	im->stop = NULL;

	/* No more upstream/downstream links.
	 */
	im__link_break_all( im );

	/* What resources are associated with this IMAGE descriptor?
	 */
	if( im->baseaddr ) {
		/* MMAP file.
		 */
#ifdef DEBUG_IO
		printf( "im__close: unmapping file ..\n" );
#endif /*DEBUG_IO*/

		if( im_unmapfile( im ) )
			return( -1 );
		im->data = NULL;
	}

	/* Is there a file descriptor?
	 */
	if( im->fd != -1 ) {
#ifdef DEBUG_IO
		printf( "im__close: closing output file ..\n" );
#endif /*DEBUG_IO*/

		if( im->dtype == IM_OPENOUT && im__writehist( im ) ) 
			result = -1;
		if( close( im->fd ) == -1 ) {
			im_error( "im_close", _( "unable to close fd for %s" ), 
				im->filename );
			result = -1;
		}
		im->fd = -1;
	}

	/* Any image data?
	 */
	if( im->data ) {
		/* Buffer image. Only free stuff we know we allocated.
		 */
		if( im->dtype == IM_SETBUF ) {
#ifdef DEBUG_IO
			printf( "im__close: freeing buffer ..\n" );
#endif /*DEBUG_IO*/
			im_free( im->data );
			im->dtype = IM_NONE;
		}

		im->data = NULL;
	}

	/* Junk all callbacks, perform close callbacks.
	 */
	IM_FREEF( im_slist_free_all, im->evalstartfns );
	IM_FREEF( im_slist_free_all, im->evalfns );
	IM_FREEF( im_slist_free_all, im->evalendfns );
	IM_FREEF( im_slist_free_all, im->invalidatefns );
	IM_FREEF( im_slist_free_all, im->writtenfns );
	result |= im__trigger_callbacks( im->closefns );
	IM_FREEF( im_slist_free_all, im->closefns );

	/* Reset other state.
	 */
	im->dtype = IM_NONE;
	im->dhint = IM_SMALLTILE;
	im->kill = 0;
	im->close_pending = 0;
	im->sizeof_header = IM_SIZEOF_HEADER;

#ifdef DEBUG_IO
	printf( "im__close: final success for %s (%p)\n", 
		im->filename, im );
#endif /*DEBUG_IO*/

	return( result );
}

/**
 * im_close:
 * @im: image to close
 *
 * Frees all resources associated with @im. 
 *
 * If there are open #REGION s on @im, close is delayed until the last region
 * is freed.
 *
 * See also: im_open().
 *
 * Returns: 0 on success and 1 on error.
 */
int 
im_close( IMAGE *im )
{
	int result = 0;

	/* No action for NULL image.
	 */
	if( !im )
		return( result );

	if( im->regions ) {
		/* There are regions left on this image. 
		 * Set close_pending and return. The image will be then 
		 * be closed when the last region is freed 
		 * (see im_region_free()). 
		 */
#ifdef DEBUG_NEW
		printf( "im_close: pending close for 0x%p, \"%s\"\n", 
			im, im->filename );
#endif /*DEBUG_NEW*/

		im->close_pending = 1;
	}
	else if( !im->closing ) {
		/* Is this descriptor currently being closed somewhere else? 
		 * This prevents infinite descent if a close callback
		 * includes an im_close for this image. 
		 */
		im->closing = 1;

		if( im__close( im ) ) 
			result = -1;

#ifdef DEBUG_NEW
		printf( "im_close: freeing IMAGE 0x%p, \"%s\"\n", 
			im, im->filename );
#endif /*DEBUG_NEW*/

		/* Final cleanup.
		 */
		result |= im__trigger_callbacks( im->postclosefns );
		IM_FREEF( im_slist_free_all, im->postclosefns );
		IM_FREEF( g_mutex_free, im->sslock );
		IM_FREE( im->filename );
		IM_FREE( im->Hist );
		IM_FREEF( im__gslist_gvalue_free, im->history_list );
		im__meta_destroy( im );
		g_mutex_lock( im__global_lock );
		im__open_images = g_slist_remove( im__open_images, im );
		g_mutex_unlock( im__global_lock );
		im__time_destroy( im );
		IM_FREE( im );
	}

	return( result );
}
