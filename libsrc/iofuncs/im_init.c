/* @(#) Initialise the IMAGE to impossible startup values. Install the
 * @(#) filename.
 * @(#) 
 * @(#) IMAGE *im_init( char *filename )
 *
 * Copyright: Nicos Dessipris & Kirk Martinez, 1990
 * Written on: 13/02/1990
 * Modified on : 3/6/92 22/2/93
 * 15/4/93 J.Cupitt
 *	- init for partial image buffers added
 *	- init for type field
 *	- filename added
 * 10/5/93 J.Cupitt
 *	- allocates space for IMAGE too, and returns new data
 * 23/2/94 JC
 *	- ANSIfied, man page revised
 * 16/8/94 JC
 *	- evalend callbacks added
 * 28/11/94 JC
 *	- new compression fields added, thr added
 * 24/10/95 JC
 *	- now tracks open images ... see also im_close() and debug.c
 * 1/12/04 JC
 *	- added an im_init_world() to help old progs
 * 30/9/05
 * 	- added sizeof_header
 * 2/1/07
 * 	- init magic
 * 	- init history_list
 * 7/11/07
 * 	- added preclose and evalstart
 * 9/8/08
 * 	- lock global image list (thanks lee)
 * 19/3/09
 *	- add nodata 
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
#define DEBUG_NEW
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vips/vips.h>
#include <vips/debug.h>
#include <vips/thread.h>
#include <vips/internal.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* Make a new IMAGE structure, set fields to an initial state. We set the
 * filename field only.
 */
IMAGE *
im_init( const char *filename )
{	
	IMAGE *im;

	/* Pass in a nonsense name for argv0 ... this init world is only here
	 * for old programs which are missing an im_init_world() call. We must
	 * have threads set up before we can process.
	 */
	if( im_init_world( "vips" ) )
		im_error_clear();

	if( !(im = IM_NEW( NULL, IMAGE )) )
		return( NULL );

#ifdef DEBUG_NEW
	printf( "im_init: new IMAGE 0x%p, \"%s\"\n", im, filename );
#endif /*DEBUG_NEW*/

	im->Xsize = -1;
	im->Ysize = -1;
	im->Bands = -1;
	im->Bbits = -1;
	im->BandFmt = -1;
	im->Coding = -1;
	im->Type = -1;
	im->Xres = 1.0;
	im->Yres = 1.0;
	im->Length = 0;
	im->Compression = 0;
	im->Level = 0;
	im->Xoffset = 0;
	im->Yoffset = 0;

	im->Hist = NULL;

	im->data = NULL;
	im->time = NULL;
	im->kill = 0;

	im->dtype = IM_NONE;
	im->fd = -1;
	im->baseaddr = NULL;
	im->length = 0;
	im->closefns = NULL;
	im->evalfns = NULL;
	im->evalendfns = NULL;
	im->closing = 0;
	im->close_pending = 0;

	/* Default to native order.
	 */
	im->magic = im_amiMSBfirst() ?  IM_MAGIC_SPARC : IM_MAGIC_INTEL;

	im->start = NULL;
	im->generate = NULL;
	im->stop = NULL;
	im->client1 = NULL;
	im->client2 = NULL;
	im->sslock = g_mutex_new();
	im->regions = NULL;
	im->dhint = IM_SMALLTILE;

	im->Meta = NULL;
	im->Meta_traverse = NULL;

	/* Default to the VIPS header size. Can be changed later.
	 */
	im->sizeof_header = IM_SIZEOF_HEADER;

	im->windows = NULL;

	im->parents = NULL;
	im->children = NULL;
	im->serial = 0;

	im->history_list = NULL;

	im->progress = NULL;

	im->evalstartfns = NULL;
	im->preclosefns = NULL;
	im->invalidatefns = NULL;

	im->nodata = 0;

	if( !(im->filename = im_strdup( NULL, filename )) ) {
		im_close( im );
		return( NULL );
	}

	g_mutex_lock( im__global_lock );
	im__open_images = g_slist_prepend( im__open_images, im );
	g_mutex_unlock( im__global_lock );

	return( im );
}
