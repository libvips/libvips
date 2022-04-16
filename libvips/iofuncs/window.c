/* Manage sets of mmap buffers on an image.
 * 
 * 30/10/06
 *	- from region.c
 * 19/3/09
 *	- block mmaps of nodata images
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
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
    02110-1301  USA

 */

/*

    These files are distributed with VIPS - http://www.vips.ecs.soton.ac.uk

 */

/*
#define DEBUG_TOTAL
#define DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <glib/gi18n-lib.h>

#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif /*HAVE_UNISTD_H*/
#include <errno.h>
#include <string.h>
#ifdef HAVE_SYS_MMAN_H
#include <sys/mman.h>
#endif

#include <vips/vips.h>
#include <vips/internal.h>
#include <vips/thread.h>

#ifdef G_OS_WIN32
#include <windows.h>
#endif /*G_OS_WIN32*/

/* Sanity checking ... write to this during read tests to make sure we don't
 * get optimized out.
 */
int vips__read_test;

/* Add this many lines above and below the mmap() window.
 */
int vips__window_margin_pixels = VIPS__WINDOW_MARGIN_PIXELS;

/* Always map at least this many bytes. There's no point making tiny windows
 * on small files.
 */
int vips__window_margin_bytes = VIPS__WINDOW_MARGIN_BYTES;

/* Track global mmap usage.
 */
#ifdef DEBUG_TOTAL
static int total_mmap_usage = 0;
static int max_mmap_usage = 0;
#endif /*DEBUG_TOTAL*/

static int
vips_window_unmap( VipsWindow *window )
{
	/* unmap the old window
	 */
	if( window->baseaddr ) {
		if( vips__munmap( window->baseaddr, window->length ) )
			return( -1 );

#ifdef DEBUG_TOTAL
		g_mutex_lock( vips__global_lock );
		total_mmap_usage -= window->length;
		g_assert( total_mmap_usage >= 0 );
		g_mutex_unlock( vips__global_lock );
#endif /*DEBUG_TOTAL*/

		window->data = NULL;
		window->baseaddr = NULL;
		window->length = 0;
	}

	return( 0 );
}

static int
vips_window_free( VipsWindow *window )
{
	VipsImage *im = window->im;

	g_assert( window->ref_count == 0 );

#ifdef DEBUG
	printf( "** vips_window_free: window top = %d, height = %d (%p)\n",
		window->top, window->height, window );
	printf( "vips_window_unref: %d windows left\n",
		g_slist_length( im->windows ) );
#endif /*DEBUG*/

	g_assert( g_slist_find( im->windows, window ) );
	im->windows = g_slist_remove( im->windows, window );

	if( vips_window_unmap( window ) )
		return( -1 );

	window->im = NULL;

	g_free( window );

	return( 0 );
}

int
vips_window_unref( VipsWindow *window )
{
	VipsImage *im = window->im;

	g_mutex_lock( im->sslock );

#ifdef DEBUG
	printf( "vips_window_unref: window top = %d, height = %d, count = %d\n",
		window->top, window->height, window->ref_count );
#endif /*DEBUG*/

	g_assert( window->ref_count > 0 );

	window->ref_count -= 1;

	if( window->ref_count == 0 ) {
		if( vips_window_free( window ) ) {
			g_mutex_unlock( im->sslock );
			return( -1 );
		}
	}

	g_mutex_unlock( im->sslock );

	return( 0 );
}

#ifdef DEBUG_TOTAL
static void
trace_mmap_usage( void )
{
	g_mutex_lock( vips__global_lock );
	{
		static int last_total = 0;
		int total = total_mmap_usage / (1024 * 1024);
		int max = max_mmap_usage / (1024 * 1024);

		if( total != last_total ) {
			printf( "vips_window_set: current mmap "
				"usage of ~%dMB (high water mark %dMB)\n", 
				total, max );
			last_total = total;
		}
	}
	g_mutex_unlock( vips__global_lock );
}
#endif /*DEBUG_TOTAL*/

static int
vips_getpagesize( void )
{
	static int pagesize = 0;

	if( !pagesize ) {
#ifdef G_OS_WIN32
		SYSTEM_INFO si;

		GetSystemInfo( &si );

		pagesize = si.dwAllocationGranularity;
#else /*!G_OS_WIN32*/
		pagesize = sysconf(_SC_PAGESIZE);
#endif /*G_OS_WIN32*/

#ifdef DEBUG_TOTAL
		printf( "vips_getpagesize: 0x%x\n", pagesize );
#endif /*DEBUG_TOTAL*/
	}

	return( pagesize );
}

/* Map a window into a file.
 */
static int
vips_window_set( VipsWindow *window, int top, int height )
{
	int pagesize = vips_getpagesize();

	void *baseaddr;
	gint64 start, end, pagestart;
	size_t length, pagelength;

	/* Calculate start and length for our window. 
	 */
	start = window->im->sizeof_header + 
		VIPS_IMAGE_SIZEOF_LINE( window->im ) * top;
	length = VIPS_IMAGE_SIZEOF_LINE( window->im ) * height;

	pagestart = start - start % pagesize;
	end = start + length;
	pagelength = end - pagestart;

	/* Make sure we have enough file.
	 */
	if( end > window->im->file_length ) {
		vips_error( "vips_window_set", 
			_( "unable to read data for \"%s\", %s" ),
			window->im->filename, _( "file has been truncated" ) );
		return( -1 );
	}

	if( vips_window_unmap( window ) )
		return( -1 );

	if( !(baseaddr = vips__mmap( window->im->fd, 
		0, pagelength, pagestart )) )
		return( -1 ); 

	window->baseaddr = baseaddr;
	window->length = pagelength;

	window->data = (VipsPel *) baseaddr + (start - pagestart);
	window->top = top;
	window->height = height;

	/* Sanity check ... make sure the data pointer is readable.
	 */
	vips__read_test &= window->data[0];

#ifdef DEBUG_TOTAL
	g_mutex_lock( vips__global_lock );
	total_mmap_usage += window->length;
	if( total_mmap_usage > max_mmap_usage )
		max_mmap_usage = total_mmap_usage;
	g_mutex_unlock( vips__global_lock );
	trace_mmap_usage();
#endif /*DEBUG_TOTAL*/

	return( 0 );
}

/* Make a new window.
 */
static VipsWindow *
vips_window_new( VipsImage *im, int top, int height )
{
	VipsWindow *window;

	if( !(window = VIPS_NEW( NULL, VipsWindow )) )
		return( NULL );

	window->ref_count = 0;
	window->im = im;
	window->top = 0;
	window->height = 0;
	window->data = NULL;
	window->baseaddr = NULL;
	window->length = 0;
	im->windows = g_slist_prepend( im->windows, window );

	if( vips_window_set( window, top, height ) ) {
		vips_window_free( window );
		return( NULL );
	}
	window->ref_count = 1;

#ifdef DEBUG
	printf( "** vips_window_new: window top = %d, height = %d (%p)\n",
		window->top, window->height, window );
#endif /*DEBUG*/

	return( window );
}

/* A request for an area of pixels.
 */
typedef struct {
	int top;
	int height;
} request_t;

static void *
vips_window_fits( VipsWindow *window, request_t *req, void *b )
{
	if( window->top <= req->top && 
		window->top + window->height >= req->top + req->height )
		return( window );

	return( NULL );
}

/* Find an existing window that fits within top/height and return a ref.
 */
static VipsWindow *
vips_window_find( VipsImage *im, int top, int height )
{
	request_t req;
	VipsWindow *window;

	req.top = top;
	req.height = height;
	window = vips_slist_map2( im->windows, 
		(VipsSListMap2Fn) vips_window_fits, &req, NULL );

	if( window ) {
		window->ref_count += 1;

#ifdef DEBUG
		printf( "vips_window_find: ref window top = %d, height = %d, "
			"count = %d\n",
			top, height, window->ref_count );
#endif /*DEBUG*/
	}

	return( window );
}

/* Update a window to make it enclose top/height. 
 */
VipsWindow *
vips_window_take( VipsWindow *window, VipsImage *im, int top, int height )
{
	int margin;

	/* We have a window and it has the pixels we need.
	 */
	if( window &&
		window->top <= top &&
		window->top + window->height >= top + height ) 
		return( window );

	g_mutex_lock( im->sslock );

	/* We have a window and we are the only ref to it ... scroll.
	 */
	if( window &&
		window->ref_count == 1 ) {
		if( vips_window_set( window, top, height ) ) {
			g_mutex_unlock( im->sslock );
			vips_window_unref( window );

			return( NULL );
		}

		g_mutex_unlock( im->sslock );

		return( window );
	}

	/* There's more than one ref to the window. We can just decrement.
	 * Don't call _unref, since we've inside the lock.
	 */
	if( window ) 
		window->ref_count -= 1;

	/* Is there an existing window we can reuse?
	 */
	if( (window = vips_window_find( im, top, height )) ) {
		g_mutex_unlock( im->sslock );

		return( window );
	}

	/* We have to make a new window. Make it a bit bigger than strictly 
	 * necessary.
	 */
	margin = VIPS_MIN( vips__window_margin_pixels,
		vips__window_margin_bytes / VIPS_IMAGE_SIZEOF_LINE( im ) );
	top -= margin;
	height += margin * 2;
	top = VIPS_CLIP( 0, top, im->Ysize - 1 );
	height = VIPS_CLIP( 0, height, im->Ysize - top );

	if( !(window = vips_window_new( im, top, height )) ) {
		g_mutex_unlock( im->sslock );
		return( NULL );
	}

	g_mutex_unlock( im->sslock );

	return( window );
}

void
vips_window_print( VipsWindow *window )
{
	printf( "VipsWindow: %p ref_count = %d, ", window, window->ref_count );
	printf( "im = %p, ", window->im );
	printf( "top = %d, ", window->top );
	printf( "height = %d, ", window->height );
	printf( "data = %p, ", window->data );
	printf( "baseaddr = %p, ", window->baseaddr );
	printf( "length = %zd\n", window->length );
}
