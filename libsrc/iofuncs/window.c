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
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

 */

/*

    These files are distributed with VIPS - http://www.vips.ecs.soton.ac.uk

 */

/*
#define DEBUG_TOTAL
#define DEBUG_ENVIRONMENT
#define DEBUG
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
#include <errno.h>
#include <string.h>
#ifdef HAVE_SYS_MMAN_H
#include <sys/mman.h>
#endif
#include <assert.h>

#include <vips/vips.h>
#include <vips/internal.h>
#include <vips/thread.h>

#ifdef OS_WIN32
#include <windows.h>
#endif /*OS_WIN32*/

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* Sanity checking ... write to this during read tests to make sure we don't
 * get optimised out.
 */
int im__read_test;

/* Add this many lines above and below the mmap() window.
 */
int im__window_margin = IM__WINDOW_MARGIN;

/* Track global mmap usage.
 */
#ifdef DEBUG_TOTAL
static int total_mmap_usage = 0;
static int max_mmap_usage = 0;
#endif /*DEBUG_TOTAL*/

static int
im_window_unmap( im_window_t *window )
{
	/* unmap the old window
	 */
	if( window->baseaddr ) {
		if( im__munmap( window->baseaddr, window->length ) )
			return( -1 );

#ifdef DEBUG_TOTAL
		g_mutex_lock( im__global_lock );
		total_mmap_usage -= window->length;
		assert( total_mmap_usage >= 0 );
		g_mutex_unlock( im__global_lock );
#endif /*DEBUG_TOTAL*/

		window->data = NULL;
		window->baseaddr = NULL;
		window->length = 0;
	}

	return( 0 );
}

static int
im_window_free( im_window_t *window )
{
	assert( window->ref_count == 0 );

#ifdef DEBUG
	printf( "** im_window_free: window top = %d, height = %d (%p)\n",
		window->top, window->height, window );
#endif /*DEBUG*/

	if( im_window_unmap( window ) )
		return( -1 );

	window->im = NULL;

	im_free( window );

	return( 0 );
}

int
im_window_unref( im_window_t *window )
{
	IMAGE *im = window->im;

	g_mutex_lock( im->sslock );

#ifdef DEBUG
	printf( "im_window_unref: window top = %d, height = %d, count = %d\n",
		window->top, window->height, window->ref_count );
#endif /*DEBUG*/

	assert( window->ref_count > 0 );

	window->ref_count -= 1;

	if( window->ref_count == 0 ) {
		assert( g_slist_find( im->windows, window ) );
		im->windows = g_slist_remove( im->windows, window );

#ifdef DEBUG
		printf( "im_window_unref: %d windows left\n",
			g_slist_length( im->windows ) );
#endif /*DEBUG*/

		if( im_window_free( window ) ) {
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
	g_mutex_lock( im__global_lock );
	{
		static int last_total = 0;
		int total = total_mmap_usage / (1024 * 1024);
		int max = max_mmap_usage / (1024 * 1024);

		if( total != last_total ) {
			printf( "im_window_set: current mmap "
				"usage of ~%dMB (high water mark %dMB)\n", 
				total, max );
			last_total = total;
		}
	}
	g_mutex_unlock( im__global_lock );
}
#endif /*DEBUG_TOTAL*/

static int
im_getpagesize()
{
	static int pagesize = 0;

	if( !pagesize ) {
#ifdef OS_WIN32
		SYSTEM_INFO si;

		GetSystemInfo( &si );

		pagesize = si.dwAllocationGranularity;
#else /*OS_WIN32*/
		pagesize = getpagesize();
#endif /*OS_WIN32*/

#ifdef DEBUG_TOTAL
		printf( "im_getpagesize: 0x%x\n", pagesize );
#endif /*DEBUG_TOTAL*/
	}

	return( pagesize );
}

/* Map a window into a file.
 */
static int
im_window_set( im_window_t *window, int top, int height )
{
	int pagesize = im_getpagesize();

	void *baseaddr;
	gint64 start, end, pagestart;
	size_t length, pagelength;

	/* Calculate start and length for our window.
	 */
	start = window->im->sizeof_header + 
		(gint64) IM_IMAGE_SIZEOF_LINE( window->im ) * top;
	length = (size_t) IM_IMAGE_SIZEOF_LINE( window->im ) * height;

	pagestart = start - start % pagesize;
	end = start + length;
	pagelength = end - pagestart;

	/* Make sure we have enough file.
	 */
	if( end > window->im->file_length ) {
		im_error( "im_window_set", 
			_( "unable to read data for \"%s\", %s" ),
			window->im->filename, _( "file has been truncated" ) );
		return( -1 );
	}

	if( !(baseaddr = im__mmap( window->im->fd, 0, pagelength, pagestart )) )
		return( -1 ); 

	window->baseaddr = baseaddr;
	window->length = pagelength;

	window->data = (char *) baseaddr + (start - pagestart);
	window->top = top;
	window->height = height;

	/* Sanity check ... make sure the data pointer is readable.
	 */
	im__read_test &= window->data[0];

#ifdef DEBUG_TOTAL
	g_mutex_lock( im__global_lock );
	total_mmap_usage += window->length;
	if( total_mmap_usage > max_mmap_usage )
		max_mmap_usage = total_mmap_usage;
	g_mutex_unlock( im__global_lock );
	trace_mmap_usage();
#endif /*DEBUG_TOTAL*/

	return( 0 );
}

/* Make a new window.
 */
static im_window_t *
im_window_new( IMAGE *im, int top, int height )
{
	im_window_t *window;

	if( !(window = IM_NEW( NULL, im_window_t )) )
		return( NULL );

	window->ref_count = 0;
	window->im = im;
	window->top = 0;
	window->height = 0;
	window->data = NULL;
	window->baseaddr = NULL;
	window->length = 0;

	if( im_window_set( window, top, height ) ) {
		im_window_free( window );
		return( NULL );
	}

	im->windows = g_slist_prepend( im->windows, window );
	window->ref_count += 1;

#ifdef DEBUG
	printf( "** im_window_new: window top = %d, height = %d (%p)\n",
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
im_window_fits( im_window_t *window, request_t *req )
{
	if( window->top <= req->top && 
		window->top + window->height >= req->top + req->height )
		return( window );

	return( NULL );
}

/* Find an existing window that fits within top/height and return a ref.
 */
static im_window_t *
im_window_find( IMAGE *im, int top, int height )
{
	request_t req;
	im_window_t *window;

	req.top = top;
	req.height = height;
	window = im_slist_map2( im->windows, 
		(VSListMap2Fn) im_window_fits, &req, NULL );

	if( window ) {
		window->ref_count += 1;

#ifdef DEBUG
		printf( "im_window_find: ref window top = %d, height = %d, "
			"count = %d\n",
			top, height, window->ref_count );
#endif /*DEBUG*/
	}

	return( window );
}

/* Return a ref to a window that encloses top/height.
 */
im_window_t *
im_window_ref( IMAGE *im, int top, int height )
{
	im_window_t *window;
#ifdef DEBUG_ENVIRONMENT
	static const char *str = NULL;
#endif /*DEBUG_ENVIRONMENT*/

#ifdef DEBUG_ENVIRONMENT
	if( !str ) {
		if( (str = g_getenv( "IM_WINDOW_MARGIN" )) ) {
			printf( "iofuncs/region.c: "
				"compiled with DEBUG_ENVIRONMENT enabled\n" );
			im__window_margin = atoi( str );
			printf( "im_region_create: setting window margin to %d "
				"from environment\n", im__window_margin );
		}
		else
			str = "done";
	}
#endif /*DEBUG_ENVIRONMENT*/

	g_mutex_lock( im->sslock );

	if( !(window = im_window_find( im, top, height )) ) {
		/* No existing window ... make a new one.
		 */
		top -= im__window_margin;
		height += im__window_margin * 2;
		top = IM_CLIP( 0, top, im->Ysize - 1 );
		height = IM_CLIP( 0, height, im->Ysize - top );

		if( !(window = im_window_new( im, top, height )) ) {
			g_mutex_unlock( im->sslock );
			return( NULL );
		}
	}

	g_mutex_unlock( im->sslock );

	return( window );
}

void
im_window_print( im_window_t *window )
{
	printf( "im_window_t: %p ref_count = %d, ", window, window->ref_count );
	printf( "im = %p, ", window->im );
	printf( "top = %d, ", window->top );
	printf( "height = %d, ", window->height );
	printf( "data = %p, ", window->data );
	printf( "baseaddr = %p, ", window->baseaddr );
	printf( "length = %zd\n", window->length );
}
