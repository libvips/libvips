/* @(#) memory.c: mem handling stuff
 *
 * 2/11/99 JC
 *	- from im_open.c and callback.c
 *	- malloc tracking stuff added
 * 11/3/01 JC
 * 	- im_strncpy() added
 * 20/4/01 JC
 * 	- im_(v)snprintf() added
 * 6/7/05
 *	- more tracking for DEBUGM
 * 20/10/06
 * 	- return NULL for size <= 0
 * 11/5/06
 * 	- abort() on malloc() failure with DEBUG
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
#include <stdarg.h>
#include <string.h>
#include <assert.h>

#include <vips/vips.h>
#include <vips/thread.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* Define for simple malloc tracking ... better to use dmalloc if you can.
#define DEBUGM
 */

/* abort() on memory errors.
#define DEBUG
 */

#ifdef DEBUG
#  warning DEBUG on in libsrc/iofuncs/memory.c
#endif /*DEBUG*/

/* Track total alloc/total free here for debugging.
 */
#ifdef DEBUGM
static size_t int total_mem_alloc = 0;
static unsigned int total_allocs = 0;
static size_t int high_water_mark = 0;
static GMutex *malloc_mutex = NULL;
static GSList *malloc_list = NULL;
static const int trace_freq = 100;	/* Msg every this many malloc/free */
static int next_trace = 0;
#endif /*DEBUGM*/

/* VIPS free function. Try to put all vips free() through this.
 */
int
im_free( void *s )
{
#ifdef DEBUGM
{
	size_t size;

	s = (void *) ((char*)s - 16);
	size = *((size_t*)s);
	g_mutex_lock( malloc_mutex );

	assert( g_slist_find( malloc_list, s ) );
	malloc_list = g_slist_remove( malloc_list, s );
	assert( !g_slist_find( malloc_list, s ) );
	malloc_list = g_slist_remove( malloc_list, s );
	assert( total_allocs > 0 );

	total_mem_alloc -= size;
	total_allocs -= 1;

	next_trace += 1;
	if( next_trace > trace_freq ) {
		printf( "im_free: %d, %d allocs, total %.3gM, "
			"high water %.3gM\n", 
			size,
			total_allocs,
			total_mem_alloc / (1024.0 * 1024.0), 
			high_water_mark / (1024.0 * 1024.0) );
		next_trace = 0;
	}

	g_mutex_unlock( malloc_mutex );
}
#endif /*DEBUGM*/

#ifdef DEBUG
	if( !s )
		abort();
#endif /*DEBUG*/

	free( s );

	return( 0 );
}

/* Malloc local to a descriptor. Try to put all vips malloc through this. Not
 * thread-safe if im != NULL.
 */
void *
im_malloc( IMAGE *im, size_t size )
{
        void *buf;

#ifdef DEBUGM
	/* Assume the first im_malloc() is single-threaded.
	 */
	if( !malloc_mutex )
		malloc_mutex = g_mutex_new();
#endif /*DEBUGM*/

#ifdef DEBUGM
	/* If debugging mallocs, need an extra sizeof(uint) bytes to track 
	 * size of this block. Ask for an extra 16 to make sure we don't break
	 * alignment rules.
	 */
	size += 16;
#endif /*DEBUGM*/

        if( !(buf = malloc( size )) ) {
#ifdef DEBUG
		abort();
#endif /*DEBUG*/

		im_error( "im_malloc", 
			_( "out of memory --- size == %dMB" ), 
			(int) (size / (1024.0*1024.0))  );
		im_warn( "im_malloc", 
			_( "out of memory --- size == %dMB" ), 
			(int) (size / (1024.0*1024.0))  );
                return( NULL );
	}

#ifdef DEBUGM
	/* Record number alloced.
	 */
	g_mutex_lock( malloc_mutex );
	assert( !g_slist_find( malloc_list, buf ) );
	malloc_list = g_slist_prepend( malloc_list, buf );
	*((size_t*)buf) = size;
	buf = (void *) ((char*)buf + 16);
	total_mem_alloc += size;
	if( total_mem_alloc > high_water_mark ) 
		high_water_mark = total_mem_alloc;
	total_allocs += 1;

	next_trace += 1;
	if( next_trace > trace_freq ) {
		printf( "im_malloc: %d, %d allocs, total %.3gM, "
			"high water %.3gM\n", 
			size, 
			total_allocs,
			total_mem_alloc / (1024.0 * 1024.0),
			high_water_mark / (1024.0 * 1024.0) );
		next_trace = 0;
	}

	g_mutex_unlock( malloc_mutex );

	/* Handy to breakpoint on this printf() for catching large mallocs().
	 */
	if( size > 1000000 ) 
		printf( "woah! big!\n" );
#endif /*DEBUGM*/
 
        if( im && im_add_close_callback( im, 
		(im_callback_fn) im_free, buf, NULL ) ) {
                im_free( buf );
                return( NULL );
        }
 
        return( buf );
}
