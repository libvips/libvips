/* : mem handling stuff
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
 * 20/10/09
 * 	- gtkdoc comment
 * 6/11/09
 *	- im_malloc()/im_free() now call g_try_malloc()/g_free() ... removes 
 *	  confusion over whether to use im_free() or g_free() for things like 
 *	  im_header_string()
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

#include <vips/vips.h>
#include <vips/thread.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/**
 * SECTION: memory
 * @short_description: memory utilities
 * @stability: Stable
 * @include: vips/vips.h
 *
 * Simple memory allocation utilities. These functions and macros help
 * allocate and free memory. Most of VIPS uses them, though some parts use
 * the g_malloc() system instead, confusingly.
 *
 * Use these functions for large allocations, such as arrays of image data. 
 * vips uses vips_alloc_get_mem(), which gives the amount of memory currently
 * allocated via these functions, to decide when to start dropping cache.
 *
 * If you compile with %DEBUGM it will track allocations for you, though
 * valgrind or dmalloc are better solutions.
 */

/* Define for simple malloc tracking ... better to use dmalloc if you can.
#define DEBUGM
 */

/* g_assert( 0 ) on memory errors.
#define DEBUG
 */

#ifdef DEBUG
#  warning DEBUG on in libsrc/iofuncs/memory.c
#endif /*DEBUG*/

static size_t vips_alloc_mem = 0;
static unsigned int vips_allocs = 0;
static size_t vips_alloc_mem_highwater = 0;
static GMutex *vips_alloc_mutex = NULL;

#ifdef DEBUGM
/* Track total alloc/total free here for debugging.
 */
static GSList *malloc_list = NULL;
static const int trace_freq = 100;	/* Msg every this many malloc/free */
static int next_trace = 0;
#endif /*DEBUGM*/

/**
 * VIPS_NEW:
 * @IM: allocate memory local to @IM, or %NULL for no auto-free
 * @T: type of thing to allocate
 *
 * Returns: A pointer of type @T *, or %NULL on error.
 */

/**
 * VIPS_ARRAY:
 * @IM: allocate memory local to @IM, or %NULL for no auto-free
 * @N: number of @T 's to allocate
 * @T: type of thing to allocate
 *
 * Returns: A pointer of type @T *, or %NULL on error.
 */

/**
 * vips_free:
 * @s: memory to free
 *
 * VIPS free function. VIPS tries to use this instead of free(). It always
 * returns zero, so it can be used as a callback handler. 
 *
 * Only use it to free
 * memory that was previously allocated with vips_malloc() with a %NULL first
 * argument.
 *
 * Returns: 0
 */
int
vips_free( void *s )
{
	size_t size;

	/* Keep the size of the alloc in the previous 16 bytes. Ensures
	 * alignment rules are kept.
	 */
	s = (void *) ((char*)s - 16);
	size = *((size_t*)s);

	g_mutex_lock( vips_alloc_mutex );

	if( vips_allocs <= 0 ) 
		vips_warn( "vips_malloc", 
			"%s", _( "vips_free: too many frees" ) );
	vips_alloc_mem -= size;
	vips_allocs -= 1;

#ifdef DEBUGM
	g_assert( g_slist_find( malloc_list, s ) );
	malloc_list = g_slist_remove( malloc_list, s );
	g_assert( !g_slist_find( malloc_list, s ) );
	malloc_list = g_slist_remove( malloc_list, s );

	next_trace += 1;
	if( next_trace > trace_freq ) {
		printf( "vips_free: %d, %d allocs, total %.3gM, "
			"high water %.3gM\n", 
			size,
			vips_allocs,
			vips_alloc_mem / (1024.0 * 1024.0), 
			vips_alloc_mem_highwater / (1024.0 * 1024.0) );
		next_trace = 0;
	}
#endif /*DEBUGM*/

	g_mutex_unlock( vips_alloc_mutex );

#ifdef DEBUG
	if( !s )
		g_assert( 0 );
#endif /*DEBUG*/

	g_free( s );

	return( 0 );
}

static void
vips_malloc_cb( VipsImage *image, char *buf )
{
	vips_free( buf );
}

/* g_mutex_new() is a macro.
 */
static void *
vips_alloc_mutex_new( void *data )
{
	return( g_mutex_new() );
}

/**
 * vips_malloc:
 * @image: allocate memory local to this #VipsImage, or %NULL
 * @size: number of bytes to allocate
 *
 * Malloc local to @im, that is, the memory will be automatically 
 * freed for you when the image is closed. If @im is %NULL, you need to free
 * the memory explicitly with vips_free().
 * If allocation fails vips_malloc() returns %NULL and 
 * sets an error message.
 *
 * If two threads try to allocate local to the same @im at the same time, you 
 * can get heap corruption. 
 *
 * Returns: a pointer to the allocated memory, or %NULL on error.
 */
void *
vips_malloc( VipsImage *image, size_t size )
{
	static GOnce vips_alloc_once = G_ONCE_INIT;

        void *buf;

	vips_alloc_mutex = g_once( &vips_alloc_once, 
		vips_alloc_mutex_new, NULL );

	/* Need an extra sizeof(size_t) bytes to track 
	 * size of this block. Ask for an extra 16 to make sure we don't break
	 * alignment rules.
	 */
	size += 16;

        if( !(buf = g_try_malloc( size )) ) {
#ifdef DEBUG
		g_assert( 0 );
#endif /*DEBUG*/

		vips_error( "vips_malloc", 
			_( "out of memory --- size == %dMB" ), 
			(int) (size / (1024.0*1024.0))  );
		vips_warn( "vips_malloc", 
			_( "out of memory --- size == %dMB" ), 
			(int) (size / (1024.0*1024.0))  );

                return( NULL );
	}

	g_mutex_lock( vips_alloc_mutex );

#ifdef DEBUGM
	g_assert( !g_slist_find( malloc_list, buf ) );
	malloc_list = g_slist_prepend( malloc_list, buf );
#endif /*DEBUGM*/

	*((size_t *)buf) = size;
	buf = (void *) ((char *)buf + 16);

	vips_alloc_mem += size;
	if( vips_alloc_mem > vips_alloc_mem_highwater ) 
		vips_alloc_mem_highwater = vips_alloc_mem;
	vips_allocs += 1;

#ifdef DEBUGM
	next_trace += 1;
	if( next_trace > trace_freq ) {
		printf( "vips_malloc: %d, %d allocs, total %.3gM, "
			"high water %.3gM\n", 
			size, 
			vips_allocs,
			vips_alloc_mem / (1024.0 * 1024.0),
			vips_alloc_mem_highwater / (1024.0 * 1024.0) );
		next_trace = 0;
	}
#endif /*DEBUGM*/

	g_mutex_unlock( vips_alloc_mutex );

#ifdef DEBUGM
	/* Handy to breakpoint on this printf() for catching large mallocs().
	 */
	if( size > 1000000 ) 
		printf( "woah! big!\n" );
#endif /*DEBUGM*/
 
        if( image )
		g_signal_connect( image, "postclose", 
			G_CALLBACK( vips_malloc_cb ), buf );

        return( buf );
}

/* strdup local to a descriptor.
 */
char *
vips_strdup( VipsImage *image, const char *str )
{
	int l = strlen( str );
	char *buf;

	if( !(buf = (char *) vips_malloc( image, l + 1 )) )
		return( NULL );
	strcpy( buf, str );

	return( buf );
}

/**
 * vips_alloc_get_mem:
 *
 * Returns the number of bytes currently allocated via vips_malloc() and
 * friends. vips uses this figure to decide when to start dropping cache, see
 * #VipsOperation.
 *
 * Returns: the number of currently allocated bytes
 */
size_t
vips_alloc_get_mem( void )
{
	return( vips_alloc_mem );
}

/**
 * vips_alloc_get_mem_highwater:
 *
 * Returns the largest number of bytes simultaneously allocated via 
 * vips_malloc() and friends. 
 *
 * Returns: the largest number of currently allocated bytes
 */
size_t
vips_alloc_get_mem_highwater( void )
{
	return( vips_alloc_mem_highwater );
}

/**
 * vips_alloc_get_allocs:
 *
 * Returns the number active allocations. 
 *
 * Returns: the number active allocations
 */
unsigned int
vips_alloc_get_allocs( void )
{
	return( vips_allocs );
}

