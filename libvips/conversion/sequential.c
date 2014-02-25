/* Like copy, but ensure sequential access. 
 *
 * Handy with sequential for loading files formats which are strictly
 * top-to-bottom, like PNG. 
 *
 * 15/2/12
 * 	- from VipsForeignLoad
 * 14/7/12
 * 	- support skip forwards as well, so we can do extract/insert
 * 10/8/12
 * 	- add @trace option
 * 21/8/12
 * 	- remove skip forward, instead do thread stalling and have an
 * 	  integrated cache
 * 	- use linecache
 * 4/9/12
 * 	- stop all threads on error
 * 	- don't stall forever, just delay ahead threads
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

    You should have received a cache of the GNU Lesser General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
    02110-1301  USA

 */

/*

    These files are distributed with VIPS - http://www.vips.ecs.soton.ac.uk

 */

/*
#define VIPS_DEBUG_GREEN
#define VIPS_DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vips/vips.h>
#include <vips/internal.h>
#include <vips/debug.h>

#include "pconversion.h"

/* Stall threads that run ahead for up to this long, in seconds.
 *
 * This has to be a long time: if we're trying to use all cores on a busy 
 * system, it could be ages until all the other threads get a chance to run. 
 */
#define STALL_TIME (1.0)

typedef struct _VipsSequential {
	VipsConversion parent_instance;

	VipsImage *in;
	int tile_height;
	VipsAccess access;
	gboolean trace;

	/* Lock access to y_pos with this, use the cond to wake up stalled
	 * threads.
	 */
	GMutex *lock;
	GCond *ready;

	/* The next read from our source will fetch this scanline, ie. it's 0
	 * when we start.
	 */
	int y_pos;

	/* If one thread gets an error, we must stop all threads, otherwise we
	 * can stall and never wake.
	 */
	int error;
} VipsSequential;

typedef VipsConversionClass VipsSequentialClass;

G_DEFINE_TYPE( VipsSequential, vips_sequential, VIPS_TYPE_CONVERSION );

static void
vips_sequential_dispose( GObject *gobject )
{
	VipsSequential *sequential = (VipsSequential *) gobject;

	VIPS_FREEF( vips_g_mutex_free, sequential->lock );
	VIPS_FREEF( vips_g_cond_free, sequential->ready );

	G_OBJECT_CLASS( vips_sequential_parent_class )->dispose( gobject );
}

static int
vips_sequential_generate( VipsRegion *or, 
	void *seq, void *a, void *b, gboolean *stop )
{
	VipsSequential *sequential = (VipsSequential *) b;
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( sequential );
        VipsRect *r = &or->valid;
	VipsRegion *ir = (VipsRegion *) seq;

	VIPS_DEBUG_MSG_GREEN( "thread %p request for line %d, height %d\n", 
		g_thread_self(), r->top, r->height );

	if( sequential->trace )
		vips_info( class->nickname, 
			"request for line %d, height %d", 
			r->top, r->height );

	VIPS_GATE_START( "vips_sequential_generate: wait" );

	g_mutex_lock( sequential->lock );

	VIPS_GATE_STOP( "vips_sequential_generate: wait" );

	VIPS_DEBUG_MSG_GREEN( "thread %p has lock ...\n", g_thread_self() ); 

	/* If we've seen an error, everything must stop.
	 */
	if( sequential->error ) {
		g_mutex_unlock( sequential->lock );
		return( -1 );
	}

	if( r->top > sequential->y_pos /* &&
		sequential->y_pos > 0 */ ) {
		/* We have started reading (y_pos > 0) and this request is for
		 * stuff beyond that, stall for a while to give other
		 * threads time to catch up.
		 * 
		 * The stall can be cancelled by a signal on @ready.
		 *
		 * We don't stall forever, since an error would be better than
		 * deadlock, and we don't fail on timeout, since the timeout 
		 * may be harmless.
		 */
#ifdef HAVE_COND_INIT
		gint64 time;

		time = g_get_monotonic_time () + 
			STALL_TIME * G_TIME_SPAN_SECOND;
#else
		GTimeVal time;

		g_get_current_time( &time );
		g_time_val_add( &time, STALL_TIME * 1000000 );
#endif

		VIPS_DEBUG_MSG_GREEN( "thread %p stalling for up to %gs ...\n", 
			g_thread_self(), STALL_TIME ); 

		VIPS_GATE_START( "vips_sequential_generate: wait" );

		/* Exit the loop on timeout or condition passes. We have to
		 * be wary of spurious wakeups. 
		 */
		while( r->top > sequential->y_pos )
#ifdef HAVE_COND_INIT
			if( !g_cond_wait_until( sequential->ready, 
				sequential->lock, time ) )
				break;
#else
			if( !g_cond_timed_wait( sequential->ready, 
				sequential->lock, &time ) )
				break;
#endif

		VIPS_GATE_STOP( "vips_sequential_generate: wait" );

		VIPS_DEBUG_MSG_GREEN( "thread %p awake again ...\n", 
			g_thread_self() ); 
	}

	if( r->top > sequential->y_pos ) {
		/* This is a request for something some way down the image, 
		 * and we've fallen through from the stall above. 
		 *
		 * Probably the operation is something like extract_area and 
		 * we should skip the initial part of the image. In fact, 
		 * we read to cache, since it may be useful.
		 */
		VipsRect area;

		VIPS_DEBUG_MSG_GREEN( "thread %p skipping to line %d ...\n", 
			g_thread_self(),
			r->top );

		area.left = 0;
		area.top = sequential->y_pos;
		area.width = 1;
		area.height = r->top - sequential->y_pos;
		if( vips_region_prepare( ir, &area ) ) {
			VIPS_DEBUG_MSG( "thread %p error, unlocking ...\n", 
				g_thread_self() ); 
			sequential->error = -1;
			g_cond_broadcast( sequential->ready );
			g_mutex_unlock( sequential->lock );
			return( -1 );
		}

		sequential->y_pos = VIPS_RECT_BOTTOM( &area );
	}

	/* This is a request for old or present pixels -- serve from cache.
	 * This may trigger further, sequential reads.
	 */
	VIPS_DEBUG_MSG_GREEN( "thread %p reading ...\n", g_thread_self() ); 
	if( vips_region_prepare( ir, r ) ||
		vips_region_region( or, ir, r, r->left, r->top ) ) {
		VIPS_DEBUG_MSG( "thread %p error, unlocking ...\n", 
			g_thread_self() ); 
		sequential->error = -1;
		g_cond_broadcast( sequential->ready );
		g_mutex_unlock( sequential->lock );
		return( -1 );
	}

	if( VIPS_RECT_BOTTOM( r ) > sequential->y_pos ) {
		/* This request has moved the read point. Update it, and wake 
		 * up all stalled threads for a retry.
		 */
		sequential->y_pos = VIPS_RECT_BOTTOM( r );

		VIPS_DEBUG_MSG_GREEN( "thread %p updating y_pos to %d and "
			"waking stalled\n", 
			g_thread_self(),
			sequential->y_pos ); 

		g_cond_broadcast( sequential->ready );
	}

	VIPS_DEBUG_MSG_GREEN( "thread %p unlocking ...\n", g_thread_self() ); 

	g_mutex_unlock( sequential->lock );

	return( 0 );
}

static int
vips_sequential_build( VipsObject *object )
{
	VipsConversion *conversion = VIPS_CONVERSION( object );
	VipsSequential *sequential = (VipsSequential *) object;

	VipsImage *t;

	VIPS_DEBUG_MSG( "vips_sequential_build\n" );

	if( VIPS_OBJECT_CLASS( vips_sequential_parent_class )->build( object ) )
		return( -1 );

	if( vips_image_pio_input( sequential->in ) )
		return( -1 );

	if( vips_linecache( sequential->in, &t, 
		"tile_height", sequential->tile_height,
		"access", sequential->access,
		NULL ) )
		return( -1 );

	vips_object_local( object, t ); 

	if( vips_image_pipelinev( conversion->out, 
		VIPS_DEMAND_STYLE_THINSTRIP, t, NULL ) )
		return( -1 );
	if( vips_image_generate( conversion->out,
		vips_start_one, vips_sequential_generate, vips_stop_one, 
		t, sequential ) )
		return( -1 );

	return( 0 );
}

static void
vips_sequential_class_init( VipsSequentialClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	VIPS_DEBUG_MSG( "vips_sequential_class_init\n" );

	gobject_class->dispose = vips_sequential_dispose;
	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "sequential";
	vobject_class->description = _( "check sequential access" );
	vobject_class->build = vips_sequential_build;

	VIPS_ARG_IMAGE( class, "in", 1, 
		_( "Input" ), 
		_( "Input image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsSequential, in ) );

	VIPS_ARG_BOOL( class, "trace", 2, 
		_( "trace" ), 
		_( "trace pixel requests" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsSequential, trace ),
		TRUE );

	VIPS_ARG_INT( class, "tile_height", 3, 
		_( "Tile height" ), 
		_( "Tile height in pixels" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsSequential, tile_height ),
		1, 1000000, 1 );

	VIPS_ARG_ENUM( class, "access", 6, 
		_( "Strategy" ), 
		_( "Expected access pattern" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsSequential, access ),
		VIPS_TYPE_ACCESS, VIPS_ACCESS_SEQUENTIAL );
}

static void
vips_sequential_init( VipsSequential *sequential )
{
	sequential->trace = FALSE;
	sequential->access = VIPS_ACCESS_SEQUENTIAL;
	sequential->lock = vips_g_mutex_new();
	sequential->ready = vips_g_cond_new();
	sequential->tile_height = 1;
	sequential->error = 0;
}

/**
 * vips_sequential:
 * @in: input image
 * @out: output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * @trace: trace requests
 * @strip_height: height of cache strips
 * @access: access pattern
 *
 * This operation behaves rather like vips_copy() between images
 * @in and @out, except that it checks that pixels are only requested
 * top-to-bottom. If a thread makes an out of order request, it is stalled
 * until the pack catches up.
 *
 * This operation is useful for loading file formats which are 
 * strictly top-to-bottom, like PNG. 
 *
 * If @trace is true, the operation will print diagnostic messages for each
 * block of pixels which are processed. This can help find the cause of
 * non-sequential accesses. 
 *
 * @strip_height can be used to set the size of the tiles that
 * vips_sequential() uses. The default value is 1.
 *
 * @access can be set to #VIPS_ACCESS_SEQUENTIAL_UNBUFFERED, meaning don't
 * keep a large cache behind the read point. This can save some memory. 
 *
 * See also: vips_image_cache().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_sequential( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "sequential", ap, in, out );
	va_end( ap );

	return( result );
}
