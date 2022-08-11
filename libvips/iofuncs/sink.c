/* A sink that's not attached to anything, eg. find image average,
 * 
 * 28/3/10
 * 	- from im_iterate(), reworked for threadpool
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
#define VIPS_DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <glib/gi18n-lib.h>

#include <stdio.h>
#include <stdlib.h>

#include <vips/vips.h>
#include <vips/thread.h>
#include <vips/internal.h>
#include <vips/debug.h>

#include "sink.h"

/* A part of the image we are scanning. 
 *
 * We can't let any threads fall too far behind as that would mess up seq
 * image sources. Keep track of two areas moving down the image, and stall if
 * the previous area still has active threads. 
 */
typedef struct _SinkArea {
	struct _Sink *sink;

	VipsRect rect;		/* Part of image this area covers */
        VipsSemaphore n_thread;	/* Number of threads scanning this area */
} SinkArea;

/* Per-call state.
 */
typedef struct _Sink {
	SinkBase sink_base;

	/* We need a temp "p" image between the source image and us to
	 * make sure we can't damage the original.
	 */
	VipsImage *t;

	/* Mutex for serialising calls to VipsStartFn and VipsStopFn.
	 */
	GMutex *sslock;

	/* Call params.
	 */
	VipsStartFn start_fn;
	VipsGenerateFn generate_fn;
	VipsStopFn stop_fn;
	void *a;
	void *b;

	/* We are current scanning area, we'll delay starting a new
	 * area if old_area (the previous position) hasn't completed. 
	 */
	SinkArea *area;
	SinkArea *old_area;

} Sink;

/* Our per-thread state.
 */
typedef struct _SinkThreadState {
	VipsThreadState parent_object;

	/* Sequence value for this thread.
	 */
        void *seq;

	/* The region we walk over sink.t copy. We can't use
	 * parent_object.reg, it's defined on the outer image.
	 */
	VipsRegion *reg;

	/* The area we were allocated from. 
	 */
        SinkArea *area;

} SinkThreadState;

typedef struct _SinkThreadStateClass {
	VipsThreadStateClass parent_class;

} SinkThreadStateClass;

G_DEFINE_TYPE( SinkThreadState, sink_thread_state, VIPS_TYPE_THREAD_STATE );

static void
sink_area_free( SinkArea *area )
{
	vips_semaphore_destroy( &area->n_thread );
	g_free( area );
}

static SinkArea *
sink_area_new( Sink *sink )
{
	SinkArea *area;

	if( !(area = VIPS_NEW( NULL, SinkArea )) )
		return( NULL );
	area->sink = sink;
	vips_semaphore_init( &area->n_thread, 0, "n_thread" );

	return( area );
}

/* Move an area to a position.
 */
static void 
sink_area_position( SinkArea *area, int top, int height )
{
	Sink *sink = area->sink;

	VipsRect all, rect;

	all.left = 0;
	all.top = 0;
	all.width = sink->sink_base.im->Xsize;
	all.height = sink->sink_base.im->Ysize;

	rect.left = 0;
	rect.top = top;
	rect.width = sink->sink_base.im->Xsize;
	rect.height = height;

	vips_rect_intersectrect( &all, &rect, &area->rect );
}

/* Our VipsThreadpoolAllocate function ... move the thread to the next tile
 * that needs doing. If we fill the current area, we block until the previous
 * area is finished, then swap areas. 
 *
 * If all tiles are done, we return FALSE to end iteration.
 */
static gboolean
sink_area_allocate_fn( VipsThreadState *state, void *a, gboolean *stop )
{
	SinkThreadState *sstate = (SinkThreadState *) state;
	Sink *sink = (Sink *) a;
	SinkBase *sink_base = (SinkBase *) sink;

	VipsRect image;
	VipsRect tile;

	VIPS_DEBUG_MSG( "sink_area_allocate_fn: %p\n", g_thread_self() );

	/* Is the state x/y OK? New line or maybe new buffer or maybe even 
	 * all done.
	 */
	if( sink_base->x >= sink->area->rect.width ) {
		sink_base->x = 0;
		sink_base->y += sink_base->tile_height;

		if( sink_base->y >= VIPS_RECT_BOTTOM( &sink->area->rect ) ) {
			/* Block until the previous area is done.
			 */
			if( sink->area->rect.top > 0 ) 
				vips_semaphore_downn( 
					&sink->old_area->n_thread, 0 );

			/* End of image?
			 */
			if( sink_base->y >= sink_base->im->Ysize ) {
				*stop = TRUE;
				return( 0 );
			}

			/* Swap buffers.
			 */
			VIPS_SWAP( SinkArea *, 
				sink->area, sink->old_area );

			/* Position buf at the new y.
			 */
			sink_area_position( sink->area, 
				sink_base->y, sink_base->n_lines );
		}
	}

	/* x, y and buf are good: save params for thread.
	 */
	image.left = 0;
	image.top = 0;
	image.width = sink_base->im->Xsize;
	image.height = sink_base->im->Ysize;
	tile.left = sink_base->x;
	tile.top = sink_base->y;
	tile.width = sink_base->tile_width;
	tile.height = sink_base->tile_height;
	vips_rect_intersectrect( &image, &tile, &state->pos );

	/* The thread needs to know which area it's writing to.
	 */
	sstate->area = sink->area;

	VIPS_DEBUG_MSG( "  %p allocated %d x %d:\n", 
		g_thread_self(), state->pos.left, state->pos.top );

	/* Add to the number of writers on the area.
	 */
	vips_semaphore_upn( &sink->area->n_thread, -1 );

	/* Move state on.
	 */
	sink_base->x += sink_base->tile_width;

	/* Add the number of pixels we've just allocated to progress.
	 */
	sink_base->processed += state->pos.width * state->pos.height;

	return( 0 );
}

/* Call a thread's stop function. 
 */
static int
sink_call_stop( Sink *sink, SinkThreadState *state )
{
	if( state->seq && sink->stop_fn ) {
		int result;

		VIPS_DEBUG_MSG( "sink_call_stop: state = %p\n", state );

		VIPS_GATE_START( "sink_call_stop: wait" );

		g_mutex_lock( sink->sslock );

		VIPS_GATE_STOP( "sink_call_stop: wait" );

		result = sink->stop_fn( state->seq, sink->a, sink->b );

		g_mutex_unlock( sink->sslock );

		if( result ) {
			SinkBase *sink_base = (SinkBase *) sink;

			vips_error( "vips_sink", 
				_( "stop function failed for image \"%s\"" ), 
				sink_base->im->filename );
			return( -1 );
		}

		state->seq = NULL;
	}

	return( 0 );
}

static void
sink_thread_state_dispose( GObject *gobject )
{
	SinkThreadState *state = (SinkThreadState *) gobject;
	Sink *sink = (Sink *) ((VipsThreadState *) state)->a;

	sink_call_stop( sink, state );
	VIPS_UNREF( state->reg );

	G_OBJECT_CLASS( sink_thread_state_parent_class )->dispose( gobject );
}

/* Call the start function for this thread, if necessary.
 */
static int
sink_call_start( Sink *sink, SinkThreadState *state )
{
	if( !state->seq && sink->start_fn ) {
		VIPS_DEBUG_MSG( "sink_call_start: state = %p\n", state );

		VIPS_GATE_START( "sink_call_start: wait" );

		g_mutex_lock( sink->sslock );

		VIPS_GATE_STOP( "sink_call_start: wait" );

		state->seq = sink->start_fn( sink->t, sink->a, sink->b );

		g_mutex_unlock( sink->sslock );

		if( !state->seq ) {
			SinkBase *sink_base = (SinkBase *) sink;

			vips_error( "vips_sink", 
				_( "start function failed for image \"%s\"" ), 
				sink_base->im->filename );
			return( -1 );
		}
	}

	return( 0 );
}

static int
sink_thread_state_build( VipsObject *object )
{
	SinkThreadState *state = (SinkThreadState *) object;
	Sink *sink = (Sink *) ((VipsThreadState *) state)->a;

	if( !(state->reg = vips_region_new( sink->t )) ||
		sink_call_start( sink, state ) )
		return( -1 );

	return( VIPS_OBJECT_CLASS( 
		sink_thread_state_parent_class )->build( object ) );
}

static void
sink_thread_state_class_init( SinkThreadStateClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = VIPS_OBJECT_CLASS( class );

	gobject_class->dispose = sink_thread_state_dispose;

	object_class->build = sink_thread_state_build;
	object_class->nickname = "sinkthreadstate";
	object_class->description = _( "per-thread state for sink" );
}

static void
sink_thread_state_init( SinkThreadState *state )
{
	state->seq = NULL;
	state->reg = NULL;
}

VipsThreadState *
vips_sink_thread_state_new( VipsImage *im, void *a )
{
	return( VIPS_THREAD_STATE( vips_object_new( 
		sink_thread_state_get_type(), 
		vips_thread_state_set, im, a ) ) );
}

static void
sink_free( Sink *sink )
{
	VIPS_FREEF( vips_g_mutex_free, sink->sslock );
	VIPS_FREEF( sink_area_free, sink->area );
	VIPS_FREEF( sink_area_free, sink->old_area );
	VIPS_FREEF( g_object_unref, sink->t );
}

void
vips_sink_base_init( SinkBase *sink_base, VipsImage *image )
{
	/* Always clear kill before we start looping. See the 
	 * call to vips_image_iskilled() below.
	 */
	vips_image_set_kill( image, FALSE );

	sink_base->im = image;
	sink_base->x = 0;
	sink_base->y = 0;

	vips_get_tile_size( image, 
		&sink_base->tile_width, &sink_base->tile_height, 
		&sink_base->n_lines );

	sink_base->processed = 0;
}

static int
sink_init( Sink *sink, 
	VipsImage *image, 
	VipsStartFn start_fn, VipsGenerateFn generate_fn, VipsStopFn stop_fn,
	void *a, void *b )
{
	g_assert( generate_fn );

	vips_sink_base_init( &sink->sink_base, image );

	sink->t = NULL;
	sink->sslock = vips_g_mutex_new();
	sink->start_fn = start_fn;
	sink->generate_fn = generate_fn;
	sink->stop_fn = stop_fn;
	sink->a = a;
	sink->b = b;

	sink->area = NULL;
	sink->old_area = NULL;

	if( !(sink->t = vips_image_new()) ||
		!(sink->area = sink_area_new( sink )) ||
		!(sink->old_area = sink_area_new( sink )) ||
		vips_image_write( sink->sink_base.im, sink->t ) ) {
		sink_free( sink );
		return( -1 );
	}

	return( 0 );
}

static int 
sink_work( VipsThreadState *state, void *a )
{
	SinkThreadState *sstate = (SinkThreadState *) state;
	Sink *sink = (Sink *) a;
	SinkArea *area = sstate->area;

	int result;

	result = vips_region_prepare( sstate->reg, &state->pos );
	if( !result )
		result = sink->generate_fn( sstate->reg, sstate->seq,
			sink->a, sink->b, &state->stop );

	/* Tell the allocator we're done.
	 */
	vips_semaphore_upn( &area->n_thread, 1 );

	return( result );
}

int 
vips_sink_base_progress( void *a )
{
	SinkBase *sink_base = (SinkBase *) a;

	VIPS_DEBUG_MSG( "vips_sink_base_progress:\n" ); 

	/* Trigger any eval callbacks on our source image and
	 * check for errors.
	 */
	vips_image_eval( sink_base->im, sink_base->processed );
	if( vips_image_iskilled( sink_base->im ) )
		return( -1 );

	return( 0 );
}

/**
 * vips_sink_tile: (method)
 * @im: scan over this image
 * @tile_width: tile width
 * @tile_height: tile height
 * @start_fn: start sequences with this function
 * @generate_fn: generate pixels with this function
 * @stop_fn: stop sequences with this function
 * @a: user data
 * @b: user data
 *
 * Loops over an image. @generate_fn is called for every 
 * pixel in the image, with
 * the @reg argument being a region of calculated pixels.
 *
 * Each set of pixels is @tile_width by @tile_height pixels (less at the 
 * image edges). This is handy for things like writing a tiled TIFF image, 
 * where tiles have to be generated with a certain size.
 *
 * See also: vips_sink(), vips_get_tile_size().
 *
 * Returns: 0 on success, or -1 on error.
 */
int
vips_sink_tile( VipsImage *im, 
	int tile_width, int tile_height,
	VipsStartFn start_fn, VipsGenerateFn generate_fn, VipsStopFn stop_fn,
	void *a, void *b )
{
	Sink sink;
	int result;

	g_assert( vips_object_sanity( VIPS_OBJECT( im ) ) );

	/* We don't use this, but make sure it's set in case any old binaries
	 * are expecting it.
	 */
	im->Bbits = vips_format_sizeof( im->BandFmt ) << 3;
 
	if( sink_init( &sink, im, start_fn, generate_fn, stop_fn, a, b ) )
		return( -1 );

	if( tile_width > 0 ) {
		sink.sink_base.tile_width = tile_width;
		sink.sink_base.tile_height = tile_height;
	}

	/* vips_sink_base_progress() signals progress on im, so we have to do
	 * pre/post on that too.
	 */
	vips_image_preeval( im );

	sink_area_position( sink.area, 0, sink.sink_base.n_lines );
	result = vips_threadpool_run( im, 
		vips_sink_thread_state_new,
		sink_area_allocate_fn, 
		sink_work, 
		vips_sink_base_progress, 
		&sink );

	vips_image_posteval( im );

	sink_free( &sink );

	vips_image_minimise_all( im );

	return( result );
}

/**
 * vips_sink: (method)
 * @im: scan over this image
 * @start_fn: start sequences with this function
 * @generate_fn: generate pixels with this function
 * @stop_fn: stop sequences with this function
 * @a: user data
 * @b: user data
 *
 * Loops over an image. @generate_fn is called for every pixel in 
 * the image, with
 * the @reg argument being a region of calculated pixels. vips_sink() is
 * used to implement operations like vips_avg() which have no image output.
 *
 * Each set of pixels is sized according to the requirements of the image
 * pipeline that generated @im.
 *
 * See also: vips_image_generate(), vips_image_new().
 *
 * Returns: 0 on success, or -1 on error.
 */
int
vips_sink( VipsImage *im, 
	VipsStartFn start_fn, VipsGenerateFn generate_fn, VipsStopFn stop_fn,
	void *a, void *b )
{
	return( vips_sink_tile( im, -1, -1, 
		start_fn, generate_fn, stop_fn, a, b ) );
}
