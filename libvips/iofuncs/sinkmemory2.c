/* SinkMemory an image to a memory buffer, keeping top-to-bottom ordering.
 *
 * For sequential operations we need to keep requests reasonably ordered: we
 * can't let some tiles get very delayed. So we need to stall starting new
 * threads if the last thread gets too far behind.
 * 
 * 17/2/12
 * 	- from sinkdisc.c
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
#define VIPS_DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif /*HAVE_UNISTD_H*/

#include <vips/vips.h>
#include <vips/internal.h>
#include <vips/thread.h>
#include <vips/threadpool.h>
#include <vips/debug.h>

#include "sink.h"

/* A part of the image we are writing. 
 */
typedef struct _SinkMemoryBuffer {
	struct _SinkMemory *write;

	VipsRegion *region;	/* Pixels */
        VipsSemaphore nwrite; 	/* Number of threads writing to region */
} SinkMemoryBuffer;

/* Per-call state.
 */
typedef struct _SinkMemory {
	SinkBase sink_base;

	/* We are current writing tiles to buf, we'll delay starting a new
	 * buffer if buf_back (the previous position) hasn't completed. 
	 */
	SinkMemoryBuffer *buf;
	SinkMemoryBuffer *buf_back;
} SinkMemory;

/* Our per-thread state ... we need to also track the buffer that pos is
 * supposed to write to.
 */
typedef struct _SinkMemoryThreadState {
	VipsThreadState parent_object;

        SinkMemoryBuffer *buf;
} SinkMemoryThreadState;

typedef struct _SinkMemoryThreadStateClass {
	VipsThreadStateClass parent_class;

} SinkMemoryThreadStateClass;

G_DEFINE_TYPE( SinkMemoryThreadState, 
	sink_memory_thread_state, VIPS_TYPE_THREAD_STATE );

static void
sink_memory_thread_state_class_init( SinkMemoryThreadStateClass *class )
{
	VipsObjectClass *object_class = VIPS_OBJECT_CLASS( class );

	object_class->nickname = "writethreadstate";
	object_class->description = _( "per-thread state for sinkmemory" );
}

static void
write_thread_state_init( SinkMemoryThreadState *state )
{
	state->buf = NULL;
}

static VipsThreadState *
write_thread_state_new( VipsImage *im, void *a )
{
	return( VIPS_THREAD_STATE( vips_object_new( 
		write_thread_state_get_type(), 
		vips_thread_state_set, im, a ) ) );
}

static void
wbuffer_free( SinkMemoryBuffer *wbuffer )
{
	VIPS_UNREF( wbuffer->region );
	vips_semaphore_destroy( &wbuffer->nwrite );
	vips_free( wbuffer );
}

static SinkMemoryBuffer *
wbuffer_new( SinkMemory *write )
{
	SinkMemoryBuffer *wbuffer;

	if( !(wbuffer = VIPS_NEW( NULL, SinkMemoryBuffer )) )
		return( NULL );
	wbuffer->write = write;
	wbuffer->region = NULL;
	vips_semaphore_init( &wbuffer->nwrite, 0, "nwrite" );

	if( !(wbuffer->region = vips_region_new( write->sink_base.im )) ) {
		wbuffer_free( wbuffer );
		return( NULL );
	}

	/* The worker threads need to be able to move the buffers around.
	 */
	vips__region_no_ownership( wbuffer->region );

#ifdef HAVE_THREADS
	/* Make this last (picks up parts of wbuffer on startup).
	 */
	if( !(wbuffer->thread = g_thread_create( wbuffer_write_thread, wbuffer, 
		TRUE, NULL )) ) {
		vips_error( "wbuffer_new", 
			"%s", _( "unable to create thread" ) );
		wbuffer_free( wbuffer );
		return( NULL );
	}
#endif /*HAVE_THREADS*/

	return( wbuffer );
}

/* Block until the previous write completes, then write the front buffer.
 */
static int
wbuffer_flush( SinkMemory *write )
{
	VIPS_DEBUG_MSG( "wbuffer_flush:\n" );

	/* Block until the other buffer has been written. We have to do this 
	 * before we can set this buffer writing or we'll lose output ordering.
	 */
	if( write->buf->area.top > 0 ) {
		vips_semaphore_down( &write->buf_back->done );

		/* Previous write suceeded?
		 */
		if( write->buf_back->write_errno ) {
			vips_error_system( write->buf_back->write_errno,
				"wbuffer_write", "%s", _( "write failed" ) );
			return( -1 ); 
		}
	}

	/* Set the background writer going for this buffer.
	 */
#ifdef HAVE_THREADS
	vips_semaphore_up( &write->buf->go );
#else
	/* No threads? SinkMemory ourselves synchronously.
	 */
	wbuffer_write( write->buf );
#endif /*HAVE_THREADS*/

	return( 0 );
}

/* Move a wbuffer to a position.
 */
static int 
wbuffer_position( SinkMemoryBuffer *wbuffer, int top, int height )
{
	VipsRect image, area;
	int result;

	image.left = 0;
	image.top = 0;
	image.width = wbuffer->write->sink_base.im->Xsize;
	image.height = wbuffer->write->sink_base.im->Ysize;

	area.left = 0;
	area.top = top;
	area.width = wbuffer->write->sink_base.im->Xsize;
	area.height = height;

	vips_rect_intersectrect( &area, &image, &wbuffer->area );

	/* The workers take turns to move the buffers.
	 */
	vips__region_take_ownership( wbuffer->region );

	result = vips_region_buffer( wbuffer->region, &wbuffer->area );

	vips__region_no_ownership( wbuffer->region );

	/* This should be an exclusive buffer, hopefully.
	 */
	g_assert( !wbuffer->region->buffer->done );

	return( result );
}

/* Our VipsThreadpoolAllocate function ... move the thread to the next tile
 * that needs doing. If no buffer is available (the bg writer hasn't yet
 * finished with it), we block. If all tiles are done, we return FALSE to end
 * iteration.
 */
static gboolean
wbuffer_allocate_fn( VipsThreadState *state, void *a, gboolean *stop )
{
	SinkMemoryThreadState *wstate =  (SinkMemoryThreadState *) state;
	SinkMemory *write = (SinkMemory *) a;
	SinkBase *sink_base = (SinkBase *) write;

	VipsRect image;
	VipsRect tile;

	VIPS_DEBUG_MSG( "wbuffer_allocate_fn:\n" );

	/* Is the state x/y OK? New line or maybe new buffer or maybe even 
	 * all done.
	 */
	if( sink_base->x >= write->buf->area.width ) {
		sink_base->x = 0;
		sink_base->y += sink_base->tile_height;

		if( sink_base->y >= VIPS_RECT_BOTTOM( &write->buf->area ) ) {
			/* Block until the last write is done, then set write
			 * of the front buffer going.
			 */
			if( wbuffer_flush( write ) )
				return( -1 );

			/* End of image?
			 */
			if( sink_base->y >= sink_base->im->Ysize ) {
				*stop = TRUE;
				return( 0 );
			}

			/* Swap buffers.
			 */
			{
				SinkMemoryBuffer *t;

				t = write->buf; 
				write->buf = write->buf_back; 
				write->buf_back = t;
			}

			/* Position buf at the new y.
			 */
			if( wbuffer_position( write->buf, 
				sink_base->y, sink_base->nlines ) )
				return( -1 );
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
	wstate->buf = write->buf;

	VIPS_DEBUG_MSG( "  allocated %d x %d:\n", tile.left, tile.top );

	/* Add to the number of writers on the buffer.
	 */
	vips_semaphore_upn( &write->buf->nwrite, -1 );

	/* Move state on.
	 */
	sink_base->x += sink_base->tile_width;

	return( 0 );
}

/* Our VipsThreadpoolWork function ... generate a tile!
 */
static int
wbuffer_work_fn( VipsThreadState *state, void *a )
{
	SinkMemoryThreadState *wstate = (SinkMemoryThreadState *) state;

	VIPS_DEBUG_MSG( "wbuffer_work_fn: %p %d x %d\n", 
		state, state->pos.left, state->pos.top );

	if( vips_region_prepare_to( state->reg, wstate->buf->region, 
		&state->pos, state->pos.left, state->pos.top ) ) {
		VIPS_DEBUG_MSG( "wbuffer_work_fn: %p error!\n", state );
		return( -1 );
	}
	VIPS_DEBUG_MSG( "wbuffer_work_fn: %p done\n", state );

	/* Tell the bg write thread we've left.
	 */
	vips_semaphore_upn( &wstate->buf->nwrite, 1 );

	return( 0 );
}

static void
write_init( SinkMemory *write, 
	VipsImage *image, VipsRegionSinkMemory write_fn, void *a )
{
	vips_sink_base_init( &write->sink_base, image );

	write->buf = wbuffer_new( write );
	write->buf_back = wbuffer_new( write );
	write->write_fn = write_fn;
	write->a = a;
}

static void
write_free( SinkMemory *write )
{
	VIPS_FREEF( wbuffer_free, write->buf );
	VIPS_FREEF( wbuffer_free, write->buf_back );
}

/**
 * VipsRegionSinkMemory:
 * @region: get pixels from here
 * @area: area to write
 * @a: client data
 *
 * The function should write the pixels in @area from @region. @a is the 
 * value passed into vips_discsink().
 *
 * See also: vips_sink_disc().
 *
 * Returns: 0 on success, -1 on error.
 */

/**
 * vips_sink_disc:
 * @im: image to process
 * @write_fn: called for every batch of pixels
 * @a: client data
 *
 * vips_sink_disc() loops over @im, top-to-bottom, generating it in sections.
 * As each section is produced, @write_fn is called.
 *
 * @write_fn is always called single-threaded (though not always from the same
 * thread), it's always given image
 * sections in top-to-bottom order, and there are never any gaps.
 *
 * This operation is handy for making image sinks which output to things like 
 * disc files.
 *
 * See also: vips_concurrency_set().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_sink_disc( VipsImage *im, VipsRegionSinkMemory write_fn, void *a )
{
	SinkMemory write;
	int result;

	vips_image_preeval( im );

	write_init( &write, im, write_fn, a );

	result = 0;
	if( !write.buf || 
		!write.buf_back || 
		wbuffer_position( write.buf, 0, write.sink_base.nlines ) ||
		vips_threadpool_run( im, 
			write_thread_state_new, 
			wbuffer_allocate_fn, 
			wbuffer_work_fn, 
			vips_sink_base_progress, 
			&write ) )  
		result = -1;

	/* Just before allocate signalled stop, it set write.buf writing. We
	 * need to wait for this write to finish. 
	 *
	 * We can't just free the buffers (which will wait for the bg threads 
	 * to finish), since the bg thread might see the kill before it gets a 
	 * chance to write.
	 *
	 * If the pool exited with an error, write.buf might not have been
	 * started (if the allocate failed), and in any case, we don't care if
	 * the final write went through or not.
	 */
	if( !result )
		vips_semaphore_down( &write.buf->done );

	vips_image_posteval( im );

	write_free( &write );

	return( result );
}
