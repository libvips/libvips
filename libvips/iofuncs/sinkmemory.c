/* SinkMemory an image to a memory buffer, keeping top-to-bottom ordering.
 *
 * For sequential operations we need to keep requests reasonably ordered: we
 * can't let some tiles get very delayed. So we need to stall starting new
 * threads if the last thread gets too far behind.
 * 
 * 17/2/12
 * 	- from sinkdisc.c
 * 23/2/12
 * 	- we could deadlock if generate failed
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

#include <vips/vips.h>
#include <vips/internal.h>
#include <vips/thread.h>
#include <vips/threadpool.h>
#include <vips/debug.h>

#include "sink.h"

/* A part of the image we are writing. 
 */
typedef struct _SinkMemoryArea {
	struct _SinkMemory *memory;

	VipsRect rect;		/* Part of image this area covers */
        VipsSemaphore nwrite; 	/* Number of threads writing to this area */
} SinkMemoryArea;

/* Per-call state.
 */
typedef struct _SinkMemory {
	SinkBase sink_base;

	/* We are current writing tiles to area, we'll delay starting a new
	 * area if old_area (the previous position) hasn't completed. 
	 */
	SinkMemoryArea *area;
	SinkMemoryArea *old_area;

	/* A region covering the whole of the output image ... we write to
	 * this from many workers with vips_region_prepare_to().
	 */
	VipsRegion *region;
} SinkMemory;

/* Our per-thread state ... we need to also track the area that pos is
 * supposed to write to.
 */
typedef struct _SinkMemoryThreadState {
	VipsThreadState parent_object;

        SinkMemoryArea *area;
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

	object_class->nickname = "sinkmemorythreadstate";
	object_class->description = _( "per-thread state for sinkmemory" );
}

static void
sink_memory_thread_state_init( SinkMemoryThreadState *state )
{
}

static VipsThreadState *
sink_memory_thread_state_new( VipsImage *image, void *a )
{
	return( VIPS_THREAD_STATE( vips_object_new( 
		sink_memory_thread_state_get_type(), 
		vips_thread_state_set, image, a ) ) );
}

static void
sink_memory_area_free( SinkMemoryArea *area )
{
	vips_semaphore_destroy( &area->nwrite );
	vips_free( area );
}

static SinkMemoryArea *
sink_memory_area_new( SinkMemory *memory )
{
	SinkMemoryArea *area;

	if( !(area = VIPS_NEW( NULL, SinkMemoryArea )) )
		return( NULL );
	area->memory = memory;
	vips_semaphore_init( &area->nwrite, 0, "nwrite" );

	return( area );
}

/* Move an area to a position.
 */
static void 
sink_memory_area_position( SinkMemoryArea *area, int top, int height )
{
	SinkMemory *memory = area->memory;

	VipsRect all, rect;

	all.left = 0;
	all.top = 0;
	all.width = memory->sink_base.im->Xsize;
	all.height = memory->sink_base.im->Ysize;

	rect.left = 0;
	rect.top = top;
	rect.width = memory->sink_base.im->Xsize;
	rect.height = height;

	vips_rect_intersectrect( &all, &rect, &area->rect );
}

/* Our VipsThreadpoolAllocate function ... move the thread to the next tile
 * that needs doing. If we fill the current area, we block until the previous
 * area is finished, then swap areas. 
 * If all tiles are done, we return FALSE to end
 * iteration.
 */
static gboolean
sink_memory_area_allocate_fn( VipsThreadState *state, void *a, gboolean *stop )
{
	SinkMemoryThreadState *wstate = (SinkMemoryThreadState *) state;
	SinkMemory *memory = (SinkMemory *) a;
	SinkBase *sink_base = (SinkBase *) memory;

	VipsRect image;
	VipsRect tile;

	VIPS_DEBUG_MSG( "sink_memory_area_allocate_fn:\n" );

	/* Is the state x/y OK? New line or maybe new buffer or maybe even 
	 * all done.
	 */
	if( sink_base->x >= memory->area->rect.width ) {
		sink_base->x = 0;
		sink_base->y += sink_base->tile_height;

		if( sink_base->y >= VIPS_RECT_BOTTOM( &memory->area->rect ) ) {
			/* Block until the previous area is done.
			 */
			if( memory->area->rect.top > 0 ) 
				vips_semaphore_downn( 
					&memory->old_area->nwrite, 0 );

			/* End of image?
			 */
			if( sink_base->y >= sink_base->im->Ysize ) {
				*stop = TRUE;
				return( 0 );
			}

			/* Swap buffers.
			 */
			VIPS_SWAP( SinkMemoryArea *, 
				memory->area, memory->old_area );

			/* Position buf at the new y.
			 */
			sink_memory_area_position( memory->area, 
				sink_base->y, sink_base->nlines );
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
	wstate->area = memory->area;

	VIPS_DEBUG_MSG( "  allocated %d x %d:\n", tile.left, tile.top );

	/* Add to the number of writers on the area.
	 */
	vips_semaphore_upn( &memory->area->nwrite, -1 );

	/* Move state on.
	 */
	sink_base->x += sink_base->tile_width;

	/* Add the number of pixels we've just allocated to progress.
	 */
	sink_base->processed += state->pos.width * state->pos.height;

	return( 0 );
}

/* Our VipsThreadpoolWork function ... generate a tile!
 */
static int
sink_memory_area_work_fn( VipsThreadState *state, void *a )
{
	SinkMemory *memory = (SinkMemory *) a;
	SinkMemoryThreadState *wstate = (SinkMemoryThreadState *) state;
	SinkMemoryArea *area = wstate->area;

	int result;

	VIPS_DEBUG_MSG( "sink_memory_area_work_fn: %p %d x %d\n", 
		state, state->pos.left, state->pos.top );

	result = vips_region_prepare_to( state->reg, memory->region, 
		&state->pos, state->pos.left, state->pos.top );

	VIPS_DEBUG_MSG( "sink_memory_area_work_fn: %p result = %d\n", 
		state, result );

	/* Tell the allocator we're done.
	 */
	vips_semaphore_upn( &area->nwrite, 1 );

	return( result );
}

static void
sink_memory_free( SinkMemory *memory )
{
	VIPS_FREEF( sink_memory_area_free, memory->area );
	VIPS_FREEF( sink_memory_area_free, memory->old_area );
	VIPS_UNREF( memory->region );
}

static int
sink_memory_init( SinkMemory *memory, VipsImage *image )
{
	VipsRect all;

	vips_sink_base_init( &memory->sink_base, image );
	memory->area = NULL;
	memory->old_area = NULL;

	all.left = 0;
	all.top = 0;
	all.width = image->Xsize;
	all.height = image->Ysize;

	if( !(memory->region = vips_region_new( image )) ||
		vips_region_image( memory->region, &all ) ||
		!(memory->area = sink_memory_area_new( memory )) ||
		!(memory->old_area = sink_memory_area_new( memory )) ) {
		sink_memory_free( memory );
		return( -1 );
	}

	return( 0 );
}

/**
 * vips_sink_memory:
 * @im: generate this image to memory
 *
 * Loops over an image, generating it to a memory buffer attached to the
 * image. 
 *
 * See also: vips_sink(), vips_get_tile_size().
 *
 * Returns: 0 on success, or -1 on error.
 */
int
vips_sink_memory( VipsImage *image )
{
	SinkMemory memory;
	int result;

	VIPS_DEBUG_MSG( "vips_sink_memory2:\n" );

	if( sink_memory_init( &memory, image ) )
		return( -1 );

	vips_image_preeval( image );

	result = 0;
	sink_memory_area_position( memory.area, 0, memory.sink_base.nlines );
	if( vips_threadpool_run( image, 
		sink_memory_thread_state_new, 
		sink_memory_area_allocate_fn, 
		sink_memory_area_work_fn, 
		vips_sink_base_progress, 
		&memory ) )  
		result = -1;

	vips_image_posteval( image );

	sink_memory_free( &memory );

	VIPS_DEBUG_MSG( "vips_sink_memory2: done\n" );

	return( result );
}
