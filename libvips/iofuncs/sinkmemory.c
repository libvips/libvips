/* Write an image to a memory buffer.
 * 
 * 16/4/10
 * 	- from vips_sink()
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
#include <vips/thread.h>
#include <vips/internal.h>
#include <vips/debug.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* Per-call state.
 */
typedef struct _Sink {
	VipsImage *im; 

	/* A big region for the image memory. All the threads write to this.
	 */
	REGION *all;

	/* The position we're at in the image.
	 */
	int x;
	int y;

	/* The tilesize we've picked.
	 */
	int tile_width;
	int tile_height;
	int nlines;
} Sink;

static void
sink_free( Sink *sink )
{
	VIPS_FREEF( im_region_free, sink->all );
}

static int
sink_init( Sink *sink, VipsImage *im ) 
{
	Rect all;

	sink->im = im; 
	sink->x = 0;
	sink->y = 0;

	all.left = 0;
	all.top = 0;
	all.width = im->Xsize;
	all.height = im->Ysize;

	if( !(sink->all = im_region_create( im )) ||
		im_region_image( sink->all, &all ) ) {
		sink_free( sink );
		return( -1 );
	}

	vips_get_tile_size( im, 
		&sink->tile_width, &sink->tile_height, &sink->nlines );

	return( 0 );
}

static int 
sink_allocate( VipsThreadState *state, void *a, gboolean *stop )
{
	Sink *sink = (Sink *) a;

	Rect image, tile;

	/* Is the state x/y OK? New line or maybe all done.
	 */
	if( sink->x >= sink->im->Xsize ) {
		sink->x = 0;
		sink->y += sink->tile_height;

		if( sink->y >= sink->im->Ysize ) {
			*stop = TRUE;

			return( 0 );
		}
	}

	/* x, y and buf are good: save params for thread.
	 */
	image.left = 0;
	image.top = 0;
	image.width = sink->im->Xsize;
	image.height = sink->im->Ysize;
	tile.left = sink->x;
	tile.top = sink->y;
	tile.width = sink->tile_width;
	tile.height = sink->tile_height;
	im_rect_intersectrect( &image, &tile, &state->pos );

	/* Move state on.
	 */
	sink->x += sink->tile_width;

	return( 0 );
}

static int 
sink_work( VipsThreadState *state, void *a )
{
	Sink *sink = (Sink *) a;

	if( im_prepare_to( state->reg, sink->all, 
		&state->pos, state->pos.left, state->pos.top ) )
		return( -1 );

	return( 0 );
}

static int 
sink_progress( void *a )
{
	Sink *sink = (Sink *) a;

	VIPS_DEBUG_MSG( "sink_progress: %d x %d\n",
		sink->tile_width, sink->tile_height );

	/* Trigger any eval callbacks on our source image and
	 * check for errors.
	 */
	if( im__handle_eval( sink->im, 
		sink->tile_width, sink->tile_height ) )
		return( -1 );

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
vips_sink_memory( VipsImage *im ) 
{
	Sink sink;
	int result;

	g_assert( !im_image_sanity( im ) );

	/* We don't use this, but make sure it's set in case any old binaries
	 * are expecting it.
	 */
	im->Bbits = vips_format_sizeof( im->BandFmt ) << 3;
 
	if( sink_init( &sink, im ) )
		return( -1 );

	if( im__start_eval( im ) ) {
		sink_free( &sink );
		return( -1 );
	}

	result = vips_threadpool_run( im, 
		vips_thread_state_new,
		sink_allocate, 
		sink_work, 
		sink_progress, 
		&sink );

	im__end_eval( im );

	sink_free( &sink );

	return( result );
}
