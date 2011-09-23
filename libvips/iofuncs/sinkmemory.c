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

#include "sink.h"

/* Per-call state.
 */
typedef struct _Sink {
	SinkBase sink_base;

	/* A big region for the image memory. All the threads write to this.
	 */
	VipsRegion *all;
} Sink;

static void
sink_free( Sink *sink )
{
	VIPS_UNREF( sink->all );
}

static int
sink_init( Sink *sink, VipsImage *im ) 
{
	VipsRect all;

	vips_sink_base_init( &sink->sink_base, im );

	all.left = 0;
	all.top = 0;
	all.width = im->Xsize;
	all.height = im->Ysize;

	if( !(sink->all = vips_region_new( im )) ||
		vips_region_image( sink->all, &all ) ) {
		sink_free( sink );
		return( -1 );
	}

	return( 0 );
}

static int 
sink_work( VipsThreadState *state, void *a )
{
	Sink *sink = (Sink *) a;

	if( vips_region_prepare_to( state->reg, sink->all, 
		&state->pos, state->pos.left, state->pos.top ) )
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

	g_assert( vips_object_sanity( VIPS_OBJECT( im ) ) );

	/* We don't use this, but make sure it's set in case any old binaries
	 * are expecting it.
	 */
	im->Bbits = vips_format_sizeof( im->BandFmt ) << 3;
 
	if( sink_init( &sink, im ) )
		return( -1 );

	vips_image_preeval( im );

	result = vips_threadpool_run( im, 
		vips_thread_state_new,
		vips_sink_base_allocate, 
		sink_work, 
		vips_sink_base_progress, 
		&sink );

	vips_image_posteval( im );

	sink_free( &sink );

	return( result );
}
