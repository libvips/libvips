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

	/* We need a temp "p" image between the source image and us to
	 * make sure we can't damage the original.
	 */
	VipsImage *t;

	/* The position we're at in the image.
	 */
	int x;
	int y;

	/* The tilesize we've picked.
	 */
	int tile_width;
	int tile_height;
	int nlines;

	/* Call params.
	 */
	im_start_fn start;
	im_generate_fn generate;
	im_stop_fn stop;
	void *a;
	void *b;
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
} SinkThreadState;

typedef struct _SinkThreadStateClass {
	VipsThreadStateClass parent_class;

} SinkThreadStateClass;

G_DEFINE_TYPE( SinkThreadState, sink_thread_state, VIPS_TYPE_THREAD_STATE );

/* Call a thread's stop function. 
 */
static int
sink_call_stop( Sink *sink, SinkThreadState *state )
{
	if( state->seq && sink->stop ) {
		VIPS_DEBUG_MSG( "sink_call_stop: state = %p\n", state );

		if( sink->stop( state->seq, sink->a, sink->b ) ) {
			vips_error( "vips_sink", 
				_( "stop function failed for image \"%s\"" ), 
				sink->im->filename );
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
	VIPS_FREEF( g_object_unref, state->reg );

	G_OBJECT_CLASS( sink_thread_state_parent_class )->dispose( gobject );
}

/* Call the start function for this thread, if necessary.
 */
static int
sink_call_start( Sink *sink, SinkThreadState *state )
{
	if( !state->seq && sink->start ) {
		VIPS_DEBUG_MSG( "sink_call_start: state = %p\n", state );

                state->seq = sink->start( sink->t, sink->a, sink->b );

		if( !state->seq ) {
			vips_error( "vips_sink", 
				_( "start function failed for image \"%s\"" ), 
				sink->im->filename );
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

static VipsThreadState *
sink_thread_state_new( VipsImage *im, void *a )
{
	return( VIPS_THREAD_STATE( vips_object_new( 
		sink_thread_state_get_type(), 
		vips_thread_state_set, im, a ) ) );
}

static void
sink_free( Sink *sink )
{
	VIPS_FREEF( g_object_unref, sink->t );
}

static int
sink_init( Sink *sink, 
	VipsImage *im, 
	im_start_fn start, im_generate_fn generate, im_stop_fn stop,
	void *a, void *b )
{
	sink->im = im; 
	sink->t = NULL;
	sink->x = 0;
	sink->y = 0;
	sink->start = start;
	sink->generate = generate;
	sink->stop = stop;
	sink->a = a;
	sink->b = b;

	if( !(sink->t = vips_image_new( "p" )) ||
		im_copy( sink->im, sink->t ) ) {
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
	SinkThreadState *sstate = (SinkThreadState *) state;
	Sink *sink = (Sink *) a;

	if( vips_region_prepare( sstate->reg, &state->pos ) ||
		sink->generate( sstate->reg, sstate->seq, sink->a, sink->b ) ) 
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
	vips_image_eval( sink->im, sink->tile_width, sink->tile_height );
	if( vips_image_get_kill( sink->im ) )
		return( -1 );

	return( 0 );
}

/**
 * vips_sink_tile:
 * @im: scan over this image
 * @tile_width: tile width
 * @tile_height: tile height
 * @start: start sequences with this function
 * @generate: generate pixels with this function
 * @stop: stop sequences with this function
 * @a: user data
 * @b: user data
 *
 * Loops over an image. @generate is called for every pixel in the image, with
 * the @reg argument being a region of pixels for processing. 
 * vips_sink_tile() is
 * used to implement operations like im_avg() which have no image output.
 *
 * Each set of
 * pixels is @tile_width by @tile_height pixels (less at the image edges). 
 * This is handy for things like
 * writing a tiled TIFF image, where tiles have to be generated with a certain
 * size.
 *
 * See also: vips_sink(), vips_get_tile_size().
 *
 * Returns: 0 on success, or -1 on error.
 */
int
vips_sink_tile( VipsImage *im, 
	int tile_width, int tile_height,
	VipsStart start, VipsGenerate generate, VipsStop stop,
	void *a, void *b )
{
	Sink sink;
	int result;

	g_assert( !im_image_sanity( im ) );

	/* We don't use this, but make sure it's set in case any old binaries
	 * are expecting it.
	 */
	im->Bbits = vips_format_sizeof( im->BandFmt ) << 3;
 
	if( sink_init( &sink, im, start, generate, stop, a, b ) )
		return( -1 );

	if( tile_width > 0 ) {
		sink.tile_width = tile_width;
		sink.tile_height = tile_height;
	}

	vips_image_preeval( sink.t );

	result = vips_threadpool_run( im, 
		sink_thread_state_new,
		sink_allocate, 
		sink_work, 
		sink_progress, 
		&sink );

	vips_image_posteval( sink.t );

	sink_free( &sink );

	return( result );
}

/**
 * vips_sink:
 * @im: scan over this image
 * @start: start sequences with this function
 * @generate: generate pixels with this function
 * @stop: stop sequences with this function
 * @a: user data
 * @b: user data
 *
 * Loops over an image. @generate is called for every pixel in the image, with
 * the @reg argument being a region of pixels for processing. vips_sink() is
 * used to implement operations like im_avg() which have no image output.
 *
 * Each set of pixels is sized according to the requirements of the image
 * pipeline that generated @im.
 *
 * See also: im_generate(), im_open().
 *
 * Returns: 0 on success, or -1 on error.
 */
int
vips_sink( VipsImage *im, 
	VipsStart start, VipsGenerate generate, VipsStop stop,
	void *a, void *b )
{
	return( vips_sink_tile( im, -1, -1, start, generate, stop, a, b ) );
}
