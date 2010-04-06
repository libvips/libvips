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
#define DEBUG
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

	/* Keep the sequence value in VipsThreadState->d.
	 */
	im_start_fn start;
	im_generate_fn generate;
	im_stop_fn stop;
	void *a;
	void *b;
} Sink;

static void
sink_free( Sink *sink )
{
	IM_FREEF( im_close, sink->t );
}

static int
sink_init( Sink *sink, 
	VipsImage *im, 
	im_start_fn start, im_generate_fn generate, im_stop_fn stop,
	void *a, void *b )
{
	sink->im = im; 
	sink->t = NULL;
	sink->start = start;
	sink->generate = generate;
	sink->stop = stop;
	sink->a = a;
	sink->b = b;

	if( !(sink->t = im_open( "iterate", "p" )) ||
		im_copy( sink->im, sink->t ) ) {
		sink_free( sink );
		return( -1 );
	}

	vips_get_tile_size( im, 
		&sink->tile_width, &sink->tile_height, &sink->nlines );

	return( 0 );
}

/* Call the start function for this thread, if necessary.
 */
static int
sink_call_start( Sink *sink, VipsThreadState *state )
{
	if( !state->d && sink->start ) {
#ifdef DEBUG
		printf( "sink_call_start: state = %p\n", state );
#endif /*DEBUG*/
                state->d = sink->start( sink->t, sink->a, sink->b );

		if( !state->d ) {
			im_error( "vips_sink", 
				_( "start function failed for image \"%s\"" ), 
				sink->im->filename );
			return( -1 );
		}
	}

	return( 0 );
}

/* Call a thread's stop function. 
 */
static int
sink_call_stop( Sink *sink, VipsThreadState *state )
{
	if( state->d && sink->stop ) {
#ifdef DEBUG
		printf( "sink_call_stop: state = %p\n", state );
#endif /*DEBUG*/

		if( sink->stop( state->d, sink->a, sink->b ) ) {
			im_error( "vips_sink", 
				_( "stop function failed for image \"%s\"" ), 
				sink->im->filename );
			return( -1 );
		}

		state->d = NULL;
	}

	return( 0 );
}

static int 
sink_allocate( VipsThreadState *state, 
	void *a, void *b, void *c, gboolean *stop )
{
	Sink *sink = (Sink *) a;

	Rect image, tile;

	/* Is the state x/y OK? New line or maybe all done.
	 */
	if( sink->x >= sink->im->Xsize ) {
		sink->x = 0;
		sink->y += sink->tile_height;

		if( sink->y >= sink->im->Ysize ) {
			sink_call_stop( sink, state );
			*stop = TRUE;
			return( 0 );
		}
	}

	sink_call_start( sink, state );

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
	write->x += write->tile_width;

	return( 0 );
}

static int 
sink_work( VipsThreadState *state, void *a, void *b, void *c )
{
	Sink *sink = (Sink *) a;

	if( im_prepare( state->reg, &state->pos ) ||
		sink->generate( state->reg, state->d, sink->a, sink->b ) ) {
		sink_call_stop( sink, state );
		return( -1 );
	}

	return( 0 );
}

static int 
sink_progress( void *a, void *b, void *c )
{
	Sink *sink = (Sink *) a;

	/* Trigger any eval callbacks on our source image and
	 * check for errors.
	 */
	if( im__handle_eval( sink->im, 
		sink->tile_width, sink->tile_height ) )
		return( -1 );

	return( 0 );
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
 * the @reg argument being a region of pixels for processing. im_iterate() is
 * used to implement operations like im_avg() which have no image output.
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
	Sink sink;
	int result;

	g_assert( !im_image_sanity( im ) );

	/* We don't use this, but make sure it's set in case any old binaries
	 * are expecting it.
	 */
	im->Bbits = im_bits_of_fmt( im->BandFmt );
 
	if( sink_init( &sink, im, start, generate, stop, a, b ) )
		return( -1 );

	if( im__start_eval( sink.t ) ) {
		sink_free( &sink );
		return( -1 );
	}

	result = vips_threadpool_run( im, 
		sink_allocate, sink_work, sink_progress, &sink, NULL );

	im__end_eval( sink.t );

	sink_free( &sink );

	return( result );
}
