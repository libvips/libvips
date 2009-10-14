/* Manage pipelines of partial images.
 * 
 * J.Cupitt, 17/4/93.
 * 1/7/93 JC
 *	- adapted for partial v2
 * 9/5/94
 *	- new thread stuff added, with a define to turn it off
 * 21/11/94 JC
 *	- pw and ph wrong way round!
 * 24/5/95 JC
 *	- redone, now works in pipelines!
 * 30/8/96 JC
 *	- more sharing with im_generate()
 * 2/3/98 JC
 *	- IM_ANY added
 * 19/1/99 JC
 *	- oops, threads were broken :(
 * 30/7/99 RP JC
 *	- threads reorganised for POSIX
 * 25/10/03 JC
 *	- read via a buffer image so we work with mmap window images
 * 27/11/06
 * 	- merge threadgroup stuff
 * 7/11/07
 * 	- new eval start/progress/end system
 * 7/10/09
 * 	- gtkdoc comments
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
#define DEBUG_IO
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <stdlib.h>

#include <vips/vips.h>
#include <vips/internal.h>
#include <vips/debug.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* Track this stuff during an im_iterate().
 */
typedef struct _Iterate {
	IMAGE *im; 

	/* We need a temp "p" image between the source image and us to
	 * make sure we can't damage the original.
	 */
	IMAGE *t;

	/* Store our sequence values in tg->thr[i]->a. The seq values in the
	 * regions are used by the im_copy() to t.
	 */
	im_threadgroup_t *tg;

	im_start_fn start;
	im_generate_fn generate;
	im_stop_fn stop;
	void *b;
	void *c;
} Iterate;

/* Call all stop functions.
 */
static int
iterate_call_all_stop( Iterate *iter, im_threadgroup_t *tg )
{
	int i;

	for( i = 0; i < tg->nthr; i++ ) {
		if( tg->thr[i]->a && iter->stop ) {
			if( iter->stop( tg->thr[i]->a, iter->b, iter->c ) )
				/* Drastic!
				 */
				im_error( "im_iterate", 
					_( "stop function failed "
						"for image \"%s\"" ), 
					iter->im->filename );
			tg->thr[i]->a = NULL;
		}
	}

	return( 0 );
}

static void
iterate_free( Iterate *iter )
{
	/* Check all the stop functions have been called.
	 */
	if( iter->tg ) {
		int i;

		for( i = 0; i < iter->tg->nthr; i++ ) 
			g_assert( !iter->tg->thr[i]->a ); 
	}

	IM_FREEF( im_threadgroup_free, iter->tg );
	IM_FREEF( im_close, iter->t );
}

/* Call the start function for this thread, if necessary.
 */
static int
iterate_call_start( Iterate *iter, im_thread_t *thr )
{
	if( !thr->a && iter->start ) {
                g_mutex_lock( iter->t->sslock );
                thr->a = iter->start( iter->t, iter->b, iter->c );
                g_mutex_unlock( iter->t->sslock );

		if( !thr->a ) {
			im_error( "im_iterate", 
				_( "start function failed for image \"%s\"" ), 
				iter->im->filename );
			return( -1 );
		}
	}

	return( 0 );
}

/* Our generate function. We need to call the user's start function from the
 * worker thread so that any regions it makes are owned by the thread.
 */
static int
iterate_gen( REGION *reg, void *seq, void *a, void *b )
{
	Iterate *iter = (Iterate *) a;
	im_thread_t *thr = (im_thread_t *) b;

	/* Make sure the start function has run and we have the sequence value
	 * set.
	 */
	iterate_call_start( iter, thr );
	seq = thr->a;

	return( iter->generate( reg, seq, iter->b, iter->c ) );
}

static int
iterate_init( Iterate *iter, 
	IMAGE *im, 
	im_start_fn start, im_generate_fn generate, im_stop_fn stop,
	void *b, void *c )
{
	iter->im = im; 
	iter->t = NULL;
	iter->tg = NULL;
	iter->start = start;
	iter->generate = generate;
	iter->stop = stop;
	iter->b = b;
	iter->c = c;

	if( !(iter->t = im_open( "iterate", "p" )) ||
		im_copy( iter->im, iter->t ) ||
		!(iter->tg = im_threadgroup_create( iter->t )) ) {
		iterate_free( iter );
		return( -1 );
	}

	iter->tg->work = iterate_gen;
	iter->tg->inplace = 0;

#ifdef DEBUG_IO
	if( iter->tg->nthr > 1 )
		im_diagnostics( "im_iterate: using %d threads", 
			iter->tg->nthr );
#endif /*DEBUG_IO*/

	return( 0 );
}

/* Loop over an image, preparing in parts with threads.
 */
static int
iterate_loop( Iterate *iter, im_threadgroup_t *tg, IMAGE *t )
{
	int x, y;
	Rect image;

	/* Set up.
	 */
	tg->inplace = 0;

	image.left = 0;
	image.top = 0;
	image.width = t->Xsize;
	image.height = t->Ysize;

	/* Loop over or, attaching to all sub-parts in turn.
	 */
	for( y = 0; y < t->Ysize; y += tg->ph )
		for( x = 0; x < t->Xsize; x += tg->pw ) {
			im_thread_t *thr;
			Rect pos;
			Rect clipped;

			/* thrs appear on idle when the child thread does
			 * threadgroup_idle_add and hits the 'go' semaphore.
			 */
                        thr = im_threadgroup_get( tg );

			/* Set the position we want to generate with this
			 * thread.
			 */
			pos.left = x;
			pos.top = y;
			pos.width = tg->pw;
			pos.height = tg->ph;
			im_rect_intersectrect( &image, &pos, &clipped );

			thr->pos = clipped; 

			/* Other stuff we want passed to iterate_gen().
			 */
			thr->b = iter;
			thr->c = thr;

			/* Start worker going.
			 */
			im_threadgroup_trigger( thr );

			/* Trigger any eval callbacks on our source image,
			 * check for errors.
			 */
			if( im__handle_eval( t, tg->pw, tg->ph ) ||
				im_threadgroup_iserror( tg ) ) {
				/* Don't kill threads yet ... we may want to
				 * get some error stuff out of them.
				 */
				im_threadgroup_wait( tg );
				return( -1 );
			}
		}

	/* Wait for all threads to hit 'go' again.
	 */
	im_threadgroup_wait( tg );

	/* Test for any errors.
	 */
	if( im_threadgroup_iserror( tg ) )
		return( -1 );

	return( 0 );
}

/**
 * im_iterate:
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
im_iterate( IMAGE *im, 
	im_start_fn start, im_generate_fn generate, im_stop_fn stop,
	void *b, void *c )
{
	Iterate iter;
	int result;

	g_assert( !im_image_sanity( im ) );

	if( iterate_init( &iter, im, start, generate, stop, b, c ) )
		return( -1 );

	/* Signal start of eval.
	 */
	if( im__start_eval( iter.t ) ) {
		iterate_free( &iter );
		return( -1 );
	}

	/* Loop and generate multi-thread. 
	 */
	result = iterate_loop( &iter, iter.tg, iter.t );

	/* Signal end of eval.
	 */
	result |= im__end_eval( iter.t );
	result |= iterate_call_all_stop( &iter, iter.tg );
	iterate_free( &iter );

	return( result );
}
