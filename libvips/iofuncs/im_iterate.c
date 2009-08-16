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

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* Loop over an image, preparing in parts with threads.
 */
static int
eval_to_image( im_threadgroup_t *tg, IMAGE *im )
{
	int x, y;
	Rect image;

	/* Set up.
	 */
	tg->inplace = 0;

	image.left = 0;
	image.top = 0;
	image.width = im->Xsize;
	image.height = im->Ysize;

	/* Loop over or, attaching to all sub-parts in turn.
	 */
	for( y = 0; y < im->Ysize; y += tg->ph )
		for( x = 0; x < im->Xsize; x += tg->pw ) {
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

			/* Start worker going.
			 */
			im_threadgroup_trigger( thr );

			/* Trigger any eval callbacks on our source image,
			 * check for errors.
			 */
			if( im__handle_eval( im, tg->pw, tg->ph ) ||
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

static int
iterate( im_threadgroup_t *tg, IMAGE *im, 
	im_start_fn start, im_generate_fn generate, im_stop_fn stop,
	void *b, void *c )
{	
	int i;
	int res;

#ifdef DEBUG_IO
	if( tg && tg->nthr > 1 )
		im_diagnostics( "im_iterate: using %d threads", tg->nthr );
#endif /*DEBUG_IO*/

	/* Call all the start functions, and pop in the sequence values.
	 */
	for( i = 0; i < tg->nthr; i++ ) {
		if( start && !(tg->thr[i]->a = start( im, b, c )) ) {
			im_error( "im_iterate", 
				_( "start function failed for image \"%s\"" ), 
				im->filename );
			return( -1 );
		}
		tg->thr[i]->b = b;
		tg->thr[i]->c = c;
	}

	/* Loop and generate multi-thread. 
	 */
	res = eval_to_image( tg, im );

	/* Call all stop functions.
	 */
	for( i = 0; i < tg->nthr; i++ ) {
		if( tg->thr[i]->a && stop ) {
			/* Trigger the stop function. 
			 */
			if( stop( tg->thr[i]->a, b, c ) )
				/* Drastic!
				 */
				im_error( "im_iterate", 
					_( "stop function failed "
						"for image \"%s\"" ), 
					im->filename );
			tg->thr[i]->a = NULL;
		}
	}

	return( res );
}

/* Scan region over image in small pieces.
 */
int
im_iterate( IMAGE *im, 
	im_start_fn start, im_generate_fn generate, im_stop_fn stop,
	void *b, void *c )
{
	IMAGE *t;
	im_threadgroup_t *tg;
	int result;

	g_assert( !im_image_sanity( im ) );

	if( !(t = im_open( "iterate", "p" )) )
		return( -1 );
	if( im_copy( im, t ) ) {
		im_close( t );
		return( -1 );
	}

	if( !(tg = im_threadgroup_create( t )) ) {
		im_close( t );
		return( -1 );
	}
	tg->work = generate;
	tg->inplace = 0;

#ifdef DEBUG_IO
	if( tg && tg->nthr > 1 )
		im_diagnostics( "im_iterate: using %d threads", tg->nthr );
#endif /*DEBUG_IO*/

	/* Signal start of eval.
	 */
	if( im__start_eval( t ) )
		return( -1 );

	result = iterate( tg, t, start, generate, stop, b, c );

	/* Signal end of eval.
	 */
	result |= im__end_eval( t );

	im_threadgroup_free( tg );
	im_close( t );

	return( result );
}
