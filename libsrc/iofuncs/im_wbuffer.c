/* Double-buffered write.
 * 
 * 2/11/07
 * 	- cut from im_generate
 * 7/11/07
 * 	- trigger start/end eval callbacks
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
#include <stdarg.h>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif /*HAVE_UNISTD_H*/

#include <vips/vips.h>
#include <vips/internal.h>
#include <vips/thread.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* A buffer we are going to write to disc in a background thread.
 */
typedef struct _WriteBuffer {
	im_threadgroup_t *tg;	/* What makes the pixels */
	REGION *region;		/* Pixels */
	Rect area;		/* Part of image this region covers */
        im_semaphore_t go; 	/* Start bg thread loop */
        im_semaphore_t nwrite; 	/* Number of threads writing to region */
        im_semaphore_t done; 	/* Bg thread has done write */
        int write_errno;	/* Save write errors here */
	GThread *thread;	/* BG writer thread */
	gboolean kill;		/* Set to ask thread to exit */
	im_wbuffer_fn write_fn;	/* BG write with this */
	void *a;		/* Client data */
	void *b;
} WriteBuffer;

static void
wbuffer_free( WriteBuffer *wbuffer )
{
        /* Is there a thread running this region? Kill it!
         */
        if( wbuffer->thread ) {
                wbuffer->kill = TRUE;
		im_semaphore_up( &wbuffer->go );

		/* Return value is always NULL (see wbuffer_write_thread).
		 */
		(void) g_thread_join( wbuffer->thread );
#ifdef DEBUG_CREATE
		printf( "wbuffer_free: g_thread_join()\n" );
#endif /*DEBUG_CREATE*/

		wbuffer->thread = NULL;
        }

	IM_FREEF( im_region_free, wbuffer->region );
	im_semaphore_destroy( &wbuffer->go );
	im_semaphore_destroy( &wbuffer->nwrite );
	im_semaphore_destroy( &wbuffer->done );
	im_free( wbuffer );
}

static void
wbuffer_write( WriteBuffer *wbuffer )
{
	wbuffer->write_errno = wbuffer->write_fn( wbuffer->region, 
		&wbuffer->area, wbuffer->a, wbuffer->b );

#ifdef DEBUG
	printf( "wbuffer_write: %d bytes from wbuffer %p\n", 
		wbuffer->region->bpl * wbuffer->area.height, wbuffer );
#endif /*DEBUG*/
}

#ifdef HAVE_THREADS
/* Run this as a thread to do a BG write.
 */
static void *
wbuffer_write_thread( void *data )
{
	WriteBuffer *wbuffer = (WriteBuffer *) data;

	for(;;) {
		im_semaphore_down( &wbuffer->go );

		if( wbuffer->kill )
			break;

		/* Wait for all writer threads to leave this wbuffer.
		 */
		im_semaphore_downn( &wbuffer->nwrite, 0 );

		wbuffer_write( wbuffer );

		/* Signal write complete.
		 */
		im_semaphore_up( &wbuffer->done );
	}

	return( NULL );
}
#endif /*HAVE_THREADS*/

static WriteBuffer *
wbuffer_new( im_threadgroup_t *tg, im_wbuffer_fn write_fn, void *a, void *b )
{
	WriteBuffer *wbuffer;

	if( !(wbuffer = IM_NEW( NULL, WriteBuffer )) )
		return( NULL );
	wbuffer->tg = tg;
	wbuffer->region = NULL;
	im_semaphore_init( &wbuffer->go, 0, "go" );
	im_semaphore_init( &wbuffer->nwrite, 0, "nwrite" );
	im_semaphore_init( &wbuffer->done, 0, "done" );
	wbuffer->write_errno = 0;
	wbuffer->thread = NULL;
	wbuffer->kill = FALSE;
	wbuffer->write_fn = write_fn;
	wbuffer->a = a;
	wbuffer->b = b;

	if( !(wbuffer->region = im_region_create( tg->im )) ) {
		wbuffer_free( wbuffer );
		return( NULL );
	}

#ifdef HAVE_THREADS
	/* Make this last (picks up parts of wbuffer on startup).
	 */
	if( !(wbuffer->thread = g_thread_create( wbuffer_write_thread, wbuffer, 
		TRUE, NULL )) ) {
		im_error( "wbuffer_new", _( "unable to create thread" ) );
		wbuffer_free( wbuffer );
		return( NULL );
	}
#endif /*HAVE_THREADS*/

	return( wbuffer );
}

/* At end of work_fn ... need to tell wbuffer write thread that we're done.
 */
static int
wbuffer_work_fn( REGION *region, WriteBuffer *wbuffer )
{
	im_semaphore_upn( &wbuffer->nwrite, 1 );

	return( 0 );
}

/* Attach a wbuffer to a position.
 */
static int 
wbuffer_position( WriteBuffer *wbuffer, 
	int left, int top, int width, int height )
{
	Rect image, area;

	image.left = 0;
	image.top = 0;
	image.width = wbuffer->tg->im->Xsize;
	image.height = wbuffer->tg->im->Ysize;

	area.left = left;
	area.top = top;
	area.width = width;
	area.height = height;

	im_rect_intersectrect( &area, &image, &wbuffer->area );
	if( im_region_buffer( wbuffer->region, &wbuffer->area ) )
		return( -1 );

	/* This should be an exclusive buffer, hopefully.
	 */
	assert( !wbuffer->region->buffer->done );

	return( 0 );
}

/* Loop over a wbuffer filling it threadily.
 */
static int
wbuffer_fill( WriteBuffer *wbuffer )
{
	Rect *area = &wbuffer->area;
	im_threadgroup_t *tg = wbuffer->tg;
	IMAGE *im = tg->im;
	Rect image;

	int x, y;

#ifdef DEBUG
        printf( "wbuffer_fill: starting for wbuffer %p at line %d\n", 
		wbuffer, area->top ); 
#endif /*DEBUG*/

	image.left = 0;
	image.top = 0;
	image.width = im->Xsize;
	image.height = im->Ysize;

	/* Loop over area, sparking threads for all sub-parts in turn.
	 */
	for( y = area->top; y < IM_RECT_BOTTOM( area ); y += tg->ph )
		for( x = area->left; x < IM_RECT_RIGHT( area ); x += tg->pw ) {
			im_thread_t *thr;
			Rect pos;
			Rect clipped;

			/* thrs appear on idle when the child thread does
			 * threadgroup_idle_add and hits the 'go' semaphore.
			 */
                        thr = im_threadgroup_get( tg );

			/* Set the position we want to generate with this
			 * thread. Clip against the size of the image and the
			 * space available in or.
			 */
			pos.left = x;
			pos.top = y;
			pos.width = tg->pw;
			pos.height = tg->ph;
			im_rect_intersectrect( &pos, &image, &clipped );
			im_rect_intersectrect( &clipped, area, &clipped );

			/* Note params.
			 */
			thr->oreg = wbuffer->region; 
			thr->pos = clipped; 
			thr->x = clipped.left;
			thr->y = clipped.top;
			thr->a = wbuffer;

#ifdef DEBUG
			printf( "wbuffer_fill: starting for tile at %d x %d\n",
				x, y );
#endif /*DEBUG*/

			/* Add writer to n of writers on wbuffer, set it going.
			 */
			im_semaphore_upn( &wbuffer->nwrite, -1 );
			im_threadgroup_trigger( thr );

			/* Trigger any eval callbacks on our source image and
			 * check for errors.
			 */
			if( im__handle_eval( tg->im, tg->pw, tg->ph ) ||
				im_threadgroup_iserror( tg ) ) {
				/* Don't kill threads yet ... we may want to
				 * get some error stuff out of them.
				 */
				im_threadgroup_wait( tg );
				return( -1 );
			}
		}

	return( 0 );
}

/* Eval to file.
 */
static int
wbuffer_eval_to_file( WriteBuffer *b1, WriteBuffer *b2 )
{
	im_threadgroup_t *tg = b1->tg;
	IMAGE *im = tg->im;
        int y;

	assert( b1->tg == b2->tg );

#ifdef DEBUG
        int nstrips;

        nstrips = 0;
        printf( "wbuffer_eval_to_file: partial image output to file\n" );
#endif /*DEBUG*/

	/* Note we'll be working to fill a contigious area.
	 */
	tg->inplace = 1;

	/* What threads do at the end of each tile ... decrement the nwrite
	 * semaphore.
	 */
	tg->work = (im__work_fn) wbuffer_work_fn;

        /* Fill to in steps, write each to the output.
         */
        for( y = 0; y < im->Ysize; y += tg->nlines ) {
		/* Attach to this position in image.
		 */
		if( wbuffer_position( b1, 0, y, im->Xsize, tg->nlines ) )
			return( -1 );

		/* Spark off threads to fill with data.
		 */
		if( wbuffer_fill( b1 ) )
			return( -1 );

		/* We have to keep the ordering on wbuffer writes, so we can't
		 * have more than one background write going at once. Plus we
		 * want to make sure write()s don't get interleaved. Wait for
		 * the previous BG write (if any) to finish.
		 */
		if( y > 0 ) {
			im_semaphore_down( &b2->done );

			/* Previous write suceeded?
			 */
			if( b2->write_errno ) {
				im_error_system( b2->write_errno, 
					"im__eval_to_file", 
					_( "write failed" ) );
				return( -1 ); 
			}
		}

		/* b1 write can go.
		 */
		im_semaphore_up( &b1->go );

#ifndef HAVE_THREADS
		/* No threading ... just write.
		 */
		wbuffer_write( b1 );
#endif /*HAVE_THREADS*/

		/* Rotate wbuffers.
		 */
		{
			WriteBuffer *t;

			t = b1; b1 = b2; b2 = t;
		}

#ifdef DEBUG
                nstrips++;
#endif /*DEBUG*/
        }

	/* Wait for all threads to finish, check for any errors.
	 */
	im_threadgroup_wait( tg );
	im_semaphore_down( &b2->done );
	if( im_threadgroup_iserror( tg ) ) 
		return( -1 );
	if( b1->write_errno || b2->write_errno ) {
		im_error_system( 
			b1->write_errno ? b1->write_errno : b2->write_errno,
			"im__eval_to_file", _( "write failed" ) );
		return( -1 ); 
	}

#ifdef DEBUG
        printf( "wbuffer_eval_to_file: success! %d strips written\n", nstrips );
#endif /*DEBUG*/

        return( 0 );
}

int
im_wbuffer( im_threadgroup_t *tg, 
	im_wbuffer_fn write_fn, void *a, void *b )
{
	WriteBuffer *b1, *b2;
	int result;

	if( im__start_eval( tg->im ) )
		return( -1 );

	result = 0;

	b1 = wbuffer_new( tg, write_fn, a, b );
	b2 = wbuffer_new( tg, write_fn, a, b );

	if( !b1 || !b2 || wbuffer_eval_to_file( b1, b2 ) )  
		result = -1;

	im__end_eval( tg->im );
	wbuffer_free( b1 );
	wbuffer_free( b2 );

	return( result );
}
