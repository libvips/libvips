/* Manage pipelines of partial images.
 * 
 * J.Cupitt, 17/4/93.
 * 1/7/93 JC
 *	- adapted for partial v2
 *	- ANSIfied
 * 6/7/93 JC
 *	- im_setupout() conventions clarified - see autorewind in
 *	  im_iocheck().
 * 20/7/93 JC
 *	- eval callbacks added
 * 7/9/93 JC
 *	- demand hint mechanism added
 * 25/10/93
 *	- asynchronous output mechanisms removed, as no observable speed-up
 * 9/5/94
 *      - new thread stuff added, with a define to turn it off
 * 15/8/94
 *	- start & stop functions can now be NULL for no-op
 * 7/10/94 JC
 *	- evalend callback system added
 * 23/12/94 JC
 *	- IM_ARRAY uses added
 * 22/2/95 JC
 *	- im_fill_copy() added
 *	- im_region_region() uses modified
 * 24/4/95 JC & KM
 *	- im_fill_lines() bug removed
 * 30/8/96 JC
 *	- revised and simplified ... some code shared with im_iterate()
 *	- new im_generate_region() added
 * 2/3/98 JC
 *	- IM_ANY added
 * 20/7/99 JC
 *	- tile geometry made into ints for easy tuning
 * 30/7/99 RP JC
 *	- threads reorganised for POSIX
 * 29/9/99 JC
 *	- threadgroup stuff added
 * 15/4/04
 *	- better how-many-pixels-calculated
 * 27/11/06
 * 	- merge background write stuff
 * 7/11/07
 * 	- new start/end eval callbacks
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

/* Start and stop functions for one image in, input image is first user data.
 */
void *
im_start_one( IMAGE *out, void *client, void *dummy )
{
	IMAGE *in = (IMAGE *) client;

	return( im_region_create( in ) );
}

int
im_stop_one( void *seq, void *dummy1, void *dummy2 )
{
	REGION *reg = (REGION *) seq;

	im_region_free( reg );

	return( 0 );
}

/* Stop and start functions for many images in. First client is pointer to 
 * null-terminated array of input images.
 */
int
im_stop_many( void *seq, void *dummy1, void *dummy2 )
{
	REGION **ar = (REGION **) seq;

        if( ar ) {
		int i;

		for( i = 0; ar[i]; i++ )
			im_region_free( ar[i] );
		im_free( (char *) ar );
	}

	return( 0 );
}

void *
im_start_many( IMAGE *out, void *client, void *dummy )
{
	IMAGE **in = (IMAGE **) client;

	int i, n;
	REGION **ar;

	/* How many images?
	 */
	for( n = 0; in[n]; n++ )
		;

	/* Alocate space for region array.
	 */
	if( !(ar = IM_ARRAY( NULL, n + 1, REGION * )) )
		return( NULL );

	/* Create a set of regions.
	 */
	for( i = 0; i < n; i++ )
		if( !(ar[i] = im_region_create( in[i] )) ) {
			im_stop_many( ar, NULL, NULL );
			return( NULL );
		}
	ar[n] = NULL;

	return( ar );
}

/* Convenience function - make a null-terminated array of input images.
 * Use with im_start_many.
 */
IMAGE **
im_allocate_input_array( IMAGE *out, ... )
{
	va_list ap;
	IMAGE **ar;
	IMAGE *im;
	int i, n;

	/* Count input images.
	 */
	va_start( ap, out );
	for( n = 0; (im = va_arg( ap, IMAGE * )); n++ )
		;
	va_end( ap );

	/* Allocate array.
	 */
	if( !(ar = IM_ARRAY( out, n + 1, IMAGE * )) )
		return( NULL );

	/* Fill array.
	 */
	va_start( ap, out );
	for( i = 0; i < n; i++ )
		ar[i] = va_arg( ap, IMAGE * );
	va_end( ap );
	ar[n] = NULL;

	return( ar );
}

/* Loop over a big region, filling it in many small pieces with threads.
 */
static int
eval_to_region( REGION *or, im_threadgroup_t *tg )
{
	Rect *r = &or->valid;
	Rect image;

	int x, y;

	image.left = 0;
	image.top = 0;
	image.width = or->im->Xsize;
	image.height = or->im->Ysize;

	/* Note we'll be working to fill a contigious area.
	 */
	tg->inplace = 1;

	/* Loop over or, attaching to all sub-parts in turn.
	 */
	for( y = r->top; y < IM_RECT_BOTTOM( r ); y += tg->ph )
		for( x = r->left; x < IM_RECT_RIGHT( r ); x += tg->pw ) {
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
			im_rect_intersectrect( &clipped, r, &clipped );

			/* Note params and start work.
			 */
			thr->oreg = or; 
			thr->pos = clipped; 
			thr->x = clipped.left;
			thr->y = clipped.top;
			im_threadgroup_trigger( thr );

			/* Check for errors.
			 */
			if( im_threadgroup_iserror( tg ) ) {
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

	if( im_threadgroup_iserror( tg ) )
		return( -1 );

	return( 0 );
}

/* Output to a memory area. Might be im_setbuf(), im_mmapin()/im_makerw() or
 * im_mmapinrw(). 
 */
static int
eval_to_memory( im_threadgroup_t *tg, REGION *or )
{
	int y, chunk;
	IMAGE *im = or->im;
	int result;

	result = 0;

#ifdef DEBUG_IO
	int ntiles = 0;
        printf( "eval_to_memory: partial image output to memory area\n" );
#endif /*DEBUG_IO*/

	/* Signal start of eval.
	 */
	if( im__start_eval( im ) )
		return( -1 );

	/* Choose a chunk size ... 1/100th of the height of the image, about.
	 * This sets the granularity of user feedback on eval progress, but
	 * does not affect mem requirements etc.
	 */
	chunk = (im->Ysize / 100) + 1;

	/* Loop down the output image, evaling each chunk. 
	 */
	for( y = 0; y < im->Ysize; y += chunk ) {
		Rect pos;

		/* Attach or to this position in image.
		 */
		pos.left = 0;
		pos.top = y;
		pos.width = im->Xsize;
		pos.height = IM_MIN( chunk, im->Ysize - y );
		if( (result = im_region_image( or, &pos )) ) 
			break;

		/* Ask for evaluation of this area.
		 */
		if( (result = eval_to_region( or, tg )) ) 
			break;

		/* Trigger any eval callbacks on our source image.
		 */
		if( (result = im__handle_eval( im, pos.width, pos.height )) )
			break;

#ifdef DEBUG_IO
		ntiles++;
#endif /*DEBUG_IO*/
	}

	/* Signal end of eval.
	 */
	result |= im__end_eval( im );

#ifdef DEBUG_IO
	printf( "eval_to_memory: %d patches written\n", ntiles );
#endif /*DEBUG_IO*/

	return( result );
}

/* A write function for VIPS images. Just write() the pixel data.
 */
static int
write_vips( REGION *region, Rect *area, void *a, void *b )
{
	size_t nwritten, count;
	void *buf;

	count = region->bpl * area->height;
	buf = IM_REGION_ADDR( region, 0, area->top );
	do {
		nwritten = write( region->im->fd, buf, count ); 
		if( nwritten == (size_t) -1 ) 
			return( errno );

		buf = (void *) ((char *) buf + nwritten);
		count -= nwritten;
	} while( count > 0 );

	return( 0 );
}

/* Attach a generate function to an image.
 */
int
im_generate( IMAGE *im,
	im_start_fn start, im_generate_fn generate, im_stop_fn stop,
        void *a, void *b )
{
        int res;
	REGION *or;
	im_threadgroup_t *tg;

	g_assert( !im_image_sanity( im ) );

	if( im->Xsize <= 0 || im->Ysize <= 0 || im->Bands <= 0 ) {
		im_error( "im_generate", _( "bad dimensions" ) );
		return( -1 );
	}
 
        /* Look at output type to decide our action.
         */
        switch( im->dtype ) {
        case IM_PARTIAL:
                /* Output to partial image. Just attach functions and return.
                 */
                if( im->generate || im->start || im->stop ) {
                        im_error( "im_generate", _( "func already attached" ) );
                        return( -1 );
                }

                im->start = start;
                im->generate = generate;
                im->stop = stop;
                im->client1 = a;
                im->client2 = b;
 
#ifdef DEBUG_IO
                printf( "im_generate: attaching partial callbacks\n" );
#endif /*DEBUG_IO*/
 
                break;
 
        case IM_SETBUF:
        case IM_SETBUF_FOREIGN:
        case IM_MMAPINRW:
        case IM_OPENOUT:
                /* Eval now .. sanity check.
                 */
                if( im->generate || im->start || im->stop ) {
                        im_error( "im_generate", _( "func already attached" ) );
                        return( -1 );
                }

                /* Get output ready.
                 */
                if( im_setupout( im ) )
                        return( -1 );

                /* Attach callbacks.
                 */
                im->start = start;
                im->generate = generate;
                im->stop = stop;
                im->client1 = a;
                im->client2 = b;

                /* Evaluate. Two output styles: to memory area (im_setbuf()
                 * or im_mmapinrw()) or to file (im_openout()).
                 */
		if( !(or = im_region_create( im )) )
			return( -1 );
		if( !(tg = im_threadgroup_create( im )) ) {
			im_region_free( or );
			return( -1 );
		}
                if( im->dtype == IM_OPENOUT )
                        res = im_wbuffer( tg, write_vips, NULL, NULL );
                else
                        res = eval_to_memory( tg, or );

                /* Clean up.
                 */
		im_threadgroup_free( tg );
		im_region_free( or );

                /* Error?
                 */
                if( res )
                        return( -1 );
 
                break;
 
        default:
                /* Not a known output style.
                 */
		im_error( "im_generate", _( "unable to output to a %s image" ),
			im_dtype2char( im->dtype ) );
                return( -1 );
        }
 
        return( 0 );
}

/* Generate a region of pixels ... with threads! Very like im_prepare(), but
 * threaded and does sub-division. 
 */
int
im_prepare_thread( im_threadgroup_t *tg, REGION *or, Rect *r )
{
	IMAGE *im = or->im;

	g_assert( !im_image_sanity( im ) );

	switch( im->dtype ) {
	case IM_PARTIAL:
                if( im_region_fill( or, r,
			(im_region_fill_fn) eval_to_region, tg ) )
                        return( -1 );

		break;

	case IM_OPENIN:
	case IM_SETBUF:
        case IM_SETBUF_FOREIGN:
	case IM_MMAPIN:
	case IM_MMAPINRW:
		/* Attach to existing buffer.
		 */
		if( im_region_image( or, r ) )
			return( -1 );

		break;

	default:
		im_error( "im_prepare_thread", _( "unable to input from a %s "
			"image" ), im_dtype2char( im->dtype ) );
		return( -1 );
	}

	return( 0 );
}
