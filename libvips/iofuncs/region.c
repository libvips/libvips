/* Make and destroy partial image regions.
 * 
 * J.Cupitt, 8/4/93.
 * 1/7/93 JC
 *	- adapted for partial v2
 *	- ANSIfied
 * 15/8/94 JC
 *	- start & stop can now be NULL for no-op
 * 12/5/94 JC
 *      - threads v2.0 added
 * 22/2/95 JC
 *	- im_region_region() args changed
 * 22/6/95 JC
 *	- im_region_local() did not always reset the data pointer
 * 18/11/98 JC
 *	- init a, b, c also now, to help rtc avoid spurious checks
 * 29/6/01 JC
 *	- im_region_free() now frees immediately
 * 6/8/02 JC
 *	- new mmap() window regions
 * 5/11/02 JC
 *	- fix for mmap a local region
 * 28/2/05
 *	- shrink local region memory if required much-greater-than allocated
 * 3/6/05
 *	- im_region_region() allows Bands and BandFmt to differ, provided
 *	  sizeof( pel ) is the same ... makes im_copy_morph() work
 * 30/10/06
 * 	- switch to im_window_t for mmap window stuff
 * 29/11/06
 * 	- switch to im_buffer_t for local mem buffer stuff
 * 19/1/07
 * 	- im_region_image() only sets r, not whole image
 * 1'2'07
 * 	- gah, im_region_image() could still break (thanks Mikkel)
 * 23/7/08
 * 	- added im_region_print()
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
#define DEBUG_MOVE 
#define DEBUG_ENVIRONMENT 1
#define DEBUG_CREATE
#define DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif /*HAVE_UNISTD_H*/
#include <errno.h>
#include <string.h>
#ifdef HAVE_SYS_MMAN_H
#include <sys/mman.h>
#endif
#include <assert.h>

#include <vips/vips.h>
#include <vips/internal.h>
#include <vips/thread.h>
#include <vips/debug.h>

#ifdef OS_WIN32
#include <windows.h>
#endif /*OS_WIN32*/

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/**
 * SECTION: region
 * @short_description: small, rectangular parts of images
 * @stability: Stable
 * @see_also: <link linkend="libvips-image">image</link>
 * @include: vips/vips.h
 *
 * A #REGION is a small part of an image and some pixels. You use regions to
 * read pixels out of images without having to have the whole image in memory
 * at once.
 *
 * A region can be a memory buffer, part of a memory-mapped file, part of some
 * other image, or part of some other region.
 */

/**
 * REGION:
 * @im: the #IMAGE that this region is defined on
 * @valid: the #Rect of pixels that this region represents
 *
 * A small part of an #IMAGE. @valid holds the left/top/width/height of the
 * area of pixels that are available from the region. 
 *
 * See also: IM_REGION_ADDR(), im_region_create(), im_prepare().
 */

/**
 * IM_REGION_LSKIP:
 * @R: a #REGION
 *
 * Returns: the number of bytes to add to move down a scanline.
 */

/**
 * IM_REGION_N_ELEMENTS:
 * @R: a #REGION
 *
 * Returns: the number of band elements across a region.
 */

/**
 * IM_REGION_SIZEOF_LINE:
 * @R: a #REGION
 *
 * Returns: the number of bytes across a region.
 */

/**
 * IM_REGION_ADDR:
 * @R: a #REGION
 * @X: x coordinate
 * @Y: y coordinate
 *
 * This macro returns a pointer to a pixel in a region. The (x, y) coordinates
 * need to be within the #Rect (@R->valid).
 * 
 * If DEBUG is defined, you get a version that checks bounds for you.
 *
 * Returns: the address of pixel (x,y) in the region.
 */

/**
 * IM_REGION_ADDR_TOPLEFT:
 * @R: a #REGION
 *
 * This macro returns a pointer to the top-left pixel in the #REGION, that is,
 * the pixel at (@R->valid.left, @R->valid.top).
 * 
 * Returns: the address of the top-left pixel in the region.
 */

#ifdef DEBUG
/* Track all regions here for debugging.
 */
static GSList *im__regions_all = NULL;
#endif /*DEBUG*/

/* Call a start function if no sequence is running on this REGION.
 */
int
im__call_start( REGION *reg )
{
	IMAGE *im = reg->im;

        /* Have we a sequence running on this region? Start one if not.
         */
        if( !reg->seq && im->start ) {
                g_mutex_lock( im->sslock );
                reg->seq = im->start( im, im->client1, im->client2 );
                g_mutex_unlock( im->sslock );
 
                if( !reg->seq ) {
                        im_error( "im__call_start", 
				_( "start function failed for image %s" ),
                                im->filename );
                        return( -1 );
                }
        }

        return( 0 );
}

/* Call a stop function if a sequence is running in this REGION. No error
 * return, really.
 */
void
im__call_stop( REGION *reg )
{
	IMAGE *im = reg->im;
	int res;

        /* Stop any running sequence.
         */
        if( reg->seq && im->stop ) {
                g_mutex_lock( im->sslock );
                res = im->stop( reg->seq, im->client1, im->client2 );
                g_mutex_unlock( im->sslock );

		if( res )
                        error_exit( "panic: user stop callback failed "
				"for image %s", im->filename );
 
                reg->seq = NULL;
        }
}

/* If a region is being created in one thread (eg. the main thread) and then
 * used in another (eg. a worker thread), the new thread needs to tell VIPS
 * to stop sanity assert() fails. The previous owner needs to
 * im__region_no_ownership() before we can call this.
 */
void
im__region_take_ownership( REGION *reg )
{
	/* Lock so that there's a memory barrier with the thread doing the
	 * im__region_no_ownership() before us.
	 */
	g_mutex_lock( reg->im->sslock );

	assert( reg->thread == NULL );

	/* We don't want to move shared buffers: the other region using this
	 * buffer will still be on the other thread. Not sure if this will
	 * ever happen: if it does, we'll need to dup the buffer.
	 */
	assert( !reg->buffer || reg->buffer->ref_count == 1 );

	reg->thread = g_thread_self();

	g_mutex_unlock( reg->im->sslock );
}

void
im__region_check_ownership( REGION *reg )
{
	if( reg->thread ) {
		assert( reg->thread == g_thread_self() );
		if( reg->buffer && reg->buffer->cache )
			assert( reg->thread == reg->buffer->cache->thread );
	}
}

/* Call this from the relinquishing thread. Removes the buffer (if any) from
 * this thread's buffer cache.
 */
void
im__region_no_ownership( REGION *reg )
{
	g_mutex_lock( reg->im->sslock );

	im__region_check_ownership( reg );

	reg->thread = NULL;
	if( reg->buffer )
		im_buffer_undone( reg->buffer );

	g_mutex_unlock( reg->im->sslock );
}

/**
 * im_region_create:
 * @im: image to create this region on
 *
 * Create a region. #REGION s start out empty, you need to call im_prepare() to
 * fill them with pixels.
 *
 * See also: im_prepare(), im_region_free().
 */
REGION *
im_region_create( IMAGE *im )
{	
	REGION *reg;

	g_assert( !im_image_sanity( im ) );

	if( !(reg = IM_NEW( NULL, REGION )) )
		return( NULL );

	reg->im = im;
	reg->valid.left = 0;
	reg->valid.top = 0;
	reg->valid.width = 0;
	reg->valid.height = 0;
	reg->type = IM_REGION_NONE;
	reg->data = NULL;
	reg->bpl = 0;
	reg->seq = NULL;
	reg->thread = NULL;
	reg->window = NULL;
	reg->buffer = NULL;

	im__region_take_ownership( reg );

	/* We're usually inside the ss lock anyway. But be safe ...
	 */
	g_mutex_lock( im->sslock );
	im->regions = g_slist_prepend( im->regions, reg );
	g_mutex_unlock( im->sslock );

#ifdef DEBUG
	g_mutex_lock( im__global_lock );
	im__regions_all = g_slist_prepend( im__regions_all, reg );
	printf( "%d regions in vips\n", g_slist_length( im__regions_all ) );
	g_mutex_unlock( im__global_lock );
#endif /*DEBUG*/

	return( reg );
}

/* Free any resources we have.
 */
static void
im_region_reset( REGION *reg )
{
	IM_FREEF( im_window_unref, reg->window );
	IM_FREEF( im_buffer_unref, reg->buffer );
}

/**
 * im_region_free:
 * @reg: #REGION to free
 *
 * Free a region and any resources it holds.
 *
 * If @im has previously been closed, then freeing the last #REGION on @in can
 * cause @im to finally be freed as well.
 */
void 
im_region_free( REGION *reg )
{	
	IMAGE *im;

        if( !reg )
		return;
        im = reg->im;

        /* Stop this sequence.
         */
        im__call_stop( reg );

	/* Free any attached memory.
	 */
	im_region_reset( reg );

	/* Detach from image. 
	 */
	g_mutex_lock( im->sslock );
	im->regions = g_slist_remove( im->regions, reg );
	g_mutex_unlock( im->sslock );
	reg->im = NULL;

	/* Was this the last region on an image with close_pending? If yes,
	 * close the image too.
	 */
	if( !im->regions && im->close_pending ) {
#ifdef DEBUG_IO
		printf( "im_region_free: closing pending image \"%s\"\n",
			im->filename );
#endif /*DEBUG_IO*/
		/* Time to close the image.
		 */
		im->close_pending = 0;
		im_close( im );
	}

	im_free( reg );

#ifdef DEBUG
	g_mutex_lock( im__global_lock );
	assert( g_slist_find( im__regions_all, reg ) );
	im__regions_all = g_slist_remove( im__regions_all, reg );
	printf( "%d regions in vips\n", g_slist_length( im__regions_all ) );
	g_mutex_unlock( im__global_lock );
#endif /*DEBUG*/
}

/* Region should be a pixel buffer. On return, check
 * reg->buffer->done to see if there are pixels there already. Otherwise, you
 * need to calculate.
 */

/**
 * im_region_buffer:
 * @reg: region to operate upon
 * @r: #Rect of pixels you need to be able to address
 *
 * The region is transformed so that at least @r pixels are available as a
 * memory buffer. 
 *
 * Returns: 0 on success, or -1 for error.
 */
int
im_region_buffer( REGION *reg, Rect *r )
{
	IMAGE *im = reg->im;

	Rect image;
	Rect clipped;

	im__region_check_ownership( reg );

	/* Clip against image.
	 */
	image.top = 0;
	image.left = 0;
	image.width = im->Xsize;
	image.height = im->Ysize;
	im_rect_intersectrect( r, &image, &clipped );

	/* Test for empty.
	 */
	if( im_rect_isempty( &clipped ) ) {
		im_error( "im_region_buffer", 
			"%s", _( "valid clipped to nothing" ) );
		return( -1 );
	}

	/* Already have stuff?
	 */
	if( reg->type == IM_REGION_BUFFER &&
		im_rect_includesrect( &reg->valid, &clipped ) &&
		reg->buffer &&
		!reg->buffer->invalid ) 
		return( 0 );

	/* Don't call im_region_reset() ... we combine buffer unref and new
	 * buffer ref in one call to reduce malloc/free cycling.
	 */
	IM_FREEF( im_window_unref, reg->window );
	if( !(reg->buffer = im_buffer_unref_ref( reg->buffer, im, &clipped )) )
		return( -1 );

	/* Init new stuff.
	 */
	reg->valid = reg->buffer->area;
	reg->bpl = IM_IMAGE_SIZEOF_PEL( im ) * reg->buffer->area.width;
	reg->type = IM_REGION_BUFFER;
	reg->data = reg->buffer->buf;

	return( 0 );
}

/**
 * im_region_image:
 * @reg: region to operate upon
 * @r: #Rect of pixels you need to be able to address
 *
 * The region is transformed so that at least @r pixels are available directly
 * from the image. The image needs to be a memory buffer or represent a file
 * on disc that has been mapped or can be mapped. 
 *
 * Returns: 0 on success, or -1 for error.
 */
int
im_region_image( REGION *reg, Rect *r )
{
	Rect image;
	Rect clipped;

	/* Sanity check.
	 */
	im__region_check_ownership( reg );

	/* Clip against image.
	 */
	image.top = 0;
	image.left = 0;
	image.width = reg->im->Xsize;
	image.height = reg->im->Ysize;
	im_rect_intersectrect( r, &image, &clipped );

	/* Test for empty.
	 */
	if( im_rect_isempty( &clipped ) ) {
		im_error( "im_region_image", 
			"%s", _( "valid clipped to nothing" ) );
		return( -1 );
	}

	if( reg->im->data ) {
		/* We have the whole image available ... easy!
		 */
		im_region_reset( reg );

		/* We can't just set valid = clipped, since this may be an
		 * incompletely calculated memory buffer. Just set valid to r.
		 */
		reg->valid = clipped;
		reg->bpl = IM_IMAGE_SIZEOF_LINE( reg->im );
		reg->data = reg->im->data +
			(gint64) clipped.top * IM_IMAGE_SIZEOF_LINE( reg->im ) +
			clipped.left * IM_IMAGE_SIZEOF_PEL( reg->im );
		reg->type = IM_REGION_OTHER_IMAGE;
	}
	else if( reg->im->dtype == IM_OPENIN ) {
		/* No complete image data ... but we can use a rolling window.
		 */
		if( reg->type != IM_REGION_WINDOW || !reg->window ||
			reg->window->top > clipped.top ||
			reg->window->top + reg->window->height < 
				clipped.top + clipped.height ) {
			im_region_reset( reg );

			if( !(reg->window = im_window_ref( reg->im, 
				clipped.top, clipped.height )) )
				return( -1 );

			reg->type = IM_REGION_WINDOW;
		}

		/* Note the area the window actually represents.
		 */
		reg->valid.left = 0;
		reg->valid.top = reg->window->top;
		reg->valid.width = reg->im->Xsize;
		reg->valid.height = reg->window->height;
		reg->bpl = IM_IMAGE_SIZEOF_LINE( reg->im );
		reg->data = reg->window->data;
	}
	else {
		im_error( "im_region_image", 
			"%s", _( "bad image type" ) );
		return( -1 );
	}

	return( 0 );
}

/**
 * im_region_region:
 * @reg: region to operate upon
 * @dest: region to connect to
 * @r: #Rect of pixels you need to be able to address
 * @x: postion of @r in @dest
 * @y: postion of @r in @dest
 *
 * Make IM_REGION_ADDR() on @reg go to @dest instead. 
 *
 * @r is the part of @reg which you want to be able to address (this
 * effectively becomes the valid field), (@x, @y) is the top LH corner of the
 * corresponding area in @dest.
 *
 * Performs all clipping necessary to ensure that @reg->valid is indeed
 * valid.
 *
 * If the region we attach to is modified, we can be left with dangling 
 * pointers! If the region we attach to is on another image, the two images 
 * must have 
 * the same sizeof( pel ).
 *
 * Returns: 0 on success, or -1 for error.
 */
int
im_region_region( REGION *reg, REGION *dest, Rect *r, int x, int y )
{
	Rect image;
	Rect wanted;
	Rect clipped;
	Rect clipped2;
	Rect final;

	/* Sanity check.
	 */
	if( !dest->data || 
		IM_IMAGE_SIZEOF_PEL( dest->im ) != 
			IM_IMAGE_SIZEOF_PEL( reg->im ) ) {
		im_error( "im_region_region", 
			"%s", _( "inappropriate region type" ) );
		return( -1 );
	}
	im__region_check_ownership( reg );

	/* We can't test

		assert( dest->thread == g_thread_self() );

	 * since we can have several threads writing to the same region in
	 * threadgroup.
	 */

	/* Clip r against size of the image.
	 */
	image.top = 0;
	image.left = 0;
	image.width = reg->im->Xsize;
	image.height = reg->im->Ysize;
	im_rect_intersectrect( r, &image, &clipped );

	/* Translate to dest's coordinate space and clip against the available
	 * pixels.
	 */
	wanted.left = x + (clipped.left - r->left);
	wanted.top = y + (clipped.top - r->top);
	wanted.width = clipped.width;
	wanted.height = clipped.height;

	/* Test that dest->valid is large enough.
	 */
	if( !im_rect_includesrect( &dest->valid, &wanted ) ) {
		im_error( "im_region_region", 
			"%s", _( "dest too small" ) );
		return( -1 );
	}

	/* Clip against the available pixels.
	 */
	im_rect_intersectrect( &wanted, &dest->valid, &clipped2 );

	/* Translate back to reg's coordinate space and set as valid.
	 */
	final.left = r->left + (clipped2.left - wanted.left);
	final.top = r->top + (clipped2.top - wanted.top);
	final.width = clipped2.width;
	final.height = clipped2.height;

	/* Test for empty.
	 */
	if( im_rect_isempty( &final ) ) {
		im_error( "im_region_region", 
			"%s", _( "valid clipped to nothing" ) );
		return( -1 );
	}

	/* Init new stuff.
	 */
	im_region_reset( reg );
	reg->valid = final;
	reg->bpl = dest->bpl;
	reg->data = IM_REGION_ADDR( dest, clipped2.left, clipped2.top );
	reg->type = IM_REGION_OTHER_REGION;

	return( 0 );
}

/**
 * im_region_equalsregion:
 * @reg1: region to test
 * @reg2: region to test
 *
 * Do two regions point to the same piece of image? ie. 
 *
 * |[
 * 	IM_REGION_ADDR( reg1, x, y ) == IM_REGION_ADDR( reg2, x, y ) &&
 * 	*IM_REGION_ADDR( reg1, x, y ) == 
 * 		*IM_REGION_ADDR( reg2, x, y ) for all x, y, reg1, reg2.
 * ]|
 *
 * Returns: non-zero on equality.
 */
int
im_region_equalsregion( REGION *reg1, REGION *reg2 )
{
	return( reg1->im == reg2->im &&
		im_rect_equalsrect( &reg1->valid, &reg2->valid ) &&
		reg1->data == reg2->data );
}

/**
 * im_region_position:
 * @reg: region to operate upon
 * @x: position to move to
 * @y: position to move to
 *
 * Set the position of a region. This only affects reg->valid, ie. the way
 * pixels are addressed, not reg->data, the pixels which are addressed. Clip
 * against the size of the image. Do not allow negative positions, or
 * positions outside the image.
 *
 * Returns: 0 on success, or -1 for error.
 */
int
im_region_position( REGION *reg, int x, int y )
{
	Rect req, image, clipped;

	/* Clip!
	 */
	image.top = 0;
	image.left = 0;
	image.width = reg->im->Xsize;
	image.height = reg->im->Ysize;
	req.top = y;
	req.left = x;
	req.width = reg->valid.width;
	req.height = reg->valid.height;
	im_rect_intersectrect( &image, &req, &clipped );
	if( x < 0 || y < 0 || im_rect_isempty( &clipped ) ) {
		im_error( "im_region_position", 
			"%s", _( "bad position" ) );
		return( -1 );
	}

	reg->valid = clipped;

	return( 0 );
}

int
im_region_fill( REGION *reg, Rect *r, im_region_fill_fn fn, void *a )
{
	assert( reg->im->dtype == IM_PARTIAL );
	assert( reg->im->generate );

	/* Should have local memory.
	 */
	if( im_region_buffer( reg, r ) )
		return( -1 );

	/* Evaluate into or, if we've not got calculated pixels.
	 */
	if( !reg->buffer->done ) {
		if( fn( reg, a ) )
			return( -1 );

		/* Publish our results.
		 */
		if( reg->buffer )
			im_buffer_done( reg->buffer );
	}

	return( 0 );
}

/* Handy for debug.
 */
void
im_region_print( REGION *region )
{
	printf( "REGION: %p, ", region );
	printf( "im = %p, ", region->im );
	printf( "valid.left = %d, ", region->valid.left );
	printf( "valid.top = %d, ", region->valid.top );
	printf( "valid.width = %d, ", region->valid.width );
	printf( "valid.height = %d, ", region->valid.height );
	printf( "type = %d, ", region->type );
	printf( "data = %p, ", region->data );
	printf( "bpl = %d, ", region->bpl );
	printf( "seq = %p, ", region->seq );
	printf( "thread = %p, ", region->thread );
	printf( "window = %p, ", region->window );
	printf( "buffer = %p\n", region->buffer );
}
