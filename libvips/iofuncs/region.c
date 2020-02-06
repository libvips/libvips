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
 * 5/3/10
 * 	- move invalid stuff to region
 * 3/3/11
 * 	- move on top of VipsObject, rename as VipsRegion
 * 23/2/17
 * 	- multiply transparent images through alpha in vips_region_shrink()
 * 13/6/18 harukizaemon
 * 	- add VipsRegionShrink parameter to vips_region_shrink()
 * 9/6/19
 * 	- saner behaviour for vips_region_fetch() if the request is partly 
 * 	  outside the image
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
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
    02110-1301  USA

 */

/*

    These files are distributed with VIPS - http://www.vips.ecs.soton.ac.uk

 */

/*
#define DEBUG_MOVE 
#define DEBUG_ENVIRONMENT 1
#define DEBUG_CREATE
#define DEBUG
#define VIPS_DEBUG
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
#include <string.h>

#include <vips/vips.h>
#include <vips/internal.h>
#include <vips/thread.h>
#include <vips/debug.h>

/**
 * SECTION: region
 * @short_description: small, rectangular parts of images
 * @stability: Stable
 * @see_also: <link linkend="VipsImage">image</link>, 
 * <link linkend="libvips-generate">generate</link>
 * @include: vips/vips.h
 *
 * A #VipsRegion is a small part of an image. You use regions to
 * read pixels out of images without having to have the whole image in memory
 * at once.
 *
 * A region can be a memory buffer, part of a memory-mapped file, part of some
 * other image, or part of some other region.
 *
 * Regions must be created, used and freed all within the same thread, since
 * they can reference private per-thread caches. VIPS sanity-checks region
 * ownership in various places, so you are likely to see g_assert() errors if
 * you don't follow this rule.
 *
 * There
 * is API to transfer ownership of regions between threads, but hopefully this
 * is only needed within VIPS, so we don't expose it. Hopefully.
 */

/**
 * VipsRegion:
 * @im: the #VipsImage that this region is defined on
 * @valid: the #VipsRect of pixels that this region represents
 *
 * A small part of a #VipsImage. @valid holds the left/top/width/height of the
 * area of pixels that are available from the region. 
 *
 * See also: VIPS_REGION_ADDR(), vips_region_new(), vips_region_prepare().
 */

/**
 * VIPS_REGION_LSKIP:
 * @R: a #VipsRegion
 *
 * Returns: The number of bytes to add to move down a scanline.
 */

/**
 * VIPS_REGION_N_ELEMENTS:
 * @R: a #VipsRegion
 *
 * Returns: The number of band elements across a region.
 */

/**
 * VIPS_REGION_SIZEOF_LINE:
 * @R: a #VipsRegion
 *
 * Returns: The number of bytes across a region.
 */

/**
 * VIPS_REGION_ADDR:
 * @R: a #VipsRegion
 * @X: x coordinate
 * @Y: y coordinate
 *
 * This macro returns a pointer to a pixel in a region. The (@X, @Y) 
 * coordinates need to be within the #VipsRect (@R->valid).
 * 
 * If DEBUG is defined, you get a version that checks bounds for you.
 *
 * See also: vips_region_prepare().
 *
 * Returns: The address of pixel (@X,@Y) in @R.
 */

/**
 * VIPS_REGION_ADDR_TOPLEFT:
 * @R: a #VipsRegion
 *
 * This macro returns a pointer to the top-left pixel in the #VipsRegion, that 
 * is, the pixel at (@R->valid.left, @R->valid.top).
 *
 * See also: vips_region_prepare().
 * 
 * Returns: The address of the top-left pixel in the region.
 */

/* Properties.
 */
enum {
	PROP_IMAGE = 1,
	PROP_LAST
}; 

G_DEFINE_TYPE( VipsRegion, vips_region, VIPS_TYPE_OBJECT );

#ifdef VIPS_DEBUG
static GSList *vips__regions_all = NULL;
#endif /*VIPS_DEBUG*/

static void
vips_region_finalize( GObject *gobject )
{
#ifdef VIPS_DEBUG
	VIPS_DEBUG_MSG( "vips_region_finalize: " );
	vips_object_print_name( VIPS_OBJECT( gobject ) );
	VIPS_DEBUG_MSG( "\n" );
#endif /*VIPS_DEBUG*/

#ifdef VIPS_DEBUG
	g_mutex_lock( vips__global_lock );
	vips__regions_all = g_slist_remove( vips__regions_all, gobject ); 
	g_mutex_unlock( vips__global_lock );
#endif /*VIPS_DEBUG*/

	G_OBJECT_CLASS( vips_region_parent_class )->finalize( gobject );
}

/* Call a start function if no sequence is running on this VipsRegion.
 */
int
vips__region_start( VipsRegion *region )
{
	VipsImage *image = region->im;

        if( !region->seq && image->start_fn ) {
		VIPS_GATE_START( "vips__region_start: wait" );

                g_mutex_lock( image->sslock );

		VIPS_GATE_STOP( "vips__region_start: wait" );

                region->seq = image->start_fn( image, 
			image->client1, image->client2 );

                g_mutex_unlock( image->sslock );
 
                if( !region->seq ) {
#ifdef DEBUG
                        printf( "vips__region_start: "
				"start function failed for image %s",
                                image->filename );
#endif /*DEBUG*/

                        return( -1 );
                }
        }

        return( 0 );
}

/* Call a stop function if a sequence is running in this VipsRegion. 
 */
void
vips__region_stop( VipsRegion *region )
{
	VipsImage *image = region->im;

        if( region->seq && image->stop_fn ) {
		int result;

		VIPS_GATE_START( "vips__region_stop: wait" );

                g_mutex_lock( image->sslock );

		VIPS_GATE_STOP( "vips__region_stop: wait" );

               	result = image->stop_fn( region->seq, 
			image->client1, image->client2 );

                g_mutex_unlock( image->sslock );

		/* stop function can return an error, but we have nothing we
		 * can really do with it, sadly.
		 */
		if( result )
                        g_warning( "stop callback failed for image %s", 
				image->filename );
 
                region->seq = NULL;
        }
}

static void
vips_region_dispose( GObject *gobject )
{
	VipsRegion *region = VIPS_REGION( gobject );
	VipsImage *image = region->im;

#ifdef VIPS_DEBUG
	VIPS_DEBUG_MSG( "vips_region_dispose: " );
	vips_object_print_name( VIPS_OBJECT( gobject ) );
	VIPS_DEBUG_MSG( "\n" );
#endif /*VIPS_DEBUG*/

	vips_object_preclose( VIPS_OBJECT( gobject ) );

        /* Stop this sequence.
         */
        vips__region_stop( region );

	/* Free any attached memory.
	 */
	VIPS_FREEF( vips_window_unref, region->window );
	VIPS_FREEF( vips_buffer_unref, region->buffer );

	/* Detach from image. 
	 */
	VIPS_GATE_START( "vips_region_dispose: wait" );

	g_mutex_lock( image->sslock );

	VIPS_GATE_STOP( "vips_region_dispose: wait" );

	image->regions = g_slist_remove( image->regions, region );

	g_mutex_unlock( image->sslock );

	region->im = NULL;

	g_object_unref( image );

	G_OBJECT_CLASS( vips_region_parent_class )->dispose( gobject );
}

static void
vips_region_dump( VipsObject *object, VipsBuf *buf )
{
	VipsRegion *region = VIPS_REGION( object );

	vips_buf_appendf( buf, "VipsRegion: %p, ", region );
	vips_buf_appendf( buf, "im = %p, ", region->im );
	vips_buf_appendf( buf, "valid.left = %d, ", region->valid.left );
	vips_buf_appendf( buf, "valid.top = %d, ", region->valid.top );
	vips_buf_appendf( buf, "valid.width = %d, ", region->valid.width );
	vips_buf_appendf( buf, "valid.height = %d, ", region->valid.height );
	vips_buf_appendf( buf, "type = %d, ", region->type );
	vips_buf_appendf( buf, "data = %p, ", region->data );
	vips_buf_appendf( buf, "bpl = %d, ", region->bpl );
	vips_buf_appendf( buf, "seq = %p, ", region->seq );
	vips_buf_appendf( buf, "thread = %p, ", region->thread );
	vips_buf_appendf( buf, "window = %p, ", region->window );
	vips_buf_appendf( buf, "buffer = %p, ", region->buffer );
	vips_buf_appendf( buf, "invalid = %d", region->invalid );

	VIPS_OBJECT_CLASS( vips_region_parent_class )->dump( object, buf );
}

static void
vips_region_summary( VipsObject *object, VipsBuf *buf )
{
	VipsRegion *region = VIPS_REGION( object );

	vips_buf_appendf( buf, "VipsRegion: %p, ", region );
	vips_buf_appendf( buf, "im = %p, ", region->im );
	vips_buf_appendf( buf, "left = %d, ", region->valid.left );
	vips_buf_appendf( buf, "top = %d, ", region->valid.top );
	vips_buf_appendf( buf, "width = %d, ", region->valid.width );
	vips_buf_appendf( buf, "height = %d", region->valid.height );

	if( region->buffer && region->buffer->buf )
		vips_buf_appendf( buf, ", %.3gMB", 
			region->buffer->bsize / (1024 * 1024.0) );

	VIPS_OBJECT_CLASS( vips_region_parent_class )->summary( object, buf );
}

/* If a region is being created in one thread (eg. the main thread) and then
 * used in another (eg. a worker thread), the new thread needs to tell VIPS
 * to stop sanity g_assert() fails. The previous owner needs to
 * vips__region_no_ownership() before we can call this.
 */
void
vips__region_take_ownership( VipsRegion *region )
{
	/* Lock so that there's a memory barrier with the thread doing the
	 * vips__region_no_ownership() before us.
	 */
	VIPS_GATE_START( "vips__region_take_ownership: wait" );

	g_mutex_lock( region->im->sslock );

	VIPS_GATE_STOP( "vips__region_take_ownership: wait" );

	if( region->thread != g_thread_self() ) {
		g_assert( region->thread == NULL );

		/* We don't want to move shared buffers: the other region 
		 * using this buffer will still be on the other thread. 
		 * Not sure if this will ever happen: if it does, we'll 
		 * need to dup the buffer.
		 */
		g_assert( !region->buffer || 
			region->buffer->ref_count == 1 );

		region->thread = g_thread_self();
	}

	g_mutex_unlock( region->im->sslock );
}

void
vips__region_check_ownership( VipsRegion *region )
{
	if( region->thread ) {
		g_assert( region->thread == g_thread_self() );
		if( region->buffer && region->buffer->cache )
			g_assert( region->thread == 
				region->buffer->cache->thread );
	}
}

/* Call this from the relinquishing thread. Removes the buffer (if any) from
 * this thread's buffer cache.
 */
void
vips__region_no_ownership( VipsRegion *region )
{
	VIPS_GATE_START( "vips__region_no_ownership: wait" );

	g_mutex_lock( region->im->sslock );

	VIPS_GATE_STOP( "vips__region_no_ownership: wait" );

	vips__region_check_ownership( region );

	region->thread = NULL;
	if( region->buffer )
		vips_buffer_undone( region->buffer );

	g_mutex_unlock( region->im->sslock );
}

static int
vips_region_build( VipsObject *object )
{
	VipsRegion *region = VIPS_REGION( object );
	VipsImage *image = region->im;

	VIPS_DEBUG_MSG( "vips_region_build: %p\n", region );

	if( VIPS_OBJECT_CLASS( vips_region_parent_class )->build( object ) )
		return( -1 );

	vips__region_take_ownership( region );

	/* We're usually inside the ss lock anyway. But be safe ...
	 */
	VIPS_GATE_START( "vips_region_build: wait" );

	g_mutex_lock( image->sslock );

	VIPS_GATE_STOP( "vips_region_build: wait" );

	image->regions = g_slist_prepend( image->regions, region );

	g_mutex_unlock( image->sslock );

	return( 0 );
}

static void
vips_region_class_init( VipsRegionClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	gobject_class->finalize = vips_region_finalize;
	gobject_class->dispose = vips_region_dispose;

	vobject_class->summary = vips_region_summary;
	vobject_class->dump = vips_region_dump;
	vobject_class->build = vips_region_build;
}

static void
vips_region_init( VipsRegion *region )
{
	region->type = VIPS_REGION_NONE;

#ifdef VIPS_DEBUG
	g_mutex_lock( vips__global_lock );
	vips__regions_all = g_slist_prepend( vips__regions_all, region ); 
	printf( "vips_region_init: %d regions in vips\n", 
		g_slist_length( vips__regions_all ) ); 
	g_mutex_unlock( vips__global_lock );
#endif /*VIPS_DEBUG*/
}

/**
 * vips_region_new: (constructor)
 * @image: image to create this region on
 *
 * Create a region. #VipsRegion s start out empty, you need to call 
 * vips_region_prepare() to fill them with pixels.
 *
 * See also: vips_region_prepare().
 */
VipsRegion *
vips_region_new( VipsImage *image )
{
	VipsRegion *region;

	/* Ref quickly, we want to make sure we keep the image around.
	 * We can't use the property system, we need to be very threaded.
	 */
	g_object_ref( image );
	g_assert( G_OBJECT( image )->ref_count > 1 );
	g_assert( vips_object_sanity( VIPS_OBJECT( image ) ) );

	region = VIPS_REGION( g_object_new( VIPS_TYPE_REGION, NULL ) );
	region->im = image;

	if( vips_object_build( VIPS_OBJECT( region ) ) ) {
		VIPS_UNREF( region );
		return( NULL );
	}

	g_assert( vips_object_sanity( VIPS_OBJECT( region ) ) );

	return( region ); 
}

/* Region should be a pixel buffer. On return, check
 * reg->buffer->done to see if there are pixels there already. Otherwise, you
 * need to calculate.
 */

/**
 * vips_region_buffer: (method)
 * @reg: region to operate upon
 * @r: #VipsRect of pixels you need to be able to address
 *
 * The region is transformed so that at least @r pixels are available as a
 * memory buffer that can be written to. 
 *
 * Returns: 0 on success, or -1 for error.
 */
int
vips_region_buffer( VipsRegion *reg, const VipsRect *r )
{
	VipsImage *im = reg->im;

	VipsRect image;
	VipsRect clipped;

	vips__region_check_ownership( reg );

	/* Clip against image.
	 */
	image.top = 0;
	image.left = 0;
	image.width = im->Xsize;
	image.height = im->Ysize;
	vips_rect_intersectrect( r, &image, &clipped );

	/* Test for empty.
	 */
	if( vips_rect_isempty( &clipped ) ) {
		vips_error( "VipsRegion", 
			"%s", _( "valid clipped to nothing" ) );
		return( -1 );
	}

	VIPS_FREEF( vips_window_unref, reg->window );

	/* Have we been asked to drop caches? We want to throw everything
	 * away.
	 *
	 * If not, try to reuse the current buffer.
	 */
	if( reg->invalid ) {
		VIPS_FREEF( vips_buffer_unref, reg->buffer );
		reg->invalid = FALSE;

		if( !(reg->buffer = vips_buffer_new( im, &clipped )) ) 
			return( -1 );
	}
	else {
		/* We combine buffer unref and new buffer ref in one call 
		 * to reduce malloc/free cycling.
		 */
		if( !(reg->buffer = 
			vips_buffer_unref_ref( reg->buffer, im, &clipped )) ) 
			return( -1 );
	}

	/* Init new stuff.
	 */
	reg->valid = reg->buffer->area;
	reg->bpl = VIPS_IMAGE_SIZEOF_PEL( im ) * reg->buffer->area.width;
	reg->type = VIPS_REGION_BUFFER;
	reg->data = reg->buffer->buf;

	return( 0 );
}

/**
 * vips_region_image: (method)
 * @reg: region to operate upon
 * @r: #VipsRect of pixels you need to be able to address
 *
 * The region is transformed so that at least @r pixels are available to be 
 * read from the image. The image needs to be a memory buffer or represent a 
 * file on disc that has been mapped or can be mapped. 
 *
 * Returns: 0 on success, or -1 for error.
 */
int
vips_region_image( VipsRegion *reg, const VipsRect *r )
{
	VipsImage *image = reg->im;

	VipsRect all;
	VipsRect clipped;

	/* Sanity check.
	 */
	vips__region_check_ownership( reg );

	/* Clip against image.
	 */
	all.top = 0;
	all.left = 0;
	all.width = image->Xsize;
	all.height = image->Ysize;
	vips_rect_intersectrect( r, &all, &clipped );

	if( vips_rect_isempty( &clipped ) ) {
		vips_error( "VipsRegion", 
			"%s", _( "valid clipped to nothing" ) );
		return( -1 );
	}

	reg->invalid = FALSE;
	VIPS_FREEF( vips_buffer_unref, reg->buffer );

	if( image->data ) {
		/* We have the whole image available ... easy!
		 */
		VIPS_FREEF( vips_window_unref, reg->window );

		/* We can't just set valid = whole image, since this may be an
		 * incompletely calculated memory buffer. Just set valid to r.
		 */
		reg->valid = clipped;
		reg->bpl = VIPS_IMAGE_SIZEOF_LINE( image );
		reg->data = VIPS_IMAGE_ADDR( image, clipped.left, clipped.top );
		reg->type = VIPS_REGION_OTHER_IMAGE;
	}
	else if( image->dtype == VIPS_IMAGE_OPENIN ) {
		/* No complete image data ... but we can use a rolling window.
		 */
		reg->type = VIPS_REGION_WINDOW;
		if( !(reg->window = vips_window_take( reg->window, image, 
			clipped.top, clipped.height )) )
			return( -1 );

		/* Note the area the window actually represents.
		 */
		reg->valid.left = 0;
		reg->valid.top = reg->window->top;
		reg->valid.width = image->Xsize;
		reg->valid.height = reg->window->height;
		reg->bpl = VIPS_IMAGE_SIZEOF_LINE( image );
		reg->data = reg->window->data;
	}
	else {
		VIPS_FREEF( vips_window_unref, reg->window );

		vips_error( "VipsRegion", "%s", _( "bad image type" ) );
		return( -1 );
	}

	return( 0 );
}

/**
 * vips_region_region: (method)
 * @reg: region to operate upon
 * @dest: region to connect to
 * @r: #VipsRect of pixels you need to be able to address
 * @x: postion of @r in @dest
 * @y: postion of @r in @dest
 *
 * Make VIPS_REGION_ADDR() on @reg go to @dest instead. 
 *
 * @r is the part of @reg which you want to be able to address (this
 * effectively becomes the valid field), (@x, @y) is the top LH corner of the
 * corresponding area in @dest.
 *
 * Performs all clipping necessary to ensure that @reg->valid is indeed
 * valid.
 *
 * If the region we attach to is moved or destroyed, we can be left with 
 * dangling pointers! If the region we attach to is on another image, the 
 * two images must have the same sizeof( pel ).
 *
 * Returns: 0 on success, or -1 for error.
 */
int
vips_region_region( VipsRegion *reg, 
	VipsRegion *dest, const VipsRect *r, int x, int y )
{
	VipsRect image;
	VipsRect wanted;
	VipsRect clipped;
	VipsRect clipped2;
	VipsRect final;

	/* Sanity check.
	 */
	if( !dest->data ) {
		vips_error( "VipsRegion", 
			"%s", _( "no pixel data on attached image" ) );
		return( -1 );
	}
	if( VIPS_IMAGE_SIZEOF_PEL( dest->im ) != 
		VIPS_IMAGE_SIZEOF_PEL( reg->im ) ) {
		vips_error( "VipsRegion", 
			"%s", _( "images do not match in pixel size" ) );
		return( -1 );
	}
	vips__region_check_ownership( reg );

	/* We can't test

		g_assert( dest->thread == g_thread_self() );

	 * since we can have several threads writing to the same region in
	 * threadgroup.
	 */

	/* Clip r against size of the image.
	 */
	image.top = 0;
	image.left = 0;
	image.width = reg->im->Xsize;
	image.height = reg->im->Ysize;
	vips_rect_intersectrect( r, &image, &clipped );

	/* Translate to dest's coordinate space and clip against the available
	 * pixels.
	 */
	wanted.left = x + (clipped.left - r->left);
	wanted.top = y + (clipped.top - r->top);
	wanted.width = clipped.width;
	wanted.height = clipped.height;

	/* Test that dest->valid is large enough.
	 */
	if( !vips_rect_includesrect( &dest->valid, &wanted ) ) {
		vips_error( "VipsRegion", 
			"%s", _( "dest too small" ) );
		return( -1 );
	}

	/* Clip against the available pixels.
	 */
	vips_rect_intersectrect( &wanted, &dest->valid, &clipped2 );

	/* Translate back to reg's coordinate space and set as valid.
	 */
	final.left = r->left + (clipped2.left - wanted.left);
	final.top = r->top + (clipped2.top - wanted.top);
	final.width = clipped2.width;
	final.height = clipped2.height;

	/* Test for empty.
	 */
	if( vips_rect_isempty( &final ) ) {
		vips_error( "VipsRegion", 
			"%s", _( "valid clipped to nothing" ) );
		return( -1 );
	}

	/* Init new stuff.
	 */
	VIPS_FREEF( vips_buffer_unref, reg->buffer );
	VIPS_FREEF( vips_window_unref, reg->window );
	reg->invalid = FALSE;
	reg->valid = final;
	reg->bpl = dest->bpl;
	reg->data = VIPS_REGION_ADDR( dest, clipped2.left, clipped2.top );
	reg->type = VIPS_REGION_OTHER_REGION;

	return( 0 );
}

/**
 * vips_region_equalsregion:
 * @reg1: region to test
 * @reg2: region to test
 *
 * Do two regions point to the same piece of image? ie. 
 *
 * |[
 * 	VIPS_REGION_ADDR( reg1, x, y ) == VIPS_REGION_ADDR( reg2, x, y ) &&
 * 	*VIPS_REGION_ADDR( reg1, x, y ) == 
 * 		*VIPS_REGION_ADDR( reg2, x, y ) for all x, y, reg1, reg2.
 * ]|
 *
 * Returns: non-zero on equality.
 */
int
vips_region_equalsregion( VipsRegion *reg1, VipsRegion *reg2 )
{
	return( reg1->im == reg2->im &&
		vips_rect_equalsrect( &reg1->valid, &reg2->valid ) &&
		reg1->data == reg2->data );
}

/**
 * vips_region_position: (method)
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
vips_region_position( VipsRegion *reg, int x, int y )
{
	VipsRect req, image, clipped;

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
	vips_rect_intersectrect( &image, &req, &clipped );
	if( x < 0 || y < 0 || vips_rect_isempty( &clipped ) ) {
		vips_error( "VipsRegion", "%s", _( "bad position" ) );
		return( -1 );
	}

	reg->valid = clipped;
	reg->invalid = FALSE;

	return( 0 );
}

int
vips_region_fill( VipsRegion *reg, 
	const VipsRect *r, VipsRegionFillFn fn, void *a )
{
	g_assert( reg->im->dtype == VIPS_IMAGE_PARTIAL );
	g_assert( reg->im->generate_fn );

	/* You'd think we could check reg and see if it already has some of 
	 * the pixels we need. If it does, we could copy them and only
	 * generate the new ones. 
	 *
	 * However, we usually have neighbouring regions on different threads,
	 * so from the point of view of this thread, we will get no overlaps
	 * on successive prepare requests. 
	 */

	/* Should have local memory.
	 */
	if( vips_region_buffer( reg, r ) )
		return( -1 );

	/* Evaluate into or, if we've not got calculated pixels.
	 */
	if( !reg->buffer->done ) {
		if( fn( reg, a ) )
			return( -1 );

		/* Publish our results.
		 */
		if( reg->buffer )
			vips_buffer_done( reg->buffer );
	}

	return( 0 );
}

#define FILL_LINE( TYPE, Q, N, V ) { \
	int x; \
	TYPE *QT = (TYPE *) Q; \
	\
	for( x = 0; x < (N); x++ )  \
		QT[x] = (V); \
}

/**
 * vips_region_paint: (method)
 * @reg: region to operate upon
 * @r: area to paint
 * @value: value to paint
 *
 * Paints @value into @reg covering rectangle @r. 
 * @r is clipped against 
 * @reg->valid.
 *
 * For int images, @value is 
 * passed to memset(), so it usually needs to be 0 or 255. For float images,
 * value is cast to a float and copied in to each band element. 
 *
 * @r is clipped against
 * @reg->valid.
 *
 * See also: vips_region_black().
 */
void
vips_region_paint( VipsRegion *reg, const VipsRect *r, int value )
{
	VipsRect clipped;

	vips_rect_intersectrect( r, &reg->valid, &clipped );
	if( !vips_rect_isempty( &clipped ) ) {
		VipsPel *q = VIPS_REGION_ADDR( reg, clipped.left, clipped.top );
		size_t ls = VIPS_REGION_LSKIP( reg );
		size_t wd = clipped.width * VIPS_IMAGE_SIZEOF_PEL( reg->im );
		int y;

		if( vips_band_format_isint( reg->im->BandFmt ) ) { 
			for( y = 0; y < clipped.height; y++ ) {
				memset( (char *) q, value, wd );
				q += ls;
			}
		}
		else {
			gboolean iscomplex = 
				vips_band_format_iscomplex( reg->im->BandFmt );
			int nele = clipped.width * reg->im->Bands * 
				(iscomplex ?  2 : 1);
			VipsPel *q1;

			switch( reg->im->BandFmt ) { 
			case VIPS_FORMAT_FLOAT:
			case VIPS_FORMAT_COMPLEX:
				FILL_LINE( float, q, nele, value );
				break;

			case VIPS_FORMAT_DOUBLE:
			case VIPS_FORMAT_DPCOMPLEX:
				FILL_LINE( double, q, nele, value );
				break;

			default:
				g_assert_not_reached();
			}

			q1 = q + ls;

			for( y = 1; y < clipped.height; y++ ) {
				memcpy( (char *) q1, (char *) q, wd );
				q1 += ls;
			}
		}
	}
}

/**
 * vips_region_paint_pel: (method)
 * @reg: region to operate upon
 * @r: area to paint
 * @ink: value to paint
 *
 * Paints @ink into @reg covering rectangle @r. @r is clipped against 
 * @reg->valid.
 *
 * @ink should be a byte array of the same size as an image pixel containing
 * the binary value to write into the pixels.
 *
 * See also: vips_region_paint().
 */
void
vips_region_paint_pel( VipsRegion *reg, const VipsRect *r, const VipsPel *ink )
{
	VipsRect ovl;

	vips_rect_intersectrect( r, &reg->valid, &ovl );
	if( !vips_rect_isempty( &ovl ) ) {
		int ps = VIPS_IMAGE_SIZEOF_PEL( reg->im );
		int ws = ovl.width * ps;
		int ls = VIPS_REGION_LSKIP( reg );

		VipsPel *to, *q;
		int x, y, z;

		/* We plot the first line pointwise, then memcpy() it for the
		 * subsequent lines.
		 */
		to = VIPS_REGION_ADDR( reg, ovl.left, ovl.top );

		q = to;
		for( x = 0; x < ovl.width; x++ ) {
			/* Faster than memcpy() for about n<20.
			 */
			for( z = 0; z < ps; z++ )
				q[z] = ink[z];

			q += ps;
		}

		q = to + ls;
		for( y = 1; y < ovl.height; y++ ) {
			memcpy( q, to, ws );
			q += ls;
		}
	}
}

/**
 * vips_region_black: (method)
 * @reg: region to operate upon
 *
 * Paints 0 into the valid part of @reg.
 *
 * See also: vips_region_paint().
 */
void
vips_region_black( VipsRegion *reg )
{
	vips_region_paint( reg, &reg->valid, 0 );
}

/**
 * vips_region_copy:
 * @reg: source region 
 * @dest: (inout): destination region 
 * @r: #VipsRect of pixels you need to copy
 * @x: postion of @r in @dest
 * @y: postion of @r in @dest
 *
 * Copy from one region to another. Copy area @r from inside @reg to @dest,
 * positioning the area of pixels at @x, @y. The two regions must have pixels
 * which are the same size.
 *
 * See also: vips_region_paint().
 */
void
vips_region_copy( VipsRegion *reg, 
	VipsRegion *dest, const VipsRect *r, int x, int y )
{
	int z;
	int len = VIPS_IMAGE_SIZEOF_PEL( reg->im ) * r->width;
	VipsPel *p = VIPS_REGION_ADDR( reg, r->left, r->top );
	VipsPel *q = VIPS_REGION_ADDR( dest, x, y );
	int plsk = VIPS_REGION_LSKIP( reg );
	int qlsk = VIPS_REGION_LSKIP( dest );

#ifdef DEBUG
	/* Find the area we will write to in dest.
	 */
	VipsRect output;

	printf( "vips_region_copy: sanity check\n" );

	output.left = x;
	output.top = y;
	output.width = r->width;
	output.height = r->height;

	/* Must be inside dest->valid.
	 */
	g_assert( vips_rect_includesrect( &dest->valid, &output ) );

	/* Check the area we are reading from in reg.
	 */
	g_assert( vips_rect_includesrect( &reg->valid, r ) );

	/* VipsPel size must be the same.
	 */
	g_assert( VIPS_IMAGE_SIZEOF_PEL( reg->im ) == 
		VIPS_IMAGE_SIZEOF_PEL( dest->im ) );
#endif /*DEBUG*/

	/* Copy the scanlines. 
	 *
	 * Special case: if the two sets of scanlines are end-to-end (this
	 * happens if we are copying complete regions) we can do a single
	 * memcpy() for the whole thing. This is a little faster since we 
	 * won't have to do unaligned copies.
	 */
	if( len == plsk &&
		len == qlsk ) 
		memcpy( q, p, len * r->height );
	else
		for( z = 0; z < r->height; z++ ) {
			memcpy( q, p, len );

			p += plsk;
			q += qlsk;
		}
}

/* Generate area @target in @to using pixels in @from. 
 *
 * VIPS_CODING_LABQ only.
 */
static void
vips_region_shrink_labpack( VipsRegion *from, 
	VipsRegion *to, const VipsRect *target )
{
	int ls = VIPS_REGION_LSKIP( from );

	int x, y;

	for( y = 0; y < target->height; y++ ) {
		VipsPel *p = VIPS_REGION_ADDR( from, 
			target->left * 2, (target->top + y) * 2 );
		VipsPel *q = VIPS_REGION_ADDR( to, 
			target->left, target->top + y );

		/* Ignore the extra bits for speed.
		 */
		for( x = 0; x < target->width; x++ ) {
			signed char *sp = (signed char *) p;
			unsigned char *up = (unsigned char *) p;

			int l = up[0] + up[4] + 
				up[ls] + up[ls + 4];
			int a = sp[1] + sp[5] + 
				sp[ls + 1] + sp[ls + 5];
			int b = sp[2] + sp[6] + 
				sp[ls + 2] + sp[ls + 6];

			q[0] = (l + 2) >> 2;
			q[1] = a >> 2;
			q[2] = b >> 2;
			q[3] = 0;

			q += 4;
			p += 8;
		}
	}
}

#define SHRINK_TYPE_MEAN_INT( TYPE ) \
	for( x = 0; x < target->width; x++ ) { \
		TYPE *tp = (TYPE *) p; \
		TYPE *tp1 = (TYPE *) (p + ls); \
		TYPE *tq = (TYPE *) q; \
 		\
		for( z = 0; z < nb; z++ ) { \
			int tot = tp[z] + tp[z + nb] +  \
				tp1[z] + tp1[z + nb]; \
			\
			tq[z] = (tot + 2) >> 2; \
		} \
		\
		/* Move on two pels in input. \
		 */ \
		p += ps << 1; \
		q += ps; \
	}

#define SHRINK_TYPE_MEAN_FLOAT( TYPE )  \
	for( x = 0; x < target->width; x++ ) { \
		TYPE *tp = (TYPE *) p; \
		TYPE *tp1 = (TYPE *) (p + ls); \
		TYPE *tq = (TYPE *) q; \
		\
		for( z = 0; z < nb; z++ ) { \
			double tot = tp[z] + tp[z + nb] +  \
				tp1[z] + tp1[z + nb]; \
			\
			tq[z] = tot / 4; \
		} \
		\
		/* Move on two pels in input. \
		 */ \
		p += ps << 1; \
		q += ps; \
	}

/* Generate area @target in @to using pixels in @from. Non-complex.
 */
static void
vips_region_shrink_uncoded_mean( VipsRegion *from,
	VipsRegion *to, const VipsRect *target )
{
	int ls = VIPS_REGION_LSKIP( from );
	int ps = VIPS_IMAGE_SIZEOF_PEL( from->im );
	int nb = from->im->Bands;

	int x, y, z;

	for( y = 0; y < target->height; y++ ) {
		VipsPel *p = VIPS_REGION_ADDR( from, 
			target->left * 2, (target->top + y) * 2 );
		VipsPel *q = VIPS_REGION_ADDR( to, 
			target->left, target->top + y );

		/* Process this line of pels.
		 */
		switch( from->im->BandFmt ) {
		case VIPS_FORMAT_UCHAR:
			SHRINK_TYPE_MEAN_INT( unsigned char );  break;
		case VIPS_FORMAT_CHAR:
			SHRINK_TYPE_MEAN_INT( signed char );  break;
		case VIPS_FORMAT_USHORT:
			SHRINK_TYPE_MEAN_INT( unsigned short );  break;
		case VIPS_FORMAT_SHORT:
			SHRINK_TYPE_MEAN_INT( signed short );  break;
		case VIPS_FORMAT_UINT:
			SHRINK_TYPE_MEAN_INT( unsigned int );  break;
		case VIPS_FORMAT_INT:
			SHRINK_TYPE_MEAN_INT( signed int );  break;
		case VIPS_FORMAT_FLOAT:
			SHRINK_TYPE_MEAN_FLOAT( float );  break;
		case VIPS_FORMAT_DOUBLE:
			SHRINK_TYPE_MEAN_FLOAT( double );  break;

		default:
			g_assert_not_reached();
		}
	}
}

/* This method is implemented so as to perform well and to always select an
 * output pixel from one of the input pixels. As such we make only the
 * following guarantees:
 *
 * ONLY works for non-complex uncoded images pixel types
 * ALWAYS draws from the input values
 * NEVER interpolates
 * NOT stable with respect to the ordered set of input values
 * IS stable with respect to the initial arrangement of input values
 */
#define SHRINK_TYPE_MEDIAN( TYPE ) { \
	int ls = VIPS_REGION_LSKIP( from ); \
	\
	for( x = 0; x < target->width; x++ ) { \
		TYPE *tp = (TYPE *) p; \
		TYPE *tp1 = (TYPE *) (p + ls); \
		TYPE *tq = (TYPE *) q; \
		\
		for( z = 0; z < nb; z++ ) { \
        		tq[z] = VIPS_MIN( \
					VIPS_MAX( tp[z], tp[z + nb] ), \
					VIPS_MAX( tp1[z], tp1[z + nb] ) \
				); \
		} \
		\
		/* Move on two pels in input. \
		 */ \
		p += ps << 1; \
		q += ps; \
	} \
}

/* This method is implemented so as to perform well and to always select an
 * output pixel from one of the input pixels. As such we make only the
 * following guarantees:
 *
 * ONLY works for non-complex uncoded images pixel types
 * ALWAYS draws from the input values
 * NEVER interpolates
 * NOT stable with respect to the ordered set of input values
 * IS stable with respect to the initial arrangement of input values
 */
#define SHRINK_TYPE_MODE( TYPE ) { \
	int ls = VIPS_REGION_LSKIP( from ); \
	\
	for( x = 0; x < target->width; x++ ) { \
		TYPE *tp = (TYPE *) p; \
		TYPE *tp1 = (TYPE *) (p + ls); \
		TYPE *tq = (TYPE *) q; \
		\
		for( z = 0; z < nb; z++ ) { \
			TYPE v[] = {tp[z], tp[z + nb], tp1[z], tp1[z + nb]}; \
		    	int b0 = (v[0] == v[1]) | \
				(v[0] == v[2]) | \
				(v[0] == v[3]); \
    			int b1 = (v[1] == v[0]) | \
				(v[1] == v[2]) | \
				(v[1] == v[3]); \
    			int index = ((~b0) & 0x1) + (~(b0 ^ b1) & 0x1); \
			\
        		tq[z] = v[index]; \
		} \
		\
		p += ps << 1; \
		q += ps; \
	} \
}

#define SHRINK_TYPE_MAX( TYPE ) { \
	int ls = VIPS_REGION_LSKIP( from ); \
	\
	for( x = 0; x < target->width; x++ ) { \
		TYPE *tp = (TYPE *) p; \
		TYPE *tp1 = (TYPE *) (p + ls); \
		TYPE *tq = (TYPE *) q; \
		\
		for( z = 0; z < nb; z++ ) { \
        		tq[z] = VIPS_MAX( \
					VIPS_MAX( tp[z], tp[z + nb] ), \
					VIPS_MAX( tp1[z], tp1[z + nb] ) \
				); \
		} \
		\
		p += ps << 1; \
		q += ps; \
	} \
}

#define SHRINK_TYPE_MIN( TYPE ) { \
	int ls = VIPS_REGION_LSKIP( from ); \
	\
	for( x = 0; x < target->width; x++ ) { \
		TYPE *tp = (TYPE *) p; \
		TYPE *tp1 = (TYPE *) (p + ls); \
		TYPE *tq = (TYPE *) q; \
		\
		for( z = 0; z < nb; z++ ) { \
        		tq[z] = VIPS_MIN( \
					VIPS_MIN( tp[z], tp[z + nb] ), \
					VIPS_MIN( tp1[z], tp1[z + nb] ) \
				); \
		} \
		\
		p += ps << 1; \
		q += ps; \
	} \
}

#define SHRINK_TYPE_NEAREST( TYPE ) { \
	for( x = 0; x < target->width; x++ ) { \
		TYPE *tp = (TYPE *) p; \
		TYPE *tq = (TYPE *) q; \
		\
		for( z = 0; z < nb; z++ ) \
        		tq[z] = tp[z]; \
		\
		p += ps << 1; \
		q += ps; \
	} \
}

#define VIPS_REGION_SHRINK( OP ) \
static void \
vips_region_shrink_uncoded_ ## OP( VipsRegion *from, \
	VipsRegion *to, const VipsRect *target ) \
{ \
	int ps = VIPS_IMAGE_SIZEOF_PEL( from->im ); \
	int nb = from->im->Bands; \
 	\
	int x, y, z; \
 	\
	for( y = 0; y < target->height; y++ ) { \
		VipsPel *p = VIPS_REGION_ADDR( from, \
			target->left * 2, (target->top + y) * 2 ); \
		VipsPel *q = VIPS_REGION_ADDR( to, \
			target->left, target->top + y ); \
 		\
		/* Process this line of pels. \
		 */ \
		switch( from->im->BandFmt ) { \
		case VIPS_FORMAT_UCHAR: \
			SHRINK_TYPE_ ## OP( unsigned char );  break; \
		case VIPS_FORMAT_CHAR: \
			SHRINK_TYPE_ ## OP( signed char );  break; \
		case VIPS_FORMAT_USHORT: \
			SHRINK_TYPE_ ## OP( unsigned short );  break; \
		case VIPS_FORMAT_SHORT: \
			SHRINK_TYPE_ ## OP( signed short );  break; \
		case VIPS_FORMAT_UINT: \
			SHRINK_TYPE_ ## OP( unsigned int );  break; \
		case VIPS_FORMAT_INT: \
			SHRINK_TYPE_ ## OP( signed int );  break; \
		case VIPS_FORMAT_FLOAT: \
			SHRINK_TYPE_ ## OP( float );  break; \
		case VIPS_FORMAT_DOUBLE: \
			SHRINK_TYPE_ ## OP( double );  break; \
 		\
		default: \
			g_assert_not_reached(); \
		} \
	} \
} 

VIPS_REGION_SHRINK( MAX );
VIPS_REGION_SHRINK( MIN );
VIPS_REGION_SHRINK( MODE );
VIPS_REGION_SHRINK( MEDIAN );
VIPS_REGION_SHRINK( NEAREST );

/* Generate area @target in @to using pixels in @from. Non-complex.
 */
static void
vips_region_shrink_uncoded( VipsRegion *from,
	VipsRegion *to, const VipsRect *target, VipsRegionShrink method )
{
	switch( method ) {
		case VIPS_REGION_SHRINK_MEAN:
			vips_region_shrink_uncoded_mean( from, to, target );
			break;

		case VIPS_REGION_SHRINK_MEDIAN:
			vips_region_shrink_uncoded_MEDIAN( from, to, target );
			break;

		case VIPS_REGION_SHRINK_MODE:
			vips_region_shrink_uncoded_MODE( from, to, target );
			break;

		case VIPS_REGION_SHRINK_MAX:
			vips_region_shrink_uncoded_MAX( from, to, target );
			break;

		case VIPS_REGION_SHRINK_MIN:
			vips_region_shrink_uncoded_MIN( from, to, target );
			break;

		case VIPS_REGION_SHRINK_NEAREST:
			vips_region_shrink_uncoded_NEAREST( from, to, target );
			break;

		default:
			g_assert_not_reached();
	}
}

/* No point having an int path, this will always be horribly slow.
 */
#define SHRINK_ALPHA_TYPE( TYPE ) { \
	TYPE *tp = (TYPE *) p; \
	TYPE *tp1 = (TYPE *) (p + ls); \
	TYPE *tq = (TYPE *) q; \
	\
	for( x = 0; x < target->width; x++ ) { \
		/* Make the input alphas. \
		 */ \
		double a1 = tp[nb - 1]; \
		double a2 = tp[nb + nb - 1]; \
		double a3 = tp1[nb - 1]; \
		double a4 = tp1[nb + nb - 1]; \
		\
		/* Output alpha. \
		 */ \
		double a = (a1 + a2 + a3 + a4) / 4.0; \
		\
		if( a == 0 ) { \
			for( z = 0; z < nb; z++ ) \
				tq[z] = 0; \
		} \
		else { \
			for( z = 0; z < nb - 1; z++ ) \
				tq[z] = (a1 * tp[z] + a2 * tp[z + nb] + \
					 a3 * tp1[z] + a4 * tp1[z + nb]) / \
					(4.0 * a); \
			tq[z] = a; \
		} \
		\
		/* Move on two pels in input. \
		 */ \
		tp += nb << 1; \
		tp1 += nb << 1; \
		tq += nb; \
	} \
}

/* Generate area @target in @to using pixels in @from. Non-complex. Use the
 * last band as alpha.
 */
static void
vips_region_shrink_alpha( VipsRegion *from, 
	VipsRegion *to, const VipsRect *target )
{
	int ls = VIPS_REGION_LSKIP( from );
	int nb = from->im->Bands;

	int x, y, z;

	for( y = 0; y < target->height; y++ ) {
		VipsPel *p = VIPS_REGION_ADDR( from, 
			target->left * 2, (target->top + y) * 2 );
		VipsPel *q = VIPS_REGION_ADDR( to, 
			target->left, target->top + y );

		/* Process this line of pels.
		 */
		switch( from->im->BandFmt ) {
		case VIPS_FORMAT_UCHAR:	
			SHRINK_ALPHA_TYPE( unsigned char ); break; 
		case VIPS_FORMAT_CHAR:	
			SHRINK_ALPHA_TYPE( signed char ); break; 
		case VIPS_FORMAT_USHORT:	
			SHRINK_ALPHA_TYPE( unsigned short ); break; 
		case VIPS_FORMAT_SHORT:	
			SHRINK_ALPHA_TYPE( signed short ); break; 
		case VIPS_FORMAT_UINT:	
			SHRINK_ALPHA_TYPE( unsigned int ); break; 
		case VIPS_FORMAT_INT:	
			SHRINK_ALPHA_TYPE( signed int ); break; 
		case VIPS_FORMAT_FLOAT:	
			SHRINK_ALPHA_TYPE( float ); break; 
		case VIPS_FORMAT_DOUBLE:	
			SHRINK_ALPHA_TYPE( double ); break; 

		default:
			g_assert_not_reached();
		}
	}
}

/**
 * vips_region_shrink_method:
 * @from: source region
 * @to: (inout): destination region
 * @target: #VipsRect of pixels you need to copy
 * @method: method to use when generating target pixels
 *
 * Write the pixels @target in @to from the x2 larger area in @from.
 * Non-complex uncoded images and LABQ only. Images with alpha (see
 * vips_image_hasalpha()) shrink with pixels scaled by alpha to avoid fringing.
 *
 * @method selects the method used to do the 2x2 shrink. 
 *
 * See also: vips_region_copy().
 */
int
vips_region_shrink_method( VipsRegion *from, VipsRegion *to, 
	const VipsRect *target, VipsRegionShrink method )
{
	VipsImage *image = from->im;

	if( vips_check_coding_noneorlabq( "vips_region_shrink_method", image ) )
		return( -1 );

	if( from->im->Coding == VIPS_CODING_NONE ) {
		if( vips_check_noncomplex( "vips_region_shrink_method", 
			image ) )
			return( -1 );

		if( vips_image_hasalpha( image ) )
			vips_region_shrink_alpha( from, to, target );
		else
			vips_region_shrink_uncoded( from, to, target, method );
	}
	else
		vips_region_shrink_labpack( from, to, target );

	return( 0 );
}

/**
 * vips_region_shrink: (skip)
 * @from: source region
 * @to: (inout): destination region
 * @target: #VipsRect of pixels you need to copy
 *
 * Write the pixels @target in @to from the x2 larger area in @from.
 * Non-complex uncoded images and LABQ only. Images with alpha (see
 * vips_image_hasalpha()) shrink with pixels scaled by alpha to avoid fringing.
 *
 * This is a compatibility stub that just calls vips_region_shrink_method().
 *
 * See also: vips_region_shrink_method().
 */
int
vips_region_shrink( VipsRegion *from, VipsRegion *to, const VipsRect *target )
{
	return( vips_region_shrink_method( from, to, target, 
		VIPS_REGION_SHRINK_MEAN ) ); 
}

/* Generate into a region. 
 */
static int
vips_region_generate( VipsRegion *reg )
{
	VipsImage *im = reg->im;

	gboolean stop;

        /* Start new sequence, if necessary.
         */
        if( vips__region_start( reg ) )
		return( -1 );

	/* Ask for evaluation.
	 */
	stop = FALSE;
	if( im->generate_fn( reg, reg->seq, im->client1, im->client2, &stop ) )
		return( -1 );
	if( stop ) {
		vips_error( "vips_region_generate", 
			"%s", _( "stop requested" ) );
		return( -1 );
	}

	return( 0 );
}

/** 
 * vips_region_prepare: (method)
 * @reg: region to prepare
 * @r: #VipsRect of pixels you need to be able to address
 *
 * vips_region_prepare() fills @reg with pixels. After calling, 
 * you can address at least the area @r with VIPS_REGION_ADDR() and get 
 * valid pixels.
 *
 * vips_region_prepare() runs in-line, that is, computation is done by 
 * the calling thread, no new threads are involved, and computation 
 * blocks until the pixels are ready.
 *
 * Use vips_sink_screen() to calculate an area of pixels in the 
 * background.
 *
 * See also: vips_sink_screen(), 
 * vips_region_prepare_to().
 *
 * Returns: 0 on success, or -1 on error.
 */
int
vips_region_prepare( VipsRegion *reg, const VipsRect *r )
{	
	VipsImage *im = reg->im;

	VipsRect save = *r;

	vips__region_check_ownership( reg );

	if( vips_image_iskilled( im ) )
		return( -1 );

	/* We use save for sanity checking valid: we test at the end that the
	 * pixels we have generated are indeed all the ones that were asked
	 * for.
	 *
	 * However, r may be clipped by the image size, so we need to clip
	 * save as well to make sure we don't fail the assert due to that.
	 */
{	
	VipsRect image;

	image.left = 0;
	image.top = 0;
	image.width = reg->im->Xsize;
	image.height = reg->im->Ysize;
	vips_rect_intersectrect( &save, &image, &save );
}

#ifdef DEBUG
        printf( "vips_region_prepare: "
		"left = %d, top = %d, width = %d, height = %d\n",
		r->left, r->top, r->width, r->height );
#endif /*DEBUG*/

	switch( im->dtype ) {
	case VIPS_IMAGE_PARTIAL:
		if( vips_region_fill( reg, r, 
			(VipsRegionFillFn) vips_region_generate, NULL ) )
			return( -1 );

		break;

	case VIPS_IMAGE_SETBUF:
	case VIPS_IMAGE_SETBUF_FOREIGN:
	case VIPS_IMAGE_MMAPIN:
	case VIPS_IMAGE_MMAPINRW:
	case VIPS_IMAGE_OPENIN:
		/* Attach to existing buffer.
		 */
		if( vips_region_image( reg, r ) )
			return( -1 );

		break;

	default:
		vips_error( "vips_region_prepare", 
			_( "unable to input from a %s image" ),
			vips_enum_string( VIPS_TYPE_DEMAND_STYLE, im->dtype ) );
		return( -1 );
	}

	/* valid should now include all the pixels that were asked for.
	 */
	g_assert( vips_rect_includesrect( &reg->valid, &save ) );

	return( 0 );
}

/* We need to make pixels using reg's generate function, and write the result
 * to dest.
 */
static int
vips_region_prepare_to_generate( VipsRegion *reg, 
	VipsRegion *dest, const VipsRect *r, int x, int y )
{
	VipsImage *im = reg->im;
	VipsPel *p;

	if( !im->generate_fn ) {
		vips_error( "vips_region_prepare_to",
			"%s", _( "incomplete header" ) );
		return( -1 );
	}

	if( vips_region_region( reg, dest, r, x, y ) )
		return( -1 );

	/* Remember where reg is pointing now.
	 */
	p = VIPS_REGION_ADDR( reg, reg->valid.left, reg->valid.top );

	/* Run sequence into reg.
	 */
	if( vips_region_generate( reg ) )
		return( -1 );

	/* The generate function may not have actually made any pixels ... it
	 * might just have redirected reg to point somewhere else. If it has,
	 * we need an extra copy operation.
	 */
	if( VIPS_REGION_ADDR( reg, reg->valid.left, reg->valid.top ) != p )
		vips_region_copy( reg, dest, r, x, y );

	return( 0 );
}

/** 
 * vips_region_prepare_to: (method)
 * @reg: region to prepare
 * @dest: (inout): region to write to
 * @r: #VipsRect of pixels you need to be able to address
 * @x: postion of @r in @dest
 * @y: postion of @r in @dest
 *
 * Like vips_region_prepare(): fill @reg with the pixels in area @r. 
 *
 * Unlike vips_region_prepare(), rather than writing the result to @reg, the 
 * pixels are written into @dest at offset @x, @y. 
 *
 * Also unlike vips_region_prepare(), @dest is not set up for writing for 
 * you with vips_region_buffer(). You can
 * point @dest at anything, and pixels really will be written there. 
 * This makes vips_region_prepare_to() useful for making the ends of 
 * pipelines.
 *
 * See also: vips_region_prepare(), vips_sink_disc().
 *
 * Returns: 0 on success, or -1 on error
 */
int
vips_region_prepare_to( VipsRegion *reg, 
	VipsRegion *dest, const VipsRect *r, int x, int y )
{
	VipsImage *im = reg->im;
	VipsRect image;
	VipsRect wanted;
	VipsRect clipped;
	VipsRect clipped2;
	VipsRect final;

	if( vips_image_iskilled( im ) )
		return( -1 );

	/* Sanity check.
	 */
	if( !dest->data || 
		dest->im->BandFmt != reg->im->BandFmt ||
		dest->im->Bands != reg->im->Bands ) {
		vips_error( "vips_region_prepare_to", 
			"%s", _( "inappropriate region type" ) );
		return( -1 );
	}

	/* clip r first against the size of reg->im, then again against the 
	 * memory we have available to write to on dest. Just like 
	 * vips_region_region()
	 */
	image.top = 0;
	image.left = 0;
	image.width = reg->im->Xsize;
	image.height = reg->im->Ysize;
	vips_rect_intersectrect( r, &image, &clipped );

	g_assert( clipped.left == r->left );
	g_assert( clipped.top == r->top );

	wanted.left = x + (clipped.left - r->left);
	wanted.top = y + (clipped.top - r->top);
	wanted.width = clipped.width;
	wanted.height = clipped.height;

	/* Test that dest->valid is large enough.
	 */
	if( !vips_rect_includesrect( &dest->valid, &wanted ) ) {
		vips_error( "vips_region_prepare_to", 
			"%s", _( "dest too small" ) );
		return( -1 );
	}

	vips_rect_intersectrect( &wanted, &dest->valid, &clipped2 );

	/* Translate back to reg's coordinate space and set as valid.
	 */
	final.left = r->left + (clipped2.left - wanted.left);
	final.top = r->top + (clipped2.top - wanted.top);
	final.width = clipped2.width;
	final.height = clipped2.height;

	x = clipped2.left;
	y = clipped2.top;

	if( vips_rect_isempty( &final ) ) {
		vips_error( "vips_region_prepare_to", 
			"%s", _( "valid clipped to nothing" ) );
		return( -1 );
	}

#ifdef DEBUG
        printf( "vips_region_prepare_to: "
		"left = %d, top = %d, width = %d, height = %d\n",
		final.left, final.top, final.width, final.height );
#endif /*DEBUG*/

	/* Input or output image type?
	 */
	switch( im->dtype ) {
	case VIPS_IMAGE_OPENOUT:
	case VIPS_IMAGE_PARTIAL:
		/* We are generating with a sequence. 
		 */
		if( vips_region_prepare_to_generate( reg, dest, &final, x, y ) )
			return( -1 );

		break;

	case VIPS_IMAGE_MMAPIN:
	case VIPS_IMAGE_MMAPINRW:
	case VIPS_IMAGE_OPENIN:
		/* Attach to existing buffer and copy to dest.
		 */
		if( vips_region_image( reg, &final ) )
			return( -1 );
		vips_region_copy( reg, dest, &final, x, y );

		break;

	case VIPS_IMAGE_SETBUF:
	case VIPS_IMAGE_SETBUF_FOREIGN:
		/* Could be either input or output. If there is a generate
		 * function, we are outputting.
		 */
		if( im->generate_fn ) {
			if( vips_region_prepare_to_generate( reg, 
				dest, &final, x, y ) )
				return( -1 );
		}
		else {
			if( vips_region_image( reg, &final ) )
				return( -1 );
			vips_region_copy( reg, dest, &final, x, y );
		}

		break;

	default:
		vips_error( "vips_region_prepare_to", 
			_( "unable to input from a %s image" ), 
			vips_enum_nick( VIPS_TYPE_DEMAND_STYLE, im->dtype ) );
		return( -1 );
	}

	/* We've written fresh pixels to dest, it's no longer invalid (if it
	 * was).
	 *
	 * We need this extra thing here because, unlike 
	 * vips_region_prepare(), we don't vips_region_buffer() dest before 
	 * writing it.
	 */
	dest->invalid = FALSE;

	return( 0 );
}

/* Don't use this, use vips_reorder_prepare_many() instead.
 */
int
vips_region_prepare_many( VipsRegion **reg, const VipsRect *r )
{
	for( ; *reg; ++reg )
		if( vips_region_prepare( *reg, r ) )
			return( -1 );

	return( 0 );
}

/** 
 * vips_region_fetch: (method)
 * @reg: region to fetch pixels from
 * @left: area of pixels to fetch
 * @top: area of pixels to fetch
 * @width: area of pixels to fetch
 * @height: area of pixels to fetch
 *
 * Generate an area of pixels and return a copy. The result must be freed
 * with g_free(). The requested area must be completely inside the image.
 *
 * This is equivalent to vips_region_prepare(), followed by a memcpy. It is
 * convenient for language bindings.
 *
 * Returns: A copy of the pixel data.
 */
VipsPel *
vips_region_fetch( VipsRegion *region, 
	int left, int top, int width, int height, size_t *len )
{
	VipsRect request;
	VipsRect image;
	int y;
	VipsPel *result;
	VipsPel *p, *q;
	size_t skip;
	size_t line;

	g_assert( width > 0 );
	g_assert( height > 0 );

	image.left = 0;
	image.top = 0;
	image.width = region->im->Xsize;
	image.height = region->im->Ysize;
	request.left = left;
	request.top = top;
	request.width = width;
	request.height = height;
	if( !vips_rect_includesrect( &image, &request ) )
		return( NULL );
	if( vips_region_prepare( region, &request ) )
		return( NULL );

	skip = VIPS_REGION_LSKIP( region );
	line = VIPS_IMAGE_SIZEOF_PEL( region->im ) * request.width;
	if( !(result = (VipsPel *) vips_malloc( NULL, line * request.height )) )
		return( NULL );

	p = VIPS_REGION_ADDR( region, request.left, request.top );
	q = result;
	for( y = 0; y < request.height; y++ )  {
		memcpy( q, p, line ); 

		p += skip;
		q += line;
	}

	if( len )
		*len = request.height * line;

	return( result );
}

/**
 * vips_region_width: (method)
 * @region: fetch width from this
 *
 * Returns: Width of the pixels held in region.
 */
int
vips_region_width( VipsRegion *region )
{
	return( region->valid.width );
}	

/**
 * vips_region_height: (method)
 * @region: fetch height from this
 *
 * Returns: Height of the pixels held in region.
 */
int
vips_region_height( VipsRegion *region )
{
	return( region->valid.height );
}	

/** 
 * vips_region_invalidate: (method)
 * @reg: region to invalidate
 *
 * Mark a region as containing invalid pixels. Calling this function means
 * that the next time vips_region_prepare() is called, the region will be
 * recalculated.
 *
 * This is faster than calling vips_image_invalidate_all(), but obviously only
 * affects a single region. 
 *
 * See also: vips_image_invalidate_all(), vips_region_prepare().
 */
void 
vips_region_invalidate( VipsRegion *reg )
{
	reg->invalid = TRUE;
}

#ifdef VIPS_DEBUG
static void *
vips_region_dump_all_cb( VipsRegion *region, size_t *alive )
{
	char str[2048];
	VipsBuf buf = VIPS_BUF_STATIC( str );

	vips_object_summary( VIPS_OBJECT( region ), &buf ); 
	printf( "%s\n", vips_buf_all( &buf ) ); 

	if( region->buffer && region->buffer->buf )
		*alive += region->buffer->bsize;

	return( NULL ); 
}

void
vips_region_dump_all( void )
{
	size_t alive;

	g_mutex_lock( vips__global_lock );
	alive = 0;
	printf( "%d regions in vips\n", g_slist_length( vips__regions_all ) );
	vips_slist_map2( vips__regions_all, 
		(VipsSListMap2Fn) vips_region_dump_all_cb, &alive, NULL );
	printf( "%gMB alive\n", alive / (1024 * 1024.0) ); 
	g_mutex_unlock( vips__global_lock );
}
#endif /*VIPS_DEBUG*/

#ifdef DEBUG_LEAK
void
vips__region_count_pixels( VipsRegion *region, const char *nickname )
{
	VipsImage *image = region->im;
	VipsImagePixels *pixels = g_object_get_qdata( G_OBJECT( image ), 
		vips__image_pixels_quark ); 

	g_mutex_lock( vips__global_lock );
	if( !pixels->tpels )
		pixels->tpels = VIPS_IMAGE_N_PELS( image ); 
	if( !pixels->nickname )
		pixels->nickname = nickname; 
	pixels->npels += region->valid.width * region->valid.height;
	g_mutex_unlock( vips__global_lock );
}
#endif /*DEBUG_LEAK*/
