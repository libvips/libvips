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
#include <string.h>

#include <vips/vips.h>
#include <vips/internal.h>
#include <vips/thread.h>
#include <vips/debug.h>

/**
 * SECTION: region
 * @short_description: small, rectangular parts of images
 * @stability: Stable
 * @see_also: <link linkend="libvips-image">image</link>, 
 * <link linkend="libvips-generate">generate</link>
 * @include: vips/vips.h
 *
 * A #VipsRegion is a small part of an image and some pixels. You use regions to
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
 * This macro returns a pointer to a pixel in a region. The (x, y) coordinates
 * need to be within the #VipsRect (@R->valid).
 * 
 * If DEBUG is defined, you get a version that checks bounds for you.
 *
 * Returns: The address of pixel (x,y) in the region.
 */

/**
 * VIPS_REGION_ADDR_TOPLEFT:
 * @R: a #VipsRegion
 *
 * This macro returns a pointer to the top-left pixel in the #VipsRegion, that 
 * is, the pixel at (@R->valid.left, @R->valid.top).
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

static void
vips_region_finalize( GObject *gobject )
{
#ifdef VIPS_DEBUG
	VIPS_DEBUG_MSG( "vips_region_finalize: " );
	vips_object_print( VIPS_OBJECT( gobject ) );
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
                g_mutex_lock( image->sslock );
                region->seq = image->start_fn( image, 
			image->client1, image->client2 );
                g_mutex_unlock( image->sslock );
 
                if( !region->seq ) {
                        vips_error( "vips__region_start", 
				_( "start function failed for image %s" ),
                                image->filename );
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
	IMAGE *image = region->im;

        if( region->seq && image->stop_fn ) {
		int result;

                g_mutex_lock( image->sslock );
               	result = image->stop_fn( region->seq, 
			image->client1, image->client2 );
                g_mutex_unlock( image->sslock );

		/* stop function can return an error, but we have nothing we
		 * can really do with it, sadly.
		 */
		if( result )
                        vips_warn( "VipsRegion", 
				"stop callback failed for image %s", 
				image->filename );
 
                region->seq = NULL;
        }
}

/* Free any resources we have.
 */
static void
vips_region_reset( VipsRegion *region )
{
	VIPS_FREEF( vips_window_unref, region->window );
	VIPS_FREEF( vips_buffer_unref, region->buffer );
	region->invalid = FALSE;
}

static void
vips_region_dispose( GObject *gobject )
{
	VipsRegion *region = VIPS_REGION( gobject );
	VipsImage *image = region->im;

#ifdef VIPS_DEBUG
	VIPS_DEBUG_MSG( "vips_region_dispose: " );
	vips_object_print( VIPS_OBJECT( gobject ) );
#endif /*VIPS_DEBUG*/

	vips_object_preclose( VIPS_OBJECT( gobject ) );

        /* Stop this sequence.
         */
        vips__region_stop( region );

	/* Free any attached memory.
	 */
	vips_region_reset( region ); 

	/* Detach from image. 
	 */
	g_mutex_lock( image->sslock );
	image->regions = g_slist_remove( image->regions, region );
	g_mutex_unlock( image->sslock );
	region->im = NULL;
	g_object_unref( image );

	G_OBJECT_CLASS( vips_region_parent_class )->dispose( gobject );
}

static void
vips_region_print( VipsObject *object, VipsBuf *buf )
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

	VIPS_OBJECT_CLASS( vips_region_parent_class )->print( object, buf );
}

static void
vips_region_print_summary( VipsObject *object, VipsBuf *buf )
{
	VipsRegion *region = VIPS_REGION( object );

	vips_buf_appendf( buf, "VipsRegion: %p, ", region );
	vips_buf_appendf( buf, "im = %p, ", region->im );
	vips_buf_appendf( buf, "left = %d, ", region->valid.left );
	vips_buf_appendf( buf, "top = %d, ", region->valid.top );
	vips_buf_appendf( buf, "width = %d, ", region->valid.width );
	vips_buf_appendf( buf, "height = %d", region->valid.height );

	VIPS_OBJECT_CLASS( vips_region_parent_class )->
		print_summary( object, buf );
}

static void
vips_region_sanity( VipsObject *object, VipsBuf *buf )
{
	VipsRegion *region = VIPS_REGION( object );

	vips_object_sanity( VIPS_OBJECT( region->im ) );

	switch( region->im->dtype ) { 
	case VIPS_IMAGE_PARTIAL:
		/* Start and stop can be NULL, but not generate.
		 */
		if( !region->im->generate_fn )
			vips_buf_appends( buf, "generate NULL in partial\n" );
		break;
	
	default:
		break;
	}

	VIPS_OBJECT_CLASS( vips_region_parent_class )->sanity( object, buf );
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
	g_mutex_lock( region->im->sslock );

	if( region->thread != g_thread_self() ) {
		g_assert( region->thread == NULL );

		/* We don't want to move shared buffers: the other region 
		 * using this buffer will still be on the other thread. 
		 * Not sure if this will ever happen: if it does, we'll 
		 * need to dup the buffer.
		 */
		g_assert( !region->buffer || region->buffer->ref_count == 1 );

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
	g_mutex_lock( region->im->sslock );

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
	g_mutex_lock( image->sslock );
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

	vobject_class->print = vips_region_print;
	vobject_class->print_summary = vips_region_print_summary;
	vobject_class->print = vips_region_sanity;
	vobject_class->build = vips_region_build;
}

static void
vips_region_init( VipsRegion *region )
{
	region->type = VIPS_REGION_NONE;
}

/**
 * vips_region_new:
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

	region = VIPS_REGION( g_object_new( VIPS_TYPE_REGION, NULL ) );

	/* We can't use the property system, we need to be very threaded.
	 */
	region->im = image;
	g_object_ref( image );

	if( vips_object_build( VIPS_OBJECT( region ) ) ) {
		VIPS_UNREF( region );
		return( NULL );
	}

#ifdef DEBUG
	g_assert( vips_object_sanity( VIPS_OBJECT( image ) ) );
	g_assert( vips_object_sanity( VIPS_OBJECT( region ) ) );
#endif /*DEBUG*/

	return( region ); 
}

/* Region should be a pixel buffer. On return, check
 * reg->buffer->done to see if there are pixels there already. Otherwise, you
 * need to calculate.
 */

/**
 * vips_region_buffer:
 * @reg: region to operate upon
 * @r: #VipsRect of pixels you need to be able to address
 *
 * The region is transformed so that at least @r pixels are available as a
 * memory buffer. 
 *
 * Returns: 0 on success, or -1 for error.
 */
int
vips_region_buffer( VipsRegion *reg, VipsRect *r )
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

	/* Have we been asked to drop caches? We want to throw everything
	 * away.
	 *
	 * If not, try to reuse the current buffer.
	 */
	if( reg->invalid ) {
		vips_region_reset( reg );
		if( !(reg->buffer = vips_buffer_new( im, &clipped )) ) 
			return( -1 );
	}
	else {
		/* Don't call vips_region_reset() ... we combine buffer unref 
		 * and new buffer ref in one call to reduce malloc/free 
		 * cycling.
		 */
		VIPS_FREEF( vips_window_unref, reg->window );
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
 * vips_region_image:
 * @reg: region to operate upon
 * @r: #VipsRect of pixels you need to be able to address
 *
 * The region is transformed so that at least @r pixels are available directly
 * from the image. The image needs to be a memory buffer or represent a file
 * on disc that has been mapped or can be mapped. 
 *
 * Returns: 0 on success, or -1 for error.
 */
int
vips_region_image( VipsRegion *reg, VipsRect *r )
{
	VipsRect image;
	VipsRect clipped;

	/* Sanity check.
	 */
	vips__region_check_ownership( reg );

	/* Clip against image.
	 */
	image.top = 0;
	image.left = 0;
	image.width = reg->im->Xsize;
	image.height = reg->im->Ysize;
	vips_rect_intersectrect( r, &image, &clipped );

	/* Test for empty.
	 */
	if( vips_rect_isempty( &clipped ) ) {
		vips_error( "VipsRegion", 
			"%s", _( "valid clipped to nothing" ) );
		return( -1 );
	}

	if( reg->im->data ) {
		/* We have the whole image available ... easy!
		 */
		vips_region_reset( reg );

		/* We can't just set valid = clipped, since this may be an
		 * incompletely calculated memory buffer. Just set valid to r.
		 */
		reg->valid = clipped;
		reg->bpl = VIPS_IMAGE_SIZEOF_LINE( reg->im );
		reg->data = reg->im->data +
			clipped.top * VIPS_IMAGE_SIZEOF_LINE( reg->im ) +
			clipped.left * VIPS_IMAGE_SIZEOF_PEL( reg->im );
		reg->type = VIPS_REGION_OTHER_IMAGE;
	}
	else if( reg->im->dtype == VIPS_IMAGE_OPENIN ) {
		/* No complete image data ... but we can use a rolling window.
		 */
		if( reg->type != VIPS_REGION_WINDOW || !reg->window ||
			reg->window->top > clipped.top ||
			reg->window->top + reg->window->height < 
				clipped.top + clipped.height ) {
			vips_region_reset( reg );

			if( !(reg->window = vips_window_ref( reg->im, 
				clipped.top, clipped.height )) )
				return( -1 );

			reg->type = VIPS_REGION_WINDOW;
		}

		/* Note the area the window actually represents.
		 */
		reg->valid.left = 0;
		reg->valid.top = reg->window->top;
		reg->valid.width = reg->im->Xsize;
		reg->valid.height = reg->window->height;
		reg->bpl = VIPS_IMAGE_SIZEOF_LINE( reg->im );
		reg->data = reg->window->data;
	}
	else {
		vips_error( "VipsRegion", 
			"%s", _( "bad image type" ) );
		return( -1 );
	}

	return( 0 );
}

/**
 * vips_region_region:
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
 * If the region we attach to is modified, we can be left with dangling 
 * pointers! If the region we attach to is on another image, the two images 
 * must have 
 * the same sizeof( pel ).
 *
 * Returns: 0 on success, or -1 for error.
 */
int
vips_region_region( VipsRegion *reg, 
	VipsRegion *dest, VipsRect *r, int x, int y )
{
	VipsRect image;
	VipsRect wanted;
	VipsRect clipped;
	VipsRect clipped2;
	VipsRect final;

	/* Sanity check.
	 */
	if( !dest->data || 
		VIPS_IMAGE_SIZEOF_PEL( dest->im ) != 
			VIPS_IMAGE_SIZEOF_PEL( reg->im ) ) {
		vips_error( "VipsRegion", 
			"%s", _( "inappropriate region type" ) );
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
	vips_region_reset( reg );
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
 * vips_region_position:
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
vips_region_fill( VipsRegion *reg, VipsRect *r, VipsRegionFillFn fn, void *a )
{
	g_assert( reg->im->dtype == VIPS_IMAGE_PARTIAL );
	g_assert( reg->im->generate_fn );

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

/**
 * vips_region_paint:
 * @reg: region to operate upon
 * @r: area to paint
 * @value: value to paint
 *
 * Paints @value into @reg covering rectangle @r. @value is passed to
 * memset(), so it usually needs to be 0 or 255. @r is clipped against
 * @reg->valid.
 *
 * See also: vips_region_black().
 */
void
vips_region_paint( VipsRegion *reg, VipsRect *r, int value )
{
	VipsRect ovl;

	vips_rect_intersectrect( r, &reg->valid, &ovl );
	if( !vips_rect_isempty( &ovl ) ) {
		PEL *q = (PEL *) VIPS_REGION_ADDR( reg, ovl.left, ovl.top );
		int wd = ovl.width * VIPS_IMAGE_SIZEOF_PEL( reg->im );
		int ls = VIPS_REGION_LSKIP( reg );
		int y;

		for( y = 0; y < ovl.height; y++ ) {
			memset( (char *) q, value, wd );
			q += ls;
		}
	}
}

/**
 * vips_region_paint_pel:
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
vips_region_paint_pel( VipsRegion *reg, VipsRect *r, PEL *ink )
{
	VipsRect ovl;

	vips_rect_intersectrect( r, &reg->valid, &ovl );
	if( !vips_rect_isempty( &ovl ) ) {
		int ps = VIPS_IMAGE_SIZEOF_PEL( reg->im );
		int ws = ovl.width * ps;
		int ls = VIPS_REGION_LSKIP( reg );

		PEL *to, *q;
		int x, y, z;

		/* We plot the first line pointwise, then memcpy() it for the
		 * subsequent lines.
		 */
		to = (PEL *) VIPS_REGION_ADDR( reg, ovl.left, ovl.top );

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
 * vips_region_black:
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
 * @dest: destination region 
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
vips_region_copy( VipsRegion *reg, VipsRegion *dest, VipsRect *r, int x, int y )
{
	int z;
	int len = VIPS_IMAGE_SIZEOF_PEL( reg->im ) * r->width;
	PEL *p = VIPS_REGION_ADDR( reg, r->left, r->top );
	PEL *q = VIPS_REGION_ADDR( dest, x, y );
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

	/* PEL size must be the same.
	 */
	g_assert( VIPS_IMAGE_SIZEOF_PEL( reg->im ) == 
		VIPS_IMAGE_SIZEOF_PEL( dest->im ) );
#endif /*DEBUG*/

	for( z = 0; z < r->height; z++ ) {
		memcpy( q, p, len );

		p += plsk;
		q += qlsk;
	}
}

/* Generate into a region. 
 */
static int
vips_region_generate( VipsRegion *reg )
{
	VipsImage *im = reg->im;

        /* Start new sequence, if necessary.
         */
        if( vips__region_start( reg ) )
		return( -1 );

	/* Ask for evaluation.
	 */
	if( im->generate_fn( reg, reg->seq, im->client1, im->client2 ) )
		return( -1 );

	return( 0 );
}

/** 
 * vips_region_prepare:
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
 * Use vips_region_prepare_thread() to calculate an area of pixels with many
 * threads. Use vips_sink_screen() to calculate an area of pixels in the 
 * background.
 *
 * See also: vips_region_prepare_thread(), vips_sink_screen(), 
 * vips_region_prepare_to().
 *
 * Returns: 0 on success, or -1 on error.
 */
int
vips_region_prepare( VipsRegion *reg, VipsRect *r )
{	
	VipsImage *im = reg->im;

	VipsRect save = *r;

	vips__region_check_ownership( reg );

	if( vips_image_get_kill( im ) )
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
			VIPS_ENUM_STRING( VIPS_TYPE_DEMAND_STYLE, im->dtype ) );
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
	VipsRegion *dest, VipsRect *r, int x, int y )
{
	IMAGE *im = reg->im;
	PEL *p;

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
 * vips_region_prepare_to:
 * @reg: region to prepare
 * @dest: region to write to
 * @r: #VipsRect of pixels you need to be able to address
 * @x: postion of @r in @dest
 * @y: postion of @r in @dest
 *
 * Like vips_region_prepare(): fill @reg with data, ready to be read from by 
 * our caller. Unlike vips_region_prepare(), rather than allocating memory 
 * local to @reg for the result, we guarantee that we will fill the pixels 
 * in @dest at offset @x, @y. In other words, we generate an extra copy 
 * operation if necessary. 
 *
 * Also unlike vips_region_prepare(), @dest is not set up for writing for 
 * you with
 * vips_region_buffer(). You can
 * point @dest at anything, and pixels really will be written there. 
 * This makes vips_prepare_to() useful for making the ends of pipelines, since
 * it (effectively) makes a break in the pipe.
 *
 * See also: vips_region_prepare(), vips_sink_disc().
 *
 * Returns: 0 on success, or -1 on error
 */
int
vips_region_prepare_to( VipsRegion *reg, 
	VipsRegion *dest, VipsRect *r, int x, int y )
{
	VipsImage *im = reg->im;
	VipsRect image;
	VipsRect wanted;
	VipsRect clipped;
	VipsRect clipped2;
	VipsRect final;

	if( vips_image_get_kill( im ) )
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
			VIPS_ENUM_NICK( VIPS_TYPE_DEMAND_STYLE, im->dtype ) );
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

int
vips_region_prepare_many( VipsRegion **reg, VipsRect *r )
{
	for( ; *reg; ++reg )
		if( vips_region_prepare( *reg, r ) )
			return( -1 );

	return( 0 );
}
