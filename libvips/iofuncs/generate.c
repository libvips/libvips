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
 * 7/10/09
 * 	- gtkdoc comments
 * 16/4/10
 * 	- remove threadgroup stuff
 * 24/3/11
 * 	- move demand_hint stuff in here
 * 	- move to vips_ namespace
 * 7/7/12
 * 	- lock around link make/break so we can process an image from many
 * 	  threads
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
#define VIPS_DEBUG
#define DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <glib/gi18n-lib.h>

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
#ifdef HAVE_IO_H
#include <io.h>
#endif /*HAVE_IO_H*/

#include <vips/vips.h>
#include <vips/internal.h>
#include <vips/thread.h>
#include <vips/debug.h>

/**
 * SECTION: generate
 * @short_description: calculate pixels and pixel buffers
 * @stability: Stable
 * @see_also: <link linkend="VipsImage">VipsImage</link>, 
 * <link linkend="VipsRegion">VipsRegion</link>
 * @include: vips/vips.h
 *
 * These functions let you attach generate functions to images  
 * and ask for regions of images to be calculated.
 */

/* Max number of images we can handle.
 */
#define MAX_IMAGES (1000)

/* Make an upstream/downstream link. upstream is one of downstream's inputs.
 */
static void 
vips__link_make( VipsImage *image_up, VipsImage *image_down )
{
	g_assert( image_up );
	g_assert( image_down );

	image_up->downstream = 
		g_slist_prepend( image_up->downstream, image_down );
	image_down->upstream = 
		g_slist_prepend( image_down->upstream, image_up );

	/* Propogate the progress indicator.
	 */
	if( image_up->progress_signal && 
		!image_down->progress_signal ) 
		image_down->progress_signal = image_up->progress_signal;
}

static void *
vips__link_break( VipsImage *image_up, VipsImage *image_down, void *b )
{
	g_assert( image_up );
	g_assert( image_down );

	g_assert( g_slist_find( image_up->downstream, image_down ) );
	g_assert( g_slist_find( image_down->upstream, image_up ) );

	image_up->downstream = 
		g_slist_remove( image_up->downstream, image_down );
	image_down->upstream = 
		g_slist_remove( image_down->upstream, image_up );

	/* Unlink the progress chain.
	 */
	if( image_down->progress_signal && 
		image_down->progress_signal == image_up->progress_signal ) 
		image_down->progress_signal = NULL;

	return( NULL );
}

static void *
vips__link_break_rev( VipsImage *image_down, VipsImage *image_up, void *b )
{
	return( vips__link_break( image_up, image_down, b ) );
}

/* A VipsImage is going ... break all links.
 */
void
vips__link_break_all( VipsImage *image )
{
	g_mutex_lock( vips__global_lock );

	vips_slist_map2( image->upstream, 
		(VipsSListMap2Fn) vips__link_break, image, NULL );
	vips_slist_map2( image->downstream, 
		(VipsSListMap2Fn) vips__link_break_rev, image, NULL );

	g_assert( !image->upstream );
	g_assert( !image->downstream );

	g_mutex_unlock( vips__global_lock );
}

typedef struct _LinkMap {
	gboolean upstream;
	int serial;
	VipsSListMap2Fn fn;
	void *a;
	void *b;
} LinkMap;

static void *
vips__link_mapp( VipsImage *image, LinkMap *map, void *b ) 
{
	void *res;

	/* Loop?
	 */
	if( image->serial == map->serial )
		return( NULL );
	image->serial = map->serial;

	if( (res = map->fn( image, map->a, map->b )) )
		return( res );

	return( vips_slist_map2( map->upstream ? 
		image->upstream : image->downstream,
		(VipsSListMap2Fn) vips__link_mapp, map, NULL ) );
}

static void *
vips__link_map_cb( VipsImage *image, GSList **images, void *b )
{
	*images = g_slist_prepend( *images, image );

	return( NULL );
}

/* Apply a function to an image and all upstream or downstream images, 
 * direct and indirect. 
 */
void *
vips__link_map( VipsImage *image, gboolean upstream, 
	VipsSListMap2Fn fn, void *a, void *b )
{
	static int serial = 0;

	LinkMap map;
	GSList *images;
	GSList *p;
	void *result;

	images = NULL;

	/* The function might do anything, including removing images
	 * or invalidating other images, so we can't trigger them from within 
	 * the image loop. Instead we collect a list of images, ref them,
	 * run the functions, and unref.
	 */

	map.upstream = upstream;
	map.fn = (VipsSListMap2Fn) vips__link_map_cb;
	map.a = (void *) &images;
	map.b = NULL;

	/* We will be walking the tree of images and updating the ->serial
	 * member. There will be intense confusion if two threads try to do
	 * this at the same time.
	 */
	g_mutex_lock( vips__global_lock );

	serial += 1;
	map.serial = serial;

	vips__link_mapp( image, &map, NULL ); 

	for( p = images; p; p = p->next ) 
		g_object_ref( p->data );

	g_mutex_unlock( vips__global_lock );

	result = vips_slist_map2( images, fn, a, b );

	for( p = images; p; p = p->next ) 
		g_object_unref( p->data );
	g_slist_free( images );

	return( result );
}

/* We have to have this as a separate entry point so we can support the old
 * vips7 API.
 */
void 
vips__demand_hint_array( VipsImage *image, 
	VipsDemandStyle hint, VipsImage **in )
{
	int i, len, nany;
	VipsDemandStyle set_hint;

	/* How many input images are there? And how many are ANY?
	 */
	for( i = 0, len = 0, nany = 0; in[i]; i++, len++ )
		if( in[i]->dhint == VIPS_DEMAND_STYLE_ANY )
			nany++;

	/* Find the most restrictive of all the hints available to us.
	 *
	 * We have tried to be smarter about this in the past -- for example,
	 * detecting all ANY inputs and ignoring the hint in this case, but
	 * there are inevitably odd cases which cause problems. For example,
	 * new_from_memory, resize, affine, write_to_memory would run with
	 * FATSTRIP.
	 */
	set_hint = hint;
	for( i = 0; i < len; i++ )
		set_hint = (VipsDemandStyle) VIPS_MIN( 
			(int) set_hint, (int) in[i]->dhint );

	image->dhint = set_hint;

#ifdef DEBUG
        printf( "vips_image_pipeline_array: set dhint for \"%s\" to %s\n",
		image->filename, 
		vips_enum_nick( VIPS_TYPE_DEMAND_STYLE, image->dhint ) );
	printf( "\toperation requested %s\n", 
		vips_enum_nick( VIPS_TYPE_DEMAND_STYLE, hint ) );
	printf( "\tinputs were:\n" );
	printf( "\t" );
	for( i = 0; in[i]; i++ )
		printf( "%s ", vips_enum_nick( VIPS_TYPE_DEMAND_STYLE, 
			in[i]->dhint ) );
	printf( "\n" );
#endif /*DEBUG*/

	/* im depends on all these ims.
	 */
	g_mutex_lock( vips__global_lock );
	for( i = 0; i < len; i++ )
		vips__link_make( in[i], image );
	g_mutex_unlock( vips__global_lock );

	/* Set a flag on the image to say we remembered to call this thing.
	 * vips_image_generate() and friends check this.
	 */
	image->hint_set = TRUE;
}

/**
 * vips_image_pipeline_array: 
 * @image: (out): output image
 * @hint: demand hint for @image
 * @in: (array zero-terminated=1): %NULL-terminated array of input images 
 *
 * Add an image to a pipeline. @image depends on all of the images in @in,
 * @image prefers to supply pixels according to @hint.
 *
 * Operations can set demand hints, that is, hints to the VIPS IO system about
 * the type of region geometry they work best with. For example,
 * operations which transform coordinates will usually work best with
 * %VIPS_DEMAND_STYLE_SMALLTILE, operations which work on local windows of 
 * pixels will like %VIPS_DEMAND_STYLE_FATSTRIP.
 *
 * Header fields in @image are set from the fields in @in, with lower-numbered
 * images in @in taking priority. 
 * For example, if @in[0] and @in[1] both have an item
 * called "icc-profile", it's the profile attached to @in[0] that will end up
 * on @image.
 * Image history is completely copied from all @in. @image will have the history
 * of all the input images.
 * The array of input images can be empty, meaning @image is at the start of a
 * pipeline.
 *
 * VIPS uses the list of input images to build the tree of operations it needs
 * for the cache invalidation system. 
 *
 * See also: vips_image_pipelinev(), vips_image_generate().
 *
 * Returns: 0 on success, -1 on error.
 */
int 
vips_image_pipeline_array( VipsImage *image, 
	VipsDemandStyle hint, VipsImage **in )
{
	/* This function can be called more than once per output image. For
	 * example, jpeg header load will call this once on ->out to set the
	 * default hint, then later call it again to connect the output image
	 * up to the real image.
	 *
	 * It's only ever called first time with in[0] == NULL and second time
	 * with a real value for @in.
	 */
	vips__demand_hint_array( image, hint, in );

	if( in[0] && 
		vips__image_copy_fields_array( image, in ) )
		return( -1 ); 

	if( vips__reorder_set_input( image, in ) )
		return( -1 ); 

	return( 0 );
}

/**
 * vips_image_pipelinev:
 * @image: output image of pipeline
 * @hint: hint for this image
 * @...: %NULL-terminated list of input images 
 *
 * Build an array and call vips_image_pipeline_array().
 *
 * See also: vips_image_generate().
 */
int 
vips_image_pipelinev( VipsImage *image, VipsDemandStyle hint, ... )
{
	va_list ap;
	int i;
	VipsImage *ar[MAX_IMAGES];

	va_start( ap, hint );
	for( i = 0; i < MAX_IMAGES && 
		(ar[i] = va_arg( ap, VipsImage * )); i++ )
		;
	va_end( ap );
	if( i == MAX_IMAGES ) {
		g_warning( "%s", _( "too many images" ) );

		/* Make sure we have a sentinel there.
		 */
		ar[i - 1] = NULL;
	}

	return( vips_image_pipeline_array( image, hint, ar ) );
}

/**
 * vips_start_one:
 * @out: image to generate
 * @a: user data
 * @b: user data
 *
 * Start function for one image in. Input image is @a.
 *
 * See also: vips_image_generate().
 */
void *
vips_start_one( VipsImage *out, void *a, void *b )
{
	VipsImage *in = (VipsImage *) a;

	return( vips_region_new( in ) );
}

/**
 * vips_stop_one:
 * @seq: sequence value
 * @a: user data
 * @b: user data
 *
 * Stop function for one image in. Input image is @a.
 *
 * See also: vips_image_generate().
 */
int
vips_stop_one( void *seq, void *a, void *b )
{
	VipsRegion *reg = (VipsRegion *) seq;

	g_object_unref( reg );

	return( 0 );
}

/**
 * vips_stop_many:
 * @seq: sequence value
 * @a: user data
 * @b: user data
 *
 * Stop function for many images in. @a is a pointer to 
 * a %NULL-terminated array of input images.
 *
 * See also: vips_image_generate().
 */
int
vips_stop_many( void *seq, void *a, void *b )
{
	VipsRegion **ar = (VipsRegion **) seq;

        if( ar ) {
		int i;

		for( i = 0; ar[i]; i++ )
			g_object_unref( ar[i] );
		g_free( (char *) ar );
	}

	return( 0 );
}

/**
 * vips_start_many:
 * @out: image to generate
 * @a: user data
 * @b: user data
 *
 * Start function for many images in. @a is a pointer to 
 * a %NULL-terminated array of input images.
 *
 * See also: vips_image_generate(), vips_allocate_input_array()
 */
void *
vips_start_many( VipsImage *out, void *a, void *b )
{
	VipsImage **in = (VipsImage **) a;

	int i, n;
	VipsRegion **ar;

	/* How many images?
	 */
	for( n = 0; in[n]; n++ )
		;

	/* Alocate space for region array.
	 */
	if( !(ar = VIPS_ARRAY( NULL, n + 1, VipsRegion * )) )
		return( NULL );

	/* Create a set of regions.
	 */
	for( i = 0; i < n; i++ )
		if( !(ar[i] = vips_region_new( in[i] )) ) {
			vips_stop_many( ar, NULL, NULL );
			return( NULL );
		}
	ar[n] = NULL;

	return( ar );
}

/**
 * vips_allocate_input_array:
 * @out: free array when this image closes
 * @...: %NULL-terminated list of input images
 *
 * Convenience function --- make a %NULL-terminated array of input images.
 * Use with vips_start_many().
 *
 * See also: vips_image_generate(), vips_start_many().
 *
 * Returns: %NULL-terminated array of images. Do not free the result.
 */
VipsImage **
vips_allocate_input_array( VipsImage *out, ... )
{
	va_list ap;
	VipsImage **ar;
	int i, n;

	/* Count input images.
	 */
	va_start( ap, out );
	for( n = 0; va_arg( ap, VipsImage * ); n++ )
		;
	va_end( ap );

	/* Allocate array.
	 */
	if( !(ar = VIPS_ARRAY( out, n + 1, VipsImage * )) )
		return( NULL );

	/* Fill array.
	 */
	va_start( ap, out );
	for( i = 0; i < n; i++ ) 
		ar[i] = va_arg( ap, VipsImage * );
	va_end( ap );
	ar[n] = NULL;

	return( ar );
}

/**
 * VipsStartFn:
 * @out: image being calculated
 * @a: user data
 * @b: user data
 *
 * Start a new processing sequence for this generate function. This allocates
 * per-thread state, such as an input region.
 *
 * See also: vips_start_one(), vips_start_many().
 *
 * Returns: a new sequence value
 */

/**
 * VipsGenerateFn:
 * @out: #VipsRegion to fill
 * @seq: sequence value
 * @a: user data
 * @b: user data
 * @stop: set this to stop processing
 *
 * Fill @out->valid with pixels. @seq contains per-thread state, such as the
 * input regions. Set @stop to %TRUE to stop processing. 
 *
 * See also: vips_image_generate(), vips_stop_many().
 *
 * Returns: 0 on success, -1 on error.
 */

/**
 * VipsStopFn:
 * @seq: sequence value
 * @a: user data
 * @b: user data
 *
 * Stop a processing sequence. This frees
 * per-thread state, such as an input region.
 *
 * See also: vips_stop_one(), vips_stop_many().
 *
 * Returns: 0 on success, -1 on error.
 */

/* A write function for VIPS images. Just write() the pixel data.
 */
static int
write_vips( VipsRegion *region, VipsRect *area, void *a )
{
	size_t nwritten, count;
	void *buf;

	count = (size_t) region->bpl * area->height;
	buf = VIPS_REGION_ADDR( region, 0, area->top );

	do {
		nwritten = write( region->im->fd, buf, count ); 
		if( nwritten == (size_t) -1 ) 
			return( errno );

		buf = (void *) ((char *) buf + nwritten);
		count -= nwritten;
	} while( count > 0 );

	return( 0 );
}

/**
 * vips_image_generate:
 * @image: generate this image
 * @start_fn: start sequences with this function
 * @generate_fn: generate pixels with this function
 * @stop_fn: stop sequences with this function
 * @a: user data
 * @b: user data
 *
 * Generates an image. The action depends on the image type.
 *
 * For images created with vips_image_new(), vips_image_generate() just 
 * attaches the start/generate/stop callbacks and returns.
 *
 * For images created with vips_image_new_memory(), memory is allocated for 
 * the whole image and it is entirely generated using vips_sink_memory().
 *
 * For images created with vips_image_new_temp_file() and friends, memory for 
 * a few scanlines is allocated and
 * vips_sink_disc() used to generate the image in small chunks. As each
 * chunk is generated, it is written to disc.
 *
 * See also: vips_sink(), vips_image_new(), vips_region_prepare(). 
 *
 * Returns: 0 on success, or -1 on error.
 */
int
vips_image_generate( VipsImage *image,
	VipsStartFn start_fn, VipsGenerateFn generate_fn, VipsStopFn stop_fn,
        void *a, void *b )
{
        int res;

	VIPS_DEBUG_MSG( "vips_image_generate: %p\n", image ); 

	g_assert( generate_fn );
	g_assert( vips_object_sanity( VIPS_OBJECT( image ) ) );

	if( !image->hint_set ) {
		vips_error( "vips_image_generate", 
			"%s", _( "demand hint not set" ) );
		return( -1 );
	}

	/* We don't use this, but make sure it's set in case any old binaries
	 * are expecting it.
	 */
	image->Bbits = vips_format_sizeof( image->BandFmt ) << 3;
 
        /* Look at output type to decide our action.
         */
        switch( image->dtype ) {
        case VIPS_IMAGE_PARTIAL:
                /* Output to partial image. Just attach functions and return.
                 */
                if( image->generate_fn || 
			image->start_fn || 
			image->stop_fn ) {
                        vips_error( "VipsImage", 
				"%s", _( "generate() called twice" ) );
                        return( -1 );
                }

                image->start_fn = start_fn;
                image->generate_fn = generate_fn;
                image->stop_fn = stop_fn;
                image->client1 = a;
                image->client2 = b;
 
                VIPS_DEBUG_MSG( "vips_image_generate: "
			"attaching partial callbacks\n" );

		if( vips_image_written( image ) )
			return( -1 );
 
                break;
 
        case VIPS_IMAGE_SETBUF:
        case VIPS_IMAGE_SETBUF_FOREIGN:
        case VIPS_IMAGE_MMAPINRW:
        case VIPS_IMAGE_OPENOUT:
                /* Eval now .. sanity check.
                 */
                if( image->generate_fn || 
			image->start_fn || 
			image->stop_fn ) {
                        vips_error( "VipsImage", 
				"%s", _( "generate() called twice" ) );
                        return( -1 );
                }

                /* Attach callbacks.
                 */
                image->start_fn = start_fn;
                image->generate_fn = generate_fn;
                image->stop_fn = stop_fn;
                image->client1 = a;
                image->client2 = b;

                if( vips_image_write_prepare( image ) )
                        return( -1 );

                if( image->dtype == VIPS_IMAGE_OPENOUT ) 
			res = vips_sink_disc( image, write_vips, NULL );
                else 
                        res = vips_sink_memory( image );

                /* Error?
                 */
                if( res )
                        return( -1 );

		/* Must come before we rewind.
		 */
		if( vips_image_written( image ) )
			return( -1 );

		/* We've written to image ... rewind it ready for reading.
		 */
		if( vips_image_pio_input( image ) )
			return( -1 ); 

                break;
 
        default:
                /* Not a known output style.
                 */
		vips_error( "VipsImage", 
			_( "unable to output to a %s image" ),
			vips_enum_nick( VIPS_TYPE_IMAGE_TYPE, 
				image->dtype ) );
                return( -1 );
        }

        return( 0 );
}
