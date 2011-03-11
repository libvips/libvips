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
#include <vips/debug.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/**
 * SECTION: generate
 * @short_description: calculate pixels and pixel buffers
 * @stability: Stable
 * @see_also: <link linkend="libvips-image">image</link>, 
 * <link linkend="libvips-region">region</link>
 * @include: vips/vips.h
 *
 * These functions let you generate regions of pixels in an image
 * processing operation, and ask for regions of image to be calculated.
 */

/**
 * im_start_one:
 * @out: image to generate
 * @a: user data
 * @b: user data
 *
 * Start function for one image in. Input image is first user data.
 *
 * See also: im_generate().
 */
void *
im_start_one( IMAGE *out, void *a, void *b )
{
	IMAGE *in = (IMAGE *) a;

	return( vips_region_new( in ) );
}

/**
 * im_stop_one:
 * @seq: sequence value
 * @a: user data
 * @b: user data
 *
 * Stop function for one image in. Input image is @a.
 *
 * See also: im_generate().
 */
int
im_stop_one( void *seq, void *a, void *b )
{
	VipsRegion *reg = (VipsRegion *) seq;

	g_object_unref( reg );

	return( 0 );
}

/**
 * im_stop_many:
 * @seq: sequence value
 * @a: user data
 * @b: user data
 *
 * Stop function for many images in. First user data is a pointer to 
 * a %NULL-terminated array of input images.
 *
 * See also: im_generate().
 */
int
im_stop_many( void *seq, void *a, void *b )
{
	VipsRegion **ar = (VipsRegion **) seq;

        if( ar ) {
		int i;

		for( i = 0; ar[i]; i++ )
			g_object_unref( ar[i] );
		im_free( (char *) ar );
	}

	return( 0 );
}

/**
 * im_start_many:
 * @out: image to generate
 * @a: user data
 * @b: user data
 *
 * Start function for many images in. @a is a pointer to 
 * a %NULL-terminated array of input images.
 *
 * See also: im_generate(), im_allocate_input_array()
 */
void *
im_start_many( IMAGE *out, void *a, void *b )
{
	IMAGE **in = (IMAGE **) a;

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
			im_stop_many( ar, NULL, NULL );
			return( NULL );
		}
	ar[n] = NULL;

	return( ar );
}

/**
 * im_allocate_input_array:
 * @out: free array when this image closes
 * @Varargs: %NULL-terminated list of input images
 *
 * Convenience function --- make a %NULL-terminated array of input images.
 * Use with im_start_many().
 *
 * See also: im_generate(), im_start_many().
 *
 * Returns: %NULL-terminated array of images. Do not free the result.
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
	if( !(ar = VIPS_ARRAY( out, n + 1, IMAGE * )) )
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

/**
 * im_start_fn:
 * @out: image being calculated
 * @a: user data
 * @b: user data
 *
 * Start a new processing sequence for this generate function. This allocates
 * per-thread state, such as an input region.
 *
 * See also: im_start_one(), im_start_many().
 *
 * Returns: a new sequence value
 */

/**
 * im_generate_fn:
 * @out: #VipsRegion to fill
 * @seq: sequence value
 * @a: user data
 * @b: user data
 *
 * Fill @out->valid with pixels. @seq contains per-thread state, such as the
 * input regions.
 *
 * See also: im_generate(), im_stop_many().
 *
 * Returns: 0 on success, -1 on error.
 */

/**
 * im_stop_fn:
 * @seq: sequence value
 * @a: user data
 * @b: user data
 *
 * Stop a processing sequence. This frees
 * per-thread state, such as an input region.
 *
 * See also: im_stop_one(), im_stop_many().
 *
 * Returns: 0 on success, -1 on error.
 */

/* A write function for VIPS images. Just write() the pixel data.
 */
static int
write_vips( VipsRegion *region, Rect *area, void *a, void *b )
{
	size_t nwritten, count;
	void *buf;

	count = region->bpl * area->height;
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
 * im_generate:
 * @im: generate this image
 * @start: start sequences with this function
 * @generate: generate pixels with this function
 * @stop: stop sequences with this function
 * @a: user data
 * @b: user data
 *
 * Generates an image. The action depends on the image type.
 *
 * For images opened with "p", im_generate() just attaches the
 * start/generate/stop callbacks and returns.
 *
 * For "t" images, memory is allocated for the whole image and it is entirely
 * generated using vips_sink().
 *
 * For "w" images, memory for a few scanlines is allocated and
 * vips_sink_disc() used to generate the image in small chunks. As each
 * chunk is generated, it is written to disc.
 *
 * See also: vips_sink(), im_open(), im_prepare(), im_wrapone().
 *
 * Returns: 0 on success, or -1 on error.
 */
int
im_generate( IMAGE *im,
	im_start_fn start, im_generate_fn generate, im_stop_fn stop,
        void *a, void *b )
{
        int res;

	g_assert( vips_object_sanity( VIPS_OBJECT( im ) ) );

	if( !im->hint_set ) {
		vips_error( "im_generate", 
			"%s", _( "im_demand_hint() not set" ) );
		return( -1 );
	}

	if( im->Xsize <= 0 || im->Ysize <= 0 || im->Bands <= 0 ) {
		vips_error( "im_generate", 
			"%s", _( "bad dimensions" ) );
		return( -1 );
	}

	/* We don't use this, but make sure it's set in case any old binaries
	 * are expecting it.
	 */
	im->Bbits = vips_format_sizeof( im->BandFmt ) << 3;
 
        /* Look at output type to decide our action.
         */
        switch( im->dtype ) {
        case VIPS_IMAGE_PARTIAL:
                /* Output to partial image. Just attach functions and return.
                 */
                if( im->generate || im->start || im->stop ) {
                        vips_error( "im_generate", 
				"%s", _( "func already attached" ) );
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
 
        case VIPS_IMAGE_SETBUF:
        case VIPS_IMAGE_SETBUF_FOREIGN:
        case VIPS_IMAGE_MMAPINRW:
        case VIPS_IMAGE_OPENOUT:
                /* Eval now .. sanity check.
                 */
                if( im->generate || im->start || im->stop ) {
                        vips_error( "im_generate", 
				"%s", _( "func already attached" ) );
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

                if( im->dtype == VIPS_IMAGE_OPENOUT ) 
			res = vips_sink_disc( im,
				(VipsRegionWrite) write_vips, NULL );
                else
                        res = vips_sink_memory( im );

                /* Error?
                 */
                if( res )
                        return( -1 );
 
                break;
 
        default:
                /* Not a known output style.
                 */
		vips_error( "im_generate", _( "unable to output to a %s image" ),
			im_dtype2char( im->dtype ) );
                return( -1 );
        }

	vips_image_written( im ); 

        return( 0 );
}

