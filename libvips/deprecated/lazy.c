/* lazy open/save ... compat funcs for old im_open() behaviour
 *
 * 30/11/11
 * 	- cut from old image.c
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
#define VIPS_DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vips/vips.h>
#include <vips/debug.h>
#include <vips/internal.h>

static gboolean
vips_format_is_vips( VipsFormatClass *format )
{
	return( strcmp( VIPS_OBJECT_CLASS( format )->nickname, "vips" ) == 0 );
}

/* Lazy open.
 */

/* What we track during a delayed open.
 */
typedef struct {
	VipsImage *image;
	VipsFormatClass *format;/* Read in pixels with this */
	char *filename;		/* Get pixels from here */
	gboolean disc;		/* Read via disc requested */

	VipsImage *real;	/* The real decompressed image */
} Lazy;

static void
lazy_free_cb( VipsImage *image, Lazy *lazy )
{
	VIPS_DEBUG_MSG( "lazy_free: %p \"%s\"\n", lazy, lazy->filename );

	g_free( lazy->filename );
	VIPS_UNREF( lazy->real );
	g_free( lazy );
}

static Lazy *
lazy_new( VipsImage *image, 
	VipsFormatClass *format, const char *filename, gboolean disc )
{
	Lazy *lazy;

	lazy = g_new( Lazy, 1 );
	VIPS_DEBUG_MSG( "lazy_new: %p \"%s\"\n", lazy, filename );
	lazy->image = image;
	lazy->format = format;
	lazy->filename = g_strdup( filename );
	lazy->disc = disc;
	lazy->real = NULL;
	g_signal_connect( image, "close", G_CALLBACK( lazy_free_cb ), lazy );

	return( lazy );
}

static size_t
disc_threshold( void )
{
	static gboolean done = FALSE;
	static size_t threshold;

	if( !done ) {
		const char *env;

		done = TRUE;

		/* 100mb default.
		 */
		threshold = 100 * 1024 * 1024;

		if( (env = g_getenv( "IM_DISC_THRESHOLD" )) ) 
			threshold = vips__parse_size( env );

		if( vips__disc_threshold ) 
			threshold = vips__parse_size( vips__disc_threshold );

		VIPS_DEBUG_MSG( "disc_threshold: %zd bytes\n", threshold );
	}

	return( threshold );
}

/* Make the real underlying image: either a direct disc file, or a temp file
 * somewhere.
 */
static VipsImage *
lazy_real_image( Lazy *lazy ) 
{
	VipsImage *real;

	/* We open via disc if:
	 * - 'disc' is set
	 * - disc_threshold() has not been set to zero
	 * - the format does not support lazy read
	 * - the uncompressed image will be larger than disc_threshold()
	 */
	real = NULL;
	if( lazy->disc && 
		disc_threshold() && 
	        !(vips_format_get_flags( lazy->format, lazy->filename ) & 
			VIPS_FORMAT_PARTIAL) &&
		VIPS_IMAGE_SIZEOF_IMAGE( lazy->image ) > disc_threshold() ) 
			if( !(real = vips_image_new_disc_temp( "%s.v" )) )
				return( NULL );

	/* Otherwise, fall back to a "p".
	 */
	if( !real && 
		!(real = vips_image_new()) )
		return( NULL );

	return( real );
}

/* Our start function ... do the lazy open, if necessary, and return a region
 * on the new image.
 */
static void *
open_lazy_start( VipsImage *out, void *a, void *dummy )
{
	Lazy *lazy = (Lazy *) a;

	if( !lazy->real ) {
		if( !(lazy->real = lazy_real_image( lazy )) || 
			lazy->format->load( lazy->filename, lazy->real ) ||
			vips_image_pio_input( lazy->real ) ) {
			VIPS_UNREF( lazy->real );
			return( NULL );
		}
	}

	return( vips_region_new( lazy->real ) );
}

/* Just copy.
 */
static int
open_lazy_generate( VipsRegion *or, 
	void *seq, void *a, void *b, gboolean *stop )
{
	VipsRegion *ir = (VipsRegion *) seq;

        VipsRect *r = &or->valid;

        /* Ask for input we need.
         */
        if( vips_region_prepare( ir, r ) )
                return( -1 );

        /* Attach output region to that.
         */
        if( vips_region_region( or, ir, r, r->left, r->top ) )
                return( -1 );

        return( 0 );
}

/* Lazy open ... init the header with the first OpenLazyFn, delay actually
 * decoding pixels with the second OpenLazyFn until the first generate().
 */
static int
vips_image_open_lazy( VipsImage *image, 
	VipsFormatClass *format, const char *filename, gboolean disc )
{
	Lazy *lazy;

	lazy = lazy_new( image, format, filename, disc );

	/* Is there a ->header() function? We need to do a lazy load.
	 */
	if( format->header ) {
		/* Read header fields to init the return image. 
		 */
		if( format->header( filename, image ) )
			return( -1 );

		/* Then 'start' creates the real image and 'gen' paints 'image' 
		 * with pixels from the real image on demand.
		 */
		vips_demand_hint( image, image->dhint, NULL );
		if( vips_image_generate( image, 
			open_lazy_start, open_lazy_generate, vips_stop_one, 
			lazy, NULL ) )
			return( -1 );
	}
	else if( format->load ) {
		if( format->load( filename, image ) )
			return( -1 );
	}
	else
		g_assert( 0 );

	return( 0 );
}

/* Lazy save.
 */

/* If we write to (eg.) TIFF, actually do the write
 * to a "p" and on "written" do im_vips2tiff() or whatever. Track save
 * parameters here.
 */
typedef struct {
	int (*save_fn)();	/* Save function */
	char *filename;		/* Save args */
} SaveBlock;

/* From "written" callback: invoke a delayed save.
 */
static void
vips_image_save_cb( VipsImage *image, int *result, SaveBlock *sb )
{
	if( sb->save_fn( image, sb->filename ) )
		*result = -1;

	g_free( sb->filename );
	g_free( sb );
}

static void
vips_attach_save( VipsImage *image, int (*save_fn)(), const char *filename )
{
	SaveBlock *sb;

	sb = g_new( SaveBlock, 1 );
	sb->save_fn = save_fn;
	sb->filename = g_strdup( filename );
	g_signal_connect( image, "written", 
		G_CALLBACK( vips_image_save_cb ), sb );
}

IMAGE *
vips__deprecated_open_read( const char *filename )
{
	VipsFormatClass *format;

	if( !(format = vips_format_for_file( filename )) )
		return( NULL );

	if( vips_format_is_vips( format ) ) {
		/* For vips format, we can just the main vips path.
		 */
		return( vips_image_new_mode( filename, "rd" ) );
	}
	else {
		/* For non-vips formats we must go via the old VipsFormat
		 * system to make sure we support the "filename:options"
		 * syntax.
		 */
		IMAGE *image;

		image = vips_image_new();
		if( vips_image_open_lazy( image, format, filename, TRUE ) ) {
			g_object_unref( image );
			return( NULL );
		}

		/* Yuk. Can't g_object_set() filename since it's after
		 * construct. Just zap the new filename in.
		 */
		VIPS_FREE( image->filename );
		image->filename = g_strdup( filename );

		return( image );
	}
}

IMAGE *
vips__deprecated_open_write( const char *filename )
{
	VipsFormatClass *format;

	if( !(format = vips_format_for_name( filename )) ) 
		return( NULL );

	if( vips_format_is_vips( format ) ) 
		/* For vips format, we can just the main vips path.
		 */
		return( vips_image_new_mode( filename, "w" ) );
	else {
		/* For non-vips formats we must go via the old VipsFormat
		 * system to make sure we support the "filename:options"
		 * syntax.
		 */
		IMAGE *image;

		if( !(image = vips_image_new()) )
			return( NULL );
		vips_attach_save( image, 
			format->save, filename );
		return( image );
	}
}
