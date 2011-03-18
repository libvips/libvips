/* vips image class
 * 
 * 4/2/11
 * 	- hacked up from various places
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif /*HAVE_UNISTD_H*/
#include <ctype.h>

#include <vips/vips.h>
#include <vips/internal.h>
#include <vips/debug.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/**
 * SECTION: image
 * @short_description: the VIPS image class
 * @stability: Stable
 * @see_also: <link linkend="libvips-region">region</link>
 * @include: vips/vips.h
 *
 * The image class and associated types and macros.
 */

/**
 * VIPS_MAGIC_INTEL:
 *
 * The first four bytes of a VIPS file in Intel byte ordering.
 */

/**
 * VIPS_MAGIC_SPARC:
 *
 * The first four bytes of a VIPS file in SPARC byte ordering.
 */

/** 
 * VipsDemandStyle:
 * @VIPS_DEMAND_STYLE_SMALLTILE: demand in small (typically 64x64 pixel) tiles
 * @VIPS_DEMAND_STYLE_FATSTRIP: demand in fat (typically 10 pixel high) strips
 * @VIPS_DEMAND_STYLE_THINSTRIP: demand in thin (typically 1 pixel high) strips
 * @VIPS_DEMAND_STYLE_ANY: demand geometry does not matter
 *
 * See im_demand_hint(). Operations can hint to the VIPS image IO system about
 * the kind of demand geometry they prefer. 
 *
 * These demand styles are given below in order of increasing
 * restrictiveness.  When demanding output from a pipeline, im_generate()
 * will use the most restrictive of the styles requested by the operations 
 * in the pipeline.
 *
 * VIPS_DEMAND_STYLE_THINSTRIP --- This operation would like to output strips 
 * the width of the image and a few pels high. This is option suitable for 
 * point-to-point operations, such as those in the arithmetic package.
 *
 * This option is only efficient for cases where each output pel depends 
 * upon the pel in the corresponding position in the input image.
 *
 * VIPS_DEMAND_STYLE_FATSTRIP --- This operation would like to output strips 
 * the width of the image and as high as possible. This option is suitable 
 * for area operations which do not violently transform coordinates, such 
 * as im_conv(). 
 *
 * VIPS_DEMAND_STYLE_SMALLTILE --- This is the most general demand format.
 * Output is demanded in small (around 100x100 pel) sections. This style works 
 * reasonably efficiently, even for bizzare operations like 45 degree rotate.
 *
 * VIPS_DEMAND_STYLE_ANY --- This image is not being demand-read from a disc 
 * file (even indirectly) so any demand style is OK. It's used for things like
 * im_black() where the pixels are calculated.
 *
 * See also: vips_demand_hint().
 */

/**
 * VipsInterpretation: 
 * @VIPS_TYPE_MULTIBAND: generic many-band image
 * @VIPS_TYPE_B_W: some kind of single-band image
 * @VIPS_TYPE_HISTOGRAM: a 1D image such as a histogram or lookup table
 * @VIPS_TYPE_FOURIER: image is in fourier space
 * @VIPS_TYPE_XYZ: the first three bands are colours in CIE XYZ colourspace
 * @VIPS_TYPE_LAB: pixels are in CIE Lab space
 * @VIPS_TYPE_CMYK: the first four bands are in CMYK space
 * @VIPS_TYPE_LABQ: implies #VIPS_CODING_LABQ
 * @VIPS_TYPE_RGB: generic RGB space
 * @VIPS_TYPE_UCS: a uniform colourspace based on CMC
 * @VIPS_TYPE_LCH: pixels are in CIE LCh space
 * @VIPS_TYPE_LABS: pixels are CIE LAB coded as three signed 16-bit values
 * @VIPS_TYPE_sRGB: pixels are sRGB
 * @VIPS_TYPE_YXY: pixels are CIE Yxy
 * @VIPS_TYPE_RGB16: generic 16-bit RGB
 * @VIPS_TYPE_GREY16: generic 16-bit mono
 *
 * How the values in an image should be interpreted. For example, a
 * three-band float image of type #VIPS_TYPE_LAB should have its pixels
 * interpreted as coordinates in CIE Lab space.
 *
 * These values are set by operations as hints to user-interfaces built on top 
 * of VIPS to help them show images to the user in a meaningful way. 
 * Operations do not use these values to decide their action.
 */

/**
 * VipsBandFormat: 
 * @VIPS_FORMAT_NOTSET: invalid setting
 * @VIPS_FORMAT_UCHAR: unsigned char format
 * @VIPS_FORMAT_CHAR: char format
 * @VIPS_FORMAT_USHORT: unsigned short format
 * @VIPS_FORMAT_SHORT: short format
 * @VIPS_FORMAT_UINT: unsigned int format
 * @VIPS_FORMAT_INT: int format
 * @VIPS_FORMAT_FLOAT: float format
 * @VIPS_FORMAT_COMPLEX: complex (two floats) format
 * @VIPS_FORMAT_DOUBLE: double float format
 * @VIPS_FORMAT_DPCOMPLEX: double complex (two double) format
 *
 * The format used for each band element. 
 *
 * Each corresponnds to a native C type for the current machine. For example,
 * #VIPS_FORMAT_USHORT is <type>unsigned short</type>.
 */

/**
 * VipsCoding: 
 * @VIPS_CODING_NONE: pixels are not coded
 * @VIPS_CODING_LABQ: pixels encode 3 float CIELAB values as 4 uchar
 * @VIPS_CODING_RAD: pixels encode 3 float RGB as 4 uchar (Radiance coding)
 *
 * How pixels are coded. 
 *
 * Normally, pixels are uncoded and can be manipulated as you would expect.
 * However some file formats code pixels for compression, and sometimes it's
 * useful to be able to manipulate images in the coded format.
 */

/** 
 * VipsProgress:
 * @run: Time we have been running 
 * @eta: Estimated seconds of computation left 
 * @tpels: Number of pels we expect to calculate
 * @npels: Number of pels calculated so far
 * @percent: Percent complete
 * @start: Start time 
 *
 * A structure available to eval callbacks giving information on evaluation
 * progress. See im_add_eval_callback().
 */

/**
 * VipsImage:
 *
 * An image. These can represent an image on disc, a memory buffer, an image
 * in the process of being written to disc or a partially evaluated image
 * in memory.
 */

/**
 * VIPS_IMAGE_SIZEOF_ELEMENT:
 * @I: a #VipsImage
 *
 * Returns: sizeof() a band element.
 */

/**
 * VIPS_IMAGE_SIZEOF_PEL:
 * @I: a #VipsImage
 *
 * Returns: sizeof() a pixel.
 */

/**
 * VIPS_IMAGE_SIZEOF_LINE:
 * @I: a #VipsImage
 *
 * Returns: sizeof() a scanline of pixels.
 */

/**
 * VIPS_IMAGE_N_ELEMENTS:
 * @I: a #VipsImage
 *
 * Returns: The number of band elements in a scanline.
 */

/**
 * VIPS_IMAGE_ADDR:
 * @I: a #VipsImage
 * @X: x coordinate
 * @Y: y coordinate
 *
 * This macro returns a pointer to a pixel in an image. It only works for
 * images which are fully available in memory, so memory buffers and small
 * mapped images only.
 * 
 * If VIPS_DEBUG is defined, you get a version that checks bounds for you.
 *
 * See also: VIPS_REGION_ADDR().
 *
 * Returns: The address of pixel (x,y) in the image.
 */

/** 
 * vips_image_open_local_array:
 * @IM: image to open local to
 * @OUT: array to fill with #VipsImage *
 * @N: array size
 * @NAME: filename to open
 * @MODE: mode to open with
 *
 * Just like vips_image_open(), but opens an array of images. Handy for creating a 
 * set of temporary images for a function.
 *
 * Example:
 *
 * |[
 * VipsImage *t[5];
 *
 * if( vips_image_open_local_array( out, t, 5, "some-temps", "p" ) ||
 *   vips_add( a, b, t[0] ) ||
 *   vips_invert( t[0], t[1] ) ||
 *   vips_add( t[1], t[0], t[2] ) ||
 *   vips_costra( t[2], out ) )
 *   return( -1 );
 * ]|
 *
 * See also: vips_image_open(), vips_image_open_local(), vips_local_array().
 *
 * Returns: 0 on sucess, or -1 on error
 */

/**
 * vips_image_open_local:
 * @IM: image to open local to
 * @NAME: filename to open
 * @MODE: mode to open with
 *
 * Just like vips_image_open(), but the #VipsImage will be closed for you 
 * automatically when @IM is closed.
 *
 * See also: vips_image_open(), vips_local().
 *
 * Returns: a new #VipsImage, or %NULL on error
 */

/* Properties.
 */
enum {
	PROP_WIDTH = 1,
	PROP_HEIGHT,
	PROP_BANDS,
	PROP_FORMAT,
	PROP_FILENAME,
	PROP_KILL,
	PROP_MODE,
	PROP_DEMAND,
	PROP_SIZEOF_HEADER,
	PROP_FOREIGN_BUFFER,
	PROP_LAST
}; 

/* Our signals. 
 */
enum {
	SIG_PREEVAL,		
	SIG_EVAL,		
	SIG_POSTEVAL,		
	SIG_WRITTEN,		
	SIG_INVALIDATE,		
	SIG_LAST
};

/* Progress feedback. Only really useful for testing, tbh.
 */
int im__progress = 0;

/* A string giving the image size (in bytes of uncompressed image) above which 
 * we decompress to disc on open.  Can be eg. "12m" for 12 megabytes.
 */
char *im__disc_threshold = NULL;

static guint vips_image_signals[SIG_LAST] = { 0 };

G_DEFINE_TYPE( VipsImage, vips_image, VIPS_TYPE_OBJECT );

static void
vips_image_finalize( GObject *gobject )
{
	VipsImage *image = VIPS_IMAGE( gobject );

	/* Should be no regions defined on the image, since they all hold a
	 * ref to their host image.
	 */
	g_assert( !image->regions );

	/* Therefore there should be no windows.
	 */
	g_assert( !image->windows );

	/* Junk generate functions. 
	 */
	image->start = NULL;
	image->generate = NULL;
	image->stop = NULL;
	image->client1 = NULL;
	image->client2 = NULL;

	/* No more upstream/downstream links.
	 */
	im__link_break_all( image );

	/* Any file mapping?
	 */
	if( image->baseaddr ) {
		/* MMAP file.
		 */
		VIPS_DEBUG_MSG( "vips_image_finalize: unmapping file\n" );

		im__munmap( image->baseaddr, image->length );
		image->baseaddr = NULL;
		image->length = 0;

		/* This must have been a pointer to the mmap region, rather
		 * than a setbuf.
		 */
		image->data = NULL;
	}

	if( image->time ) {
		VIPS_FREEF( g_timer_destroy, image->time->start );
		VIPS_FREE( image->time );
	}

	/* Is there a file descriptor?
	 */
	if( image->fd != -1 ) {
		VIPS_DEBUG_MSG( "vips_image_finalize: closing output file\n" );

		if( image->dtype == VIPS_IMAGE_OPENOUT )
			(void) im__writehist( image );
		if( close( image->fd ) == -1 ) 
			vips_error( "VipsImage", 
				_( "unable to close fd for %s" ), 
				image->filename );
		image->fd = -1;
	}

	/* Any image data?
	 */
	if( image->data ) {
		/* Buffer image. Only free stuff we know we allocated.
		 */
		if( image->dtype == VIPS_IMAGE_SETBUF ) {
			VIPS_DEBUG_MSG( "vips_image_finalize: "
				"freeing buffer\n" );
			im_free( image->data );
			image->dtype = VIPS_IMAGE_NONE;
		}

		image->data = NULL;
	}

	VIPS_FREE( image->filename );
	VIPS_FREE( image->mode );

	VIPS_FREEF( g_mutex_free, image->sslock );

	VIPS_FREE( image->Hist );
	VIPS_FREEF( im__gslist_gvalue_free, image->history_list );
	im__meta_destroy( image );

	G_OBJECT_CLASS( vips_image_parent_class )->finalize( gobject );
}

static void
vips_image_dispose( GObject *gobject )
{
#ifdef VIPS_DEBUG
	VIPS_DEBUG_MSG( "vips_image_dispose: " );
	vips_object_print( VIPS_OBJECT( gobject ) );
#endif /*VIPS_DEBUG*/

	vips_object_preclose( VIPS_OBJECT( gobject ) );

	G_OBJECT_CLASS( vips_image_parent_class )->dispose( gobject );
}

static void
vips_image_print( VipsObject *object, VipsBuf *buf )
{
	VipsImage *image = VIPS_IMAGE( object );

	vips_buf_appendf( buf, 
		ngettext( 
			"%dx%d %s, %d band, %s", 
			"%dx%d %s, %d bands, %s", 
			vips_image_get_bands( image ) ),
		vips_image_get_width( image ),
		vips_image_get_height( image ),
		VIPS_ENUM_NICK( VIPS_TYPE_BAND_FORMAT, 
			vips_image_get_format( image ) ),
		vips_image_get_bands( image ),
		VIPS_ENUM_NICK( VIPS_TYPE_INTERPRETATION, 
			vips_image_get_interpretation( image ) ) );

	VIPS_OBJECT_CLASS( vips_image_parent_class )->print( object, buf );
}

static void *
vips_image_sanity_upstream( VipsImage *im_up, VipsImage *im_down )
{
	if( !g_slist_find( im_up->downstream, im_down ) ||
		!g_slist_find( im_down->upstream, im_up ) )
		return( im_up );

	return( NULL );
}

static void *
vips_image_sanity_downstream( VipsImage *im_down, VipsImage *im_up )
{
	return( vips_image_sanity_upstream( im_up, im_down ) );
}

static void
vips_image_sanity( VipsObject *object, VipsBuf *buf )
{
	VipsImage *image = VIPS_IMAGE( object );

	if( !image->filename ) 
		vips_buf_appends( buf, "NULL filename\n" );

	/* All -1 means im has been inited but never used.
	 */
	if( image->Xsize != -1 ||
		image->Ysize != -1 ||
		image->Bands != -1 ||
		image->BandFmt != -1 ) {
		if( image->Xsize <= 0 || 
			image->Ysize <= 0 || 
			image->Bands <= 0 ) 
			vips_buf_appends( buf, "bad dimensions\n" );
		if( image->BandFmt < -1 || 
			image->BandFmt > VIPS_FORMAT_DPCOMPLEX ||
			(image->Coding != -1 &&
				image->Coding != VIPS_CODING_NONE && 
				image->Coding != VIPS_CODING_LABQ &&
				image->Coding != VIPS_CODING_RAD) ||
			image->Type > VIPS_INTERPRETATION_GREY16 ||
			image->dtype > VIPS_IMAGE_PARTIAL || 
			image->dhint > VIPS_DEMAND_STYLE_ANY ) 
			vips_buf_appends( buf, "bad enum\n" );
		if( image->Xres < 0 || image->Xres < 0 ) 
			vips_buf_appends( buf, "bad resolution\n" );
	}

	if( im_slist_map2( image->upstream, 
		(VSListMap2Fn) vips_image_sanity_upstream, image, NULL ) )
		vips_buf_appends( buf, "upstream broken\n" );
	if( im_slist_map2( image->downstream, 
		(VSListMap2Fn) vips_image_sanity_downstream, image, NULL ) )
		vips_buf_appends( buf, "downstream broken\n" );

	VIPS_OBJECT_CLASS( vips_image_parent_class )->sanity( object, buf );
}

static void
vips_image_rewind( VipsObject *object )
{
	VipsImage *image = VIPS_IMAGE( object );
	char *filename;
	char *mode;

	/* The old values for filename and mode become the new defaults.
	 */
	filename = g_strdup( vips_image_get_filename( image ) );
	mode = g_strdup( vips_image_get_mode( image ) );

	VIPS_OBJECT_CLASS( vips_image_parent_class )->rewind( object );

	g_assert( image->filename == NULL );
	g_assert( image->mode == NULL );

	image->filename = filename;
	image->mode = mode;
}

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
lazy_free_cb( Lazy *lazy )
{
	VIPS_FREE( lazy->filename );
	VIPS_UNREF( lazy->real );
}

static Lazy *
lazy_new( VipsImage *image, 
	VipsFormatClass *format, const char *filename, gboolean disc )
{
	Lazy *lazy;

	VIPS_DEBUG_MSG( "lazy_new: \"%s\"\n", filename );

	if( !(lazy = VIPS_NEW( image, Lazy )) )
		return( NULL );
	lazy->image = image;
	lazy->format = format;
	lazy->filename = NULL;
	lazy->disc = disc;
	lazy->real = NULL;
	g_signal_connect( image, "close", G_CALLBACK( lazy_free_cb ), NULL );

	if( !(lazy->filename = im_strdup( NULL, filename )) )
		return( NULL );

	return( lazy );
}

typedef struct {
	const char unit;
	int multiplier;
} Unit;

static size_t
parse_size( const char *size_string )
{
	static Unit units[] = {
		{ 'k', 1024 },
		{ 'm', 1024 * 1024 },
		{ 'g', 1024 * 1024 * 1024 }
	};

	size_t size;
	int n;
	int i, j;
	char *unit;

	/* An easy way to alloc a buffer large enough.
	 */
	unit = g_strdup( size_string );
	n = sscanf( size_string, "%d %s", &i, unit );
	if( n > 0 )
		size = i;
	if( n > 1 ) {
		for( j = 0; j < VIPS_NUMBER( units ); j++ )
			if( tolower( unit[0] ) == units[j].unit ) {
				size *= units[j].multiplier;
				break;
			}
	}
	g_free( unit );

	VIPS_DEBUG_MSG( "parse_size: parsed \"%s\" as %zd\n", 
		size_string, size );

	return( size );
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
			threshold = parse_size( env );

		if( im__disc_threshold ) 
			threshold = parse_size( im__disc_threshold );

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

	/* We open to disc if:
	 * - 'disc' is set
	 * - disc_threshold() has not been set to zero
	 * - the format does not support lazy read
	 * - the image will be more than a megabyte, uncompressed
	 */
	real = NULL;
	if( lazy->disc && 
		disc_threshold() && 
	        !(vips_format_get_flags( lazy->format, lazy->filename ) & 
			VIPS_FORMAT_PARTIAL) &&
		vips_image_size( lazy->image ) > disc_threshold() ) {
			if( !(real = vips_image_new_disc_temp( "%s.v" )) )
				return( NULL );

			VIPS_DEBUG_MSG( "lazy_real_image: "
				"opening to disc file \"%s\"\n",
				real->filename );
		}

	/* Otherwise, fall back to a "p".
	 */
	if( !real && 
		!(real = vips_image_new( "p" )) )
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
			im_pincheck( lazy->real ) ) {
			VIPS_UNREF( lazy->real );
			return( NULL );
		}
	}

	return( vips_region_new( lazy->real ) );
}

/* Just copy.
 */
static int
open_lazy_generate( VipsRegion *or, void *seq, void *a, void *b )
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

	if( !(lazy = lazy_new( image, format, filename, disc )) )
		return( -1 );

	/* Read header fields to init the return image. THINSTRIP since this is
	 * probably a disc file. We can't tell yet whether we will be opening
	 * to memory, sadly, so we can't suggest ANY.
	 */
	if( format->header( filename, image ) ||
		im_demand_hint( image, VIPS_DEMAND_STYLE_THINSTRIP, NULL ) )
		return( -1 );

	/* Then 'start' creates the real image and 'gen' paints 'out' with 
	 * pixels from the real image on demand.
	 */
	if( im_generate( image, 
		open_lazy_start, open_lazy_generate, im_stop_one, 
		lazy, NULL ) )
		return( -1 );

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
vips_image_save_cb( VipsImage *image, SaveBlock *sb )
{
	/* FIXME ... what can we do with this error return?
	 */
	if( sb->save_fn( image, sb->filename ) )
		;
}

static void
vips_attach_save( VipsImage *image, int (*save_fn)(), const char *filename )
{
	SaveBlock *sb;

	if( (sb = VIPS_NEW( image, SaveBlock )) ) {
		sb->save_fn = save_fn;
		sb->filename = im_strdup( image, filename );
		g_signal_connect( image, "written", 
			G_CALLBACK( vips_image_save_cb ), sb );
	}
}

/* Progress feedback. 
 */

static int
vips_image_preeval_cb( VipsImage *image, VipsProgress *progress, int *last )
{
	int tile_width; 
	int tile_height; 
	int nlines;

	*last = -1;

	vips_get_tile_size( image, 
		&tile_width, &tile_height, &nlines );
	printf( _( "%s %s: %d threads, %d x %d tiles, groups of %d scanlines" ),
		g_get_prgname(), image->filename,
		im_concurrency_get(),
		tile_width, tile_height, nlines );
	printf( "\n" );

	return( 0 );
}

static int
vips_image_eval_cb( VipsImage *image, VipsProgress *progress, int *last )
{
	if( progress->percent != *last ) {
		printf( _( "%s %s: %d%% complete" ), 
			g_get_prgname(), image->filename, 
			progress->percent );
		printf( "\r" ); 
		fflush( stdout );

		*last = progress->percent;
	}

	return( 0 );
}

static int
vips_image_posteval_cb( VipsImage *image, VipsProgress *progress )
{
	/* Spaces at end help to erase the %complete message we overwrite.
	 */
	printf( _( "%s %s: done in %ds          \n" ), 
		g_get_prgname(), image->filename, progress->run );

	return( 0 );
}

/* Attach progress feedback, if required.
 */
static void
vips_image_add_progress( VipsImage *image )
{
	if( im__progress || 
		g_getenv( "IM_PROGRESS" ) ) {

		/* Keep the %complete we displayed last time here.
		 */
		int *last = VIPS_NEW( image, int );

		g_signal_connect( image, "preeval", 
			G_CALLBACK( vips_image_preeval_cb ), last );
		g_signal_connect( image, "eval", 
			G_CALLBACK( vips_image_eval_cb ), last );
		g_signal_connect( image, "posteval", 
			G_CALLBACK( vips_image_posteval_cb ), NULL );
	}
}

static int
vips_image_build( VipsObject *object )
{
	VipsImage *image = VIPS_IMAGE( object );
	const char *filename = image->filename;
	const char *mode = image->mode;
	VipsFormatClass *format;

	VIPS_DEBUG_MSG( "vips_image_build: %p\n", image );

	if( VIPS_OBJECT_CLASS( vips_image_parent_class )->build( object ) )
		return( -1 );

	/* Parse the mode string.
	 */
	switch( mode[0] ) {
        case 'r':
		if( !(format = vips_format_for_file( filename )) )
			return( -1 );

		if( vips_format_is_vips( format ) ) {
			/* We may need to byteswap.
			 */
			VipsFormatFlags flags = 
				vips_format_get_flags( format, filename );
			gboolean native = (flags & VIPS_FORMAT_BIGENDIAN) == 
				im_amiMSBfirst();

			if( native ) {
				if( vips_image_open_input( image ) )
					return( -1 );

				if( mode[1] == 'w' ) 
					image->dtype = VIPS_IMAGE_MMAPINRW;
			}
			else {
				VipsImage *x;

				if( !(x = vips_image_new( "p" )) )
					return( -1 );
				vips_object_local( image, x );
				if( vips_image_open_input( x ) )
					return( -1 );
				image->dtype = VIPS_IMAGE_PARTIAL;
				if( im_copy_swap( x, image ) )
					return( -1 );
			}
		}
		else {
			/* Make this a partial, generate into it from the
			 * converter.
			 */
			image->dtype = VIPS_IMAGE_PARTIAL;

			if( vips_image_open_lazy( image, format, 
				filename, mode[1] == 'd' ) )
				return( -1 );
		}

        	break;

	case 'w':
		if( !(format = vips_format_for_name( filename )) ) 
			return( -1 );

		if( vips_format_is_vips( format ) ) 
			image->dtype = VIPS_IMAGE_OPENOUT;
		else {
			image->dtype = VIPS_IMAGE_PARTIAL;
			vips_attach_save( image, 
				format->save, filename );
		}
        	break;

        case 't':
		image->dtype = VIPS_IMAGE_SETBUF;
		image->dhint = VIPS_DEMAND_STYLE_ANY;
                break;

        case 'p':
		image->dtype = VIPS_IMAGE_PARTIAL;
                break;

	case 'a':
		/* Check parameters.
		 */
		if( image->sizeof_header < 0 ) {
			vips_error( "vips_image_open_raw", 
				"%s", _( "bad parameters" ) );
			return( -1 );
		}

		if( (image->fd = im__open_image_file( filename )) == -1 ) 
			return( -1 );
		image->dtype = VIPS_IMAGE_OPENIN;
		image->dhint = VIPS_DEMAND_STYLE_THINSTRIP;

		if( image->Bands == 1 )
			image->Type = VIPS_INTERPRETATION_B_W;
		else if( image->Bands == 3 )
			image->Type = VIPS_INTERPRETATION_RGB;
		else 
			image->Type = VIPS_INTERPRETATION_MULTIBAND;

		/* Read the real file length and check against what we think 
		 * the size should be.
		 */
		if( (image->file_length = im_file_length( image->fd )) == -1 ) 
			return( -1 );

		/* Very common, so a special message.
		 */
		if( image->file_length < vips_image_size( image ) ) {
			vips_error( "VipsImage", 
				_( "unable to open %s: file too short" ), 
				image->filename );
			return( -1 );
		}

		/* Just weird. Only print a warning for this, since we should
		 * still be able to process it without coredumps.
		 */
		if( image->file_length > vips_image_size( image ) ) 
			vips_warn( "VipsImage", 
				_( "%s is longer than expected" ),
				image->filename );
		break;

	case 'm':
		if( image->Bands == 1 )
			image->Type = VIPS_INTERPRETATION_B_W;
		else if( image->Bands == 3 )
			image->Type = VIPS_INTERPRETATION_RGB;
		else 
			image->Type = VIPS_INTERPRETATION_MULTIBAND;

		image->dtype = VIPS_IMAGE_SETBUF_FOREIGN;

		break;

	default:
		vips_error( "VipsImage", _( "bad mode \"%s\"" ), mode );

		return( -1 );
        }

	vips_image_add_progress( image );

#ifdef DEBUG_VIPS
	printf( "vips_image_build: " );
	vips_object_dump( VIPS_OBJECT( image ) );
#endif /*DEBUG_VIPS*/

	return( 0 );
}

static void *
vips_region_invalidate( VipsRegion *reg )
{
	reg->invalid = TRUE;

	return( NULL );
}

static void 
vips_image_real_invalidate( VipsImage *image )
{
#ifdef DEBUG_VIPS
	printf( "vips_image_real_invalidate: " );
	vips_object_dump( VIPS_OBJECT( image ) );
#endif /*DEBUG_VIPS*/

	g_mutex_lock( image->sslock );
	(void) im_slist_map2( image->regions,
		(VSListMap2Fn) vips_region_invalidate, NULL, NULL );
	g_mutex_unlock( image->sslock );
}

static void
vips_image_class_init( VipsImageClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );
	GParamSpec *pspec;

	/* Pass in a nonsense name for argv0 ... this init world is only here
	 * for old programs which are missing an im_init_world() call. We must
	 * have threads set up before we can process.
	 */
	if( vips_init( "vips" ) )
		vips_error_clear();

	gobject_class->finalize = vips_image_finalize;
	gobject_class->dispose = vips_image_dispose;
	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "image";
	vobject_class->description = _( "VIPS image class" );

	vobject_class->print = vips_image_print;
	vobject_class->sanity = vips_image_sanity;
	vobject_class->rewind = vips_image_rewind;
	vobject_class->build = vips_image_build;

	class->invalidate = vips_image_real_invalidate;

	/* Create properties.
	 */

	/* Width / height / bands can be zero for unintialised.
	 */
	pspec = g_param_spec_int( "width", "Width",
		_( "Image width in pixels" ),
		0, 1000000, 0,
		G_PARAM_READWRITE );
	g_object_class_install_property( gobject_class, PROP_WIDTH, pspec );
	vips_object_class_install_argument( vobject_class, pspec,
		VIPS_ARGUMENT_SET_ONCE, 
		G_STRUCT_OFFSET( VipsImage, Xsize ) );
	pspec = g_param_spec_int( "height", "Height",
		_( "Image height in pixels" ),
		0, 1000000, 0,
		G_PARAM_READWRITE );
	g_object_class_install_property( gobject_class, PROP_HEIGHT, pspec );
	vips_object_class_install_argument( vobject_class, pspec,
		VIPS_ARGUMENT_SET_ONCE, 
		G_STRUCT_OFFSET( VipsImage, Ysize ) );
	pspec = g_param_spec_int( "bands", "Bands",
		_( "Number of bands in image" ),
		0, 1000000, 0, 
		G_PARAM_READWRITE );
	g_object_class_install_property( gobject_class, PROP_BANDS, pspec );
	vips_object_class_install_argument( vobject_class, pspec,
		VIPS_ARGUMENT_SET_ONCE, 
		G_STRUCT_OFFSET( VipsImage, Bands ) );

	pspec = g_param_spec_enum( "format", "Format",
		_( "Pixel format in image" ),
		VIPS_TYPE_BAND_FORMAT, VIPS_FORMAT_UCHAR, 
		G_PARAM_READWRITE );
	g_object_class_install_property( gobject_class, PROP_FORMAT, pspec );
	vips_object_class_install_argument( vobject_class, pspec,
		VIPS_ARGUMENT_SET_ONCE, 
		G_STRUCT_OFFSET( VipsImage, BandFmt ) );

	pspec = g_param_spec_string( "filename", "Filename",
		_( "Image filename" ),
		NULL, 
		G_PARAM_READWRITE );
	g_object_class_install_property( gobject_class, PROP_FILENAME, pspec );
	vips_object_class_install_argument( vobject_class, pspec,
		VIPS_ARGUMENT_CONSTRUCT, 
		G_STRUCT_OFFSET( VipsImage, filename ) );

	pspec = g_param_spec_string( "mode", "Mode",
		_( "Open mode" ),
		"p", 			/* Default to partial */
		G_PARAM_READWRITE );
	g_object_class_install_property( gobject_class, PROP_MODE, pspec );
	vips_object_class_install_argument( vobject_class, pspec,
		VIPS_ARGUMENT_CONSTRUCT, 
		G_STRUCT_OFFSET( VipsImage, mode ) );

	pspec = g_param_spec_boolean( "kill", "Kill",
		_( "Block evaluation on this image" ),
		FALSE, 
		G_PARAM_READWRITE );
	g_object_class_install_property( gobject_class, PROP_KILL, pspec );
	vips_object_class_install_argument( vobject_class, pspec,
		VIPS_ARGUMENT_NONE, 
		G_STRUCT_OFFSET( VipsImage, kill ) );

	pspec = g_param_spec_enum( "demand", "Demand",
		_( "Preferred demand style for this image" ),
		VIPS_TYPE_DEMAND_STYLE, VIPS_DEMAND_STYLE_SMALLTILE,
		G_PARAM_READWRITE );
	g_object_class_install_property( gobject_class, PROP_DEMAND, pspec );
	vips_object_class_install_argument( vobject_class, pspec,
		VIPS_ARGUMENT_NONE, 
		G_STRUCT_OFFSET( VipsImage, dhint ) );

	pspec = g_param_spec_int( "sizeof_header", "Size of header",
		_( "Offset in bytes from start of file" ),
		0, 1000000, IM_SIZEOF_HEADER, 
		G_PARAM_READWRITE );
	g_object_class_install_property( gobject_class, 
		PROP_SIZEOF_HEADER, pspec );
	vips_object_class_install_argument( vobject_class, pspec,
		VIPS_ARGUMENT_SET_ONCE | VIPS_ARGUMENT_CONSTRUCT, 
		G_STRUCT_OFFSET( VipsImage, sizeof_header ) );

	pspec = g_param_spec_pointer( "foreign_buffer", "Foreign buffer",
		"Pointer to foreign pixels",
		G_PARAM_READWRITE );
	g_object_class_install_property( gobject_class, 
		PROP_FOREIGN_BUFFER, pspec );
	vips_object_class_install_argument( vobject_class, pspec,
		VIPS_ARGUMENT_SET_ONCE | VIPS_ARGUMENT_CONSTRUCT, 
		G_STRUCT_OFFSET( VipsImage, data ) );

	/* Create signals.
	 */

	vips_image_signals[SIG_PREEVAL] = g_signal_new( "preeval",
		G_TYPE_FROM_CLASS( class ),
		G_SIGNAL_RUN_LAST,
		G_STRUCT_OFFSET( VipsImageClass, preeval ), 
		NULL, NULL,
		g_cclosure_marshal_VOID__VOID,
		G_TYPE_NONE, 0 );
	vips_image_signals[SIG_EVAL] = g_signal_new( "eval",
		G_TYPE_FROM_CLASS( class ),
		G_SIGNAL_RUN_LAST,
		G_STRUCT_OFFSET( VipsImageClass, eval ), 
		NULL, NULL,
		g_cclosure_marshal_VOID__VOID,
		G_TYPE_NONE, 0 );
	vips_image_signals[SIG_POSTEVAL] = g_signal_new( "posteval",
		G_TYPE_FROM_CLASS( class ),
		G_SIGNAL_RUN_LAST,
		G_STRUCT_OFFSET( VipsImageClass, posteval ), 
		NULL, NULL,
		g_cclosure_marshal_VOID__VOID,
		G_TYPE_NONE, 0 );

	vips_image_signals[SIG_WRITTEN] = g_signal_new( "written",
		G_TYPE_FROM_CLASS( class ),
		G_SIGNAL_RUN_LAST | G_SIGNAL_ACTION,
		G_STRUCT_OFFSET( VipsImageClass, written ), 
		NULL, NULL,
		g_cclosure_marshal_VOID__VOID,
		G_TYPE_NONE, 0 );

	vips_image_signals[SIG_INVALIDATE] = g_signal_new( "invalidate",
		G_TYPE_FROM_CLASS( class ),
		G_SIGNAL_RUN_LAST | G_SIGNAL_ACTION,
		G_STRUCT_OFFSET( VipsImageClass, invalidate ), 
		NULL, NULL,
		g_cclosure_marshal_VOID__VOID,
		G_TYPE_NONE, 0 );
}

static void
vips_image_init( VipsImage *image )
{
	/* Default to native order.
	 */
	image->magic = im_amiMSBfirst() ? VIPS_MAGIC_SPARC : VIPS_MAGIC_INTEL;

	image->Xres = 1.0;
	image->Yres = 1.0;

	image->fd = -1;			/* since 0 is stdout */
	image->sslock = g_mutex_new();

	image->sizeof_header = IM_SIZEOF_HEADER;
}

/* Set of access functions.
 */

int
vips_image_get_width( VipsImage *image )
{
	return( image->Xsize );
}

int
vips_image_get_height( VipsImage *image )
{
	return( image->Ysize );
}

int
vips_image_get_bands( VipsImage *image )
{
	return( image->Bands );
}

VipsBandFormat
vips_image_get_format( VipsImage *image )
{
	return( image->BandFmt );
}

VipsCoding
vips_image_get_coding( VipsImage *image )
{
	return( image->Coding );
}

VipsInterpretation
vips_image_get_interpretation( VipsImage *image )
{
	return( image->Type );
}

double
vips_image_get_xres( VipsImage *image )
{
	return( image->Xres );
}

double
vips_image_get_yres( VipsImage *image )
{
	return( image->Yres );
}

int
vips_image_get_xoffset( VipsImage *image )
{
	return( image->Xoffset );
}

int
vips_image_get_yoffset( VipsImage *image )
{
	return( image->Yoffset );
}

const char *
vips_image_get_filename( VipsImage *image )
{
	return( image->filename );
}

const char *
vips_image_get_mode( VipsImage *image )
{
	return( image->mode );
}

size_t 
vips_image_size( VipsImage *image )
{
	return( VIPS_IMAGE_SIZEOF_LINE( image ) * image->Ysize );
}

void
vips_image_written( VipsImage *image )
{
#ifdef VIPS_DEBUG
	printf( "vips_image_written: " );
	vips_object_print( VIPS_OBJECT( image ) );
#endif /*VIPS_DEBUG*/

	g_signal_emit( image, vips_image_signals[SIG_WRITTEN], 0 );
}

void
vips_image_invalidate( VipsImage *image )
{
#ifdef VIPS_DEBUG
	printf( "vips_image_invalidate: " );
	vips_object_print( VIPS_OBJECT( image ) );
#endif /*VIPS_DEBUG*/

	g_signal_emit( image, vips_image_signals[SIG_INVALIDATE], 0 );
}

static void *
vips_image_invalidate_all_cb( VipsImage *image )
{
	vips_image_invalidate( image );

	return( NULL );
}

/**
 * vips_image_invalidate_all:
 * @image: #VipsImage to invalidate
 *
 * Invalidate all pixel caches on an @image and any derived images. The 
 * "invalidate" callback is triggered for all invalidated images.
 */
void
vips_image_invalidate_all( VipsImage *image )
{
	(void) im__link_map( image, 
		(VSListMap2Fn) vips_image_invalidate_all_cb, NULL, NULL );
}

/* Attach a new time struct, if necessary, and reset it.
 */
static int
vips_progress_add( VipsImage *image )
{
	VipsProgress *progress;

	if( !image->time &&
		!(image->time = VIPS_NEW( NULL, VipsProgress )) )
		return( -1 );
	progress = image->time;
	if( !progress->start )
		progress->start = g_timer_new();

	progress->im = image;
	g_timer_start( progress->start );
	progress->run = 0;
	progress->eta = 0;
	progress->tpels = (gint64) image->Xsize * image->Ysize;
	progress->npels = 0;
	progress->percent = 0;

	return( 0 );
}

void
vips_image_preeval( VipsImage *image )
{
	if( image->progress_signal ) {
#ifdef VIPS_DEBUG
		printf( "vips_image_preeval: " );
		vips_object_print( VIPS_OBJECT( image ) );
#endif /*VIPS_DEBUG*/

		g_assert( vips_object_sanity( 
			VIPS_OBJECT( image->progress_signal ) ) );

		(void) vips_progress_add( image->progress_signal );

		g_signal_emit( image->progress_signal, 
			vips_image_signals[SIG_PREEVAL], 0, image->time );
	}
}

/* Another w * h pixels have been processed.
 */
void
vips_image_eval( VipsImage *image, int w, int h )
{
	if( image->progress_signal ) {
		VipsProgress *progress = image->time;
		float prop;

#ifdef VIPS_DEBUG
		printf( "vips_image_eval: " );
		vips_object_print( VIPS_OBJECT( image ) );
#endif /*VIPS_DEBUG*/

		g_assert( vips_object_sanity( 
			VIPS_OBJECT( image->progress_signal ) ) );

		progress->run = g_timer_elapsed( progress->start, NULL );
		progress->npels += w * h;
		prop = (float) progress->npels / (float) progress->tpels;
		progress->percent = 100 * prop;
		if( prop > 0.1 ) 
			progress->eta = (1.0 / prop) * progress->run - 
				progress->run;

		g_signal_emit( image->progress_signal, 
			vips_image_signals[SIG_EVAL], 0, progress );
	}
}

void
vips_image_posteval( VipsImage *image )
{
	if( image->progress_signal ) {
#ifdef VIPS_DEBUG
		printf( "vips_image_posteval: " );
		vips_object_print( VIPS_OBJECT( image ) );
#endif /*VIPS_DEBUG*/

		g_assert( vips_object_sanity( 
			VIPS_OBJECT( image->progress_signal ) ) );

		g_signal_emit( image->progress_signal, 
			vips_image_signals[SIG_POSTEVAL], 0, image->time );
	}
}

gboolean
vips_image_get_kill( VipsImage *image )
{
	/* Has kill been set for this image? If yes, abort evaluation.
	 */
	if( image->kill ) 
		vips_error( "vips_image_test_kill", 
			_( "killed for image \"%s\"" ), image->filename );

	return( image->kill );
}

void
vips_image_set_kill( VipsImage *image, gboolean kill )
{
	if( !image->kill ) 
		VIPS_DEBUG_MSG( "vips_image_set_kill: %s\n", image->filename );

	image->kill = kill;
}

/* Make a name for a filename-less image. Use immediately, don'#t free the
 * result.
 */
static const char *
vips_image_temp_name( void )
{
	static int serial = 0;
	static char name[256];

	im_snprintf( name, 256, "temp-%d", serial++ );

	return( name );
}

/**
 * vips_image_new:
 * @mode: mode to open with
 *
 * vips_image_new() examines the mode string and creates an 
 * appropriate #VipsImage.
 *
 * <itemizedlist>
 *   <listitem> 
 *     <para>
 *       <emphasis>"t"</emphasis>
 *       creates a temporary memory buffer image.
 *     </para>
 *   </listitem>
 *   <listitem> 
 *     <para>
 *       <emphasis>"p"</emphasis>
 *       creates a "glue" descriptor you can use to join two image 
 *       processing operations together.
 *     </para>
 *   </listitem>
 * </itemizedlist>
 *
 * Returns: the new #VipsImage, or %NULL on error.
 */
VipsImage *
vips_image_new( const char *mode )
{
	VipsImage *image;

	image = VIPS_IMAGE( g_object_new( VIPS_TYPE_IMAGE, NULL ) );
	g_object_set( image,
		"filename", vips_image_temp_name(),
		"mode", mode,
		NULL );
	if( vips_object_build( VIPS_OBJECT( image ) ) ) {
		VIPS_UNREF( image );
		return( NULL );
	}

	return( image ); 
}

/**
 * vips_image_new_from_file:
 * @filename: file to open
 * @mode: mode to open with
 *
 * vips_image_new_from_file() examines the mode string and creates an 
 * appropriate #VipsImage.
 *
 * <itemizedlist>
 *   <listitem> 
 *     <para>
 *       <emphasis>"r"</emphasis>
 *       opens the named file for reading. If the file is not in the native 
 *       VIPS format for your machine, vips_image_new_from_file() 
 *       automatically converts the file for you in memory. 
 *
 *       For some large files (eg. TIFF) this may 
 *       not be what you want, it can fill memory very quickly. Instead, you
 *       can either use "rd" mode (see below), or you can use the lower-level 
 *       API and control the loading process yourself. See 
 *       #VipsBandFormat. 
 *
 *       vips_image_new_from_file() can read files in most formats.
 *
 *       Note that <emphasis>"r"</emphasis> mode works in at least two stages. 
 *       It should return quickly and let you check header fields. It will
 *       only actually read in pixels when you first access them. 
 *     </para>
 *   </listitem>
 *   <listitem> 
 *     <para>
 *       <emphasis>"rd"</emphasis>
 *	 opens the named file for reading. If the uncompressed image is larger 
 *	 than a threshold and the file format does not support random access, 
 *	 rather than uncompressing to memory, vips_image_new_from_file() will 
 *	 uncompress to a temporary disc file. This file will be automatically 
 *	 deleted when the IMAGE is closed.
 *
 *	 See im_system_image() for an explanation of how VIPS selects a
 *	 location for the temporary file.
 *
 *	 The disc threshold can be set with the "--vips-disc-threshold"
 *	 command-line argument, or the IM_DISC_THRESHOLD environment variable.
 *	 The value is a simple integer, but can take a unit postfix of "k", 
 *	 "m" or "g" to indicate kilobytes, megabytes or gigabytes.
 *
 *	 For example:
 *
 *       |[
 *         vips --vips-disc-threshold "500m" im_copy fred.tif fred.v
 *       ]|
 *
 *       will copy via disc if "fred.tif" is more than 500 Mbytes
 *       uncompressed. The default threshold is 100MB.
 *     </para>
 *   </listitem>
 *   <listitem> 
 *     <para>
 *       <emphasis>"w"</emphasis>
 *       opens the named file for writing. It looks at the file name 
 *       suffix to determine the type to write -- for example:
 *
 *       |[
 *         vips_image_new_from_file( "fred.tif", "w" )
 *       ]|
 *
 *       will write in TIFF format.
 *     </para>
 *   </listitem>
 *   <listitem> 
 *     <para>
 *       <emphasis>"rw"</emphasis>
 *       opens the named file for reading and writing. This will only work for 
 *       VIPS files in a format native to your machine. It is only for 
 *       paintbox-type applications.
 *     </para>
 *   </listitem>
 * </itemizedlist>
 *
 * Returns: the new #VipsImage, or %NULL on error.
 */
VipsImage *
vips_image_new_from_file( const char *filename, const char *mode )
{
	VipsImage *image;

	image = VIPS_IMAGE( g_object_new( VIPS_TYPE_IMAGE, NULL ) );
	g_object_set( image,
		"filename", filename,
		"mode", mode,
		NULL );
	if( vips_object_build( VIPS_OBJECT( image ) ) ) {
		VIPS_UNREF( image );
		return( NULL );
	}

	return( image ); 
}

/**
 * vips_image_new_from_file_raw:
 * @filename: filename to open
 * @xsize: image width
 * @ysize: image height
 * @bands: image bands (or bytes per pixel)
 * @offset: bytes to skip at start of file
 *
 * This function maps the named file and returns a #VipsImage you can use to
 * read it.
 *
 * It returns an 8-bit image with @bands bands. If the image is not 8-bit, use 
 * im_copy_set() to transform the descriptor after loading it.
 *
 * See also: im_copy_set(), im_raw2vips(), vips_image_new_from_file().
 *
 * Returns: the new #VipsImage, or %NULL on error.
 */
VipsImage *
vips_image_new_from_file_raw( const char *filename, 
	int xsize, int ysize, int bands, int offset )
{
	VipsImage *image;

	image = VIPS_IMAGE( g_object_new( VIPS_TYPE_IMAGE, NULL ) );
	g_object_set( image,
		"filename", filename,
		"mode", "a",
		"width", xsize,
		"height", ysize,
		"bands", bands,
		"sizeof_header", offset,
		NULL );
	if( vips_object_build( VIPS_OBJECT( image ) ) ) {
		VIPS_UNREF( image );
		return( NULL );
	}

	return( image );
}

/**
 * vips_image_new_from_memory:
 * @buffer: start of memory area
 * @xsize: image width
 * @ysize: image height
 * @bands: image bands (or bytes per pixel)
 * @bandfmt: image format
 *
 * This function wraps an #IMAGE around a memory buffer. VIPS does not take
 * responsibility for the area of memory, it's up to you to make sure it's
 * freed when the image is closed. See for example im_add_close_callback().
 *
 * See also: im_binfile(), im_raw2vips(), im_open().
 *
 * Returns: the new #VipsImage, or %NULL on error.
 */
VipsImage *
vips_image_new_from_memory( void *buffer, 
	int xsize, int ysize, int bands, VipsBandFormat bandfmt )
{
	VipsImage *image;

	image = VIPS_IMAGE( g_object_new( VIPS_TYPE_IMAGE, NULL ) );
	g_object_set( image,
		"filename", vips_image_temp_name(),
		"mode", "m",
		"foreign_buffer", buffer,
		"width", xsize,
		"height", ysize,
		"bands", bands,
		"format", bandfmt,
		NULL );
	if( vips_object_build( VIPS_OBJECT( image ) ) ) {
		VIPS_UNREF( image );
		return( NULL );
	}

	return( image );
}

static void
vips_image_new_temp_cb( VipsImage *image )
{
	g_assert( image->filename );

	g_unlink( image->filename );
}

/**
 * vips_image_new_disc_temp:
 * @format: format of file
 *
 * Make a "w" disc #VipsImage which will be automatically unlinked when it is
 * destroyed. @format is something like "%s.v" for a vips file.
 *
 * The file is created in the temporary directory, see im__temp_name().
 *
 * See also: im__temp_name().
 *
 * Returns: the new #VipsImage, or %NULL on error.
 */
VipsImage *
vips_image_new_disc_temp( const char *format )
{
	char *name;
	VipsImage *image;

	if( !(name = im__temp_name( format )) )
		return( NULL );

	if( !(image = vips_image_new_from_file( name, "w" )) ) {
		g_free( name );
		return( NULL );
	}
	g_free( name );

	/* Needs to be postclose so we can rewind after write without
	 * deleting the file.
	 */
	g_signal_connect( image, "postclose", 
		G_CALLBACK( vips_image_new_temp_cb ), NULL );

	return( image );
}

/**
 * vips_image_isMSBfirst:
 * @image: image to test
 *
 * Return %TRUE if @image is in most-significant-
 * byte first form. This is the byte order used on the SPARC
 * architecture and others. 
 */
gboolean
vips_image_isMSBfirst( VipsImage *image )
{	
	if( image->magic == VIPS_MAGIC_SPARC )
		return( 1 );
	else
		return( 0 );
}

/**
 * vips_image_isfile:
 * @image: image to test
 *
 * Return %TRUE if @image represents a file on disc in some way. 
 */
gboolean vips_image_isfile( VipsImage *image )
{
	switch( image->dtype ) {
	case VIPS_IMAGE_MMAPIN:
	case VIPS_IMAGE_MMAPINRW:
	case VIPS_IMAGE_OPENOUT:
	case VIPS_IMAGE_OPENIN:
		return( 1 );

	case VIPS_IMAGE_PARTIAL:
	case VIPS_IMAGE_SETBUF:
	case VIPS_IMAGE_SETBUF_FOREIGN:
	case VIPS_IMAGE_NONE:
		return( 0 );

	default:
		g_assert( FALSE ); 
		return( 0 );
	}
}

/**
 * vips_image_ispartial:
 * @image: image to test
 *
 * Return %TRUE if @im represents a partial image (a delayed calculation).
 */
gboolean 
vips_image_ispartial( VipsImage *image )
{
	if( image->dtype == VIPS_IMAGE_PARTIAL )
		return( 1 );
	else
		return( 0 );
}

/* This is used by (eg.) IM_IMAGE_SIZEOF_ELEMENT() to calculate object
 * size.
 */
const size_t vips__image_sizeof_bandformat[] = {
	sizeof( unsigned char ), 	/* VIPS_FORMAT_UCHAR */
	sizeof( signed char ), 		/* VIPS_FORMAT_CHAR */
	sizeof( unsigned short ), 	/* VIPS_FORMAT_USHORT */
	sizeof( unsigned short ), 	/* VIPS_FORMAT_SHORT */
	sizeof( unsigned int ), 	/* VIPS_FORMAT_UINT */
	sizeof( unsigned int ), 	/* VIPS_FORMAT_INT */
	sizeof( float ), 		/* VIPS_FORMAT_FLOAT */
	2 * sizeof( float ), 		/* VIPS_FORMAT_COMPLEX */
	sizeof( double ), 		/* VIPS_FORMAT_DOUBLE */
	2 * sizeof( double ) 		/* VIPS_FORMAT_DPCOMPLEX */
};

/* Return number of bytes for a band format, or -1 on error.
 */
int 
vips_format_sizeof( VipsBandFormat format )
{
	return( (format < 0 || format > VIPS_FORMAT_DPCOMPLEX) ?
		vips_error( "vips_format_sizeof", 
			_( "unknown band format %d" ), format ), -1 :
		vips__image_sizeof_bandformat[format] );
}

/**
 * vips_image_copy_fields_array:
 * @out: image to copy to
 * @in: %NULL-terminated array of images to copy from
 *
 * Copy fields from all the input images to the output image. There must be at
 * least one input image. 
 *
 * The first input image is used to set the main fields of @out (@XSize, @Coding
 * and so on). 
 *
 * Metadata from all the image is merged on to @out, with lower-numbered items 
 * overriding higher. So for example, if @in[0] and @in[1] both have an item
 * called "icc-profile", it's the profile attached to @in[0] that will end up
 * on @out.
 *
 * Image history is completely copied from all @in. @out will have the history
 * of all the intput images.
 *
 * See also: vips_image_copy_fieldsv(), vips_image_copy_fields().
 *
 * Returns: 0 on success, -1 on error.
 */
int 
vips_image_copy_fields_array( IMAGE *out, IMAGE *in[] )
{
	int i;
	int ni;

	g_assert( in[0] );

	out->Xsize = in[0]->Xsize;
	out->Ysize = in[0]->Ysize;
	out->Bands = in[0]->Bands;
	out->Bbits = in[0]->Bbits;
	out->BandFmt = in[0]->BandFmt;
	out->Type = in[0]->Type;
	out->Coding = in[0]->Coding;
	out->Xres = in[0]->Xres;
	out->Yres = in[0]->Yres;
	out->Xoffset = 0;
	out->Yoffset = 0;

	/* Count number of images.
	 */
	for( ni = 0; in[ni]; ni++ ) 
		;

	/* Need to copy last-to-first so that in0 meta will override any
	 * earlier meta.
	 */
	im__meta_destroy( out );
	for( i = ni - 1; i >= 0; i-- ) 
		if( im__meta_cp( out, in[i] ) )
			return( -1 );

	/* Merge hists first to last.
	 */
	for( i = 0; in[i]; i++ )
		out->history_list = im__gslist_gvalue_merge( out->history_list,
			in[i]->history_list );

	return( 0 );
}

/* Max number of images we can handle.
 */
#define MAX_IMAGES (1000)

/**
 * vips_image_copy_fieldsv:
 * @out: image to copy to
 * @in1: first image to copy from
 * @Varargs: %NULL-terminated list of images to copy from
 *
 * Copy fields from all the input images to the output image. A convenience
 * function over vips_image_copy_fields_array(). 
 *
 * See also: vips_image_copy_fields_array(), vips_image_copy_fields().
 *
 * Returns: 0 on success, -1 on error.
 */
int 
vips_image_copy_fieldsv( IMAGE *out, IMAGE *in1, ... )
{
	va_list ap;
	int i;
	IMAGE *in[MAX_IMAGES];

	in[0] = in1;
	va_start( ap, in1 );
	for( i = 1; i < MAX_IMAGES && (in[i] = va_arg( ap, IMAGE * )); i++ ) 
		;
	va_end( ap );
	if( i == MAX_IMAGES ) {
		vips_error( "im_cp_descv", 
			"%s", _( "too many images" ) );
		return( -1 );
	}

	return( vips_image_copy_fields_array( out, in ) );
}

/**
 * vips_image_copy_fields:
 * @out: image to copy to
 * @in: image to copy from
 *
 * Copy fields from @in to @out. A convenience
 * function over vips_image_copy_fields_array(). 
 *
 * See also: vips_image_copy_fields_array(), vips_image_copy_fieldsv().
 *
 * Returns: 0 on success, -1 on error.
 */
int 
vips_image_copy_fields( IMAGE *out, IMAGE *in )
{
	return( vips_image_copy_fieldsv( out, in, NULL ) ); 
}

int
vips_image_new_array( VipsImage *parent, VipsImage **images, int n )
{
	int i;

	for( i = 0; i < n; i++ )
		if( !(images[i] = vips_image_new( "p" )) ) 
			return( -1 );

	return( 0 );
}

/**
 * vips_image_init_fields:
 * @image: image to init
 * @xsize: image width
 * @ysize: image height
 * @bands: image bands
 * @bandfmt: band format
 * @coding: image coding
 * @type: image type
 * @xres: horizontal resolution, pixels per millimetre
 * @yres: vertical resolution, pixels per millimetre
 * @xo: x offset
 * @yo: y offset
 *
 * A convenience function to set the header fields after creating an image.
 * Normally you copy the fields from one of your input images with
 * vips_image_copy_fields() and then make
 * any adjustments you need, but if you are creating an image from scratch,
 * for example im_black() or im_jpeg2vips(), you do need to set all the
 * fields yourself.
 *
 * See also: vips_image_copy_fields().
 */
void 
vips_image_init_fields( VipsImage *image, 
	int xsize, int ysize, int bands, 
	VipsBandFormat format, VipsCoding coding, 
	VipsInterpretation interpretation, 
	float xres, float yres,
	int xo, int yo )
{
	g_object_set( image,
		"width", xsize,
		"height", ysize,
		"bands", bands,
		"format", format,
		NULL );

	image->Coding = coding;
	image->Type = interpretation;
	image->Xres = xres;
	image->Yres = yres;
	image->Xoffset = xo;
	image->Yoffset = yo;
}

/**
 * vips_image_write_line:
 * @image: image to write to
 * @ypos: vertical position of scan-line to write
 * @linebuffer: scanline of pixels
 *
 * Write a line of pixels to an image. This function must be called repeatedly
 * with @ypos increasing from 0 to @YSize -
 * @linebuffer must be IM_IMAGE_SIZEOF_LINE() bytes long.
 *
 * See also: im_setupout(), im_generate().
 *
 * Returns: 0 on success, or -1 on error.
 */
int
vips_image_write_line( VipsImage *image, int ypos, PEL *linebuffer )
{	
	int linesize = VIPS_IMAGE_SIZEOF_LINE( image );

	/* Is this the start of eval?
	 */
	if( ypos == 0 )
		vips_image_preeval( image );

	/* Possible cases for output: FILE or SETBUF.
	 */
	switch( image->dtype ) {
	case VIPS_IMAGE_SETBUF:
	case VIPS_IMAGE_SETBUF_FOREIGN:
		memcpy( VIPS_IMAGE_ADDR( image, 0, ypos ), 
			linebuffer, linesize );
		break;

	case VIPS_IMAGE_OPENOUT:
		/* Don't use ypos for this.
		 */
		if( im__write( image->fd, linebuffer, linesize ) )
			return( -1 );
		break;

	default:
		vips_error( "im_writeline", 
			_( "unable to output to a %s image" ),
			VIPS_ENUM_STRING( VIPS_TYPE_DEMAND_STYLE, 
				image->dtype ) );
		return( -1 );
	}

	/* Trigger evaluation callbacks for this image.
	 */
	vips_image_eval( image, image->Xsize, 1 );
	if( im__test_kill( image ) )
		return( -1 );

	/* Is this the end of eval?
	 */
	if( ypos == image->Ysize - 1 ) {
		vips_image_posteval( image );
		vips_image_written( image );
	}

	return( 0 );
}


