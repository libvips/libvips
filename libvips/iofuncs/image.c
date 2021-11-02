/* vips image class
 * 
 * 4/2/11
 * 	- hacked up from various places
 * 6/6/13
 * 	- vips_image_write() didn't ref non-partial sources
 * 18/4/15
 * 	- add vips_image_copy_memory()
 * 25/11/15
 * 	- add vips_image_new_from_memory_copy()
 * 10/6/16
 * 	- vips_image_write() does not ref input for non-partial images
 * 29/10/16
 * 	- add vips_image_hasalpha()
 * 11/10/17
 * 	- more severing for vips_image_write()
 * 3/4/18
 * 	- better rules for hasalpha
 * 9/10/18
 * 	- fix up vips_image_dump(), it was still using ints not enums
 * 10/12/19
 * 	- add vips_image_new_from_source() / vips_image_write_to_target()
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

/**
 * SECTION: image
 * @short_description: the VIPS image class
 * @stability: Stable
 * @see_also: <link linkend="libvips-header">header</link> 
 * <link linkend="VipsRegion">VipsRegion</link> 
 * <link linkend="libvips-generate">generate</link>
 * <link linkend="VipsOperation">VipsOperation</link> 
 * @include: vips/vips.h
 *
 * The image class and associated types and macros.
 *
 * Images can be created from formatted files on disc, from C-style arrays on
 * disc, from formatted areas of memory, or from C-style arrays in memory. See
 * vips_image_new_from_file() and friends. 
 * Creating an image is fast. VIPS reads just enough of
 * the image to be able to get the various properties, such as width in
 * pixels. It delays reading any pixels until they are really needed.
 *
 * Once you have an image, you can get properties from it in the usual way. 
 * You can use projection functions, like vips_image_get_width() or 
 * g_object_get(), to get %GObject properties. 
 * 
 * VIPS images are three-dimensional arrays, the dimensions being width, 
 * height and bands. Each dimension can be up to 2 ** 31 pixels (or band 
 * elements). An image has a format, meaning the machine number type used 
 * to represent each value. VIPS supports 10 formats, from 8-bit unsigned 
 * integer up to 128-bit double complex, see vips_image_get_format(). 
 *
 * In VIPS, images are uninterpreted arrays, meaning that from the point of 
 * view of most operations, they are just large collections of numbers. 
 * There's no difference between an RGBA (RGB with alpha) image and a CMYK 
 * image, for example, they are both just four-band images. It's up to the 
 * user of the library to pass the right sort of image to each operation. 
 *
 * To take an example, VIPS has vips_Lab2XYZ(), an operation to transform 
 * an image from CIE LAB colour space to CIE XYZ space. It assumes the 
 * first three bands represent pixels in LAB colour space and returns an 
 * image where the first three bands are transformed to XYZ and any 
 * remaining bands are just copied. Pass it a RGB image by mistake and 
 * you'll just get nonsense.
 *
 * VIPS has a feature to help (a little) with this: it sets a 
 * #VipsInterpretation hint for each image (see 
 * vips_image_get_interpretation()); a hint which says how pixels should
 * be interpreted. For example, vips_Lab2XYZ() will set the
 * interpretation of the output image to #VIPS_INTERPRETATION_XYZ. A
 * few utility operations will also use interpretation as a guide. For
 * example, you can give vips_colourspace() an input image and a desired
 * colourspace and it will use the input's interpretation hint to apply
 * the best sequence of colourspace transforms to get to the desired space.
 *
 * Use things like vips_invert() to manipulate your images. When you are done,
 * you can write images to disc files (with vips_image_write_to_file()),
 * to formatted memory buffers (with vips_image_write_to_buffer()) and to
 * C-style memory arrays (with vips_image_write_to_memory().
 *
 * You can also write images to other images. Create, for example, a temporary
 * disc image with vips_image_new_temp_file(), then write your image to that
 * with vips_image_write(). You can create several other types of image and
 * write to them, see vips_image_new_memory(), for example. 
 *
 * See <link linkend="VipsOperation">operation</link> for an introduction to
 * running operations on images, see <link
 * linkend="libvips-header">header</link> for getting and setting image
 * metadata. See <link linkend="VipsObject">object</link> for a discussion of
 * the lower levels. 
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
 * VipsAccess:
 * @VIPS_ACCESS_RANDOM: can read anywhere
 * @VIPS_ACCESS_SEQUENTIAL: top-to-bottom reading only, but with a small buffer
 *
 * The type of access an operation has to supply. See vips_tilecache()
 * and #VipsForeign. 
 *
 * @VIPS_ACCESS_RANDOM means requests can come in any order. 
 *
 * @VIPS_ACCESS_SEQUENTIAL means requests will be top-to-bottom, but with some
 * amount of buffering behind the read point for small non-local accesses. 
 */

/** 
 * VipsDemandStyle:
 * @VIPS_DEMAND_STYLE_SMALLTILE: demand in small (typically 64x64 pixel) tiles
 * @VIPS_DEMAND_STYLE_FATSTRIP: demand in fat (typically 10 pixel high) strips
 * @VIPS_DEMAND_STYLE_THINSTRIP: demand in thin (typically 1 pixel high) strips
 * @VIPS_DEMAND_STYLE_ANY: demand geometry does not matter
 *
 * See vips_image_pipelinev(). Operations can hint to the VIPS image IO 
 * system about the kind of demand geometry they prefer. 
 *
 * These demand styles are given below in order of increasing
 * restrictiveness.  When demanding output from a pipeline, 
 * vips_image_generate()
 * will use the most restrictive of the styles requested by the operations 
 * in the pipeline.
 *
 * #VIPS_DEMAND_STYLE_THINSTRIP --- This operation would like to output strips 
 * the width of the image and a few pels high. This is option suitable for 
 * point-to-point operations, such as those in the arithmetic package.
 *
 * This option is only efficient for cases where each output pel depends 
 * upon the pel in the corresponding position in the input image.
 *
 * #VIPS_DEMAND_STYLE_FATSTRIP --- This operation would like to output strips 
 * the width of the image and as high as possible. This option is suitable 
 * for area operations which do not violently transform coordinates, such 
 * as vips_conv(). 
 *
 * #VIPS_DEMAND_STYLE_SMALLTILE --- This is the most general demand format.
 * Output is demanded in small (around 100x100 pel) sections. This style works 
 * reasonably efficiently, even for bizzare operations like 45 degree rotate.
 *
 * #VIPS_DEMAND_STYLE_ANY --- This image is not being demand-read from a disc 
 * file (even indirectly) so any demand style is OK. It's used for things like
 * vips_black() where the pixels are calculated.
 *
 * See also: vips_image_pipelinev().
 */

/**
 * VipsInterpretation: 
 * @VIPS_INTERPRETATION_MULTIBAND: generic many-band image
 * @VIPS_INTERPRETATION_B_W: some kind of single-band image
 * @VIPS_INTERPRETATION_HISTOGRAM: a 1D image, eg. histogram or lookup table
 * @VIPS_INTERPRETATION_FOURIER: image is in fourier space
 * @VIPS_INTERPRETATION_XYZ: the first three bands are CIE XYZ 
 * @VIPS_INTERPRETATION_LAB: pixels are in CIE Lab space
 * @VIPS_INTERPRETATION_CMYK: the first four bands are in CMYK space
 * @VIPS_INTERPRETATION_LABQ: implies #VIPS_CODING_LABQ
 * @VIPS_INTERPRETATION_RGB: generic RGB space
 * @VIPS_INTERPRETATION_CMC: a uniform colourspace based on CMC(1:1)
 * @VIPS_INTERPRETATION_LCH: pixels are in CIE LCh space
 * @VIPS_INTERPRETATION_LABS: CIE LAB coded as three signed 16-bit values
 * @VIPS_INTERPRETATION_sRGB: pixels are sRGB
 * @VIPS_INTERPRETATION_HSV: pixels are HSV
 * @VIPS_INTERPRETATION_scRGB: pixels are scRGB
 * @VIPS_INTERPRETATION_YXY: pixels are CIE Yxy
 * @VIPS_INTERPRETATION_RGB16: generic 16-bit RGB
 * @VIPS_INTERPRETATION_GREY16: generic 16-bit mono
 * @VIPS_INTERPRETATION_MATRIX: a matrix
 *
 * How the values in an image should be interpreted. For example, a
 * three-band float image of type #VIPS_INTERPRETATION_LAB should have its 
 * pixels interpreted as coordinates in CIE Lab space.
 *
 * RGB and sRGB are treated in the same way. Use the colourspace functions if
 * you want some other behaviour.
 *
 * The gaps in numbering are historical and must be maintained. Allocate 
 * new numbers from the end.
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
 * Each corresponds to a native C type for the current machine. For example,
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
 *
 * The gaps in the numbering are historical and must be maintained. Allocate 
 * new numbers from the end.
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
 * progress. See #VipsImage::eval.
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
 * VIPS_IMAGE_N_PELS:
 * @I: a #VipsImage
 *
 * Returns: The number of pels in an image. A 64-bit unsigned int.
 */

/**
 * VIPS_IMAGE_ADDR:
 * @I: a #VipsImage
 * @X: x coordinate
 * @Y: y coordinate
 *
 * This macro returns a pointer to a pixel in an image, cast to a #VipsPel *. 
 * It only works for
 * images which are fully available in memory, so memory buffers and small
 * mapped images only.
 * 
 * If VIPS_DEBUG is defined, you get a version that checks bounds for you.
 *
 * See also: vips_image_wio_input(), vips_image_inplace(), VIPS_REGION_ADDR().
 *
 * Returns: The address of pixel (@X,@Y) in @I. 
 */

/**
 * VIPS_MATRIX:
 * @I: a #VipsImage
 * @X: x coordinate
 * @Y: y coordinate
 *
 * This macro returns a pointer to a pixel in an image, cast to a double*. The
 * image must have a single band, be #VIPS_FORMAT_DOUBLE and be 
 * fully available in memory, so memory buffers and small
 * mapped images only.
 * 
 * If VIPS_DEBUG is defined, you get a version that checks bounds and image
 * type for you.
 *
 * See also: vips_image_wio_input(), vips_image_inplace(), vips_check_matrix(). 
 *
 * Returns: The address of pixel (@X,@Y) in @I.
 */

/* Our signals. 
 */
enum {
	SIG_PREEVAL,		
	SIG_EVAL,		
	SIG_POSTEVAL,		
	SIG_WRITTEN,		
	SIG_INVALIDATE,		
	SIG_MINIMISE,		
	SIG_LAST
};

/* Progress feedback. Only really useful for testing, tbh.
 */
int vips__progress = 0;

/* A string giving the image size (in bytes of uncompressed image) above which 
 * we decompress to disc on open.  Can be eg. "12m" for 12 megabytes.
 */
char *vips__disc_threshold = NULL;

/* Minimise needs a lock.
 */
static GMutex *vips__minimise_lock = NULL;

static guint vips_image_signals[SIG_LAST] = { 0 };

G_DEFINE_TYPE( VipsImage, vips_image, VIPS_TYPE_OBJECT );

/**
 * vips_progress_set:
 * @progress: %TRUE to enable progress messages
 *
 * If set, vips will print messages about the progress of computation to
 * stdout. This can also be enabled with the --vips-progress option, or by
 * setting the environment variable VIPS_PROGRESS.
 */
void
vips_progress_set( gboolean progress )
{
	vips__progress = progress;
}

static void
vips_image_delete( VipsImage *image )
{
	if( image->delete_on_close ) {
		g_assert( image->delete_on_close_filename );

		VIPS_DEBUG_MSG( "vips_image_delete: removing temp %s\n", 
				image->delete_on_close_filename );
		g_unlink( image->delete_on_close_filename );
		VIPS_FREE( image->delete_on_close_filename );
		image->delete_on_close = FALSE;
	}
}

static void
vips_image_finalize( GObject *gobject )
{
	VipsImage *image = VIPS_IMAGE( gobject );

	VIPS_DEBUG_MSG( "vips_image_finalize: %p\n", gobject );

	/* Should be no regions defined on the image, since they all hold a
	 * ref to their host image.
	 */
	g_assert( !image->regions );

	/* Therefore there should be no windows.
	 */
	g_assert( !image->windows );

	/* Junk generate functions. 
	 */
	image->start_fn = NULL;
	image->generate_fn = NULL;
	image->stop_fn = NULL;
	image->client1 = NULL;
	image->client2 = NULL;

	/* No more upstream/downstream links.
	 */
	vips__link_break_all( image );

	if( image->time ) {
		VIPS_FREEF( g_timer_destroy, image->time->start );
		VIPS_FREE( image->time );
	}

	/* Free attached memory.
	 */
	if( image->data ) {
		if( image->dtype == VIPS_IMAGE_SETBUF ) {
			VIPS_DEBUG_MSG( "vips_image_finalize: "
				"freeing buffer\n" );
			vips_tracked_free( image->data );
			image->dtype = VIPS_IMAGE_NONE;
		}

		image->data = NULL;
	}

	/* Delete associated files.
	 */
	vips_image_delete( image );

	VIPS_FREEF( vips_g_mutex_free, image->sslock );

	VIPS_FREE( image->Hist );
	VIPS_FREEF( vips__gslist_gvalue_free, image->history_list );
	vips__meta_destroy( image );

	G_OBJECT_CLASS( vips_image_parent_class )->finalize( gobject );
}

static void
vips_image_dispose( GObject *gobject )
{
	VipsImage *image = VIPS_IMAGE( gobject );

	VIPS_DEBUG_MSG( "vips_image_dispose: %p\n", gobject );

#ifdef DEBUG_LEAK
{
	VipsImagePixels *pixels = g_object_get_qdata( G_OBJECT( image ), 
		vips__image_pixels_quark ); 

	if( pixels &&
		pixels->tpels ) {
		int compute_percent = 100.0 * pixels->npels / pixels->tpels;

		if( compute_percent > 100 ) 
			printf( "vips_image_dispose: %s %s computed %d%%\n", 
				image->filename, 
				pixels->nickname, 
				compute_percent );
	}
}
#endif /*DEBUG_LEAK*/

	vips_object_preclose( VIPS_OBJECT( gobject ) );

	/* We have to junk the fd in dispose, since we run this for rewind and
	 * we must close and reopen the file when we switch from write to
	 * read.
	 */

	/* Any file mapping?
	 */
	if( image->baseaddr ) {
		/* MMAP file.
		 */
		VIPS_DEBUG_MSG( "vips_image_dispose: unmapping file\n" );

		vips__munmap( image->baseaddr, image->length );
		image->baseaddr = NULL;
		image->length = 0;

		/* This must have been a pointer to the mmap region, rather
		 * than a setbuf.
		 */
		image->data = NULL;
	}

	/* Is there a file descriptor?
	 */
	if( image->fd != -1 ) {
		VIPS_DEBUG_MSG( "vips_image_dispose: closing output file\n" );

		if( vips_tracked_close( image->fd ) == -1 ) 
			vips_error( "VipsImage", 
				"%s", _( "unable to close fd" ) );
		image->fd = -1;
	}

	G_OBJECT_CLASS( vips_image_parent_class )->dispose( gobject );
}

static VipsObject *
vips_image_new_from_file_object( const char *string )
{
	VipsImage *image;

	vips_check_init();

	/* We mustn't _build() the object here, so we can't just call
	 * vips_image_new_from_file().
	 */
	image = VIPS_IMAGE( g_object_new( VIPS_TYPE_IMAGE, NULL ) );
	g_object_set( image,
		"filename", string,
		"mode", "r",
		NULL );

	return( VIPS_OBJECT( image ) );
}

static void
vips_image_to_string( VipsObject *object, VipsBuf *buf )
{
	VipsImage *image = VIPS_IMAGE( object );

	vips_buf_appends( buf, image->filename );
}

static int 
vips_image_write_object( VipsObject *object, const char *string )
{
	return( vips_image_write_to_file( VIPS_IMAGE( object ), string, 
		NULL ) );
}

static void *
print_field_fn( VipsImage *image, const char *field, GValue *value, void *a )
{
	VipsBuf *buf = (VipsBuf *) a;

	vips_buf_appendf( buf, "%s: ", field );
	vips_buf_appendgv( buf, value );
	vips_buf_appendf( buf, "\n" );

	return( NULL );
}

static void
vips_image_dump( VipsObject *object, VipsBuf *buf )
{
	VipsImage *image = VIPS_IMAGE( object );

	vips_buf_appendf( buf, 
		ngettext( 
			"%dx%d %s, %d band, %s", 
			"%dx%d %s, %d bands, %s", 
			vips_image_get_bands( image ) ),
		vips_image_get_width( image ),
		vips_image_get_height( image ),
		vips_enum_nick( VIPS_TYPE_BAND_FORMAT, 
			vips_image_get_format( image ) ),
		vips_image_get_bands( image ),
		vips_enum_nick( VIPS_TYPE_INTERPRETATION, 
			vips_image_get_interpretation( image ) ) );

	vips_buf_appendf( buf, ", %s", 
		vips_enum_nick( VIPS_TYPE_IMAGE_TYPE, image->dtype ) );

	VIPS_OBJECT_CLASS( vips_image_parent_class )->dump( object, buf );

	vips_buf_appendf( buf, "\n" );

	(void) vips_image_map( image, print_field_fn, (void *) buf );

	vips_buf_appendf( buf, "Hist: %s", vips_image_get_history( image ) );
}

static void
vips_image_summary( VipsObject *object, VipsBuf *buf )
{
	VipsImage *image = VIPS_IMAGE( object );
	const char *p;

	vips_buf_appendf( buf, "%dx%d",
		vips_image_get_width( image ), vips_image_get_height( image ) );
	if( vips_image_get_coding( image ) == VIPS_CODING_NONE ) {
		vips_buf_appendf( buf, 
			ngettext( 
				" %s, %d band, %s", 
				" %s, %d bands, %s", 
				vips_image_get_bands( image ) ),
			vips_enum_nick( VIPS_TYPE_BAND_FORMAT, 
				vips_image_get_format( image ) ),
			vips_image_get_bands( image ),
			vips_enum_nick( VIPS_TYPE_INTERPRETATION, 
				vips_image_get_interpretation( image ) ) );
	}
	else {
		vips_buf_appendf( buf, ", %s",
			vips_enum_nick( VIPS_TYPE_CODING, 
				vips_image_get_coding( image ) ) );
	}

	if( vips_image_get_typeof( image, VIPS_META_LOADER ) &&
		!vips_image_get_string( image, VIPS_META_LOADER, &p ) ) 
		vips_buf_appendf( buf, ", %s", p );

	VIPS_OBJECT_CLASS( vips_image_parent_class )->summary( object, buf );
}

static void *
vips_image_sanity_upstream( VipsImage *up, VipsImage *down, void *b )
{
	if( !g_slist_find( up->downstream, down ) ||
		!g_slist_find( down->upstream, up ) )
		return( up );

	return( NULL );
}

static void *
vips_image_sanity_downstream( VipsImage *down, VipsImage *up, void *b )
{
	return( vips_image_sanity_upstream( up, down, b ) );
}

static void
vips_image_sanity( VipsObject *object, VipsBuf *buf )
{
	VipsImage *image = VIPS_IMAGE( object );

	/* All 0 means im has been inited but never used.
	 */
	if( image->Xsize != 0 ||
		image->Ysize != 0 ||
		image->Bands != 0 ) {
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
			image->Type >= VIPS_INTERPRETATION_LAST ||
			image->dtype > VIPS_IMAGE_PARTIAL || 
			image->dhint > VIPS_DEMAND_STYLE_ANY ) 
			vips_buf_appends( buf, "bad enum\n" );
		if( image->Xres < 0 || 
			image->Yres < 0 ) 
			vips_buf_appends( buf, "bad resolution\n" );
	}

	/* Must lock around inter-image links.
	 */
	g_mutex_lock( vips__global_lock );

	if( vips_slist_map2( image->upstream, 
		(VipsSListMap2Fn) vips_image_sanity_upstream, image, NULL ) )
		vips_buf_appends( buf, "upstream broken\n" );
	if( vips_slist_map2( image->downstream, 
		(VipsSListMap2Fn) vips_image_sanity_downstream, image, NULL ) )
		vips_buf_appends( buf, "downstream broken\n" );

	g_mutex_unlock( vips__global_lock );

	VIPS_OBJECT_CLASS( vips_image_parent_class )->sanity( object, buf );
}

static void
vips_image_rewind( VipsObject *object )
{
	VipsImage *image = VIPS_IMAGE( object );
	char *filename;
	char *mode;

	/* This triggers a dispose. Copy filename/mode across the dispose.
	 */
	filename = g_strdup( vips_image_get_filename( image ) );
	mode = g_strdup( vips_image_get_mode( image ) );

	VIPS_OBJECT_CLASS( vips_image_parent_class )->rewind( object );

	g_assert( image->filename == NULL );
	g_assert( image->mode == NULL );

	image->filename = filename;
	image->mode = mode;
}

/* Delayed save.
 */

/* From "written" callback: save to image->filename using VipsForeign.
 */
static void
vips_image_save_cb( VipsImage *image, int *result, void *data )
{
	if( vips_foreign_save( image, image->filename, NULL ) )
		*result = -1;
}

/* Progress feedback. 
 */

static void
vips_image_preeval_cb( VipsImage *image, VipsProgress *progress, int *last )
{
	int tile_width; 
	int tile_height; 
	int n_lines;

	*last = -1;

	vips_get_tile_size( image, 
		&tile_width, &tile_height, &n_lines );
	printf( _( "%s %s: %d x %d pixels, %d threads, %d x %d tiles, "
		"%d lines in buffer" ),
		vips_get_prgname(), image->filename,
		image->Xsize, image->Ysize,
		vips_concurrency_get(),
		tile_width, tile_height, n_lines );
	printf( "\n" );
}

static void
vips_image_eval_cb( VipsImage *image, VipsProgress *progress, int *last )
{
	if( progress->percent != *last ) {
		printf( _( "%s %s: %d%% complete" ), 
			vips_get_prgname(), image->filename, 
			progress->percent );
		printf( "\r" ); 
		fflush( stdout );

		*last = progress->percent;

		/* Needs DEBUG in region.c
		vips_region_dump_all();
		 */
	}
}

static void
vips_image_posteval_cb( VipsImage *image, VipsProgress *progress, void *data )
{
	/* Spaces at end help to erase the %complete message we overwrite.
	 */
	printf( _( "%s %s: done in %.3gs          \n" ), 
		vips_get_prgname(), image->filename, 
		g_timer_elapsed( progress->start, NULL ) );
}

/* Attach progress feedback, if required.
 */
static void
vips_image_add_progress( VipsImage *image )
{
	if( vips__progress || 
		g_getenv( "VIPS_PROGRESS" )
#if ENABLE_DEPRECATED
		|| g_getenv( "IM_PROGRESS" )
#endif
		) {

		/* Keep the %complete we displayed last time here.
		 */
		int *last = VIPS_NEW( image, int );

		g_signal_connect( image, "preeval", 
			G_CALLBACK( vips_image_preeval_cb ), last );
		g_signal_connect( image, "eval", 
			G_CALLBACK( vips_image_eval_cb ), last );
		g_signal_connect( image, "posteval", 
			G_CALLBACK( vips_image_posteval_cb ), NULL );

		vips_image_set_progress( image, TRUE );
	}
}

/* We have to do a lot of work in _build() so we can work with the stuff in
 * /deprecated to support the vips7 API. We could get rid of most of this
 * stuff if we were vips8-only.
 */

static int
vips_image_build( VipsObject *object )
{
	VipsImage *image = VIPS_IMAGE( object );
	const char *filename = image->filename;
	const char *mode = image->mode;

	guint32 magic;
	guint64 sizeof_image;

	VIPS_DEBUG_MSG( "vips_image_build: %p\n", image );

	if( VIPS_OBJECT_CLASS( vips_image_parent_class )->build( object ) )
		return( -1 );

	/* Parse the mode string.
	 */
	switch( mode[0] ) {
        case 'v':
		/* Used by 'r' for native open of vips, see below. Also by
		 * vips_image_rewind_output().
		 */
		if( vips_image_open_input( image ) )
			return( -1 );

		break;

        case 'r':
		if( (magic = vips__file_magic( filename )) ) {
			/* We may need to byteswap.
			 */
			if( GUINT_FROM_BE( magic ) == image->magic ) {
				/* Native open.
				 */
				if( vips_image_open_input( image ) )
					return( -1 );
			}
			else {
				VipsImage *t; 
				VipsImage *t2;

				/* Open the image in t, then byteswap to this
				 * image.
				 */
				if( !(t = vips_image_new_mode( filename, 
					"v" )) )
					return( -1 );

				if( vips_byteswap( t, &t2, NULL ) ) {
					g_object_unref( t );
					return( -1 );
				}
				g_object_unref( t );

				image->dtype = VIPS_IMAGE_PARTIAL;
				if( vips_image_write( t2, image ) ) {
					g_object_unref( t2 );
					return( -1 );
				}
				g_object_unref( t2 );
			}
		}
		else {
			VipsImage *t;

			if( mode[1] == 's' ) {
				if( vips_foreign_load( filename, &t, 
					"access", VIPS_ACCESS_SEQUENTIAL,
					NULL ) )
					return( -1 );
			}
			else {
				if( vips_foreign_load( filename, &t, NULL ) )
					return( -1 );
			}

			image->dtype = VIPS_IMAGE_PARTIAL;
			if( vips_image_write( t, image ) ) {
				g_object_unref( t );
				return( -1 );
			}
			g_object_unref( t );
		}

        	break;

	case 'w':
{
		const char *file_op;

		/* Make sure the vips saver is there ... strange things will
		 * happen if this type is renamed or removed.
		 */
		g_assert( g_type_from_name( "VipsForeignSaveVips" ) );

		if( !(file_op = vips_foreign_find_save( filename )) )
			return( -1 );

		/* If this is the vips saver, just save directly ourselves.
		 * Otherwise save with VipsForeign when the image has been 
		 * written to.
		 */
		if( vips_isprefix( "VipsForeignSaveVips", file_op ) )
			image->dtype = VIPS_IMAGE_OPENOUT;
		else {
			image->dtype = VIPS_IMAGE_PARTIAL;
			g_signal_connect( image, "written", 
				G_CALLBACK( vips_image_save_cb ), 
				NULL );
		}
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
		if( (image->fd = vips__open_image_read( filename )) == -1 ) 
			return( -1 );
		image->dtype = VIPS_IMAGE_OPENIN;
		image->dhint = VIPS_DEMAND_STYLE_THINSTRIP;

		if( image->Bands == 1 )
			image->Type = VIPS_INTERPRETATION_B_W;
		else if( image->Bands == 3 )
			image->Type = VIPS_INTERPRETATION_sRGB;
		else 
			image->Type = VIPS_INTERPRETATION_MULTIBAND;

		/* Read the real file length and check against what we think 
		 * the size should be.
		 */
		if( (image->file_length = vips_file_length( image->fd )) == -1 )
			return( -1 );

		/* Very common, so a special message.
		 */
		sizeof_image = VIPS_IMAGE_SIZEOF_IMAGE( image ) + 
			image->sizeof_header;
		if( image->file_length < sizeof_image ) {
			vips_error( "VipsImage", 
				_( "unable to open \"%s\", file too short" ), 
				image->filename );
			return( -1 );
		}

		/* Just weird. Only print a warning for this, since we should
		 * still be able to process it without coredumps.
		 */
		if( image->file_length > sizeof_image ) 
			g_warning( _( "%s is longer than expected" ),
				image->filename );
		break;

	case 'm':
		if( image->Bands == 1 )
			image->Type = VIPS_INTERPRETATION_B_W;
		else if( image->Bands == 3 )
			image->Type = VIPS_INTERPRETATION_sRGB;
		else 
			image->Type = VIPS_INTERPRETATION_MULTIBAND;

		image->dtype = VIPS_IMAGE_SETBUF_FOREIGN;
		image->dhint = VIPS_DEMAND_STYLE_ANY;

		break;

	default:
		vips_error( "VipsImage", _( "bad mode \"%s\"" ), mode );

		return( -1 );
        }

	vips_image_add_progress( image );

	return( 0 );
}

static void *
vips_image_real_invalidate_cb( VipsRegion *reg, void *a, void *b )
{
	vips_region_invalidate( reg );

	return( NULL );
}

static void 
vips_image_real_invalidate( VipsImage *image, void *data )
{
	VIPS_DEBUG_MSG( "vips_image_real_invalidate: %p\n", image );

	VIPS_GATE_START( "vips_image_real_invalidate: wait" );

	g_mutex_lock( image->sslock );

	VIPS_GATE_STOP( "vips_image_real_invalidate: wait" );

	(void) vips_slist_map2( image->regions,
		(VipsSListMap2Fn) vips_image_real_invalidate_cb, NULL, NULL );

	g_mutex_unlock( image->sslock );
}

static void 
vips_image_real_minimise( VipsImage *image, void *data )
{
	VIPS_DEBUG_MSG( "vips_image_real_minimise: %p\n", image );
}

static void 
vips_image_real_written( VipsImage *image, int *result, void *data )
{
	VIPS_DEBUG_MSG( "vips_image_real_written: %p\n", image );

	/* For vips image write, append the xml after the data.
	 */
	if( image->dtype == VIPS_IMAGE_OPENOUT &&
		vips__writehist( image ) ) 
		*result = -1;
}

static void
vips_image_class_init( VipsImageClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	VIPS_DEBUG_MSG( "vips_image_class_init:\n" );

	/* We must have threads set up before we can process.
	 */
	vips_check_init(); 

	gobject_class->finalize = vips_image_finalize;
	gobject_class->dispose = vips_image_dispose;
	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->new_from_string = vips_image_new_from_file_object;
	vobject_class->to_string = vips_image_to_string;
	vobject_class->output_needs_arg = TRUE;
	vobject_class->output_to_arg = vips_image_write_object;

	vobject_class->nickname = "image";
	vobject_class->description = _( "image class" );

	vobject_class->dump = vips_image_dump;
	vobject_class->summary = vips_image_summary;
	vobject_class->sanity = vips_image_sanity;
	vobject_class->rewind = vips_image_rewind;
	vobject_class->build = vips_image_build;

	class->invalidate = vips_image_real_invalidate;
	class->written = vips_image_real_written;
	class->minimise = vips_image_real_minimise;

	/* Create properties.
	 */

	/* It'd be good to have these as set once at construct time, but we
	 * can't :-( 
	 *
	 * For example, a "p" image might be made with vips_image_new() and
	 * constructed, then passed to vips_copy() of whatever to be written to.
	 * That operation will then need to set width/height etc.
	 *
	 * We can't set_once either, since vips_copy() etc. need to update
	 * xoffset and friends on the way through.
	 */

	VIPS_ARG_INT( class, "width", 2, 
		_( "Width" ), 
		_( "Image width in pixels" ),
		VIPS_ARGUMENT_SET_ALWAYS,
		G_STRUCT_OFFSET( VipsImage, Xsize ),
		1, VIPS_MAX_COORD, 1 );

	VIPS_ARG_INT( class, "height", 3, 
		_( "Height" ), 
		_( "Image height in pixels" ),
		VIPS_ARGUMENT_SET_ALWAYS,
		G_STRUCT_OFFSET( VipsImage, Ysize ),
		1, VIPS_MAX_COORD, 1 );

	VIPS_ARG_INT( class, "bands", 4, 
		_( "Bands" ), 
		_( "Number of bands in image" ),
		VIPS_ARGUMENT_SET_ALWAYS,
		G_STRUCT_OFFSET( VipsImage, Bands ),
		1, VIPS_MAX_COORD, 1 );

	VIPS_ARG_ENUM( class, "format", 5, 
		_( "Format" ), 
		_( "Pixel format in image" ),
		VIPS_ARGUMENT_SET_ALWAYS,
		G_STRUCT_OFFSET( VipsImage, BandFmt ),
		VIPS_TYPE_BAND_FORMAT, VIPS_FORMAT_UCHAR ); 

	VIPS_ARG_ENUM( class, "coding", 6, 
		_( "Coding" ), 
		_( "Pixel coding" ),
		VIPS_ARGUMENT_SET_ALWAYS,
		G_STRUCT_OFFSET( VipsImage, Coding ),
		VIPS_TYPE_CODING, VIPS_CODING_NONE ); 

	VIPS_ARG_ENUM( class, "interpretation", 7, 
		_( "Interpretation" ), 
		_( "Pixel interpretation" ),
		VIPS_ARGUMENT_SET_ALWAYS,
		G_STRUCT_OFFSET( VipsImage, Type ),
		VIPS_TYPE_INTERPRETATION, VIPS_INTERPRETATION_MULTIBAND ); 

	VIPS_ARG_DOUBLE( class, "xres", 8, 
		_( "Xres" ), 
		_( "Horizontal resolution in pixels/mm" ),
		VIPS_ARGUMENT_SET_ALWAYS,
		G_STRUCT_OFFSET( VipsImage, Xres ),
		-0.0, 1000000, 0 );

	VIPS_ARG_DOUBLE( class, "yres", 9, 
		_( "Yres" ), 
		_( "Vertical resolution in pixels/mm" ),
		VIPS_ARGUMENT_SET_ALWAYS,
		G_STRUCT_OFFSET( VipsImage, Yres ),
		-0.0, 1000000, 0 );

	VIPS_ARG_INT( class, "xoffset", 10, 
		_( "Xoffset" ), 
		_( "Horizontal offset of origin" ),
		VIPS_ARGUMENT_SET_ALWAYS,
		G_STRUCT_OFFSET( VipsImage, Xoffset ),
		-VIPS_MAX_COORD, VIPS_MAX_COORD, 0 );

	VIPS_ARG_INT( class, "yoffset", 11, 
		_( "Yoffset" ), 
		_( "Vertical offset of origin" ),
		VIPS_ARGUMENT_SET_ALWAYS,
		G_STRUCT_OFFSET( VipsImage, Yoffset ),
		-VIPS_MAX_COORD, VIPS_MAX_COORD, 0 );

	VIPS_ARG_STRING( class, "filename", 12, 
		_( "Filename" ),
		_( "Image filename" ),
		VIPS_ARGUMENT_SET_ONCE | VIPS_ARGUMENT_CONSTRUCT, 
		G_STRUCT_OFFSET( VipsImage, filename ),
		NULL );

	VIPS_ARG_STRING( class, "mode", 13, 
		_( "Mode" ),
		_( "Open mode" ),
		VIPS_ARGUMENT_SET_ONCE | VIPS_ARGUMENT_CONSTRUCT, 
		G_STRUCT_OFFSET( VipsImage, mode ),
		"p" );

	VIPS_ARG_BOOL( class, "kill", 14, 
		_( "Kill" ),
		_( "Block evaluation on this image" ),
		VIPS_ARGUMENT_SET_ALWAYS, 
		G_STRUCT_OFFSET( VipsImage, kill ),
		FALSE );

	VIPS_ARG_ENUM( class, "demand", 15, 
		_( "Demand style" ), 
		_( "Preferred demand style for this image" ),
		VIPS_ARGUMENT_CONSTRUCT,
		G_STRUCT_OFFSET( VipsImage, dhint ),
		VIPS_TYPE_DEMAND_STYLE, VIPS_DEMAND_STYLE_SMALLTILE );

	VIPS_ARG_UINT64( class, "sizeof_header", 16, 
		_( "Size of header" ), 
		_( "Offset in bytes from start of file" ),
		VIPS_ARGUMENT_SET_ONCE | VIPS_ARGUMENT_CONSTRUCT, 
		G_STRUCT_OFFSET( VipsImage, sizeof_header ),
		0, 1000000000, VIPS_SIZEOF_HEADER );

	VIPS_ARG_POINTER( class, "foreign_buffer", 17, 
		_( "Foreign buffer" ),
		_( "Pointer to foreign pixels" ),
		VIPS_ARGUMENT_SET_ONCE | VIPS_ARGUMENT_CONSTRUCT, 
		G_STRUCT_OFFSET( VipsImage, data ) );

	/* Create signals.
	 */

	/**
	 * VipsImage::preeval:
	 * @image: the image to be calculated
	 * @progress: #VipsProgress for this image
	 *
	 * The ::preeval signal is emitted once before computation of @image
	 * starts. It's a good place to set up evaluation feedback.
	 *
	 * Use vips_image_set_progress() to turn on progress reporting for an
	 * image. 
	 */
	vips_image_signals[SIG_PREEVAL] = g_signal_new( "preeval",
		G_TYPE_FROM_CLASS( class ),
		G_SIGNAL_RUN_LAST,
		G_STRUCT_OFFSET( VipsImageClass, preeval ), 
		NULL, NULL,
		g_cclosure_marshal_VOID__POINTER,
		G_TYPE_NONE, 1,
		G_TYPE_POINTER );

	/**
	 * VipsImage::eval:
	 * @image: the image being calculated
	 * @progress: #VipsProgress for this image
	 *
	 * The ::eval signal is emitted once per work unit (typically a 128 x
	 * 128 area of pixels) during image computation. 
	 *
	 * You can use this signal to update user-interfaces with progress
	 * feedback. Beware of updating too frequently: you will usually
	 * need some throttling mechanism.
	 *
	 * Use vips_image_set_progress() to turn on progress reporting for an
	 * image. 
	 */
	vips_image_signals[SIG_EVAL] = g_signal_new( "eval",
		G_TYPE_FROM_CLASS( class ),
		G_SIGNAL_RUN_LAST,
		G_STRUCT_OFFSET( VipsImageClass, eval ), 
		NULL, NULL,
		g_cclosure_marshal_VOID__POINTER,
		G_TYPE_NONE, 1,
		G_TYPE_POINTER );

	/**
	 * VipsImage::posteval:
	 * @image: the image that was calculated
	 * @progress: #VipsProgress for this image
	 *
	 * The ::posteval signal is emitted once at the end of the computation 
	 * of @image. It's a good place to shut down evaluation feedback.
	 *
	 * Use vips_image_set_progress() to turn on progress reporting for an
	 * image. 
	 */
	vips_image_signals[SIG_POSTEVAL] = g_signal_new( "posteval",
		G_TYPE_FROM_CLASS( class ),
		G_SIGNAL_RUN_LAST,
		G_STRUCT_OFFSET( VipsImageClass, posteval ), 
		NULL, NULL,
		g_cclosure_marshal_VOID__POINTER,
		G_TYPE_NONE, 1,
		G_TYPE_POINTER );

	/**
	 * VipsImage::written:
	 * @image: the image that was calculated
	 * @result: set to non-zero to indicate error
	 *
	 * The ::written signal is emitted just after an image has been 
	 * written to. It is
	 * used by vips to implement things like write to foreign file
	 * formats. 
	 */
	vips_image_signals[SIG_WRITTEN] = g_signal_new( "written",
		G_TYPE_FROM_CLASS( class ),
		G_SIGNAL_RUN_LAST | G_SIGNAL_ACTION,
		G_STRUCT_OFFSET( VipsImageClass, written ), 
		NULL, NULL,
		g_cclosure_marshal_VOID__POINTER,
		G_TYPE_NONE, 1,
		G_TYPE_POINTER );

	/**
	 * VipsImage::invalidate:
	 * @image: the image that has changed
	 *
	 * The ::invalidate signal is emitted when an image or one of it's
	 * upstream data sources has been destructively modified. See
	 * vips_image_invalidate_all().
	 */
	vips_image_signals[SIG_INVALIDATE] = g_signal_new( "invalidate",
		G_TYPE_FROM_CLASS( class ),
		G_SIGNAL_RUN_LAST | G_SIGNAL_ACTION,
		G_STRUCT_OFFSET( VipsImageClass, invalidate ), 
		NULL, NULL,
		g_cclosure_marshal_VOID__VOID,
		G_TYPE_NONE, 0 );

	/**
	 * VipsImage::minimise:
	 * @image: the image that is being minimised
	 *
	 * The ::minimise signal is emitted when an image has been asked to
	 * minimise memory usage. All non-essential caches are dropped. 
	 * See vips_image_minimise_all().
	 */
	vips_image_signals[SIG_MINIMISE] = g_signal_new( "minimise",
		G_TYPE_FROM_CLASS( class ),
		G_SIGNAL_RUN_LAST | G_SIGNAL_ACTION,
		G_STRUCT_OFFSET( VipsImageClass, minimise ), 
		NULL, NULL,
		g_cclosure_marshal_VOID__VOID,
		G_TYPE_NONE, 0 );

	vips__minimise_lock = vips_g_mutex_new();
}

static void
vips_image_init( VipsImage *image )
{
	VIPS_DEBUG_MSG( "vips_image_init: %p\n", image );

	/* Default to native order.
	 */
	image->magic = vips_amiMSBfirst() ? VIPS_MAGIC_SPARC : VIPS_MAGIC_INTEL;

	image->Xsize = 1;
	image->Ysize = 1;
	image->Bands = 1;

	image->Xres = 1.0;
	image->Yres = 1.0;

	image->fd = -1;			/* since 0 is stdout */
	image->sslock = vips_g_mutex_new();

	image->sizeof_header = VIPS_SIZEOF_HEADER;

	image->mode = g_strdup( "p" );

#ifdef DEBUG_LEAK
	g_object_set_qdata_full( G_OBJECT( image ), vips__image_pixels_quark, 
		g_new0( VipsImagePixels, 1 ), (GDestroyNotify) g_free ); 
#endif /*DEBUG_LEAK*/
}

int
vips_image_written( VipsImage *image )
{
	int result;

	VIPS_DEBUG_MSG( "vips_image_written: %p\n", image );

	result = 0;
	g_signal_emit( image, vips_image_signals[SIG_WRITTEN], 0, &result );

	return( result );
}

void
vips_image_invalidate( VipsImage *image )
{
	VIPS_DEBUG_MSG( "vips_image_invalidate: %p\n", image );

	g_signal_emit( image, vips_image_signals[SIG_INVALIDATE], 0 );
}

static void *
vips_image_invalidate_all_cb( VipsImage *image, void *a, void *b )
{
	vips_image_invalidate( image );

	return( NULL );
}

/**
 * vips_image_invalidate_all: (method)
 * @image: #VipsImage to invalidate
 *
 * Invalidate all pixel caches on @image and any downstream images, that
 * is, images which depend on this image. Additionally, all operations which
 * depend upon this image are dropped from the VIPS operation cache. 
 *
 * You should call this function after
 * destructively modifying an image with something like vips_draw_circle().
 *
 * The #VipsImage::invalidate signal is emitted for all invalidated images.
 *
 * See also: vips_region_invalidate().
 */
void
vips_image_invalidate_all( VipsImage *image )
{
	VIPS_DEBUG_MSG( "vips_image_invalidate_all: %p\n", image );

	(void) vips__link_map( image, FALSE,
		(VipsSListMap2Fn) vips_image_invalidate_all_cb, NULL, NULL );
}

void
vips_image_minimise( VipsImage *image )
{
	VIPS_DEBUG_MSG( "vips_image_minimise: %p\n", image );

	g_signal_emit( image, vips_image_signals[SIG_MINIMISE], 0 );
}

static void *
vips_image_minimise_all_cb( VipsImage *image, void *a, void *b )
{
	vips_image_minimise( image );

	return( NULL );
}

/**
 * vips_image_minimise_all: (method)
 * @image: #VipsImage to minimise
 *
 * Minimise memory use on this image and any upstream images, that is, images
 * which this image depends upon. This function is called automatically at the
 * end of a computation, but it might be useful to call at other times. 
 *
 * The #VipsImage::minimise signal is emitted for all minimised images.
 */
void 
vips_image_minimise_all( VipsImage *image )
{
	/* Minimisation will modify things like sources, so we can't run it
	 * from many threads.
	 */
	g_mutex_lock( vips__minimise_lock );

	(void) vips__link_map( image, TRUE,
		(VipsSListMap2Fn) vips_image_minimise_all_cb, NULL, NULL );

	g_mutex_unlock( vips__minimise_lock );
}

/**
 * vips_image_is_sequential: (method)
 * @image: #VipsImage to minimise
 *
 * TRUE if any of the images upstream from @image were opened in sequential
 * mode. Some operations change behaviour slightly in sequential mode to
 * optimize memory behaviour.
 *
 * Returns: %TRUE if @image is in sequential mode.
 */
gboolean
vips_image_is_sequential( VipsImage *image )
{
	return( vips_image_get_typeof( image, VIPS_META_SEQUENTIAL ) );
}

/* Attach a new time struct, if necessary, and reset it.
 */
static int
vips_progress_add( VipsImage *image )
{
	VipsProgress *progress;

	VIPS_DEBUG_MSG( "vips_progress_add: %p\n", image );

	if( !(progress = image->time) ) {
		if( !(image->time = VIPS_NEW( NULL, VipsProgress )) )
			return( -1 );
		progress = image->time;

		progress->im = image;
		progress->start = NULL;
	}

	if( !progress->start )
		progress->start = g_timer_new();

	g_timer_start( progress->start );
	progress->run = 0;
	progress->eta = 0;
	progress->tpels = VIPS_IMAGE_N_PELS( image );
	progress->npels = 0;
	progress->percent = 0;

	return( 0 );
}

static void
vips_progress_update( VipsProgress *progress, guint64 processed )
{
	float prop;

	VIPS_DEBUG_MSG( "vips_progress_update: %p\n", progress );

	g_assert( progress );

	progress->run = g_timer_elapsed( progress->start, NULL );
	progress->npels = processed;
	prop = (float) progress->npels / (float) progress->tpels;
	progress->percent = 100 * prop;

	/* Don't estimate eta until we are 10% in.
	 */
	if( prop > 0.1 ) 
		progress->eta = (1.0 / prop) * progress->run - progress->run;
}

void
vips_image_preeval( VipsImage *image )
{
	if( image->progress_signal ) {
		VIPS_DEBUG_MSG( "vips_image_preeval: %p\n", image );

		g_assert( vips_object_sanity( 
			VIPS_OBJECT( image->progress_signal ) ) );

		(void) vips_progress_add( image );

		/* For vips7 compat, we also have to make sure ->time on the
		 * image that was originally marked with 
		 * vips_image_set_progress() is valid.
		 */
		(void) vips_progress_add( image->progress_signal );

		if( !vips_image_get_typeof( image, "hide-progress" ) )
			g_signal_emit( image->progress_signal, 
				vips_image_signals[SIG_PREEVAL], 0, 
				image->time );
	}
}

/* Updated the number of pixels that have been processed.
 */
void
vips_image_eval( VipsImage *image, guint64 processed )
{
	if( image->progress_signal &&
		image->time ) {
		VIPS_DEBUG_MSG( "vips_image_eval: %p\n", image );

		g_assert( vips_object_sanity( 
			VIPS_OBJECT( image->progress_signal ) ) );

		vips_progress_update( image->time, processed );

		/* For vips7 compat, update the ->time on the signalling image
		 * too, even though it may have a different width/height to
		 * the image we are actually generating.
		 */
		if( image->progress_signal->time != image->time )
			vips_progress_update( image->progress_signal->time, 
				processed );

		if( !vips_image_get_typeof( image, "hide-progress" ) )
			g_signal_emit( image->progress_signal, 
				vips_image_signals[SIG_EVAL], 0, 
				image->time );
	}
}

void
vips_image_posteval( VipsImage *image )
{
	if( image->progress_signal &&
		image->progress_signal->time ) { 
		VIPS_DEBUG_MSG( "vips_image_posteval: %p\n", image );

		g_assert( vips_object_sanity( 
			VIPS_OBJECT( image->progress_signal ) ) );

		if( !vips_image_get_typeof( image, "hide-progress" ) )
			g_signal_emit( image->progress_signal, 
				vips_image_signals[SIG_POSTEVAL], 0, 
				image->time );
	}
}

/**
 * vips_image_set_progress: (method)
 * @image: image to signal progress on
 * @progress: turn progress reporting on or off
 *
 * vips signals evaluation progress via the #VipsImage::preeval, 
 * #VipsImage::eval and #VipsImage::posteval
 * signals. Progress is signalled on the most-downstream image for which
 * vips_image_set_progress() was called.
 */
void
vips_image_set_progress( VipsImage *image, gboolean progress )
{
	if( progress && 
		!image->progress_signal ) {
		VIPS_DEBUG_MSG( "vips_image_set_progress: %p %s\n", 
			image, image->filename );
		image->progress_signal = image;
	}
	else if( !progress )
		image->progress_signal = NULL;
}

/**
 * vips_image_iskilled: (method)
 * @image: image to test
 *
 * If @image has been killed (see vips_image_set_kill()), set an error message,
 * clear the #VipsImage.kill flag and return %TRUE. Otherwise return %FALSE.
 *
 * Handy for loops which need to run sets of threads which can fail. 
 *
 * See also: vips_image_set_kill().
 *
 * Returns: %TRUE if @image has been killed. 
 */
gboolean
vips_image_iskilled( VipsImage *image )
{
	gboolean kill;

	kill = image->kill;

	/* Has kill been set for this image? If yes, abort evaluation.
	 */
	if( image->kill ) {
		VIPS_DEBUG_MSG( "vips_image_iskilled: %s (%p) killed\n", 
			image->filename, image );
		vips_error( "VipsImage", 
			_( "killed for image \"%s\"" ), image->filename );

		/* We've picked up the kill message, it's now our caller's
		 * responsibility to pass the message up the chain.
		 */
		vips_image_set_kill( image, FALSE );
	}

	return( kill );
}

/**
 * vips_image_set_kill: (method)
 * @image: image to test
 * @kill: the kill state
 *
 * Set the #VipsImage.kill flag on an image. Handy for stopping sets of
 * threads. 
 *
 * See also: vips_image_iskilled().
 */
void
vips_image_set_kill( VipsImage *image, gboolean kill )
{
	if( image->kill != kill ) 
		VIPS_DEBUG_MSG( "vips_image_set_kill: %s (%p) %d\n", 
			image->filename, image, kill );

	image->kill = kill;
}

/* Fills the given buffer with a temporary filename.
 * Assuming that "int" might be 64 Bit wide a buffer size of 26 suffices.
 */
void
vips_image_temp_name( char *name, int size )
{
	static int global_serial = 0;

	int serial = g_atomic_int_add( &global_serial, 1 );

	vips_snprintf( name, size, "temp-%d", serial );
}

/**
 * vips_image_new: (constructor)
 *
 * vips_image_new() creates a new, empty #VipsImage. 
 * If you write to one of these images, vips will just attach some callbacks,
 * no pixels will be generated. 
 *
 * Write pixels to an image with vips_image_generate() or 
 * vips_image_write_line(). Write a whole image to another image with
 * vips_image_write(). 
 *
 * Returns: (transfer full): the new #VipsImage, or %NULL on error.
 */
VipsImage *
vips_image_new( void )
{
	VipsImage *image;
	char filename[26];

	vips_check_init();

	vips_image_temp_name( filename, sizeof( filename ) );

	image = VIPS_IMAGE( g_object_new( VIPS_TYPE_IMAGE, NULL ) );
	g_object_set( image,
		"filename", filename,
		"mode", "p",
		NULL );
	if( vips_object_build( VIPS_OBJECT( image ) ) ) {
		VIPS_UNREF( image );
		return( NULL );
	}

	return( image ); 
}

VipsImage *
vips_image_new_mode( const char *filename, const char *mode )
{
	VipsImage *image;

	g_assert( filename );
	g_assert( mode );

	vips_check_init();

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
 * vips_image_new_memory: (constructor)
 *
 * vips_image_new_memory() creates a new #VipsImage which, when written to, will
 * create a memory image. 
 *
 * See also: vips_image_new().
 *
 * Returns: (transfer full): the new #VipsImage, or %NULL on error.
 */
VipsImage *
vips_image_new_memory( void )
{
	char filename[26];

	vips_image_temp_name( filename, sizeof( filename ) );
	return( vips_image_new_mode( filename, "t" ) );
}

/**
 * vips_image_memory: (constructor)
 *
 * A renamed vips_image_new_memory() ... Some gobject binding systems do not 
 * like more than one _new() method.
 *
 * See also: vips_image_new_memory().
 *
 * Returns: (transfer full): the new #VipsImage, or %NULL on error.
 */
VipsImage *
vips_image_memory( void )
{
	return( vips_image_new_memory() ); 
}

/**
 * vips_filename_get_filename:
 * @vips_filename: a filename including a set of options
 *
 * Given a vips filename like "fred.jpg[Q=90]", return a new string of
 * just the filename part, "fred.jpg" in this case. 
 *
 * Useful for language bindings. 
 *
 * See also: vips_filename_get_options().
 *
 * Returns: transfer full: just the filename component.
 */
char *
vips_filename_get_filename( const char *vips_filename )
{
	char filename[VIPS_PATH_MAX];
	char options[VIPS_PATH_MAX];

	vips__filename_split8( vips_filename, filename, options ); 

	return( g_strdup( filename ) );
}

/**
 * vips_filename_get_options:
 * @vips_filename: a filename including a set of options
 *
 * Given a vips filename like "fred.jpg[Q=90]", return a new string of
 * just the options part, "[Q=90]" in this case. 
 *
 * Useful for language bindings. 
 *
 * See also: vips_filename_get_filename().
 *
 * Returns: transfer full: just the options component.
 */
char *
vips_filename_get_options( const char *vips_filename )
{
	char filename[VIPS_PATH_MAX];
	char options[VIPS_PATH_MAX];

	vips__filename_split8( vips_filename, filename, options ); 

	return( g_strdup( options ) );
}

/**
 * vips_image_new_from_file: (constructor)
 * @name: file to open
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @access: hint #VipsAccess mode to loader
 * * @memory: force load via memory 
 *
 * vips_image_new_from_file() opens @name for reading. It can load files
 * in many image formats, including VIPS, TIFF, PNG, JPEG, FITS, Matlab,
 * OpenEXR, CSV, WebP, Radiance, RAW, PPM and others. 
 *
 * Load options may be appended to @filename as "[name=value,...]" or given as
 * a NULL-terminated list of name-value pairs at the end of the arguments.
 * Options given in the function call override options given in the filename. 
 * Many loaders add extra options, see vips_jpegload(), for example. 
 *
 * vips_image_new_from_file() always returns immediately with the header
 * fields filled in. No pixels are actually read until you first access them. 
 *
 * @access lets you set a #VipsAccess hint giving the expected access pattern 
 * for this file.
 * #VIPS_ACCESS_RANDOM means you can fetch pixels randomly from the image.
 * This is the default mode. #VIPS_ACCESS_SEQUENTIAL means you will read the
 * whole image exactly once, top-to-bottom. In this mode, vips can avoid
 * converting the whole image in one go, for a large memory saving. You are
 * allowed to make small non-local references, so area operations like 
 * convolution will work. 
 *
 * In #VIPS_ACCESS_RANDOM mode, small images are decompressed to memory and
 * then processed from there. Large images are decompressed to temporary
 * random-access files on disc and then processed from there. 
 *
 * Set @memory to %TRUE to force loading via memory. The default is to load 
 * large random access images via temporary disc files. See 
 * vips_image_new_temp_file() for an 
 * explanation of how VIPS selects a location for the temporary file.
 *
 * The disc threshold can be set with the "--vips-disc-threshold"
 * command-line argument, or the `VIPS_DISC_THRESHOLD` environment variable.
 * The value is a simple integer, but can take a unit postfix of "k", 
 * "m" or "g" to indicate kilobytes, megabytes or gigabytes.
 * The default threshold is 100 MB.
 *
 * For example:
 *
 * |[
 * VipsImage *image = vips_image_new_from_file ("fred.tif",
 * 	"page", 12,
 * 	NULL);
 * ]|
 *
 * Will open "fred.tif", reading page 12. 
 *
 * |[
 * VipsImage *image = vips_image_new_from_file ("fred.jpg[shrink=2]",
 * 	NULL);
 * ]|
 *
 * Will open "fred.jpg", downsampling by a factor of two. 
 *
 * Use vips_foreign_find_load() or vips_foreign_is_a() to see what format a 
 * file is in and therefore what options are available. If you need more 
 * control over the loading process, you can call loaders directly, see 
 * vips_jpegload(), for example. 
 *
 * See also: vips_foreign_find_load(), vips_foreign_is_a(), 
 * vips_image_write_to_file().
 *
 * Returns: (transfer full): the new #VipsImage, or %NULL on error.
 */
VipsImage *
vips_image_new_from_file( const char *name, ... )
{
	char filename[VIPS_PATH_MAX];
	char option_string[VIPS_PATH_MAX];
	const char *operation_name;
	va_list ap;
	int result;
	VipsImage *out;

	vips_check_init();

	vips__filename_split8( name, filename, option_string );

	if( !(operation_name = vips_foreign_find_load( filename )) )
		return( NULL );

	va_start( ap, name );
	result = vips_call_split_option_string( operation_name, 
		option_string, ap, filename, &out );
	va_end( ap );

	if( result )
		return( NULL ); 

	return( out );
}

/**
 * vips_image_new_from_file_RW: (constructor)
 * @filename: filename to open
 *
 * Opens the named file for simultaneous reading and writing. This will only 
 * work for VIPS files in a format native to your machine. It is only for 
 * paintbox-type applications.
 *
 * See also: vips_draw_circle().
 *
 * Returns: (transfer full): the new #VipsImage, or %NULL on error.
 */
VipsImage *
vips_image_new_from_file_RW( const char *filename )
{
	return( vips_image_new_mode( filename, "rw" ) ); 
}

/**
 * vips_image_new_from_file_raw: (constructor)
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
 * vips_copy() to transform the descriptor after loading it.
 *
 * See also: vips_copy(), vips_rawload(), vips_image_new_from_file().
 *
 * Returns: (transfer full): the new #VipsImage, or %NULL on error.
 */
VipsImage *
vips_image_new_from_file_raw( const char *filename, 
	int xsize, int ysize, int bands, guint64 offset )
{
	VipsImage *image;

	vips_check_init();

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
 * vips_image_new_from_memory: (constructor)
 * @data: (array length=size) (element-type guint8) (transfer none): start of memory area
 * @size: (type gsize): length of memory area
 * @width: image width
 * @height: image height
 * @bands: image bands (or bytes per pixel)
 * @format: image format
 *
 * This function wraps a #VipsImage around a memory area. The memory area
 * must be a simple array, for example RGBRGBRGB, left-to-right,
 * top-to-bottom. Use vips_image_new_from_buffer() to load an area of memory
 * containing an image in a format.
 *
 * VIPS does not take
 * responsibility for the area of memory, it's up to you to make sure it's
 * freed when the image is closed. See for example #VipsObject::close.
 *
 * Because VIPS is "borrowing" @data from the caller, this function is
 * extremely dangerous. Unless you are very careful, you will get crashes or
 * memory corruption. Use vips_image_new_from_memory_copy() instead if you are
 * at all unsure. 
 *
 * Use vips_copy() to set other image properties. 
 *
 * See also: vips_image_new(), vips_image_write_to_memory(),
 * vips_image_new_from_memory_copy().
 *
 * Returns: (transfer full): the new #VipsImage, or %NULL on error.
 */
VipsImage *
vips_image_new_from_memory( const void *data, size_t size,
	int width, int height, int bands, VipsBandFormat format )
{
	VipsImage *image;
	char filename[26];

	vips_check_init();
	vips_image_temp_name( filename, sizeof( filename ) );

	image = VIPS_IMAGE( g_object_new( VIPS_TYPE_IMAGE, NULL ) );
	g_object_set( image,
		"filename", filename,
		"mode", "m",
		"foreign_buffer", data,
		"width", width,
		"height", height,
		"bands", bands,
		"format", format,
		NULL );
	if( vips_object_build( VIPS_OBJECT( image ) ) ) {
		VIPS_UNREF( image );
		return( NULL );
	}

	if( size < VIPS_IMAGE_SIZEOF_IMAGE( image ) ) {
		vips_error( "VipsImage",
			_( "memory area too small --- "
				"should be %" G_GINT64_FORMAT " bytes, "
				"you passed %zd" ),
			VIPS_IMAGE_SIZEOF_IMAGE( image ), size ); 
		VIPS_UNREF( image );
		return( NULL );
	}

	return( image );
}

static void
vips_image_new_from_memory_copy_cb( VipsImage *image, void *data_copy )
{
	vips_tracked_free( data_copy );
}

/**
 * vips_image_new_from_memory_copy: (constructor)
 * @data: (array length=size) (element-type guint8) (transfer none): start of memory area
 * @size: (type gsize): length of memory area
 * @width: image width
 * @height: image height
 * @bands: image bands (or bytes per pixel)
 * @format: image format
 *
 * Like vips_image_new_from_memory(), but VIPS will make a copy of the memory 
 * area. This means more memory use and an extra copy operation, but is much 
 * simpler and safer. 
 *
 * See also: vips_image_new_from_memory().
 *
 * Returns: (transfer full): the new #VipsImage, or %NULL on error.
 */
VipsImage *
vips_image_new_from_memory_copy( const void *data, size_t size,
	int width, int height, int bands, VipsBandFormat format )
{
	void *data_copy;
	VipsImage *image;

	vips_check_init();

	if( !(data_copy = vips_tracked_malloc( size )) )
		return( NULL );
	memcpy( data_copy, data, size );
	if( !(image = vips_image_new_from_memory( data_copy, size, 
		width, height, bands, format )) ) {
		vips_tracked_free( data_copy );
		return( NULL );
	}

	g_signal_connect( image, "close", 
		G_CALLBACK( vips_image_new_from_memory_copy_cb ), data_copy );

	return( image );
}

/**
 * vips_image_new_from_buffer: (constructor)
 * @buf: (array length=len) (element-type guint8) (transfer none): image data
 * @len: (type gsize): length of memory buffer
 * @option_string: set of extra options as a string
 * @...: %NULL-terminated list of optional named arguments
 *
 * Loads an image from the formatted area of memory @buf, @len using the 
 * loader recommended by vips_foreign_find_load_buffer(). 
 * To load an unformatted area of memory, use
 * vips_image_new_from_memory(). 
 *
 * VIPS does not take
 * responsibility for the area of memory, it's up to you to make sure it's
 * freed when the image is closed. See for example #VipsObject::close.
 *
 * Load options may be given in @option_string as "[name=value,...]" or given as
 * a NULL-terminated list of name-value pairs at the end of the arguments.
 * Options given in the function call override options given in the filename. 
 *
 * See also: vips_image_write_to_buffer().
 *
 * Returns: (transfer full): the new #VipsImage, or %NULL on error.
 */
VipsImage *
vips_image_new_from_buffer( const void *buf, size_t len, 
	const char *option_string, ... )
{
	const char *operation_name;
	va_list ap;
	int result;
	VipsImage *out;
	VipsBlob *blob;

	vips_check_init();

	if( !(operation_name = 
		vips_foreign_find_load_buffer( buf, len )) )
		return( NULL );

	/* We don't take a copy of the data or free it.
	 */
	blob = vips_blob_new( NULL, buf, len );

	va_start( ap, option_string );
	result = vips_call_split_option_string( operation_name,
		option_string, ap, blob, &out );
	va_end( ap );

	vips_area_unref( VIPS_AREA( blob ) );

	if( result )
		return( NULL );

	return( out ); 
}

/**
 * vips_image_new_from_source: (constructor)
 * @source: (transfer none): source to fetch image from
 * @option_string: set of extra options as a string
 * @...: %NULL-terminated list of optional named arguments
 *
 * Loads an image from the formatted source @input, 
 * loader recommended by vips_foreign_find_load_source(). 
 *
 * Load options may be given in @option_string as "[name=value,...]" or given as
 * a NULL-terminated list of name-value pairs at the end of the arguments.
 * Options given in the function call override options given in the string. 
 *
 * See also: vips_image_write_to_target().
 *
 * Returns: (transfer full): the new #VipsImage, or %NULL on error.
 */
VipsImage *
vips_image_new_from_source( VipsSource *source, 
	const char *option_string, ... )
{
	const char *filename = 
		vips_connection_filename( VIPS_CONNECTION( source ) );

	const char *operation_name;
	va_list ap;
	int result;
	VipsImage *out;

	vips_check_init();

	vips_error_freeze();
	operation_name = vips_foreign_find_load_source( source );
	vips_error_thaw();

        if( operation_name ) { 
		va_start( ap, option_string );
		result = vips_call_split_option_string( operation_name,
			option_string, ap, source, &out );
		va_end( ap );
	}
	else if( filename ) {
		/* Try with the old file-based loaders.
		 */
		if( !(operation_name = vips_foreign_find_load( filename )) )
			return( NULL );

		va_start( ap, option_string );
		result = vips_call_split_option_string( operation_name, 
			option_string, ap, filename, &out );
		va_end( ap );
	}
	else if( vips_source_is_mappable( source ) ) {
		/* Try with the old buffer-based loaders.
		 */
		VipsBlob *blob;
		const void *buf;
		size_t len;

		if( !(blob = vips_source_map_blob( source )) )
			return( NULL );

		buf = vips_blob_get( blob, &len );
		if( !(operation_name = 
			vips_foreign_find_load_buffer( buf, len )) ) {
			vips_area_unref( VIPS_AREA( blob ) );
			return( NULL );
		}

                va_start( ap, option_string );
                result = vips_call_split_option_string( operation_name,
                        option_string, ap, blob, &out );
                va_end( ap );

		vips_area_unref( VIPS_AREA( blob ) );
	}
	else {
		vips_error( "VipsImage",
			"%s", _( "unable to load source" ) );
		result = -1;
	}

        if( result )
                return( NULL );

        return( out );
}

/**
 * vips_image_new_matrix: (constructor)
 * @width: image width
 * @height: image height
 *
 * This convenience function makes an image which is a matrix: a one-band
 * #VIPS_FORMAT_DOUBLE image held in memory.
 *
 * Use VIPS_IMAGE_ADDR(), or VIPS_MATRIX() to address pixels in the image.
 *
 * Use vips_image_set_double() to set "scale" and "offset", if required. 
 *
 * See also: vips_image_new_matrixv()
 * 
 * Returns: (transfer full): the new #VipsImage, or %NULL on error.
 */
VipsImage *
vips_image_new_matrix( int width, int height )
{
	VipsImage *image;

	vips_check_init();

	image = VIPS_IMAGE( g_object_new( VIPS_TYPE_IMAGE, NULL ) );
	g_object_set( image,
		"filename", "vips_image_new_matrix",
		"mode", "t",
		"width", width,
		"height", height,
		"bands", 1,
		"format", VIPS_FORMAT_DOUBLE,
		"interpretation", VIPS_INTERPRETATION_MATRIX,
		NULL );
	if( vips_object_build( VIPS_OBJECT( image ) ) ) {
		VIPS_UNREF( image );
		return( NULL );
	}

	if( vips_image_write_prepare( image ) ) {
		g_object_unref( image );
		return( NULL );
	}

	return( image );
}

/**
 * vips_image_new_matrixv: (constructor)
 * @width: image width
 * @height: image height
 * @...: matrix coefficients
 *
 * As vips_image_new_matrix(), but initialise the matrix from the argument
 * list. After @height should be @width * @height double constants which are
 * used to set the matrix elements. 
 *
 * See also: vips_image_new_matrix()
 * 
 * Returns: (transfer full): the new #VipsImage, or %NULL on error.
 */
VipsImage *
vips_image_new_matrixv( int width, int height, ... )
{
	va_list ap;
	VipsImage *matrix;
	int x, y;

	vips_check_init();

	matrix = vips_image_new_matrix( width, height ); 

	va_start( ap, height );
	for( y = 0; y < height; y++ )
		for( x = 0; x < width; x++ )
			*VIPS_MATRIX( matrix, x, y ) = va_arg( ap, double );
	va_end( ap );

	return( matrix ); 
}

/**
 * vips_image_new_matrix_from_array: (constructor)
 * @width: image width
 * @height: image height
 * @array: (array length=size) (transfer none): array of elements
 * @size: (type gsize): number of elements
 *
 * A binding-friendly version of vips_image_new_matrixv().
 *
 * Returns: (transfer full): the new #VipsImage, or %NULL on error.
 */
VipsImage *
vips_image_new_matrix_from_array( int width, int height, 
	const double *array, int size )
{
	VipsImage *matrix;
	int x, y;
	int i;

	if( size != width * height ) {
		vips_error( "VipsImage",
			_( "bad array length --- should be %d, you passed %d" ),
			width * height, size );
		return( NULL );
	}

	vips_check_init();

	matrix = vips_image_new_matrix( width, height ); 

	i = 0;
	for( y = 0; y < height; y++ )
		for( x = 0; x < width; x++ )
			*VIPS_MATRIX( matrix, x, y ) = array[i++];

	return( matrix ); 
}

/**
 * vips_image_matrix_from_array: (constructor)
 * @width: image width
 * @height: image height
 * @array: (array length=size) (transfer none): array of elements
 * @size: (type gsize): number of elements
 *
 * A renamed vips_image_new_matrix_from_array(). Some gobject bindings do not
 * like more than one _new method.
 *
 * Returns: (transfer full): the new #VipsImage, or %NULL on error.
 */
VipsImage *
vips_image_matrix_from_array( int width, int height, 
	const double *array, int size )
{
	return( vips_image_new_matrix_from_array( width, height, 
		array, size ) ); 
}

/**
 * vips_image_new_from_image: (constructor)
 * @image: image to copy
 * @c: (array length=n) (transfer none): array of constants
 * @n: number of constants
 *
 * Creates a new image with width, height, format, interpretation, resolution
 * and offset taken from @image, but with number of bands taken from @n and the
 * value of each band element set from @c.
 *
 * See also: vips_image_new_from_image1()
 *
 * Returns: (transfer full): the new #VipsImage, or %NULL on error.
 */
VipsImage *
vips_image_new_from_image( VipsImage *image, const double *c, int n )
{
	VipsObject *scope = (VipsObject *) vips_image_new();
	VipsImage **t = (VipsImage **) vips_object_local_array( scope, 5 );

	double *ones;
	int i;
	VipsImage *result;

	if( !(ones = VIPS_ARRAY( scope, n, double )) ) {
		g_object_unref( scope );
		return( NULL );
	}
	for( i = 0; i < n; i++ )
		ones[i] = 1.0;

	if( vips_black( &t[0], 1, 1, NULL ) ||
		vips_linear( t[0], &t[1], ones, (double *) c, n, NULL ) ||
		vips_cast( t[1], &t[2], image->BandFmt, NULL ) ||
		vips_embed( t[2], &t[3], 0, 0, image->Xsize, image->Ysize,
			"extend", VIPS_EXTEND_COPY, NULL ) ||
		vips_copy( t[3], &t[4], 
			"interpretation", image->Type,
			"xres", image->Xres,
			"yres", image->Yres,
			"xoffset", image->Xoffset,
			"yoffset", image->Yoffset,
			NULL ) ) {
		g_object_unref( scope );
		return( NULL );
	}

	result = t[4];
	g_object_ref( result );

	g_object_unref( scope );

	return( result ); 
}

/**
 * vips_image_new_from_image1: (constructor)
 * @image: image to copy
 * @c: constants
 *
 * Creates a new image with width, height, format, interpretation, resolution
 * and offset taken from @image, but with one band and each pixel having the
 * value @c.
 *
 * See also: vips_image_new_from_image()
 *
 * Returns: (transfer full): the new #VipsImage, or %NULL on error.
 */
VipsImage *
vips_image_new_from_image1( VipsImage *image, double c )
{
	return( vips_image_new_from_image( image, (const double *) &c, 1 ) );
}

/**
 * vips_image_set_delete_on_close: (method)
 * @image: image to set
 * @delete_on_close: format of file
 *
 * Sets the delete_on_close flag for the image. If this flag is set, when
 * @image is finalized, the filename held in @image->filename at the time of
 * this call is deleted.
 *
 * This function is clearly extremely dangerous, use with great caution.
 *
 * See also: vips_image_new_temp_file().
 */
void
vips_image_set_delete_on_close( VipsImage *image, gboolean delete_on_close )
{
	VIPS_DEBUG_MSG( "vips_image_set_delete_on_close: %d %s\n", 
			delete_on_close, image->filename );

	image->delete_on_close = delete_on_close;
	VIPS_FREE( image->delete_on_close_filename );
	if( delete_on_close ) 
		VIPS_SETSTR( image->delete_on_close_filename, image->filename );
}

/**
 * vips_get_disc_threshold:
 *
 * Return the number of bytes at which we flip between open via memory and
 * open via disc. This defaults to 100mb, but can be changed with the
 * VIPS_DISC_THRESHOLD environment variable or the --vips-disc-threshold
 * command-line flag. See vips_image_new_from_file(). 
 *
 * Returns: disc threshold in bytes.
 */
guint64
vips_get_disc_threshold( void )
{
	static gboolean done = FALSE;
	static guint64 threshold;

	if( !done ) {
		const char *env;

		done = TRUE;

		/* 100mb default.
		 */
		threshold = 100 * 1024 * 1024;

		if( (env = g_getenv( "VIPS_DISC_THRESHOLD" ))
#if ENABLE_DEPRECATED
			|| (env = g_getenv( "IM_DISC_THRESHOLD" ))
#endif
		  )
			threshold = vips__parse_size( env );

		if( vips__disc_threshold ) 
			threshold = vips__parse_size( vips__disc_threshold );

#ifdef DEBUG
		printf( "vips_get_disc_threshold: %zd bytes\n", threshold );
#endif /*DEBUG*/
	}

	return( threshold );
}

/**
 * vips_image_new_temp_file: (constructor)
 * @format: format of file
 *
 * Make a #VipsImage which, when written to, will create a temporary file on
 * disc. The file will be automatically deleted when the image is destroyed. 
 * @format is something like "&percnt;s.v" for a vips file.
 *
 * The file is created in the temporary directory. This is set with the
 * environment variable TMPDIR. If this is not set, then on Unix systems, vips
 * will default to /tmp. On Windows, vips uses GetTempPath() to find the
 * temporary directory. 
 *
 * See also: vips_image_new().
 *
 * Returns: the new #VipsImage, or %NULL on error.
 */
VipsImage *
vips_image_new_temp_file( const char *format )
{
	char *name;
	VipsImage *image;

	vips_check_init();

	if( !(name = vips__temp_name( format )) )
		return( NULL );

	if( !(image = vips_image_new_mode( name, "w" )) ) {
		g_free( name );
		return( NULL );
	}

	g_free( name );

	vips_image_set_delete_on_close( image, TRUE );

	return( image );
}

static int
vips_image_write_gen( VipsRegion *or, 
	void *seq, void *a, void *b, gboolean *stop )
{
	VipsRegion *ir = (VipsRegion *) seq;
	VipsRect *r = &or->valid;

	/*
	printf( "vips_image_write_gen: %p "
		"left = %d, top = %d, width = %d, height = %d\n",
		or->im,
		r->left, r->top, r->width, r->height ); 
	 */

	/* Copy with pointers.
	 */
	if( vips_region_prepare( ir, r ) ||
		vips_region_region( or, ir, r, r->left, r->top ) )
		return( -1 );

	return( 0 );
}

/**
 * vips_image_write: (method)
 * @image: image to write
 * @out: (out): write to this image
 *
 * Write @image to @out. Use vips_image_new() and friends to create the
 * #VipsImage you want to write to.
 *
 * See also: vips_image_new(), vips_copy(), vips_image_write_to_file().
 *
 * Returns: 0 on success, or -1 on error.
 */
int
vips_image_write( VipsImage *image, VipsImage *out )
{
	/* image needs to stay alive for this call. It can be unreffed during
	 * the generate.
	 */
	g_object_ref( image );

	if( vips_image_pio_input( image ) || 
		vips_image_pipelinev( out, 
			VIPS_DEMAND_STYLE_THINSTRIP, image, NULL ) ) {
		g_object_unref( image );
		return( -1 );
	}

	if( vips_image_generate( out,
		vips_start_one, vips_image_write_gen, vips_stop_one, 
		image, NULL ) ) {
		g_object_unref( image );
		return( -1 );
	}

	/* If @out is a partial image, we need to unref @image when out is
	 * unreffed.
	 *
	 * If it's not partial, perhaps a file we write to or a memory image,
	 * we need to break any links between @image and @out created by
	 * vips_image_pipelinev().
	 */
	if( vips_image_ispartial( out ) ) { 
		vips_object_local( out, image );
	}
	else {
		vips__reorder_clear( out );
		vips__link_break_all( out );
		g_object_unref( image );
	}

	return( 0 );
}

/**
 * vips_image_write_to_file: (method)
 * @image: image to write
 * @name: write to this file
 * @...: %NULL-terminated list of optional named arguments
 *
 * Writes @in to @name using the saver recommended by
 * vips_foreign_find_save(). 
 *
 * Save options may be appended to @filename as "[name=value,...]" or given as
 * a NULL-terminated list of name-value pairs at the end of the arguments.
 * Options given in the function call override options given in the filename. 
 *
 * See also: vips_image_new_from_file().
 *
 * Returns: 0 on success, or -1 on error.
 */
int
vips_image_write_to_file( VipsImage *image, const char *name, ... )
{
	char filename[VIPS_PATH_MAX];
	char option_string[VIPS_PATH_MAX];
	const char *operation_name;
	va_list ap;
	int result;

	/* Save with the new target API if we can. Fall back to the older
	 * mechanism in case the saver we need has not been converted yet.
	 *
	 * We need to hide any errors from this first phase.
	 */
	vips__filename_split8( name, filename, option_string );

	vips_error_freeze();
	operation_name = vips_foreign_find_save_target( filename );
	vips_error_thaw();

	if( operation_name ) {
		VipsTarget *target;

		if( !(target = vips_target_new_to_file( filename )) )
			return( -1 );

		va_start( ap, name );
		result = vips_call_split_option_string( operation_name, 
			option_string, ap, image, target );
		va_end( ap );

		VIPS_UNREF( target );
	}
	else if( (operation_name = vips_foreign_find_save( filename )) ) {
		va_start( ap, name );
		result = vips_call_split_option_string( operation_name, 
			option_string, ap, image, filename );
		va_end( ap );
	}
	else
		return( -1 );

	return( result );
}

/**
 * vips_image_write_to_buffer: (method)
 * @in: image to write
 * @suffix: format to write 
 * @buf: (array length=size) (element-type guint8) (transfer full): return buffer start here
 * @size: (type gsize): return buffer length here
 * @...: %NULL-terminated list of optional named arguments
 *
 * Writes @in to a memory buffer in a format specified by @suffix. 
 *
 * Save options may be appended to @suffix as "[name=value,...]" or given as
 * a NULL-terminated list of name-value pairs at the end of the arguments.
 * Options given in the function call override options given in the filename. 
 *
 * Currently only TIFF, JPEG and PNG formats are supported.
 *
 * You can call the various save operations directly if you wish, see
 * vips_jpegsave_buffer(), for example. 
 *
 * See also: vips_image_write_to_memory(), vips_image_new_from_buffer().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_image_write_to_buffer( VipsImage *in, 
	const char *suffix, void **buf, size_t *size, 
	... )
{
	char filename[VIPS_PATH_MAX];
	char option_string[VIPS_PATH_MAX];
	const char *operation_name;
	VipsBlob *blob;
	va_list ap;
	int result;

	vips__filename_split8( suffix, filename, option_string );

	vips_error_freeze();
	operation_name = vips_foreign_find_save_target( filename );
	vips_error_thaw();

	if( operation_name ) {
		VipsTarget *target;

		if( !(target = vips_target_new_to_memory()) )
			return( -1 );

		va_start( ap, size );
		result = vips_call_split_option_string( operation_name, 
			option_string, ap, in, target );
		va_end( ap );

		if( result ) {
			VIPS_UNREF( target );
			return( -1 );
		}

		g_object_get( target, "blob", &blob, NULL );
		VIPS_UNREF( target );
	}
	else if( (operation_name = 
		vips_foreign_find_save_buffer( filename )) ) {

		va_start( ap, size );
		result = vips_call_split_option_string( operation_name, 
			option_string, ap, in, &blob );
		va_end( ap );

		if( result )
			return( -1 );
	}
	else
		return( -1 );

	*buf = NULL;
	if( size ) 
		*size = 0;

	if( blob ) { 
		if( buf ) {
			*buf = VIPS_AREA( blob )->data;
			VIPS_AREA( blob )->free_fn = NULL;
		}
		if( size ) 
			*size = VIPS_AREA( blob )->length;

		vips_area_unref( VIPS_AREA( blob ) );
	}

	return( 0 );
}

/**
 * vips_image_write_to_target: (method)
 * @in: image to write
 * @suffix: format to write 
 * @target: target to write to
 * @...: %NULL-terminated list of optional named arguments
 *
 * Writes @in to @output in format @suffix.
 *
 * Save options may be appended to @suffix as "[name=value,...]" or given as
 * a NULL-terminated list of name-value pairs at the end of the arguments.
 * Options given in the function call override options given in the filename. 
 *
 * You can call the various save operations directly if you wish, see
 * vips_jpegsave_target(), for example. 
 *
 * See also: vips_image_write_to_file().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_image_write_to_target( VipsImage *in, 
	const char *suffix, VipsTarget *target, ... )
{
	char filename[VIPS_PATH_MAX];
	char option_string[VIPS_PATH_MAX];
	const char *operation_name;
	va_list ap;
	int result;

	vips__filename_split8( suffix, filename, option_string );
	if( !(operation_name = vips_foreign_find_save_target( filename )) )
		return( -1 );

	va_start( ap, target );
	result = vips_call_split_option_string( operation_name, option_string, 
		ap, in, target );
	va_end( ap );

	if( result )
		return( -1 );

	return( 0 );
}

/**
 * vips_image_write_to_memory: (method)
 * @in: image to write
 * @size: return buffer length here
 *
 * Writes @in to memory as a simple, unformatted C-style array. 
 *
 * The caller is responsible for freeing this memory with g_free(). 
 *
 * See also: vips_image_write_to_buffer().
 *
 * Returns: (array length=size) (element-type guint8) (transfer full): return buffer start here
 */
void *
vips_image_write_to_memory( VipsImage *in, size_t *size_out )
{
	void *buf;
	size_t size;
	VipsImage *x;

	size = VIPS_IMAGE_SIZEOF_IMAGE( in );
	if( !(buf = g_try_malloc( size )) ) {
		vips_error( "vips_image_write_to_memory", 
			_( "out of memory --- size == %dMB" ), 
			(int) (size / (1024.0 * 1024.0))  );
		g_warning( _( "out of memory --- size == %dMB" ), 
			(int) (size / (1024.0 * 1024.0))  );
		return( NULL );
	}

	x = vips_image_new_from_memory( buf, size,
		in->Xsize, in->Ysize, in->Bands, in->BandFmt );
	if( vips_image_write( in, x ) ) {
		g_object_unref( x );
		g_free( buf ); 
		return( NULL ); 
	}
	g_object_unref( x );

	if( size_out )
		*size_out = size;

	return( buf ); 
}

/**
 * vips_image_decode: (method)
 * @in: image to decode
 * @out: (out): write to this image
 *
 * A convenience function to unpack to a format that we can compute with. 
 * @out.coding is always #VIPS_CODING_NONE. 
 *
 * This unpacks LABQ to plain LAB. Use vips_LabQ2LabS() for a bit more speed
 * if you need it. 
 *
 * See also: vips_image_encode(), vips_LabQ2Lab(), vips_rad2float(). 
 *
 * Returns: 0 on success, or -1 on error.
 */
int
vips_image_decode( VipsImage *in, VipsImage **out )
{
	/* Keep in sync with vips__vector_to_ink().
	 */
	if( in->Coding == VIPS_CODING_LABQ ) {
		if( vips_LabQ2Lab( in, out, NULL ) )
			return( -1 );
	} 
	else if( in->Coding == VIPS_CODING_RAD ) {
		if( vips_rad2float( in, out, NULL ) )
			return( -1 );
	}
	else {
		if( vips_copy( in, out, NULL ) )
			return( -1 );
	}

	return( 0 );
}

/**
 * vips_image_decode_predict: (method)
 * @in: image to decode
 * @bands: (out): predict bands here
 * @format: (out): predict format here
 *
 * We often need to know what an image will decode to without actually
 * decoding it, for example, in arg checking.
 *
 * See also: vips_image_decode().
 */
int
vips_image_decode_predict( VipsImage *in, 
	int *out_bands, VipsBandFormat *out_format )
{
	VipsBandFormat format;
	int bands; 

	if( in->Coding == VIPS_CODING_LABQ ) {
		bands = 3;
		format = VIPS_FORMAT_FLOAT;
	}
	else if( in->Coding == VIPS_CODING_RAD ) {
		bands = 3;
		format = VIPS_FORMAT_FLOAT;
	}
	else {
		bands = in->Bands;
		format = in->BandFmt;
	}

	if( out_bands )
		*out_bands = bands;
	if( out_format )
		*out_format = format;

	return( 0 );
}

/**
 * vips_image_encode: (method)
 * @in: image to encode
 * @out: (out): write to this image
 * @coding: coding to apply
 *
 * A convenience function to pack to a coding. The inverse of
 * vips_image_decode().
 *
 * See also: vips_image_decode().
 *
 * Returns: 0 on success, or -1 on error.
 */
int
vips_image_encode( VipsImage *in, VipsImage **out, VipsCoding coding )
{
	if( coding == VIPS_CODING_LABQ ) {
		if( vips_Lab2LabQ( in, out, NULL ) )
			return( -1 );
	} 
	else if( coding == VIPS_CODING_RAD ) {
		if( vips_float2rad( in, out, NULL ) )
			return( -1 );
	}
	else {
		if( vips_copy( in, out, NULL ) )
			return( -1 );
	}

	return( 0 );
}

/**
 * vips_image_isMSBfirst: (method)
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
 * vips_image_isfile: (method)
 * @image: image to test
 *
 * Return %TRUE if @image represents a file on disc in some way. 
 */
gboolean 
vips_image_isfile( VipsImage *image )
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
 * vips_image_ispartial: (method)
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

/**
 * vips_image_hasalpha: (method)
 * @image: image to check
 *
 * Look at an image's interpretation and see if it has extra alpha bands. For
 * example, a 4-band #VIPS_INTERPRETATION_sRGB would, but a six-band 
 * #VIPS_INTERPRETATION_MULTIBAND would not. 
 *
 * Return %TRUE if @image has an alpha channel.
 */
gboolean
vips_image_hasalpha( VipsImage *image )
{
	/* The result of hasalpha is used to turn on things like
	 * premultiplication, so we are rather conservative about when we
	 * signal this. We don't want to premultiply things that should not be
	 * premultiplied.
	 */
	switch( image->Type ) { 
	case VIPS_INTERPRETATION_B_W:
	case VIPS_INTERPRETATION_GREY16:
		return( image->Bands > 1 ); 

	case VIPS_INTERPRETATION_RGB:
	case VIPS_INTERPRETATION_CMC:
	case VIPS_INTERPRETATION_LCH:
	case VIPS_INTERPRETATION_LABS:
	case VIPS_INTERPRETATION_sRGB:
	case VIPS_INTERPRETATION_YXY:
	case VIPS_INTERPRETATION_XYZ:
	case VIPS_INTERPRETATION_LAB:
	case VIPS_INTERPRETATION_RGB16:
	case VIPS_INTERPRETATION_scRGB:
	case VIPS_INTERPRETATION_HSV:
		return( image->Bands > 3 ); 

	case VIPS_INTERPRETATION_CMYK:
		return( image->Bands > 4 ); 

	default:
		/* We can't really infer anything about bands from things like
		 * HISTOGRAM or FOURIER.
		 */
		return( FALSE ); 
	}
}

/**
 * vips_image_write_prepare: (method)
 * @image: image to prepare
 *
 * Call this after setting header fields (width, height, and so on) to
 * allocate resources ready for writing. 
 *
 * Normally this function is called for you by vips_image_generate() or
 * vips_image_write_line(). You will need to call it yourself if you plan to
 * write directly to the ->data member of a memory image.
 *
 * Returns: 0 on success, or -1 on error.
 */
int
vips_image_write_prepare( VipsImage *image )
{
	g_assert( vips_object_sanity( VIPS_OBJECT( image ) ) );

	if( image->Xsize <= 0 || 
		image->Ysize <= 0 || 
		image->Bands <= 0 ) {
		vips_error( "VipsImage", "%s", _( "bad dimensions" ) );
		return( -1 );
	}

	/* We don't use this, but make sure it's set in case any old programs
	 * are expecting it.
	 */
	image->Bbits = vips_format_sizeof( image->BandFmt ) << 3;
 
	if( image->dtype == VIPS_IMAGE_PARTIAL ) {
		VIPS_DEBUG_MSG( "vips_image_write_prepare: "
			"old-style output for %s\n", image->filename );

		image->dtype = VIPS_IMAGE_SETBUF;
	}

	switch( image->dtype ) {
	case VIPS_IMAGE_MMAPINRW:
	case VIPS_IMAGE_SETBUF_FOREIGN:
		break;

	case VIPS_IMAGE_SETBUF:
		if( !image->data && 
			!(image->data = vips_tracked_malloc( 
				VIPS_IMAGE_SIZEOF_IMAGE( image ))) ) 
			return( -1 );

		break;

	case VIPS_IMAGE_OPENOUT:
		if( vips_image_open_output( image ) )
			return( -1 );

		break;

	default:
		vips_error( "VipsImage", "%s", _( "bad image descriptor" ) );
		return( -1 );
	}

	return( 0 );
}

/**
 * vips_image_write_line: (method)
 * @image: image to write to
 * @ypos: vertical position of scan-line to write
 * @linebuffer: scanline of pixels
 *
 * Write a line of pixels to an image. This function must be called repeatedly
 * with @ypos increasing from 0 to #VipsImage::height .
 * @linebuffer must be VIPS_IMAGE_SIZEOF_LINE() bytes long.
 *
 * See also: vips_image_generate().
 *
 * Returns: 0 on success, or -1 on error.
 */
int
vips_image_write_line( VipsImage *image, int ypos, VipsPel *linebuffer )
{	
	int linesize = VIPS_IMAGE_SIZEOF_LINE( image );

	/* Is this the start of eval?
	 */
	if( ypos == 0 ) {
		if( vips__image_wio_output( image ) )
			return( -1 );

		/* Always clear kill before we start looping. See the 
		 * call to vips_image_iskilled() below.
		 */
		vips_image_set_kill( image, FALSE );
		vips_image_write_prepare( image );
		vips_image_preeval( image );
	}

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
		if( vips__write( image->fd, linebuffer, linesize ) )
			return( -1 );
		break;

	default:
		vips_error( "VipsImage", 
			_( "unable to output to a %s image" ),
			vips_enum_string( VIPS_TYPE_IMAGE_TYPE, 
				image->dtype ) );
		return( -1 );
	}

	/* Trigger evaluation callbacks for this image.
	 */
	vips_image_eval( image, ypos * image->Xsize );
	if( vips_image_iskilled( image ) )
		return( -1 );

	/* Is this the end of eval?
	 */
	if( ypos == image->Ysize - 1 ) {
		vips_image_posteval( image );
		if( vips_image_written( image ) )
			return( -1 );
	}

	return( 0 );
}

/* Rewind an output file. VIPS images only.
 */
static int
vips_image_rewind_output( VipsImage *image ) 
{
	int fd;

	g_assert( image->dtype == VIPS_IMAGE_OPENOUT );

#ifdef DEBUG_IO
	printf( "vips_image_rewind_output: %s\n", image->filename );
#endif/*DEBUG_IO*/

	/* We want to keep the fd across rewind. 
	 *
	 * On Windows, we open temp files with _O_TEMPORARY. We mustn't close
	 * the file since this will delete it. 
	 *
	 * We could open the file again to keep a reference to it alive, but
	 * this is also problematic on Windows. 
	 */
	fd = image->fd;
	image->fd = -1;

	/* Free any resources the image holds and reset to a base
	 * state.
	 */
	vips_object_rewind( VIPS_OBJECT( image ) );

	/* And reopen ... recurse to get a mmaped image. 
	 *
	 * We use "v" mode to get it opened as a vips image, bypassing the
	 * file type checks. They will fail on Windows because you can't open
	 * fds more than once.
	 */
	image->fd = fd;
	g_object_set( image,
		"mode", "v",
		NULL );
	if( vips_object_build( VIPS_OBJECT( image ) ) ) {
		vips_error( "VipsImage", 
			_( "auto-rewind for %s failed" ),
			image->filename );
		return( -1 );
	}

	/* Now we've finished writing and reopened as read, we can
	 * delete-on-close. 
	 *
	 * On *nix-like systems, this will unlink the file from the 
	 * filesystem and when we exit, for whatever reason, the file
	 * we be reclaimed. 
	 *
	 * On Windows this will fail because the file is open and you can't
	 * delete open files. However, on Windows we set _O_TEMPORARY, so the 
	 * file will be deleted when the fd is finally closed.
	 */
	vips_image_delete( image );

	return( 0 );
}

/** 
 * vips_image_copy_memory: (method)
 * @image: image to copy to a memory buffer
 *
 * Make an image which is an area of memory. 
 *
 * If @image is already a memory buffer, just ref and return. If it's a file on
 * disc or a partial, allocate memory and copy the image to it. 
 *
 * This operation is thread-safe, unlike vips_image_wio_input(). 
 *
 * If you are sure that @image is not shared with another thread (perhaps you
 * have made it yourself), use vips_image_wio_input() instead.
 *
 * See also: vips_image_wio_input().
 *
 * Returns: (transfer full): the new #VipsImage, or %NULL on error.
 */
VipsImage *
vips_image_copy_memory( VipsImage *image )
{
	VipsImage *new;

	switch( image->dtype ) {
	case VIPS_IMAGE_SETBUF:
	case VIPS_IMAGE_SETBUF_FOREIGN:
	case VIPS_IMAGE_MMAPIN:
	case VIPS_IMAGE_MMAPINRW:
		/* Can read from all these, in principle anyway.
		 */
		new = image;
		g_object_ref( new );
		break;

	case VIPS_IMAGE_OPENOUT:
	case VIPS_IMAGE_OPENIN:
	case VIPS_IMAGE_PARTIAL:
		new = vips_image_new_memory();
		if( vips_image_write( image, new ) ) {
			g_object_unref( new );
			return( NULL ); 
		}
		break;

	default:
		vips_error( "vips_image_copy_memory", 
			"%s", _( "image not readable" ) );
		return( NULL );
	}

	return( new );
}

/**
 * vips_image_wio_input: (method)
 * @image: image to transform
 *
 * Check that an image is readable via the VIPS_IMAGE_ADDR() macro, that is,
 * that the entire image is in memory and all pixels can be read with 
 * VIPS_IMAGE_ADDR().  If it 
 * isn't, try to transform it so that VIPS_IMAGE_ADDR() can work. 
 *
 * Since this function modifies @image, it is not thread-safe. Only call it on
 * images which you are sure have not been shared with another thread. If the
 * image might have been shared, use the less efficient
 * vips_image_copy_memory() instead.
 *
 * See also: vips_image_copy_memory(), vips_image_pio_input(), 
 * vips_image_inplace(), VIPS_IMAGE_ADDR().
 *
 * Returns: 0 on succeess, or -1 on error.
 */
int
vips_image_wio_input( VipsImage *image )
{	
	VipsImage *t1;

	g_assert( vips_object_sanity( VIPS_OBJECT( image ) ) );

#ifdef DEBUG_IO
	printf( "vips_image_wio_input: wio input for %s\n", 
		image->filename );
#endif/*DEBUG_IO*/

	switch( image->dtype ) {
	case VIPS_IMAGE_SETBUF:
	case VIPS_IMAGE_SETBUF_FOREIGN:
		/* Should have been written to.
		 */
		if( !image->data ) {
			vips_error( "vips_image_wio_input", 
				"%s", _( "no image data" ) );
			return( -1 );
		}

		break;

	case VIPS_IMAGE_MMAPIN:
	case VIPS_IMAGE_MMAPINRW:
		/* Can read from all these, in principle anyway.
		 */
		break;

	case VIPS_IMAGE_PARTIAL:
#ifdef DEBUG_IO
		printf( "vips_image_wio_input: "
			"converting partial image to WIO\n" );
#endif/*DEBUG_IO*/

		/* Change to VIPS_IMAGE_SETBUF. First, make a memory 
		 * buffer and copy into that.
		 */
		t1 = vips_image_new_memory();
		if( vips_image_write( image, t1 ) ) {
			g_object_unref( t1 );
			return( -1 );
		}

		/* Copy new stuff in. We can't unref and free stuff, as this
		 * would kill of lots of regions and cause dangling pointers
		 * elsewhere.
		 */
		image->dtype = VIPS_IMAGE_SETBUF;
		image->data = t1->data; 
		t1->data = NULL;

		/* Close temp image.
		 */
		g_object_unref( t1 );

		/* We need to zap any start/gen/stop callbacks. If we don't,
		 * calling vips_region_prepare_to() later to read from this 
		 * image will fail, since it will think it needs to create the
		 * image, not read from it.
		 */
		image->start_fn = NULL;
		image->generate_fn = NULL;
		image->stop_fn = NULL;
		image->client1 = NULL;
		image->client2 = NULL;

		/* ... and that may confuse any regions which are trying to
		 * generate from this image.
		 */
		if( image->regions ) 
			g_warning( "rewinding image with active regions" ); 

		break;

	case VIPS_IMAGE_OPENIN:
#ifdef DEBUG_IO
		printf( "vips_image_wio_input: "
			"converting openin image for wio input\n" );
#endif/*DEBUG_IO*/

		/* just mmap() the whole thing.
		 */
		if( vips_mapfile( image ) ) 
			return( -1 );
		image->data = (VipsPel *) image->baseaddr + 
			image->sizeof_header;
		image->dtype = VIPS_IMAGE_MMAPIN;

		break;

	case VIPS_IMAGE_OPENOUT:
		/* Close file down and reopen as input. I guess this will only
		 * work for vips files?
		 */
		if( vips_image_rewind_output( image ) ||
			vips_image_wio_input( image ) ) 
			return( -1 );

		break;

	default:
		vips_error( "vips_image_wio_input", 
			"%s", _( "image not readable" ) );
		return( -1 );
	}

	return( 0 );
}

int 
vips__image_wio_output( VipsImage *image )
{
#ifdef DEBUG_IO
	printf( "vips__image_wio_output: WIO output for %s\n", 
		image->filename );
#endif/*DEBUG_IO*/

	switch( image->dtype ) {
	case VIPS_IMAGE_PARTIAL:
		/* Make sure nothing is attached.
		 */
		if( image->generate_fn ) {
			vips_error( "vips__image_wio_output", 
				"%s", _( "image already written" ) );
			return( -1 );
		}

		/* Cannot do old-style write to PARTIAL. Turn to SETBUF.
		 */
		image->dtype = VIPS_IMAGE_SETBUF;

		break;

	case VIPS_IMAGE_SETBUF:
	case VIPS_IMAGE_OPENOUT:
	case VIPS_IMAGE_SETBUF_FOREIGN:
		/* Can write to this ok. 
		 *
		 * We used to check that ->data was null and warn about
		 * writing twice, but we no longer insist that this is called
		 * before vips_image_write_prepare(), so we can't do that any
		 * more.
		 */
		break;

	default:
		vips_error( "vips__image_wio_output", 
			"%s", _( "image not writeable" ) );
		return( -1 );
	}

	return( 0 );
}
 
/**
 * vips_image_inplace: (method)
 * @image: image to make read-write
 *
 * Gets @image ready for an in-place operation, such as vips_draw_circle().
 * After calling this function you can both read and write the image with 
 * VIPS_IMAGE_ADDR().
 *
 * This method is called for you by the base class of the draw operations, 
 * there's no need to call it yourself.
 *
 * Since this function modifies @image, it is not thread-safe. Only call it on
 * images which you are sure have not been shared with another thread. 
 * All in-place operations are inherently not thread-safe, so you need to take
 * great care in any case.
 *
 * See also: vips_draw_circle(), vips_image_wio_input().
 *
 * Returns: 0 on succeess, or -1 on error.
 */
int
vips_image_inplace( VipsImage *image )
{
	/* Do an vips_image_wio_input(). This will rewind, generate, etc.
	 */
	if( vips_image_wio_input( image ) ) 
		return( -1 );

	/* Look at the type.
	 */
	switch( image->dtype ) {
	case VIPS_IMAGE_SETBUF:
	case VIPS_IMAGE_SETBUF_FOREIGN:
	case VIPS_IMAGE_MMAPINRW:
		/* No action necessary.
		 */
		break;

	case VIPS_IMAGE_MMAPIN:
		/* Try to remap read-write.
		 */
		if( vips_remapfilerw( image ) )
			return( -1 );

		break;

	default:
		vips_error( "vips_image_inplace", 
			"%s", _( "bad file type" ) );
		return( -1 );
	}

	/* This image is about to be changed (probably). Make sure it's not 
	 * in cache.
	 */
	vips_image_invalidate_all( image ); 

	return( 0 );
}

/**
 * vips_image_pio_input: (method)
 * @image: image to check
 *
 * Check that an image is readable with vips_region_prepare() and friends. 
 * If it isn't, try to transform the image so that vips_region_prepare() can 
 * work.
 *
 * See also: vips_image_pio_output(), vips_region_prepare().
 *
 * Returns: 0 on succeess, or -1 on error.
 */
int
vips_image_pio_input( VipsImage *image )
{
	g_assert( vips_object_sanity( VIPS_OBJECT( image ) ) );

#ifdef DEBUG_IO
	printf( "vips_image_pio_input: enabling partial input for %s\n", 
		image->filename );
#endif /*DEBUG_IO*/

	switch( image->dtype ) {
	case VIPS_IMAGE_SETBUF:
	case VIPS_IMAGE_SETBUF_FOREIGN:
		/* Should have been written to.
		 */
		if( !image->data ) {
			vips_error( "vips_image_pio_input", 
				"%s", _( "no image data" ) );
			return( -1 );
		}

		/* Should be no generate functions now.
		 */
		image->start_fn = NULL;
		image->generate_fn = NULL;
		image->stop_fn = NULL;

		break;

	case VIPS_IMAGE_PARTIAL:
		/* Should have had generate functions attached.
		 */
		if( !image->generate_fn ) {
			vips_error( "vips_image_pio_input", 
				"%s", _( "no image data" ) );
			return( -1 );
		}

		break;

	case VIPS_IMAGE_MMAPIN:
	case VIPS_IMAGE_MMAPINRW:
	case VIPS_IMAGE_OPENIN:
		break;

	case VIPS_IMAGE_OPENOUT:

		/* Free any resources the image holds and reset to a base
		 * state.
		 */
		if( vips_image_rewind_output( image ) )
			return( -1 );

		break;

	default:
		vips_error( "vips_image_pio_input", 
			"%s", _( "image not readable" ) );
		return( -1 );
	}

	return( 0 );
}

/**
 * vips_image_pio_output: (method)
 * @image: image to check
 *
 * Check that an image is writeable with vips_image_generate(). If it isn't,
 * try to transform the image so that vips_image_generate() can work.
 *
 * See also: vips_image_pio_input().
 *
 * Returns: 0 on succeess, or -1 on error.
 */
int 
vips_image_pio_output( VipsImage *image )
{
#ifdef DEBUG_IO
	printf( "vips_image_pio_output: enabling partial output for %s\n", 
		image->filename );
#endif /*DEBUG_IO*/

	switch( image->dtype ) {
	case VIPS_IMAGE_SETBUF:
		if( image->data ) {
			vips_error( "vips_image_pio_output", 
				"%s", _( "image already written" ) );
			return( -1 );
		}

		break;

	case VIPS_IMAGE_PARTIAL:
		if( image->generate_fn ) {
			vips_error( "vips_image_pio_output", 
				"%s", _( "image already written" ) );
			return( -1 );
		}

		break;

	case VIPS_IMAGE_OPENOUT:
	case VIPS_IMAGE_SETBUF_FOREIGN:
		break;

	default:
		vips_error( "vips_image_pio_output", 
			"%s", _( "image not writeable" ) );
		return( -1 );
	}

	return( 0 );
}

/**
 * vips_band_format_isint:
 * @format: format to test
 *
 * Return %TRUE if @format is one of the integer types.
 */
gboolean
vips_band_format_isint( VipsBandFormat format )
{
	switch( format ) {
	case VIPS_FORMAT_UCHAR:
	case VIPS_FORMAT_CHAR:
	case VIPS_FORMAT_USHORT:
	case VIPS_FORMAT_SHORT:
	case VIPS_FORMAT_UINT:
	case VIPS_FORMAT_INT:
		return( TRUE );

	case VIPS_FORMAT_FLOAT:
	case VIPS_FORMAT_DOUBLE:	
	case VIPS_FORMAT_COMPLEX:
	case VIPS_FORMAT_DPCOMPLEX:	
		return( FALSE );

	default:
		g_assert_not_reached();
		return( FALSE );
	}
}

/**
 * vips_band_format_isuint:
 * @format: format to test
 *
 * Return %TRUE if @format is one of the unsigned integer types.
 */
gboolean
vips_band_format_isuint( VipsBandFormat format )
{
	switch( format ) {
	case VIPS_FORMAT_UCHAR:
	case VIPS_FORMAT_USHORT:
	case VIPS_FORMAT_UINT:
		return( TRUE );

	case VIPS_FORMAT_INT:
	case VIPS_FORMAT_SHORT:
	case VIPS_FORMAT_CHAR:
	case VIPS_FORMAT_FLOAT:
	case VIPS_FORMAT_DOUBLE:	
	case VIPS_FORMAT_COMPLEX:
	case VIPS_FORMAT_DPCOMPLEX:	
		return( FALSE );
	
	default:
		g_assert_not_reached();
		return( FALSE );
	}
}

/**
 * vips_band_format_is8bit:
 * @format: format to test
 *
 * Return %TRUE if @format is uchar or schar.
 */
gboolean
vips_band_format_is8bit( VipsBandFormat format )
{
	switch( format ) {
	case VIPS_FORMAT_UCHAR:
	case VIPS_FORMAT_CHAR:
		return( TRUE );

	case VIPS_FORMAT_USHORT:
	case VIPS_FORMAT_SHORT:
	case VIPS_FORMAT_UINT:
	case VIPS_FORMAT_INT:
	case VIPS_FORMAT_FLOAT:
	case VIPS_FORMAT_DOUBLE:
	case VIPS_FORMAT_COMPLEX:
	case VIPS_FORMAT_DPCOMPLEX:
		return( FALSE );

	default:
		g_assert_not_reached();
		return( FALSE );
	}
}

/**
 * vips_band_format_isfloat:
 * @format: format to test
 *
 * Return %TRUE if @format is one of the float types.
 */
gboolean
vips_band_format_isfloat( VipsBandFormat format )
{
	switch( format ) {
	case VIPS_FORMAT_FLOAT:
	case VIPS_FORMAT_DOUBLE:	
		return( TRUE );

	case VIPS_FORMAT_UCHAR:
	case VIPS_FORMAT_CHAR:
	case VIPS_FORMAT_USHORT:
	case VIPS_FORMAT_SHORT:
	case VIPS_FORMAT_UINT:
	case VIPS_FORMAT_INT:
	case VIPS_FORMAT_COMPLEX:
	case VIPS_FORMAT_DPCOMPLEX:	
		return( FALSE );
	
	default:
		g_assert_not_reached();
		return( FALSE );
	}
}

/**
 * vips_band_format_iscomplex:
 * @format: format to test
 *
 * Return %TRUE if @fmt is one of the complex types.
 */
gboolean
vips_band_format_iscomplex( VipsBandFormat format )
{
	switch( format ) {
	case VIPS_FORMAT_COMPLEX:
	case VIPS_FORMAT_DPCOMPLEX:	
		return( TRUE );

	case VIPS_FORMAT_UCHAR:
	case VIPS_FORMAT_CHAR:
	case VIPS_FORMAT_USHORT:
	case VIPS_FORMAT_SHORT:
	case VIPS_FORMAT_UINT:
	case VIPS_FORMAT_INT:
	case VIPS_FORMAT_FLOAT:
	case VIPS_FORMAT_DOUBLE:	
		return( FALSE );
	
	default:
		g_assert_not_reached();
		return( FALSE );
	}
}

/**
 * vips_image_free_buffer:
 * @image: the image that contains the buffer
 * @buffer: the orignal buffer that was stolen
 *
 * Free the externally allocated buffer found in the input image. This function
 * is intended to be used with g_signal_connect.
 */
void
vips_image_free_buffer( VipsImage *image, void *buffer )
{
	free( buffer );
}

/* Handy for debugging: view an image in nip2.
 */
int
vips__view_image( VipsImage *image )
{
	VipsArrayImage *array; 
	int result;

	array = vips_array_image_new( &image, 1 );
	result = vips_system( "nip2 %s", 
		"in", array, 
		"in-format", "%s.v", 
		NULL ); 
	vips_area_unref( VIPS_AREA( array ) );

	return( result ); 
}
