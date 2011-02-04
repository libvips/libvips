/* vips image class
 * 
 * 22/5/08
 * 	- from im_open.c, im_openin.c, im_desc_hd.c, im_readhist.c,
 * 	  im_openout.c
 * 19/3/09
 *	- block mmaps of nodata images
 * 12/5/09
 *	- fix signed/unsigned warnings
 * 12/10/09
 *	- heh argh reading history always stopped after the first line
 * 9/12/09
 * 	- only wholly map input files on im_incheck() ... this reduces VM use,
 * 	  especially with large numbers of small files
 * 4/2/11
 * 	- from im_open_vips.c
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
#include <ctype.h>

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#ifdef HAVE_SYS_FILE_H
#include <sys/file.h>
#endif /*HAVE_SYS_FILE_H*/
#include <sys/stat.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif /*HAVE_UNISTD_H*/
#ifdef HAVE_IO_H
#include <io.h>
#endif /*HAVE_IO_H*/
#include <libxml/parser.h>
#include <errno.h>

#ifdef OS_WIN32
#include <windows.h>
#endif /*OS_WIN32*/

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
 * VipsType: 
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
 * VipsFormat: 
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
 * vips_open_local_array:
 * @IM: image to open local to
 * @OUT: array to fill with #VipsImage *
 * @N: array size
 * @NAME: filename to open
 * @MODE: mode to open with
 *
 * Just like vips_open(), but opens an array of images. Handy for creating a 
 * set of temporary images for a function.
 *
 * Example:
 *
 * |[
 * VipsImage *t[5];
 *
 * if( vips_open_local_array( out, t, 5, "some-temps", "p" ) ||
 *   vips_add( a, b, t[0] ) ||
 *   vips_invert( t[0], t[1] ) ||
 *   vips_add( t[1], t[0], t[2] ) ||
 *   vips_costra( t[2], out ) )
 *   return( -1 );
 * ]|
 *
 * See also: vips_open(), vips_open_local(), vips_local_array().
 *
 * Returns: 0 on sucess, or -1 on error
 */

/**
 * vips_open_local:
 * @IM: image to open local to
 * @NAME: filename to open
 * @MODE: mode to open with
 *
 * Just like vips_open(), but the #VipsImage will be closed for you 
 * automatically when @IM is closed.
 *
 * See also: vips_open(), vips_local().
 *
 * Returns: a new #VipsImage, or %NULL on error
 */

/* Try to make an O_BINARY ... sometimes need the leading '_'.
 */
#ifdef BINARY_OPEN
#ifndef O_BINARY
#ifdef _O_BINARY
#define O_BINARY _O_BINARY
#endif /*_O_BINARY*/
#endif /*!O_BINARY*/
#endif /*BINARY_OPEN*/

/* If we have O_BINARY, add it to a mode flags set.
 */
#ifdef O_BINARY
#define BINARYIZE(M) ((M) | O_BINARY)
#else /*!O_BINARY*/
#define BINARYIZE(M) (M)
#endif /*O_BINARY*/

/* Open mode for image write ... on some systems, have to set BINARY too.
 */
#define MODE_WRITE BINARYIZE (O_WRONLY | O_CREAT | O_TRUNC)

/* Mode for read/write. This is if we might later want to mmaprw () the file.
 */
#define MODE_READWRITE BINARYIZE (O_RDWR)

/* Mode for read only. This is the fallback if READWRITE fails.
 */
#define MODE_READONLY BINARYIZE (O_RDONLY)

/* Our XML namespace.
 */
#define NAMESPACE "http://www.vips.ecs.soton.ac.uk/vips" 

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
	PROP_LAST
}; 

G_DEFINE_TYPE( VipsImage, vips_image, VIPS_TYPE_OBJECT );
 
static void
vips_image_finalize( GObject *gobject )
{
	VipsImage *image = VIPS_IMAGE( gobject );

	VIPS_FREE( image->filename );
	VIPS_FREE( image->mode );

	/* Use -1 rather than 0 for unset.
	 */
	if( image->fd != -1 ) {
		close( image->fd );
		image->fd = -1;
	}

	VIPS_FREEF( g_mutex_free, image->region_lock );

	G_OBJECT_CLASS( vips_image_parent_class )->finalize( gobject );
}

#ifdef VIPS_DEBUG
static void
vips_image_dispose( GObject *gobject )
{
	VIPS_DEBUG_MSG( "vips_image_dispose: " );
	vips_object_print( VIPS_OBJECT( gobject ) );

	G_OBJECT_CLASS( vips_image_parent_class )->dispose( gobject );
}

static void
vips_image_destroy( VipsObject *object )
{
	VIPS_DEBUG_MSG( "vips_image_destroy: " );
	vips_object_print( VIPS_OBJECT( gobject ) );

	VIPS_OBJECT_CLASS( vips_image_parent_class )->destroy( object );
}
#endif /*VIPS_DEBUG*/

static gboolean
vips_format_is_vips( VipsFormatClass *format )
{
	return( strcmp( VIPS_OBJECT_CLASS( format )->nickname, "vips" ) == 0 );
}

static int
vips_image_build( VipsObject *object )
{
	VipsImage *image = VIPS_IMAGE (object);
	VipsFormatClass *format;

	VIPS_DEBUG_MSG( "vips_image_build: %p\n", image );

	/* name defaults to filename.
	 */
	if( image->filename ) {
		char *basename;

		basename = g_path_get_basename( image->filename );
		g_object_set( image, "name", basename, NULL );
		g_free( basename );
	}

	if( VIPS_OBJECT_CLASS( parent_class )->build( object ) )
		return( -1 );

	/* Parse the mode string.
	 */
	switch( image->mode[0] ) {
        case 'r':
		if( !(format = vips_format_for_file( image->filename )) )
			return( -1 );

		if( vips_format_is_vips( format ) ) {
			if( vips_open_input( image ) )
				return( -1 );

			if( image->mode[1] == 'w' ) {
				/* "rw" mode ... just sanity check and tag.
				 * The "rw" bit happens when we do an
				 * operation.
				 */

				/* If we have a different byte order 
				 * from the image, we can only process 
				 * 8 bit images.
				 */
				if( vips_image_isMSBfirst( image ) != 
						vips__amiMSBfirst() &&
					vips_format_sizeof( image->format ) !=
						1) {
					im_error( "vips_image_build",
						_( "open for read-"
						"write for native format "
						"images only" ) );
					return( -1 );
				}

				image->dtype = VIPS_IMAGE_TYPE_OPENIN;
			}
		}
		else {
			if( vips_open_sub( format, filename, mode[1] == 'd' ) )
				return( -1 );
		}

        	break;

	case 'w':
		if( (format = vips_format_for_name( filename )) ) {
			if( vips_format_is_vips( format ) ) {
				if( vips_open_output( image ) )
					return( -1 );
			}
			else {
				if( !(im = im_open( filename, "p" )) )
					return( -1 );
				if( attach_sb( im, format->save, filename ) ) {
					im_close( im );
					return( -1 );
				}
			}
		}
		else {
			char suffix[FILENAME_MAX];

			im_filename_suffix( filename, suffix );
			im_error( "im_open", 
				_( "unsupported filetype \"%s\"" ), 
				suffix );

			return( -1 );
		}
        	break;

        case 't':
		image->dtype = VIPS_IMAGE_TYPE_SETBUF;
		image->demand = VIPS_DEMAND_ANY;
                break;

        case 'p':
		image->dtype = VIPS_IMAGE_TYPE_PARTIAL;
                break;

	default:
		im_error( "vips_image_build", _( "bad mode \"%s\"" ), mode );

		return( -1 );
        }

#ifdef DEBUG_VIPS
	printf ("vips_image_build: ");
	vips_object_dump( VIPS_OBJECT( image ) );
#endif /*DEBUG_VIPS*/

	return( 0 );
}

static void
vips_image_class_init( VipsImageClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );
	GParamSpec *pspec;
	int i;

	gobject_class->finalize = vips_image_finalize;
#ifdef VIPS_DEBUG
	gobject_class->dispose = vips_image_dispose;
#endif /*VIPS_DEBUG*/
	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

#ifdef VIPS_DEBUG
	vobject_class->destroy = vips_image_destroy;
#endif /*VIPS_DEBUG*/
	vobject_class->info = vips_image_info;
	vobject_class->generate_caption = vips_image_generate_caption;
	vobject_class->copy_attributes = vips_image_copy_attributes;
	vobject_class->build = vips_image_build;

	/* Create properties.
	 */
	pspec = g_param_spec_int( "width", "Width",
		"Image width in pixels",
		0, 1000000, 0,
		G_PARAM_READWRITE );
	g_object_class_install_property( gobject_class, PROP_WIDTH, pspec );
	vips_object_class_install_argument( vobject_class, pspec,
		VIPS_ARGUMENT_SET_ONCE, 
		G_STRUCT_OFFSET( VipsImage, Xsize ) );

	pspec = g_param_spec_int( "height", "Height",
		"Image height in pixels",
		0, 1000000, 0,
		G_PARAM_READWRITE );
	g_object_class_install_property( gobject_class, PROP_HEIGHT, pspec );
	vips_object_class_install_argument( vobject_class, pspec,
		VIPS_ARGUMENT_SET_ONCE, 
		G_STRUCT_OFFSET( VipsImage, Ysize ) );

	pspec = g_param_spec_int( "bands", "Bands",
		"Number of bands in image",
		0, 1000000, 0, 
		G_PARAM_READWRITE );
	g_object_class_install_property( gobject_class, PROP_BANDS, pspec );
	vips_object_class_install_argument( vobject_class, pspec,
		VIPS_ARGUMENT_SET_ONCE, 
		G_STRUCT_OFFSET( VipsImage, Bands ) );

	pspec = g_param_spec_enum( "format", "Format",
		"Pixel format in image",
		VIPS_TYPE_FORMAT, VIPS_FORMAT_UNSIGNED8, 
		G_PARAM_READWRITE );
	g_object_class_install_property( gobject_class, PROP_FORMAT, pspec );
	vips_object_class_install_argument( vobject_class, pspec,
		VIPS_ARGUMENT_SET_ONCE, 
		G_STRUCT_OFFSET( VipsImage, BandFmt ) );

	pspec = g_param_spec_string( "filename", "Filename",
		"Image filename",
		NULL, 
		G_PARAM_READWRITE );
	g_object_class_install_property( gobject_class, PROP_FILENAME, pspec );
	vips_object_class_install_argument( vobject_class, pspec,
		VIPS_ARGUMENT_CONSTRUCT, 
		G_STRUCT_OFFSET( VipsImage, filename ) );

	pspec = g_param_spec_string( "mode", "Mode",
		"Open mode",
		"p", 			/* Default to partial */
		G_PARAM_READWRITE );
	g_object_class_install_property( gobject_class, PROP_MODE, pspec );
	vips_object_class_install_argument( vobject_class, pspec,
		VIPS_ARGUMENT_CONSTRUCT, 
		G_STRUCT_OFFSET( VipsImage, mode ) );

	pspec = g_param_spec_boolean("kill", "Kill",
		"Kill evaluation on this image",
		FALSE, 
		G_PARAM_READWRITE );
	g_object_class_install_property( gobject_class, PROP_KILL, pspec );
	vips_object_class_install_argument( vobject_class, pspec,
		VIPS_ARGUMENT_NONE, 
		G_STRUCT_OFFSET( VipsImage, kill ) );

	pspec = g_param_spec_enum( "demand", "Demand",
		"Preferred demand style for this image",
		VIPS_TYPE_DEMAND, VIPS_DEMAND_SMALLTILE,
		G_PARAM_READWRITE );
	g_object_class_install_property( gobject_class, PROP_DEMAND, pspec );
	vips_object_class_install_argument( vobject_class, pspec,
		VIPS_ARGUMENT_NONE, 
		G_STRUCT_OFFSET( VipsImage, demand ) );
}

static void
vips_image_init( VipsImage *image )
{
	/* Init to 0 is fine for most header fields. Others have default set
	 * by property system.
	 */

	image->fd = -1;			/* since 0 is stdout */
        image->sizeof_header = VIPS_SIZEOF_HEADER;
	image->region_lock = g_mutex_new ();
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

VipsFormat
vips_image_get_format( VipsImage *image )
{
	return( image->BandFmt );
}

VipsCoding
vips_image_get_coding( VipsImage *image )
{
	return( image->Coding );
}

VipsType
vips_image_get_type( VipsImage *image )
{
	return( image->Type );
}

VipsType
vips_image_get_xres( VipsImage *image )
{
	return( image->Xres );
}

VipsType
vips_image_get_yres( VipsImage *image )
{
	return( image->Yres );
}

VipsType
vips_image_get_xoffset( VipsImage *image )
{
	return( image->Xoffset );
}

VipsType
vips_image_get_yoffset( VipsImage *image )
{
	return( image->Yoffset );
}























