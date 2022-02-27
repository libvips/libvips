/* Read a file using libMagick
 * 
 * 7/1/03 JC
 *	- from im_tiff2vips
 * 3/2/03 JC
 *	- some InitializeMagick() fail with NULL arg
 * 2/11/04
 *	- im_magick2vips_header() also checks sensible width/height
 * 28/10/05
 * 	- copy attributes to meta
 * 	- write many-frame images as a big column if all frames have identical
 * 	  width/height/bands/depth
 * 31/3/06
 * 	- test for magick attr support
 * 8/5/06
 * 	- set RGB16/GREY16 if appropriate
 * 10/8/07
 * 	- support 32/64 bit imagemagick too
 * 21/2/08 
 * 	- use MaxRGB if QuantumRange is missing (thanks Bob)
 * 	- look for MAGICKCORE_HDRI_SUPPORT (thanks Marcel)
 * 	- use image->attributes if GetNextImageAttribute() is missing
 * 3/3/09
 * 	- allow funky bit depths, like 14 (thanks Mikkel)
 * 17/3/09
 * 	- reset dcm:display-range to help DICOM read
 * 20/4/09
 * 	- argh libMagick uses 255 == transparent ... we must invert all 
 * 	  alpha channels
 * 12/5/09
 *	- fix signed/unsigned warnings
 * 23/7/09
 * 	- SetImageOption() is optional (to help GM)
 * 4/2/10
 * 	- gtkdoc
 * 30/4/10
 * 	- better number of bands detection with GetImageType()
 * 	- use new API stuff, argh
 * 17/12/11
 * 	- turn into a set of read fns ready to be called from a class
 * 11/6/13
 * 	- add @all_frames option, off by default
 * 4/12/14 Lovell
 * 	- add @density option 
 * 16/2/15 mcuelenaere
 * 	- add blob read
 * 26/2/15
 * 	- close the read down early for a header read ... this saves an
 * 	  fd during file read, handy for large numbers of input images 
 * 14/2/16
 * 	- add @page option, 0 by default
 * 18/4/16
 * 	- fix @page with graphicsmagick
 * 25/11/16
 * 	- remove @all_frames, add @n
 * 23/2/17
 * 	- try using GetImageChannelDepth() instead of ->depth
 * 25/5/18
 * 	- don't use Ping, it's too unreliable
 * 24/7/18
 * 	- sniff extra filetypes
 * 4/1/19 kleisauke
 * 	- we did not chain exceptions correctly, causing a memory leak
 * 	- added wrapper funcs for exception handling
 * 4/2/19
 * 	- add profile (xmp, ipct, etc.) read
 * 12/11/21
 * 	- set "orientation"
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

/* Turn on debugging output.
#define DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <glib/gi18n-lib.h>

#ifdef ENABLE_MAGICKLOAD

#ifdef HAVE_MAGICK6

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include <vips/vips.h>
#include <vips/internal.h>

#include <magick/api.h>

#include "pforeign.h"
#include "magick.h"

/* pre-float Magick used to call this MaxRGB.
 */
#if !defined(QuantumRange)
#  define QuantumRange MaxRGB
#endif

/* And this used to be UseHDRI.
 */
#if MAGICKCORE_HDRI_SUPPORT
#  define UseHDRI 1
#endif

/* What we track during a read call.
 */
typedef struct _Read {
	char *filename;
	VipsImage *im;
	const void *buf;
	size_t len; 
	int page;
	int n;

	Image *image;
	ImageInfo *image_info;
	ExceptionInfo *exception;

	/* Number of pages in image.
	 */
	int n_pages;

	/* Number of pages we will read.
	 */
	int n_frames;

	Image **frames;
	int frame_height;

	/* Mutex to serialise calls to libMagick during threaded read.
	 */
	GMutex *lock;
} Read;

/* Can be called many times.
 */
static void
read_free( Read *read )
{
#ifdef DEBUG
	printf( "magick2vips: read_free: %s\n", read->filename );
#endif /*DEBUG*/

	VIPS_FREE( read->filename );
	VIPS_FREEF( DestroyImageList, read->image );
	VIPS_FREEF( DestroyImageInfo, read->image_info ); 
	VIPS_FREE( read->frames );
	VIPS_FREEF( magick_destroy_exception, read->exception ); 
	VIPS_FREEF( vips_g_mutex_free, read->lock );
}

/* Can be called many times.
 */
static int
read_close( VipsImage *im, Read *read )
{
	read_free( read ); 

	return( 0 );
}

static Read *
read_new( const char *filename, VipsImage *im, 
	const void *buf, const size_t len, 
	const char *density, int page, int n ) 
{
	Read *read;

	magick_genesis();

	/* IM doesn't use the -1 means end-of-file convention, change it to a
	 * very large number.
	 */
	if( n == -1 )
		n = 10000000;

	if( !(read = VIPS_NEW( im, Read )) )
		return( NULL );
	read->filename = filename ? g_strdup( filename ) : NULL;
	read->buf = buf;
	read->len = len;
	read->page = page;
	read->n = n;
	read->im = im;
	read->image = NULL;
	read->image_info = CloneImageInfo( NULL );
	read->exception = magick_acquire_exception(); 
	read->n_pages = 0;
	read->n_frames = 0;
	read->frames = NULL;
	read->frame_height = 0;
	read->lock = vips_g_mutex_new();

	g_signal_connect( im, "close", G_CALLBACK( read_close ), read );

	if( !read->image_info ) 
		return( NULL );

	if( filename ) 
		vips_strncpy( read->image_info->filename, 
			filename, MaxTextExtent );

	/* Any extra file format detection.
	 */
	if( filename ) 
		magick_sniff_file( read->image_info, filename );
	if( buf ) 
		magick_sniff_bytes( read->image_info, buf, len );

	/* Canvas resolution for rendering vector formats like SVG.
	 */
	VIPS_SETSTR( read->image_info->density, density );

	/* When reading DICOM images, we want to ignore any
	 * window_center/_width setting, since it may put pixels outside the
	 * 0-65535 range and lose data. 
	 *
	 * These window settings are attached as vips metadata, so our caller
	 * can interpret them if it wants.
	 */
  	magick_set_image_option( read->image_info, 
		"dcm:display-range", "reset" );

	if( read->page > 0 )  
		magick_set_number_scenes( read->image_info,
			read->page, read->n );

#ifdef DEBUG
	printf( "magick2vips: read_new: %s\n", read->filename );
#endif /*DEBUG*/

	return( read );
}

static int
get_bands( Image *image )
{
	int bands;
	ImageType type = GetImageType( image, &image->exception );

	switch( type ) {
	case BilevelType:
	case GrayscaleType:
		bands = 1;
		break;

	case GrayscaleMatteType:
	/* ImageMagick also has PaletteBilevelMatteType, but GraphicsMagick
	 * does not. Skip for portability.
	 */
		bands = 2;
		break;

	case PaletteType:
	case TrueColorType:
		bands = 3;
		break;

	case PaletteMatteType:
	case TrueColorMatteType:
	case ColorSeparationType:
		bands = 4;
		break;

	case ColorSeparationMatteType:
		bands = 5;
		break;

	default:
		vips_error( "magick2vips", _( "unsupported image type %d" ),
			(int) type );
		return( -1 );
	}

	return( bands );
}

static int
parse_header( Read *read )
{
	VipsImage *im = read->im;
	Image *image = read->image;

	int depth;
	Image *p;
	int i;

#ifdef DEBUG
	printf( "parse_header: filename = %s\n", read->filename );
	printf( "GetImageChannelDepth(AllChannels) = %zd\n",
		GetImageChannelDepth( image, AllChannels, &image->exception ) );
	printf( "GetImageDepth() = %zd\n",
		GetImageDepth( image, &image->exception ) );
	printf( "image->depth = %zd\n", image->depth );
	printf( "GetImageType() = %d\n",
		GetImageType( image, &image->exception ) );
	printf( "IsGrayImage() = %d\n",
		IsGrayImage( image, &image->exception ) );
	printf( "IsMonochromeImage() = %d\n",
		IsMonochromeImage( image, &image->exception ) );
	printf( "IsOpaqueImage() = %d\n",
		IsOpaqueImage( image, &image->exception ) );
	printf( "image->columns = %zd\n", image->columns ); 
	printf( "image->rows = %zd\n", image->rows ); 
#endif /*DEBUG*/

	im->Xsize = image->columns;
	im->Ysize = image->rows;
	read->frame_height = image->rows;
	im->Bands = get_bands( image );
	if( im->Xsize <= 0 ||
		im->Ysize <= 0 ||
		im->Bands <= 0 ||
		im->Xsize >= VIPS_MAX_COORD ||
		im->Ysize >= VIPS_MAX_COORD ||
		im->Bands >= VIPS_MAX_COORD ) {
		vips_error( "magick2vips",
			_( "bad image dimensions %d x %d pixels, %d bands" ),
			im->Xsize, im->Ysize, im->Bands );
		return( -1 );
	}

	/* Depth can be 'fractional'. 
	 *
	 * You'd think we should use
	 * GetImageDepth() but that seems unreliable. 16-bit mono DICOM images 
	 * are reported as depth 1, for example.
	 *
	 * Try GetImageChannelDepth(), maybe that works.
	 */
	depth = GetImageChannelDepth( image, AllChannels, &image->exception );
	im->BandFmt = -1;
	if( depth >= 1 && depth <= 8 ) 
		im->BandFmt = VIPS_FORMAT_UCHAR;
	if( depth >= 9 && depth <= 16 ) 
		im->BandFmt = VIPS_FORMAT_USHORT;
#ifdef UseHDRI
	if( depth == 32 )
		im->BandFmt = VIPS_FORMAT_FLOAT;
	if( depth == 64 )
		im->BandFmt = VIPS_FORMAT_DOUBLE;
#else /*!UseHDRI*/
	if( depth == 32 )
		im->BandFmt = VIPS_FORMAT_UINT;
#endif /*UseHDRI*/

	if( im->BandFmt == -1 ) {
		vips_error( "magick2vips", _( "unsupported bit depth %d" ),
			(int) depth );
		return( -1 );
	}

	switch( image->colorspace ) {
	case GRAYColorspace:
		if( im->BandFmt == VIPS_FORMAT_USHORT )
			im->Type = VIPS_INTERPRETATION_GREY16;
		else
			im->Type = VIPS_INTERPRETATION_B_W;
		break;

	case sRGBColorspace:
	case RGBColorspace:
		if( im->BandFmt == VIPS_FORMAT_USHORT )
			im->Type = VIPS_INTERPRETATION_RGB16;
		else
			im->Type = VIPS_INTERPRETATION_sRGB;
		break;

	case CMYKColorspace:
		im->Type = VIPS_INTERPRETATION_CMYK;
		break;

	default:
		vips_error( "magick2vips", _( "unsupported colorspace %d" ),
			(int) image->colorspace );
		return( -1 );
	}

	switch( image->units ) {
	case PixelsPerInchResolution:
		im->Xres = image->x_resolution / 25.4;
		im->Yres = image->y_resolution / 25.4;
		break;

	case PixelsPerCentimeterResolution:
		im->Xres = image->x_resolution / 10.0;
		im->Yres = image->y_resolution / 10.0;
		break;

	default:
		im->Xres = 1.0;
		im->Yres = 1.0;
		break;
	}

	/* Other fields.
	 */
	im->Coding = VIPS_CODING_NONE;

	if( vips_image_pipelinev( im, VIPS_DEMAND_STYLE_SMALLTILE, NULL ) )
		return( -1 );

	/* Set vips metadata from ImageMagick profiles.
	 */
	if( magick_set_vips_profile( im, image ) )
		return( -1 );

#ifdef HAVE_RESETIMAGEPROPERTYITERATOR
{
	char *key;

	/* This is the most recent imagemagick API, test for this first.
	 */
	ResetImagePropertyIterator( image );
	while( (key = GetNextImageProperty( image )) ) {
		char name_text[256];
		VipsBuf name = VIPS_BUF_STATIC( name_text );

		vips_buf_appendf( &name, "magick-%s", key );
		vips_image_set_string( im, 
			vips_buf_all( &name ), GetImageProperty( image, key ) );
	}
}
#elif defined(HAVE_RESETIMAGEATTRIBUTEITERATOR)
{
	const ImageAttribute *attr;

	/* magick6.1-ish and later, deprecated in 6.5ish.
	 */
	ResetImageAttributeIterator( image );
	while( (attr = GetNextImageAttribute( image )) ) {
		char name_text[256];
		VipsBuf name = VIPS_BUF_STATIC( name_text );

		vips_buf_appendf( &name, "magick-%s", attr->key );
		vips_image_set_string( im, vips_buf_all( &name ), attr->value );
	}
}
#else
{
	const ImageAttribute *attr;

	/* GraphicsMagick is missing the iterator: we have to loop ourselves.
	 * ->attributes is marked as private in the header, but there's no
	 * getter so we have to access it directly.
	 */
	for( attr = image->attributes; attr; attr = attr->next ) {
		char name_text[256];
		VipsBuf name = VIPS_BUF_STATIC( name_text );

		vips_buf_appendf( &name, "magick-%s", attr->key );
		vips_image_set_string( im, vips_buf_all( &name ), attr->value );
	}
}
#endif 

	/* Do we have a set of equal-sized frames? Append them.

	   	FIXME ... there must be an attribute somewhere from dicom read 
		which says this is a volumetric image

	 */
	read->n_pages = GetImageListLength( image );
	read->n_frames = 0;
	for( p = image; p; (p = GetNextImageInList( p )) ) {
		int p_depth = 
			GetImageChannelDepth( p, AllChannels, &p->exception );

		if( p->columns != (unsigned int) im->Xsize ||
			p->rows != (unsigned int) im->Ysize ||
			get_bands( p ) != im->Bands ||
			p_depth != depth ) {
#ifdef DEBUG
			printf( "frame %d differs\n", read->n_frames );
			printf( "%zdx%zd, %d bands\n", 
				p->columns, p->rows, get_bands( p ) );
			printf( "first frame is %dx%d, %d bands\n", 
				im->Xsize, im->Ysize, im->Bands );
#endif /*DEBUG*/

			break;
		}

		read->n_frames += 1;
	}
	if( p ) 
		/* Nope ... just do the first image in the list.
		 */
		read->n_frames = 1;

#ifdef DEBUG
	printf( "will read %d frames\n", read->n_frames );
#endif /*DEBUG*/

	if( read->n != -1 )
		read->n_frames = VIPS_MIN( read->n_frames, read->n );

	/* Record frame pointers.
	 */
	if( !(read->frames = VIPS_ARRAY( NULL, read->n_frames, Image * )) )
		return( -1 );
	p = image;
	for( i = 0; i < read->n_frames; i++ ) {
		read->frames[i] = p;
		p = GetNextImageInList( p );
	}

	if( read->n_frames > 1 ) {
		vips_image_set_int( im, VIPS_META_PAGE_HEIGHT, im->Ysize );
		im->Ysize *= read->n_frames;
	}

	vips_image_set_int( im, VIPS_META_N_PAGES, read->n_pages );

	vips_image_set_int( im, VIPS_META_ORIENTATION, 
		VIPS_CLIP( 1, image->orientation, 8 ) );

	return( 0 );
}

/* Divide by this to get 0 - MAX from a Quantum. Eg. consider QuantumRange ==
 * 65535, MAX == 255 (a Q16 ImageMagic representing an 8-bit image). Make sure
 * this can't be zero (if QuantumRange < MAX) .. can happen if we have a Q8
 * ImageMagick trying to represent a 16-bit image.
 */
#define SCALE( MAX ) \
	(QuantumRange < (MAX) ? \
		1 : \
		((QuantumRange + 1) / ((MAX) + 1)))

#define GRAY_LOOP( TYPE, MAX ) { \
	TYPE *q = (TYPE *) q8; \
	\
	for( x = 0; x < n; x++ ) \
		q[x] = pixels[x].green / SCALE( MAX ); \
}

#define GRAYA_LOOP( TYPE, MAX ) { \
	TYPE *q = (TYPE *) q8; \
	\
	for( x = 0; x < n; x++ ) { \
		q[0] = pixels[x].green / SCALE( MAX ); \
		q[1] = MAX - pixels[x].opacity / SCALE( MAX ); \
		\
		q += 2; \
	} \
}

#define RGB_LOOP( TYPE, MAX ) { \
	TYPE *q = (TYPE *) q8; \
	\
	for( x = 0; x < n; x++ ) { \
		q[0] = pixels[x].red / SCALE( MAX ); \
		q[1] = pixels[x].green / SCALE( MAX ); \
		q[2] = pixels[x].blue / SCALE( MAX ); \
		\
		q += 3; \
	} \
}

#define RGBA_LOOP( TYPE, MAX ) { \
	TYPE *q = (TYPE *) q8; \
	\
	for( x = 0; x < n; x++ ) { \
		q[0] = pixels[x].red / SCALE( MAX ); \
		q[1] = pixels[x].green / SCALE( MAX ); \
		q[2] = pixels[x].blue / SCALE( MAX ); \
		q[3] = MAX - pixels[x].opacity / SCALE( MAX ); \
		\
		q += 4; \
	} \
}

static void
unpack_pixels( VipsImage *im, VipsPel *q8, PixelPacket *pixels, int n )
{
	int x;

	switch( im->Bands ) {
	case 1:
		/* Gray.
		 */
		switch( im->BandFmt ) {
		case VIPS_FORMAT_UCHAR:	
			GRAY_LOOP( unsigned char, 255 ); break;
		case VIPS_FORMAT_USHORT: 
			GRAY_LOOP( unsigned short, 65535 ); break;
		case VIPS_FORMAT_UINT:	
			GRAY_LOOP( unsigned int, 4294967295UL ); break;
		case VIPS_FORMAT_DOUBLE:	
			GRAY_LOOP( double, QuantumRange ); break;

		default:
			g_assert_not_reached();
		}
		break;

	case 2:
		/* Gray plus alpha.
		 */
		switch( im->BandFmt ) {
		case VIPS_FORMAT_UCHAR:
			GRAYA_LOOP( unsigned char, 255 ); break;
		case VIPS_FORMAT_USHORT:	
			GRAYA_LOOP( unsigned short, 65535 ); break;
		case VIPS_FORMAT_UINT:	
			GRAYA_LOOP( unsigned int, 4294967295UL ); break;
		case VIPS_FORMAT_DOUBLE:	
			GRAYA_LOOP( double, QuantumRange ); break;

		default:
			g_assert_not_reached();
		}
		break;

	case 3:
		/* RGB.
		 */
		switch( im->BandFmt ) {
		case VIPS_FORMAT_UCHAR:	
			RGB_LOOP( unsigned char, 255 ); break;
		case VIPS_FORMAT_USHORT:	
			RGB_LOOP( unsigned short, 65535 ); break;
		case VIPS_FORMAT_UINT:	
			RGB_LOOP( unsigned int, 4294967295UL ); break;
		case VIPS_FORMAT_DOUBLE:	
			RGB_LOOP( double, QuantumRange ); break;

		default:
			g_assert_not_reached();
		}
		break;

	case 4:
		/* RGBA or CMYK.
		 */
		switch( im->BandFmt ) {
		case VIPS_FORMAT_UCHAR:
			RGBA_LOOP( unsigned char, 255 ); break;
		case VIPS_FORMAT_USHORT:	
			RGBA_LOOP( unsigned short, 65535 ); break;
		case VIPS_FORMAT_UINT:	
			RGBA_LOOP( unsigned int, 4294967295UL ); break;
		case VIPS_FORMAT_DOUBLE:	
			RGBA_LOOP( double, QuantumRange ); break;

		default:
			g_assert_not_reached();
		}
		break;

	default:
		g_assert_not_reached();
	}
}

static PixelPacket *
get_pixels( Image *image, int left, int top, int width, int height )
{
	PixelPacket *pixels;

#ifdef HAVE_GETVIRTUALPIXELS
	if( !(pixels = (PixelPacket *) GetVirtualPixels( image, 
		left, top, width, height, &image->exception )) )
#else
	if( !(pixels = GetImagePixels( image, left, top, width, height )) )
#endif
		return( NULL );

/* Can't happen if red/green/blue are doubles.
 */
#ifndef UseHDRI
	/* Unpack palette.
	 */
	if( image->storage_class == PseudoClass ) {
#ifdef HAVE_GETVIRTUALPIXELS
		IndexPacket *indexes = (IndexPacket *) 
			GetVirtualIndexQueue( image );
#else
		/* Was GetIndexes(), but that's now deprecated.
		 */
		IndexPacket *indexes = AccessMutableIndexes( image );
#endif

		int i;

		for( i = 0; i < width * height; i++ ) {
			IndexPacket x = indexes[i];

			if( x < image->colors ) {
				pixels[i].red = image->colormap[x].red;
				pixels[i].green = image->colormap[x].green;
				pixels[i].blue = image->colormap[x].blue;
			}
		}
	}
#endif /*UseHDRI*/

	return( pixels );
}

static int
magick_fill_region( VipsRegion *out, 
	void *seq, void *a, void *b, gboolean *stop )
{
	Read *read = (Read *) a;
	VipsRect *r = &out->valid;
	int y;

	for( y = 0; y < r->height; y++ ) {
		int top = r->top + y;
		int frame = top / read->frame_height;
		int line = top % read->frame_height;

		PixelPacket *pixels;

		g_mutex_lock( read->lock );
		pixels = get_pixels( read->frames[frame], 
			r->left, line, r->width, 1 );
		g_mutex_unlock( read->lock );

		if( !pixels ) {
			vips_foreign_load_invalidate( read->im );
			vips_error( "magick2vips", 
				"%s", _( "unable to read pixels" ) );
			return( -1 );
		}

		unpack_pixels( read->im, VIPS_REGION_ADDR( out, r->left, top ), 
			pixels, r->width );
	}

	return( 0 );
}

int
vips__magick_read( const char *filename, 
	VipsImage *out, const char *density, int page, int n )
{
	Read *read;

#ifdef DEBUG
	printf( "magick2vips: vips__magick_read: %s\n", filename );
#endif /*DEBUG*/

	if( !(read = read_new( filename, out, NULL, n, density, page, n )) )
		return( -1 );

#ifdef DEBUG
	printf( "magick2vips: calling ReadImage() ...\n" );
#endif /*DEBUG*/

	read->image = ReadImage( read->image_info, read->exception );
	if( !read->image ) {
		magick_vips_error( "magick2vips", read->exception );
		vips_error( "magick2vips", 
			_( "unable to read file \"%s\"" ), filename );
		return( -1 );
	}

	if( parse_header( read ) )
		return( -1 );
	if( vips_image_generate( out, 
		NULL, magick_fill_region, NULL, read, NULL ) )
		return( -1 );

	return( 0 );
}

int
vips__magick_read_header( const char *filename, 
	VipsImage *out, const char *density, int page, int n )
{
	Read *read;

#ifdef DEBUG
	printf( "vips__magick_read_header: %s\n", filename );
#endif /*DEBUG*/

	if( !(read = read_new( filename, out, NULL, 0, density, page, n )) )
		return( -1 );

#ifdef DEBUG
	printf( "vips__magick_read_header: reading image ...\n" );
#endif /*DEBUG*/

	/* It would be great if we could PingImage and just read the header,
	 * but sadly many IM coders do not support ping. The critical one for
	 * us is DICOM. TGA also has issues. 
	 */
	read->image = ReadImage( read->image_info, read->exception );
	if( !read->image ) {
		magick_vips_error( "magick2vips", read->exception );
		vips_error( "magick2vips", 
			_( "unable to read file \"%s\"" ), filename ); 
		return( -1 );
	}

	if( parse_header( read ) ) 
		return( -1 );

	if( out->Xsize <= 0 || 
		out->Ysize <= 0 ) {
		vips_error( "magick2vips", "%s", _( "bad image size" ) );
		return( -1 );
	}

	/* Just a header read: we can free the read early and save an fd.
	 */
	read_free( read );

	return( 0 );
}

int
vips__magick_read_buffer( const void *buf, const size_t len, 
	VipsImage *out, const char *density, int page, int n )
{
	Read *read;

#ifdef DEBUG
	printf( "magick2vips: vips__magick_read_buffer: %p %zu\n", buf, len );
#endif /*DEBUG*/

	if( !(read = read_new( NULL, out, buf, len, density, page, n )) )
		return( -1 );

#ifdef DEBUG
	printf( "magick2vips: calling BlobToImage() ...\n" );
#endif /*DEBUG*/

	read->image = BlobToImage( read->image_info, 
		buf, len, read->exception );
	if( !read->image ) {
		magick_vips_error( "magick2vips", read->exception );
		vips_error( "magick2vips", "%s", _( "unable to read buffer" ) );
		return( -1 );
	}

	if( parse_header( read ) )
		return( -1 );
	if( vips_image_generate( out, 
		NULL, magick_fill_region, NULL, read, NULL ) )
		return( -1 );

	return( 0 );
}

int
vips__magick_read_buffer_header( const void *buf, const size_t len, 
	VipsImage *out, const char *density, int page, int n )
{
	Read *read;

#ifdef DEBUG
	printf( "vips__magick_read_buffer_header: %p %zu\n", buf, len );
#endif /*DEBUG*/

	if( !(read = read_new( NULL, out, buf, len, density, page, n )) )
		return( -1 );

#ifdef DEBUG
	printf( "vips__magick_read_buffer_header: pinging blob ...\n" );
#endif /*DEBUG*/

	/* It would be great if we could PingBlob and just read the header,
	 * but sadly many IM coders do not support ping well. The critical one 
	 * for us is DICOM. TGA also has issues. 
	 */
	read->image = BlobToImage( read->image_info, 
		buf, len, read->exception );
	if( !read->image ) {
		magick_vips_error( "magick2vips", read->exception );
		vips_error( "magick2vips", "%s", _( "unable to ping blob" ) );
		return( -1 );
	}

	if( parse_header( read ) ) 
		return( -1 );

	if( out->Xsize <= 0 || 
		out->Ysize <= 0 ) {
		vips_error( "magick2vips", "%s", _( "bad image size" ) );
		return( -1 );
	}

	return( 0 );
}

#endif /*HAVE_MAGICK6*/

#endif /*ENABLE_MAGICKLOAD*/
