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
#include <vips/intl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include <vips/vips.h>

#if HAVE_MAGICK || HAVE_MAGICK7

#if HAVE_MAGICK
	#include <magick/api.h>
	/* pre-float Magick used to call this MaxRGB.
 	*/
	#if !defined(QuantumRange)
	#  define QuantumRange MaxRGB
	#endif
	#define MaxPathExtent MaxTextExtent
#elif HAVE_MAGICK7
	#include <MagickCore/MagickCore.h>
	#define MaxPathExtent MagickPathExtent
#endif

/* What we track during a write call.
 */
typedef struct _Write {
	VipsImage *im;

	Image *images;
	ImageInfo *image_info;
	ExceptionInfo *exception;

	Image *current_image;
	char *map;
	StorageType storageType;
} Write;

#if HAVE_MAGICK

/* And this used to be UseHDRI.
 */
#if MAGICKCORE_HDRI_SUPPORT
#  define UseHDRI 1
#endif

#include "pforeign.h"

/* What we track during a read call.
 */
typedef struct _Read {
	char *filename;
	VipsImage *im;
	int page;
	int n;

	Image *image;
	ImageInfo *image_info;
	ExceptionInfo exception;

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
	if ( (&read->exception)->signature == MagickSignature ) {
		DestroyExceptionInfo( &read->exception );
	}
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
	const char *density, int page, int n )
{
	Read *read;
	static int inited = 0;

	if( !inited ) {
#ifdef HAVE_MAGICKCOREGENESIS
		MagickCoreGenesis( vips_get_argv0(), MagickFalse );
#else /*!HAVE_MAGICKCOREGENESIS*/
		InitializeMagick( "" );
#endif /*HAVE_MAGICKCOREGENESIS*/
		inited = 1;
	}

	/* IM doesn't use the -1 means end-of-file convention, change it to a
	 * very large number.
	 */
	if( n == -1 )
		n = 100000;

	if( !(read = VIPS_NEW( im, Read )) )
		return( NULL );
	read->filename = filename ? g_strdup( filename ) : NULL;
	read->page = page;
	read->n = n;
	read->im = im;
	read->image = NULL;
	read->image_info = CloneImageInfo( NULL );
	GetExceptionInfo( &read->exception );
	read->n_frames = 0;
	read->frames = NULL;
	read->frame_height = 0;
	read->lock = vips_g_mutex_new();

	g_signal_connect( im, "close", G_CALLBACK( read_close ), read );

	if( !read->image_info ) 
		return( NULL );

	if( filename ) 
		vips_strncpy( read->image_info->filename, 
			filename, MaxPathExtent );

	/* Canvas resolution for rendering vector formats like SVG.
	 */
	VIPS_SETSTR( read->image_info->density, density );

#ifdef HAVE_SETIMAGEOPTION
	/* When reading DICOM images, we want to ignore any
	 * window_center/_width setting, since it may put pixels outside the
	 * 0-65535 range and lose data. 
	 *
	 * These window settings are attached as vips metadata, so our caller
	 * can interpret them if it wants.
	 */
  	SetImageOption( read->image_info, "dcm:display-range", "reset" );
#endif /*HAVE_SETIMAGEOPTION*/

	if( read->page > 0 ) { 
#ifdef HAVE_NUMBER_SCENES 
		/* I can't find docs for these fields, but this seems to work.
		 */
		char page[256];

		read->image_info->scene = read->page;
		read->image_info->number_scenes = read->n;

		/* Some IMs must have the string version set as well.
		 */
		vips_snprintf( page, 256, "%d-%d", 
			read->page, read->page + read->n );
		read->image_info->scenes = strdup( page );
#else /*!HAVE_NUMBER_SCENES*/
		/* This works with GM 1.2.31 and probably others.
		 */
		read->image_info->subimage = read->page;
		read->image_info->subrange = read->n;
#endif
	}

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
	if( (im->Bands = get_bands( image )) < 0 )
		return( -1 );

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

	case RGBColorspace:
		if( im->BandFmt == VIPS_FORMAT_USHORT )
			im->Type = VIPS_INTERPRETATION_RGB16;
		else
			im->Type = VIPS_INTERPRETATION_RGB;
		break;

	case sRGBColorspace:
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

	vips_image_pipelinev( im, VIPS_DEMAND_STYLE_SMALLTILE, NULL );

	/* Three ways to loop over attributes / properties :-(
	 */

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
	read->n_frames = 0;
	for( p = image; p; (p = GetNextImageInList( p )) ) {
		if( p->columns != (unsigned int) im->Xsize ||
			p->rows != (unsigned int) im->Ysize ||
			get_bands( p ) != im->Bands ) {
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
	printf( "image has %d frames\n", read->n_frames );
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
		IndexPacket *indexes = GetIndexes( image );
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

	if( !(read = read_new( filename, out, density, page, n )) )
		return( -1 );

#ifdef DEBUG
	printf( "magick2vips: calling ReadImage() ...\n" );
#endif /*DEBUG*/

	read->image = ReadImage( read->image_info, &read->exception );
	if( !read->image ) {
		vips_error( "magick2vips", _( "unable to read file \"%s\"\n"
			"libMagick error: %s %s" ),
			filename, 
			read->exception.reason, read->exception.description );
		return( -1 );
	}

	if( parse_header( read ) )
		return( -1 );
	if( vips_image_generate( out, 
		NULL, magick_fill_region, NULL, read, NULL ) )
		return( -1 );

	return( 0 );
}

/* This has severe issues. See:
 *
 * http://www.imagemagick.org/discourse-server/viewtopic.php?f=1&t=20017
 */
int
vips__magick_read_header( const char *filename, 
	VipsImage *out, const char *density, int page, int n )
{
	Read *read;

#ifdef DEBUG
	printf( "vips__magick_read_header: %s\n", filename );
#endif /*DEBUG*/

	if( !(read = read_new( filename, out, density, page, n )) )
		return( -1 );

#ifdef DEBUG
	printf( "vips__magick_read_header: pinging image ...\n" );
#endif /*DEBUG*/

	read->image = PingImage( read->image_info, &read->exception );
	if( !read->image ) {
		vips_error( "magick2vips", _( "unable to ping file "
			"\"%s\"\nlibMagick error: %s %s" ),
			filename, 
			read->exception.reason, read->exception.description );
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

	if( !(read = read_new( NULL, out, density, page, n )) )
		return( -1 );

#ifdef DEBUG
	printf( "magick2vips: calling BlobToImage() ...\n" );
#endif /*DEBUG*/

	read->image = BlobToImage( read->image_info, 
		buf, len, &read->exception );
	if( !read->image ) {
		vips_error( "magick2vips", _( "unable to read buffer\n"
			"libMagick error: %s %s" ),
			read->exception.reason, read->exception.description );
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

	if( !(read = read_new( NULL, out, density, page, n )) )
		return( -1 );

#ifdef DEBUG
	printf( "vips__magick_read_buffer_header: pinging blob ...\n" );
#endif /*DEBUG*/

	read->image = PingBlob( read->image_info, buf, len, &read->exception );
	if( !read->image ) {
		vips_error( "magick2vips", _( "unable to ping blob\n"
			"libMagick error: %s %s" ),
			read->exception.reason, read->exception.description );
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

#endif /*HAVE_MAGICK*/

#ifdef HAVE_MAGICK7

static Image*
magick_acquire_image( const ImageInfo *image_info, ExceptionInfo *exception )
{
	return AcquireImage( image_info, exception );
}

static void
magick_acquire_next_image( const ImageInfo *image_info, Image *image,
	ExceptionInfo *exception)
{
	AcquireNextImage( image_info, image, exception );
}

static int
magick_set_image_size( Image *image, const size_t width, const size_t height,
	ExceptionInfo *exception)
{
	return SetImageExtent( image, width, height, exception );
}

static int
magick_import_pixels( Image *image, const ssize_t x, const ssize_t y,
	const size_t width, const size_t height, const char *map,
	const StorageType type,const void *pixels, ExceptionInfo *exception )
{
	return ImportImagePixels( image, x, y, width, height, map,
		type, pixels, exception );
}

static void
magick_set_property( Image *image, const char *property, const char *value,
	ExceptionInfo *exception )
{
	(void) SetImageProperty( image, property, value, exception );
}

static void
magick_inherit_exception( Write *write, Image *image ) {
	(void) write;
	(void) image;
}

#endif /*HAVE_MAGICK7 */

#ifdef HAVE_MAGICK

static Image*
magick_acquire_image(const ImageInfo *image_info, ExceptionInfo *exception)
{
	(void) exception;
	return AcquireImage( image_info );
}

static void
magick_acquire_next_image( const ImageInfo *image_info, Image *image,
	ExceptionInfo *exception )
{
	(void) exception;
	AcquireNextImage( image_info, image );
}

static int
magick_set_image_size( Image *image, const size_t width, const size_t height,
	ExceptionInfo *exception )
{
	(void) exception;
	return SetImageExtent( image, width, height );
}

static int
magick_import_pixels( Image *image, const ssize_t x, const ssize_t y,
	const size_t width, const size_t height, const char *map,
	const StorageType type,const void *pixels, ExceptionInfo *exception )
{
	(void) exception;
	return ImportImagePixels( image, x, y, width, height, map,
		type, pixels );
}

static void
magick_set_property( Image *image, const char *property, const char *value,
	ExceptionInfo *exception )
{
	(void) exception;
	(void) SetImageProperty( image, property, value );
}

static void
magick_inherit_exception( Write *write, Image *image ) {
	InheritException( write->exception, &image->exception );
}

#endif

/* Can be called many times.
 */
static void
write_free( Write *write )
{
	VIPS_FREE( write->map );
	VIPS_FREEF( DestroyImageList, write->images );
	VIPS_FREEF( DestroyImageInfo, write->image_info );
	VIPS_FREEF( DestroyExceptionInfo, write->exception );
}

/* Can be called many times.
 */
static int
write_close( VipsImage *im, Write *write )
{
	write_free( write );

	return( 0 );
}

static Write *
write_new( VipsImage *im, const char *filename, const char *format )
{
	Write *write;
	static int inited = 0;

	if( !inited ) {
		MagickCoreGenesis( vips_get_argv0(), MagickFalse );
		inited = 1;
	}

	if( !(write = VIPS_NEW( im, Write )) )
		return( NULL );
	write->im = im;
	write->images = NULL;

	write->storageType = UndefinedPixel;
	switch( im->BandFmt ) {
		case VIPS_FORMAT_UCHAR:
			write->storageType = CharPixel;
			break;
		case VIPS_FORMAT_USHORT:
			write->storageType = ShortPixel;
			break;
		case VIPS_FORMAT_UINT:
			write->storageType = LongPixel;
			break;
		case VIPS_FORMAT_FLOAT:
			write->storageType = FloatPixel;
			break;
		case VIPS_FORMAT_DOUBLE:
			write->storageType = DoublePixel;
			break;

		default:
			write_free(write);
			return( NULL );
	}

	write->map = NULL;
	switch( im->Bands ) {
		case 1:
			write->map = g_strdup("R");
			break;
		case 2:
			write->map = g_strdup("RA");
			break;
		case 3:
			write->map = g_strdup("RGB");
			break;
		case 4:
			if( im->Type == VIPS_INTERPRETATION_CMYK )
				write->map = g_strdup("CMYK");
			else
				write->map = g_strdup("RGBA");
			break;
		case 5:
			write->map = g_strdup("CMYKA");
			break;

		default:
			write_free(write);
			return( NULL );
	}

	write->image_info = CloneImageInfo( NULL );
	if( !write->image_info) {
		write_free(write);
		return( NULL );
	}

	if( format ) {
		vips_strncpy( write->image_info->magick,
			format, MaxPathExtent );
		if ( filename ) {
			va_list ap;

			(void) vips_snprintf( write->image_info->filename, 
				MaxPathExtent, "%s:%s", format, filename );
		}
	}
	else if ( filename ) {
		vips_strncpy( write->image_info->filename,
			filename, MaxPathExtent );
	}

	write->exception = AcquireExceptionInfo();
	if( !write->exception) {
		write_free(write);
		return( NULL );
	}

	g_signal_connect( im, "close", G_CALLBACK( write_close ), write );

	return( write );
}

static int
magick_set_properties( Write *write )
{
	int number;
	const char *str;

	if( vips_image_get_typeof( write->im, "gif-delay" ) &&
		!vips_image_get_int( write->im, "gif-delay", &number ) )
		write->current_image->delay = (size_t) number;

	if( vips_image_get_typeof( write->im, "gif-loop" ) &&
		!vips_image_get_int( write->im, "gif-loop", &number ) )
		write->current_image->iterations = (size_t) number;

	if( vips_image_get_typeof( write->im, "gif-comment" ) &&
		!vips_image_get_string( write->im, "gif-comment", &str ) )
		magick_set_property( write->current_image, "comment",
			str, write->exception );
}

static int
magick_write_block( VipsRegion *region, VipsRect *area, void *a )
{
	Write *write = (Write *) a;
	MagickBooleanType status;
	void *p;

	p = VIPS_REGION_ADDR(region, area->left, area->top);

	status=magick_import_pixels( write->current_image, area->left, area->top,
			area->width, area->height, write->map, write->storageType, p,
			write->exception );

	return( status == MagickFalse ? -1 : 0 );
}

static int
magick_create_image( Write *write, VipsImage *im )
{
	Image *image;
	int status;

	if( write->images == NULL ) {
		image = magick_acquire_image( write->image_info, write->exception );
		if( image == NULL )
			return( -1 );

		write->images = image;
	}
	else {
		image=GetLastImageInList( write->images );
		magick_acquire_next_image( write->image_info, image, write->exception );
		if( GetNextImageInList( image ) == NULL )
			return( -1 );

		image=SyncNextImageInList( image );
	}

	if( !magick_set_image_size( image, im->Xsize, im->Ysize, write->exception ) )
		return( -1 );

	write->current_image=image;
	magick_set_properties( write );
	status =  vips_sink_disc( im, magick_write_block, write );
	magick_inherit_exception( write, write->current_image );
	return( status );
}

static int
magick_create_images( Write *write )
{
	int height;
	int count;
	int status;

	height = 0;
	if( vips_image_get_typeof( write->im, VIPS_META_PAGE_HEIGHT ) &&
		vips_image_get_int( write->im, VIPS_META_PAGE_HEIGHT, &height ) )
		return( magick_create_image( write, write->im ) );

	for( int top=0; top < write->im->Ysize ; top+=height ) {
		VipsImage *im;

		if( vips_crop( write->im, &im, 0, top, write->im->Xsize, height, NULL ) )
			return( -1 );

		status = magick_create_image( write, im );

		g_object_unref( im );

		if( status )
			break;
	}

	return( status );
}

static int
magick_write_images( Write *write )
{
	if( !WriteImages( write->image_info, write->images,
			write->image_info->filename, write->exception ) )
		return( -1 );

	return( 0 );
}

static int
magick_write_images_buf( Write *write, void **obuf, size_t *olen )
{
	*obuf=ImagesToBlob( write->image_info, write->images, olen,
		write->exception );

	if( !*obuf )
		return( -1 );

	return( 0 );
}

int
vips__magick_write( VipsImage *im, const char *filename,
	const char *format )
{
	Write *write;

	if( !(write = write_new( im, filename, format )) )
		return( -1 );

	if ( magick_create_images( write ) ) {
		vips_error( "magick2vips", _( "unable to write file \"%s\"\n"
			"libMagick error: %s %s" ),
			filename,
			write->exception->reason, write->exception->description );
		return( -1 );
	}

	if( magick_write_images( write ) ) {
		magick_inherit_exception( write, write->images );
		vips_error( "magick2vips", _( "unable to write file \"%s\"\n"
			"libMagick error: %s %s" ),
			filename,
			write->exception->reason, write->exception->description );
		return( -1 );
	}

	return( 0 );
}

int
vips__magick_write_buf( VipsImage *im, void **obuf, size_t *olen,
	const char *format )
{
	Write *write;

	if( !(write = write_new( im, NULL, format )) )
		return( -1 );

	if ( magick_create_images( write ) ) {
		vips_error( "magick2vips", _( "unable to write buffer \n"
			"libMagick error: %s %s" ),
			write->exception->reason, write->exception->description );
		return( -1 );
	}

	if( magick_write_images_buf( write, obuf, olen ) ) {
		vips_error( "magick2vips", _( "unable to write buffer \n"
			"libMagick error: %s %s" ),
			write->exception->reason, write->exception->description );
		return( -1 );
	}

	return( 0 );
}

#endif /*HAVE_MAGICK | HAVE_MAGICK7*/

