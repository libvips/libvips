/* Common functions for interfacing with ImageMagick.
 *
 * 22/12/17 dlemstra 
 *
 * 24/7/18
 * 	- add the sniffer
 * 16/10/20 [bfriesen]
 * 	- set matte and depth appropriately for GM in magick_import_pixels()
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <glib/gi18n-lib.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vips/vips.h>
#include <vips/internal.h>

#include "pforeign.h"
#include "magick.h"

#if defined(HAVE_MAGICK6) || defined(HAVE_MAGICK7)

/* ImageMagick can't detect some formats, like ICO and TGA, by examining the 
 * contents -- ico.c and tga.c simply do not have recognisers.
 *
 * For these formats, do the detection ourselves.
 * Return an IM format specifier, or NULL to let IM do the detection.
 *
 * For sniffing TGAs, we check that there is at least enough room for the 
 * header and that the preamble contains valid values:
 *
 * -----------------------------------------------------------
 * |0x00 | 0-255 idlength, skip                              |
 * |0x01 | 0-1, color map present                            |
 * |0x02 | Any of (0, 1, 2, 3, 9, 10, 11), Image type        |
 * -----------------------------------------------------------
 *
 * References:
 * * https://www.dca.fee.unicamp.br/~martino/disciplinas/ea978/tgaffs.pdf
 * * http://www.paulbourke.net/dataformats/tga/
 * * https://en.wikipedia.org/wiki/Truevision_TGA#Technical_details
 */
static const char *
magick_sniff( const unsigned char *bytes, size_t length )
{
	if( length >= 4 &&
		bytes[0] == 0 &&
		bytes[1] == 0 &&
		bytes[2] == 1 &&
		bytes[3] == 0 )
		return( "ICO" );

	if( length >= 5 &&
		bytes[0] == 0 && 
		bytes[1] == 1 &&
		bytes[2] == 0 &&
		bytes[3] == 0 &&
		bytes[4] == 0 )
		return( "TTF" );

	if( length >= 18 &&
		(bytes[1] == 0 || 
		 bytes[1] == 1) &&
		(bytes[2] == 0 ||
		 bytes[2] == 1 ||
		 bytes[2] == 2 ||
		 bytes[2] == 3 ||
		 bytes[2] == 9 ||
		 bytes[2] == 10 ||
		 bytes[2] == 11) )
		return( "TGA" );

	return( NULL );
}

void
magick_sniff_bytes( ImageInfo *image_info, 
	const unsigned char *bytes, size_t length )
{
	const char *format;

	if( (format = magick_sniff( bytes, length )) )
		vips_strncpy( image_info->magick, format, MaxTextExtent );
}

void
magick_sniff_file( ImageInfo *image_info, const char *filename )
{
	unsigned char bytes[256];
	size_t length;

	if( (length = vips__get_bytes( filename, bytes, 256 )) >= 4 )
		magick_sniff_bytes( image_info, bytes, 256 );
}

#endif /*defined(HAVE_MAGICK6) || defined(HAVE_MAGICK7)*/

#ifdef HAVE_MAGICK7

Image *
magick_acquire_image( const ImageInfo *image_info, ExceptionInfo *exception )
{
	return( AcquireImage( image_info, exception ) );
}

void
magick_acquire_next_image( const ImageInfo *image_info, Image *image,
	ExceptionInfo *exception )
{
	AcquireNextImage( image_info, image, exception );
}

int
magick_set_image_size( Image *image, const size_t width, const size_t height,
	ExceptionInfo *exception )
{
	return( SetImageExtent( image, width, height, exception ) );
}

int
magick_import_pixels( Image *image, const ssize_t x, const ssize_t y,
	const size_t width, const size_t height, const char *map,
	const StorageType type,const void *pixels, ExceptionInfo *exception )
{
	return( ImportImagePixels( image, x, y, width, height, map,
		type, pixels, exception ) );
}

void *
magick_images_to_blob( const ImageInfo *image_info, Image *images, 
	size_t *length, ExceptionInfo *exception )
{
	return( ImagesToBlob( image_info, images, length, exception ) );
}

void
magick_set_property( Image *image, const char *property, const char *value,
	ExceptionInfo *exception )
{
	(void) SetImageProperty( image, property, value, exception );
}

int
magick_set_profile( Image *image, 
	const char *name, const void *data, size_t length, 
	ExceptionInfo *exception )
{
	StringInfo *string;
	MagickBooleanType result;

	string = BlobToStringInfo( data, length );
	result = SetImageProfile( image, name, string, exception );
	DestroyStringInfo( string );

	return( result );
}

void *
magick_profile_map( Image *image, MagickMapProfileFn fn, void *a )
{
	char *name;

	ResetImageProfileIterator( image );
	while( (name = GetNextImageProfile( image )) ) {
		const StringInfo *profile;
		void *data;
		size_t length;
		void *result;

		profile = GetImageProfile( image, name );
		data = GetStringInfoDatum( profile );
		length = GetStringInfoLength( profile );
		if( (result = fn( image, name, data, length, a )) )
			return( result );
	}

	return( NULL );
}

ExceptionInfo *
magick_acquire_exception( void )
{
	return( AcquireExceptionInfo() );
}

void
magick_destroy_exception( ExceptionInfo *exception )
{
	VIPS_FREEF( DestroyExceptionInfo, exception ); 
}

void
magick_inherit_exception( ExceptionInfo *exception, Image *image ) 
{
	(void) exception;
	(void) image;
}

void
magick_set_number_scenes( ImageInfo *image_info, int scene, int number_scenes )
{
	/* I can't find docs for these fields, but this seems to work.
	 */
	char page[256];

	image_info->scene = scene;
	image_info->number_scenes = number_scenes;

	/* Some IMs must have the string version set as well.
	 */
	vips_snprintf( page, 256, "%d-%d", scene, scene + number_scenes );
	image_info->scenes = g_strdup( page );
}

int
magick_optimize_image_layers( Image **images, ExceptionInfo *exception )
{
	Image *tmp;

	tmp = OptimizePlusImageLayers( *images, exception );

	if( exception->severity != UndefinedException ) {
		VIPS_FREEF( DestroyImageList, tmp );
		return MagickFalse;
	}

	VIPS_FREEF( DestroyImageList, *images );
	*images = tmp;

	return MagickTrue;
}

int
magick_optimize_image_transparency( const Image *images,
	ExceptionInfo *exception )
{
	OptimizeImageTransparency( images, exception );

	return( exception->severity == UndefinedException );
}

/* Does a few bytes look like a file IM can handle?
 */
gboolean
magick_ismagick( const unsigned char *bytes, size_t length )
{
	char format[MagickPathExtent];

	magick_genesis();

	/* Try with our custom sniffers first.
	 */
	return( magick_sniff( bytes, length ) ||
		GetImageMagick( bytes, length, format ) );
}

int
magick_quantize_images( Image *images,
	const size_t depth, ExceptionInfo *exception )
{
	QuantizeInfo info;

	GetQuantizeInfo( &info );
	info.number_colors = 1 << depth;
	QuantizeImages( &info, images, exception );

	return( exception->severity == UndefinedException );
}

#endif /*HAVE_MAGICK7*/

#ifdef HAVE_MAGICK6

Image *
magick_acquire_image( const ImageInfo *image_info, ExceptionInfo *exception )
{
	(void) exception;

#ifdef HAVE_ACQUIREIMAGE
	return( AcquireImage( image_info ) );
#else /*!HAVE_ACQUIREIMAGE*/
	/* IM5-ish and GraphicsMagick use AllocateImage().
	 */
	return( AllocateImage( image_info ) );
#endif
}

void
magick_acquire_next_image( const ImageInfo *image_info, Image *image,
	ExceptionInfo *exception )
{
	(void) exception;
#ifdef HAVE_ACQUIREIMAGE
	AcquireNextImage( image_info, image );
#else /*!HAVE_ACQUIREIMAGE*/
	/* IM5-ish and GraphicsMagick use AllocateNextImage().
	 */
	AllocateNextImage( image_info, image );
#endif
}

int
magick_set_image_size( Image *image, const size_t width, const size_t height,
	ExceptionInfo *exception )
{
#ifdef HAVE_SETIMAGEEXTENT
	int result = SetImageExtent( image, width, height );

	/* IM6 sets the exception on the image.
	 */
	if( !result )
		magick_inherit_exception( exception, image );

	return( result ); 
#else /*!HAVE_SETIMAGEEXTENT*/
	(void) exception;
	image->columns = width;
	image->rows = height;

	/* imagemagick does a SyncImagePixelCache() at the end of
	 * SetImageExtent(), but GM does not really have an equivalent. Just
	 * always return True.
	 */
	return( MagickTrue );
#endif /*HAVE_SETIMAGEEXTENT*/
}

int
magick_import_pixels( Image *image, const ssize_t x, const ssize_t y,
	const size_t width, const size_t height, const char *map,
	const StorageType type, const void *pixels, ExceptionInfo *exception )
{
#ifdef HAVE_IMPORTIMAGEPIXELS
	return( ImportImagePixels( image, x, y, width, height, map,
		type, pixels ) );
#else /*!HAVE_IMPORTIMAGEPIXELS*/
	Image *constitute_image;
	unsigned int storage_type_depth;

	g_assert( image );
	g_assert( image->signature == MagickSignature );

	constitute_image = ConstituteImage( width, height, map, type, 
		pixels, &image->exception );
	if( !constitute_image ) 
		return( MagickFalse );

	/* image needs to inherit these fields from constitute_image.
	 */
	switch( type ) {
	case CharPixel: 
		storage_type_depth = sizeof( unsigned char ) * 8; 
		break;

	case ShortPixel: 
		storage_type_depth = sizeof( unsigned short ) * 8; 
		break;

	case IntegerPixel: 
		storage_type_depth = sizeof( unsigned short ) * 8; 
		break;

	case LongPixel: 
		storage_type_depth = sizeof( unsigned long ) * 8; 
		break;

	case FloatPixel: 
		storage_type_depth = sizeof( float ) * 8; 
		break;

	case DoublePixel: 
		storage_type_depth = sizeof( double ) * 8; 
		break;

	default:
		storage_type_depth = QuantumDepth;
		break;

	}
	image->depth = VIPS_MIN( storage_type_depth, QuantumDepth );
	image->matte = constitute_image->matte;

	(void) CompositeImage( image, CopyCompositeOp, constitute_image, x, y );

	DestroyImage( constitute_image );

	return( image->exception.severity == UndefinedException );
#endif /*HAVE_IMPORTIMAGEPIXELS*/
}

void *
magick_images_to_blob( const ImageInfo *image_info, Image *images, 
	size_t *length, ExceptionInfo *exception )
{
#ifdef HAVE_IMAGESTOBLOB
	return( ImagesToBlob( image_info, images, length, exception ) );
#else
	return( ImageToBlob( image_info, images, length, exception ) );
#endif /*HAVE_IMAGESTOBLOB*/
}

void
magick_set_property( Image *image, const char *property, const char *value,
	ExceptionInfo *exception )
{
	(void) exception;
#ifdef HAVE_SETIMAGEPROPERTY
	(void) SetImageProperty( image, property, value );
#else /*!HAVE_SETIMAGEPROPERTY*/
	(void) SetImageAttribute( image, property, value );
#endif /*HAVE_SETIMAGEPROPERTY*/
}

int
magick_set_profile( Image *image, 
	const char *name, const void *data, size_t length,
       	ExceptionInfo *exception )
{
	int result;

#ifdef HAVE_BLOBTOSTRINGINFO
	StringInfo *string;

	string = BlobToStringInfo( data, length );
	result = SetImageProfile( image, name, string );
	DestroyStringInfo( string );
#else /*!HAVE_BLOBTOSTRINGINFO*/
	result = SetImageProfile( image, name, data, length );
#endif /*HAVE_BLOBTOSTRINGINFO*/

	return( result );
}

void *
magick_profile_map( Image *image, MagickMapProfileFn fn, void *a )
{
	const char *name;
	const void *data;
	size_t length;
	void *result;

#ifdef HAVE_RESETIMAGEPROFILEITERATOR
	ResetImageProfileIterator( image );
	while( (name = GetNextImageProfile( image )) ) {
		const StringInfo *profile;

		profile = GetImageProfile( image, name );
		data = GetStringInfoDatum( profile );
		length = GetStringInfoLength( profile );
		if( (result = fn( image, name, data, length, a )) )
			return( result );
	}
#else /*!HAVE_RESETIMAGEPROFILEITERATOR*/
{
	ImageProfileIterator *iter; 

	iter = AllocateImageProfileIterator( image );
	while( NextImageProfile( iter, 
		&name, (const unsigned char **) &data, &length ) ) {
		if( (result = fn( image, name, data, length, a )) ) {
			DeallocateImageProfileIterator( iter );
			return( result );
		}
	}
	DeallocateImageProfileIterator( iter );
}
#endif /*HAVE_RESETIMAGEPROFILEITERATOR*/

	return( NULL );
}

ExceptionInfo *
magick_acquire_exception( void )
{
	ExceptionInfo *exception;

#ifdef HAVE_ACQUIREEXCEPTIONINFO
	/* IM6+
	 */
	exception = AcquireExceptionInfo();
#else /*!HAVE_ACQUIREEXCEPTIONINFO*/
	/* gm
	 */
	exception = g_new( ExceptionInfo, 1 );
	GetExceptionInfo( exception );
#endif /*HAVE_ACQUIREEXCEPTIONINFO*/

	return( exception );
}

void
magick_destroy_exception( ExceptionInfo *exception )
{
#ifdef HAVE_ACQUIREEXCEPTIONINFO
	/* IM6+ will free the exception in destroy.
	 */
	VIPS_FREEF( DestroyExceptionInfo, exception ); 
#else /*!HAVE_ACQUIREEXCEPTIONINFO*/
	/* gm and very old IM need to free the memory too.
	 */
	if( exception ) { 
		DestroyExceptionInfo( exception ); 
		g_free( exception );
	}
#endif /*HAVE_ACQUIREEXCEPTIONINFO*/
}

void
magick_inherit_exception( ExceptionInfo *exception, Image *image ) 
{
#ifdef HAVE_INHERITEXCEPTION
	InheritException( exception, &image->exception );
#endif /*HAVE_INHERITEXCEPTION*/
}

void
magick_set_number_scenes( ImageInfo *image_info, int scene, int number_scenes )
{
#ifdef HAVE_NUMBER_SCENES 
	/* I can't find docs for these fields, but this seems to work.
	 */
	char page[256];

	image_info->scene = scene;
	image_info->number_scenes = number_scenes;

	/* Some IMs must have the string version set as well.
	 */
	vips_snprintf( page, 256, "%d-%d", scene, scene + number_scenes );
	image_info->scenes = g_strdup( page );
#else /*!HAVE_NUMBER_SCENES*/
	/* This works with GM 1.2.31 and probably others.
	 */
	image_info->subimage = scene;
	image_info->subrange = number_scenes;
#endif
}

int
magick_optimize_image_layers( Image **images, ExceptionInfo *exception )
{
#ifdef HAVE_OPTIMIZEPLUSIMAGELAYERS
	Image *tmp;

	tmp = OptimizePlusImageLayers(*images, exception );

	if ( exception->severity != UndefinedException )
		return MagickFalse;

	VIPS_FREEF( DestroyImageList, *images );

	*images = tmp;

	return MagickTrue;
#else /*!HAVE_OPTIMIZEPLUSIMAGELAYERS*/
	g_warning( "%s", _( "layer optimization is not supported by "
		"your version of libMagick" ) );
	return MagickTrue;
#endif /*HAVE_OPTIMIZEPLUSIMAGELAYERS*/
}

int
magick_optimize_image_transparency( const Image *images,
	ExceptionInfo *exception )
{
#ifdef HAVE_OPTIMIZEIMAGETRANSPARENCY
	OptimizeImageTransparency(images, exception);
	return ( exception->severity == UndefinedException );
#else /*!HAVE_OPTIMIZEIMAGETRANSPARENCY*/
	g_warning( "%s", _( "transparency optimization is not supported by "
		"your version of libMagick" ) );
	return MagickTrue;
#endif /*HAVE_OPTIMIZEIMAGETRANSPARENCY*/
}

/* Does a few bytes look like a file IM can handle?
 */
gboolean
magick_ismagick( const unsigned char *bytes, size_t length )
{
	magick_genesis();

	/* Try with our custom sniffers first.
	 */
#ifdef HAVE_GETIMAGEMAGICK3
{
	char format[MaxTextExtent];

	return( magick_sniff( bytes, length ) ||
		GetImageMagick( bytes, length, format ) );
}
#else /*!HAVE_GETIMAGEMAGICK3*/
	/* The GM one returns a static string.
	 */
	return( magick_sniff( bytes, length ) ||
		GetImageMagick( bytes, length ) );
#endif
}

int
magick_quantize_images( Image *images,
	const size_t depth, ExceptionInfo *exception )
{
	QuantizeInfo info;

	GetQuantizeInfo( &info );
	info.number_colors = (1 << depth);
	return QuantizeImages( &info, images );
}

#endif /*HAVE_MAGICK6*/

#if defined(HAVE_MAGICK6) || defined(HAVE_MAGICK7)

void
magick_set_image_option( ImageInfo *image_info, 
	const char *name, const char *value )
{
#ifdef HAVE_SETIMAGEOPTION
  	SetImageOption( image_info, name, value );
#endif /*HAVE_SETIMAGEOPTION*/
}

typedef struct _MagickColorspaceTypeNames {
	ColorspaceType colorspace;
       const char *name;
} MagickColorspaceTypeNames;

static MagickColorspaceTypeNames magick_colorspace_names[] = {
	{ UndefinedColorspace, "UndefinedColorspace" },
	{ CMYKColorspace, "CMYKColorspace" },
	{ GRAYColorspace, "GRAYColorspace" },
	{ HSLColorspace, "HSLColorspace" },
	{ HWBColorspace, "HWBColorspace" },
	{ OHTAColorspace, "OHTAColorspace" },
	{ Rec601YCbCrColorspace, "Rec601YCbCrColorspace" },
	{ Rec709YCbCrColorspace, "Rec709YCbCrColorspace" },
	{ RGBColorspace, "RGBColorspace" },
	{ sRGBColorspace, "sRGBColorspace" },
	{ TransparentColorspace, "TransparentColorspace" },
	{ XYZColorspace, "XYZColorspace" },
	{ YCbCrColorspace, "YCbCrColorspace" },
	{ YCCColorspace, "YCCColorspace" },
	{ YIQColorspace, "YIQColorspace" },
	{ YPbPrColorspace, "YPbPrColorspace" },
	{ YUVColorspace, "YUVColorspace" },

	/* More recent imagemagicks add these.
	 */
#ifdef HAVE_CMYCOLORSPACE
	{ CMYColorspace, "CMYColorspace" },
	{ HCLColorspace, "HCLColorspace" },
	{ HSBColorspace, "HSBColorspace" },
	{ LabColorspace, "LabColorspace" },
	{ LogColorspace, "LogColorspace" },
	{ LuvColorspace, "LuvColorspace" },
#endif /*HAVE_CMYCOLORSPACE*/

#ifdef HAVE_HCLPCOLORSPACE
	{ HCLpColorspace, "HCLpColorspace" },
	{ HSIColorspace, "HSIColorspace" },
	{ HSVColorspace, "HSVColorspace" },
	{ LCHColorspace, "LCHColorspace" },
	{ LCHabColorspace, "LCHabColorspace" },
	{ LCHuvColorspace, "LCHuvColorspace" },
	{ LMSColorspace, "LMSColorspace" },
	{ scRGBColorspace, "scRGBColorspace" },
	{ xyYColorspace, "xyYColorspace" },
	{ YDbDrColorspace, "YDbDrColorspace" },
#endif /*HAVE_HCLPCOLORSPACE*/

	/* im7 has this, I think
	 *
	{ LinearGRAYColorspace, "LinearGRAYColorspace" }
	 *
	 */
};

const char *
magick_ColorspaceType2str( ColorspaceType colorspace )
{
	int i;

	for( i = 0; i < VIPS_NUMBER( magick_colorspace_names ); i++ ) 
		if( magick_colorspace_names[i].colorspace == colorspace )
			return( magick_colorspace_names[i].name );

	return( "<unknown ColorspaceType>" );
}

void
magick_vips_error( const char *domain, ExceptionInfo *exception )
{
	if( exception ) {
		if( exception->reason && 
			exception->description ) 
			vips_error( domain, _( "libMagick error: %s %s" ),
				exception->reason, exception->description );
		else if( exception->reason ) 
			vips_error( domain, _( "libMagick error: %s" ),
				exception->reason );
		else 
			vips_error( domain, "%s", _( "libMagick error:" ) );
	}
}

static void *
magick_genesis_cb( void *client )
{
	ExceptionInfo *exception;

#ifdef DEBUG
	printf( "magick_genesis_cb:\n" ); 
#endif /*DEBUG*/

#if defined(HAVE_MAGICKCOREGENESIS) || defined(HAVE_MAGICK7) 
	MagickCoreGenesis( vips_get_argv0(), MagickFalse );
#else /*!HAVE_MAGICKCOREGENESIS*/
	InitializeMagick( vips_get_argv0() );
#endif /*HAVE_MAGICKCOREGENESIS*/

	/* This forces *magick to init all loaders. We have to do this so we
	 * can sniff files with GetImageMagick(). 
	 *
	 * We don't care about errors from magickinit.
	 */
	exception = magick_acquire_exception();
	(void) GetMagickInfo( "*", exception );
	magick_destroy_exception(exception);

	return( NULL );
}

void
magick_genesis( void )
{
	static GOnce once = G_ONCE_INIT;

	VIPS_ONCE( &once, magick_genesis_cb, NULL );
}

/* Set vips metadata from a magick profile.
 */
static void *
magick_set_vips_profile_cb( Image *image, 
	const char *name, const void *data, size_t length, void *a )
{
	VipsImage *im = (VipsImage *) a;

	char name_text[256];
	VipsBuf vips_name = VIPS_BUF_STATIC( name_text );

	if( g_ascii_strcasecmp( name, "XMP" ) == 0 )
		vips_buf_appendf( &vips_name, VIPS_META_XMP_NAME );
	else if( g_ascii_strcasecmp( name, "IPTC" ) == 0 )
		vips_buf_appendf( &vips_name, VIPS_META_IPTC_NAME );
	else if( g_ascii_strcasecmp( name, "ICC" ) == 0 )
		vips_buf_appendf( &vips_name, VIPS_META_ICC_NAME );
	else if( g_ascii_strcasecmp( name, "EXIF" ) == 0 )
		vips_buf_appendf( &vips_name, VIPS_META_EXIF_NAME );
	else
		vips_buf_appendf( &vips_name, "magickprofile-%s", name );

	vips_image_set_blob_copy( im, 
		vips_buf_all( &vips_name ), data, length ); 

	if( strcmp( name, "exif" ) == 0 ) 
		(void) vips__exif_parse( im );

	return( NULL );
}

/* Set vips metadata from ImageMagick profiles.
 */
int
magick_set_vips_profile( VipsImage *im, Image *image )
{
	if( magick_profile_map( image, magick_set_vips_profile_cb, im ) )
		return( -1 );

	return( 0 );
}

typedef struct {
	Image *image;
	ExceptionInfo *exception;
} CopyProfileInfo;

static void *
magick_set_magick_profile_cb( VipsImage *im, 
	const char *name, GValue *value, CopyProfileInfo *info )
{
	char txt[256];
	VipsBuf buf = VIPS_BUF_STATIC( txt );
	const void *data;
	size_t length;

	if( strcmp( name, VIPS_META_XMP_NAME ) == 0 )
		vips_buf_appendf( &buf, "XMP" );
	else if( strcmp( name, VIPS_META_IPTC_NAME ) == 0 )
		vips_buf_appendf( &buf, "IPTC" );
	else if( strcmp( name, VIPS_META_ICC_NAME ) == 0 )
		vips_buf_appendf( &buf, "ICC" );
	else if( strcmp( name, VIPS_META_EXIF_NAME ) == 0 )
		vips_buf_appendf( &buf, "EXIF" );
	else if( vips_isprefix( "magickprofile-", name ) ) 
		vips_buf_appendf( &buf, 
			"%s", name + strlen( "magickprofile-" ) );

	if( vips_buf_is_empty( &buf ) ) 
		return( NULL );
	if( !vips_image_get_typeof( im, name ) ) 
		return( NULL );
	if( vips_image_get_blob( im, name, &data, &length ) )
		return( im );

	if( !magick_set_profile( info->image, 
		vips_buf_all( &buf ), data, length, info->exception ) )
		return( im );

	return( NULL );
}

/* Set magick metadata from a VipsImage.
 */
int
magick_set_magick_profile( Image *image, 
	VipsImage *im, ExceptionInfo *exception )
{
	CopyProfileInfo info;

	info.image = image;
	info.exception = exception;
	if( vips_image_map( im, 
		(VipsImageMapFn) magick_set_magick_profile_cb, &info ) )
		return( -1 );

	return( 0 );
}

#endif /*defined(HAVE_MAGICK6) || defined(HAVE_MAGICK7)*/
