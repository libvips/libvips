/* Common functions for interfacing with ImageMagick.
 *
 * 22/12/17 dlemstra 
 *
 * 24/7/18
 * 	- add the sniffer
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
#include <vips/intl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vips/vips.h>

#include "pforeign.h"
#include "magick.h"

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

void
magick_set_property( Image *image, const char *property, const char *value,
	ExceptionInfo *exception )
{
	(void) SetImageProperty( image, property, value, exception );
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
	image_info->scenes = strdup( page );
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
	(void) exception;
#ifdef HAVE_SETIMAGEEXTENT
	return( SetImageExtent( image, width, height ) );
#else /*!HAVE_SETIMAGEEXTENT*/
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
	(void) exception;

	/* GM does not seem to have a simple equivalent, unfortunately.
	 *
	 * Looks like we'd need to call 
	 *
	 *   extern MagickExport PixelPacket
	 *     *SetImagePixels(Image *image,const long x,const long y,
	 *                       const unsigned long columns,const unsigned
	 *                       long rows);
	 *
	 * then repack pixels into that area using map and storage_type. 
	 */
#ifdef HAVE_IMPORTIMAGEPIXELS
	return( ImportImagePixels( image, x, y, width, height, map,
		type, pixels ) );
#else /*!HAVE_IMPORTIMAGEPIXELS*/
	return( MagickFalse );
#endif /*HAVE_IMPORTIMAGEPIXELS*/
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
	image_info->scenes = strdup( page );
#else /*!HAVE_NUMBER_SCENES*/
	/* This works with GM 1.2.31 and probably others.
	 */
	image_info->subimage = scene;
	image_info->subrange = number_scenes;
#endif
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

/* ImageMagick can't detect some formats, like ICO, by examining the contents --
 * ico.c simply does not have a recogniser.
 *
 * For these formats, do the detection ourselves.
 *
 * Return an IM format specifier, or NULL to let IM do the detection.
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
#ifdef DEBUG
	printf( "magick_genesis_cb:\n" ); 
#endif /*DEBUG*/

#if defined(HAVE_MAGICKCOREGENESIS) || defined(HAVE_MAGICK7) 
	MagickCoreGenesis( vips_get_argv0(), MagickFalse );
#else /*!HAVE_MAGICKCOREGENESIS*/
	InitializeMagick( "" );
#endif /*HAVE_MAGICKCOREGENESIS*/

	return( NULL );
}

void
magick_genesis( void )
{
	static GOnce once = G_ONCE_INIT;

	VIPS_ONCE( &once, magick_genesis_cb, NULL );
}

#endif /*HAVE_MAGICK*/
