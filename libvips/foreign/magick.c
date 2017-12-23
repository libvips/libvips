/* Common functions for interfacing with ImageMagick.
 *
 * 22/12/17 dlemstra 
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

int
magick_set_image_colorspace( Image *image, const ColorspaceType colorspace,
	ExceptionInfo *exception)
{
	return( SetImageColorspace( image, colorspace, exception ) );
}

void
magick_inherit_exception( ExceptionInfo *exception, Image *image ) 
{
	(void) exception;
	(void) image;
}

#endif /*HAVE_MAGICK7*/

#ifdef HAVE_MAGICK6

Image*
magick_acquire_image(const ImageInfo *image_info, ExceptionInfo *exception)
{
	(void) exception;
	return( AcquireImage( image_info ) );
}

void
magick_acquire_next_image( const ImageInfo *image_info, Image *image,
	ExceptionInfo *exception )
{
	(void) exception;
	AcquireNextImage( image_info, image );
}

int
magick_set_image_size( Image *image, const size_t width, const size_t height,
	ExceptionInfo *exception )
{
	(void) exception;
	return( SetImageExtent( image, width, height ) );
}

int
magick_import_pixels( Image *image, const ssize_t x, const ssize_t y,
	const size_t width, const size_t height, const char *map,
	const StorageType type,const void *pixels, ExceptionInfo *exception )
{
	(void) exception;
	return( ImportImagePixels( image, x, y, width, height, map,
		type, pixels ) );
}

void
magick_set_property( Image *image, const char *property, const char *value,
	ExceptionInfo *exception )
{
	(void) exception;
	(void) SetImageProperty( image, property, value );
}

int
magick_set_image_colorspace( Image *image, const ColorspaceType colorspace,
	ExceptionInfo *exception )
{
	(void) exception;
	return( SetImageColorspace( image, colorspace ) );
}

void
magick_inherit_exception( ExceptionInfo *exception, Image *image ) 
{
	InheritException( exception, &image->exception );
}

#endif /*HAVE_MAGICK6*/

#if defined(HAVE_MAGICK6) || defined(HAVE_MAGICK7)

void
magick_vips_error( const char *domain, ExceptionInfo *exception )
{
	if( exception &&
		exception->reason &&
		exception->description )
		vips_error( domain, _( "libMagick error: %s %s" ),
			exception->reason, exception->description );
}

static void *
magick_genesis_cb( void *client )
{
#ifdef DEBUG
	printf( "magick_genesis_cb:\n" ); 
#endif /*DEBUG*/

#ifdef HAVE_MAGICKCOREGENESIS
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
