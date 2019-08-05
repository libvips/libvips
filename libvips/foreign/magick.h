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

#if defined(HAVE_MAGICK6) || defined (HAVE_MAGICK7)

#ifdef HAVE_MAGICK6
#include <magick/api.h>
#define MaxPathExtent MaxTextExtent
#endif /*HAVE_MAGICK6*/

#ifdef HAVE_MAGICK7
#include <MagickCore/MagickCore.h>
#define MaxPathExtent MagickPathExtent
#endif /*HAVE_MAGICK7*/

Image *magick_acquire_image( const ImageInfo *image_info, 
	ExceptionInfo *exception );
void magick_acquire_next_image( const ImageInfo *image_info, 
	Image *image, ExceptionInfo *exception );
int magick_set_image_size( Image *image, 
	const size_t width, const size_t height, ExceptionInfo *exception );
int magick_import_pixels( Image *image, const ssize_t x, const ssize_t y,
	const size_t width, const size_t height, const char *map,
	const StorageType type,const void *pixels, ExceptionInfo *exception );
void *magick_images_to_blob( const ImageInfo *image_info, Image *images, 
	size_t *length, ExceptionInfo *exception );
void magick_set_property( Image *image, 
	const char *property, const char *value, ExceptionInfo *exception );
typedef void *(*MagickMapProfileFn)( Image *image, 
	const char *name, const void *data, size_t length, void *a );
void *magick_profile_map( Image *image, MagickMapProfileFn fn, void *a );
int magick_set_profile( Image *image, 
	const char *name, const void *data, size_t length, 
	ExceptionInfo *exception );

void magick_set_image_option( ImageInfo *image_info, 
	const char *name, const char *value );
void magick_set_number_scenes( ImageInfo *image_info, 
	int scene, int number_scenes );

const char *magick_ColorspaceType2str( ColorspaceType colorspace );

ExceptionInfo *magick_acquire_exception( void );
void magick_destroy_exception( ExceptionInfo *exception );
void magick_inherit_exception( ExceptionInfo *exception, Image *image );

void magick_sniff_bytes( ImageInfo *image_info, 
		const unsigned char *bytes, size_t length );
void magick_sniff_file( ImageInfo *image_info, const char *filename );
void magick_vips_error( const char *domain, ExceptionInfo *exception );

void magick_genesis( void );

int magick_set_vips_profile( VipsImage *im, Image *image );
int magick_set_magick_profile( Image *image, 
	VipsImage *im, ExceptionInfo *exception );

int magick_optimize_image_layers( Image **images, ExceptionInfo *exception );
int magick_optimize_image_transparency( const Image *images,
    ExceptionInfo *exception );

gboolean magick_ismagick( const unsigned char *bytes, size_t length );

#endif /*HAVE_MAGICK6*/
