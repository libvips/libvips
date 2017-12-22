/* save with libMagick
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

/* Should be removed and added as a configure option */
#define HAVE_MAGICKSAVE 1
/* Should be removed and added as a configure option */

#ifdef HAVE_MAGICKSAVE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vips/vips.h>

#include "pforeign.h"

#ifdef HAVE_MAGICK
	#include <magick/api.h>
	/* pre-float Magick used to call this MaxRGB.
 	*/
	#define MaxPathExtent MaxTextExtent
#endif
#ifdef HAVE_MAGICK7
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
magick_set_image_colorspace( Image *image, const ColorspaceType colorspace,
	ExceptionInfo *exception)
{
	return SetImageColorspace( image, colorspace, exception );
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
magick_set_image_colorspace( Image *image, const ColorspaceType colorspace,
	ExceptionInfo *exception)
{
	(void) exception;
	return SetImageColorspace( image, colorspace );
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

#endif /*HAVE_MAGICK */

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
write_new( VipsImage *im, const char *filename, const char *format,
	const size_t quality )
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
			(void) vips_snprintf( write->image_info->filename,
				MaxPathExtent, "%s:%s", format, filename );
		}
	}
	else if ( filename ) {
		vips_strncpy( write->image_info->filename,
			filename, MaxPathExtent );
	}

	if ( quality > 0 ) {
		write->image_info->quality = quality;
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

	if( im->Bands < 3) {
		if (! magick_set_image_colorspace( image, GRAYColorspace, write->exception ) )
			return( -1 );
	}

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

	if( height == 0 )
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

static int
magick_write( VipsImage *im, const char *filename,
	const char *format, const size_t quality )
{
	Write *write;

	if( !(write = write_new( im, filename, format, quality )) )
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

static int
magick_write_buf( VipsImage *im, void **obuf, size_t *olen,
	const char *format, const size_t quality )
{
	Write *write;

	if( !(write = write_new( im, NULL, format, quality )) )
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



typedef struct _VipsForeignSaveMagick {
	VipsForeignSave parent_object;

} VipsForeignSaveMagick;

typedef VipsForeignSaveClass VipsForeignSaveMagickClass;

G_DEFINE_ABSTRACT_TYPE( VipsForeignSaveMagick, vips_foreign_save_magick,
	VIPS_TYPE_FOREIGN_SAVE );

/* Save a bit of typing.
 */
#define UC VIPS_FORMAT_UCHAR
#define US VIPS_FORMAT_USHORT
#define UI VIPS_FORMAT_UINT
#define F VIPS_FORMAT_FLOAT
#define D VIPS_FORMAT_DOUBLE

static int bandfmt_magick[10] = {
/* UC  C   US  S   UI  I   F   X   D   DX */
   UC, UC, US, US, UI, UI, F,  F,  D,  D
};

static void
vips_foreign_save_magick_class_init( VipsForeignSaveMagickClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;
	VipsForeignSaveClass *save_class = (VipsForeignSaveClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "magicksave_base";
	object_class->description = _( "save with ImageMagick" );

	/* We need to be well to the back of the queue since vips's
	* dedicated savers are usually preferable.
	*/
	foreign_class->priority = -100;

	save_class->saveable = VIPS_SAVEABLE_ANY;
	save_class->format_table = bandfmt_magick;
}

static void
vips_foreign_save_magick_init( VipsForeignSaveMagick *magick )
{
}

typedef struct _VipsForeignSaveMagickFile {
	VipsForeignSaveMagick parent_object;

	char *filename;
	char *format;
	int quality;

} VipsForeignSaveMagickFile;

typedef VipsForeignSaveMagickClass VipsForeignSaveMagickFileClass;

G_DEFINE_TYPE( VipsForeignSaveMagickFile, vips_foreign_save_magick_file,
	vips_foreign_save_magick_get_type() );

static int
vips_foreign_save_magick_file_build( VipsObject *object )
{
	VipsForeignSave *save = (VipsForeignSave *) object;
	VipsForeignSaveMagick *magick = (VipsForeignSaveMagick *) object;
	VipsForeignSaveMagickFile *file = (VipsForeignSaveMagickFile *) object;

	if( VIPS_OBJECT_CLASS( vips_foreign_save_magick_file_parent_class )->
			build( object ) )
		return( -1 );

	if( magick_write( save->ready, file->filename, file->format,
			file->quality ) )
		return( -1 );

	return( 0 );
}

static void
vips_foreign_save_magick_file_class_init(
	VipsForeignSaveMagickFileClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "magicksave";
	object_class->description = _( "save file with ImageMagick" );
	object_class->build = vips_foreign_save_magick_file_build;

	VIPS_ARG_STRING( class, "filename", 1,
		_( "Filename" ),
		_( "Filename to save to" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveMagickFile, filename ),
		NULL );

	VIPS_ARG_STRING( class, "format", 2,
		_( "Format" ),
		_( "Format to save in" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveMagickFile, format ),
		NULL );

	VIPS_ARG_INT( class, "quality", 3,
		_( "Quality" ),
		_( "Quality to use" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveMagickFile, quality ),
		0, 100, 0 );

}

static void
vips_foreign_save_magick_file_init( VipsForeignSaveMagickFile *file )
{
}

typedef struct _VipsForeignSaveMagickBuffer {
	VipsForeignSaveMagick parent_object;

	/* Save to a buffer.
	 */
	VipsArea *buf;
	char *format;
	int quality;

} VipsForeignSaveMagickBuffer;

typedef VipsForeignSaveMagickClass VipsForeignSaveMagickBufferClass;

G_DEFINE_TYPE( VipsForeignSaveMagickBuffer, vips_foreign_save_magick_buffer, 
	vips_foreign_save_magick_get_type() );

static int
vips_foreign_save_magick_buffer_build( VipsObject *object )
{
	VipsForeignSave *save = (VipsForeignSave *) object;
	VipsForeignSaveMagick *magick = (VipsForeignSaveMagick *) object;
	VipsForeignSaveMagickBuffer *buffer = (VipsForeignSaveMagickBuffer *) object;

	void *obuf;
	size_t olen;
	VipsBlob *blob;

	if( VIPS_OBJECT_CLASS( vips_foreign_save_magick_buffer_parent_class )->
		build( object ) )
		return( -1 );

	if( magick_write_buf( save->ready, &obuf, &olen,
			buffer->format, buffer->quality ) )
		return( -1 );

	/* obuf is a g_free() buffer, not vips_free().
	 */
	blob = vips_blob_new( (VipsCallbackFn) g_free, obuf, olen );
	g_object_set( buffer, "buffer", blob, NULL );
	vips_area_unref( VIPS_AREA( blob ) );

	return( 0 );
}

static void
vips_foreign_save_magick_buffer_class_init( VipsForeignSaveMagickBufferClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "magicksave_buffer";
	object_class->description = _( "save image to magick buffer" );
	object_class->build = vips_foreign_save_magick_buffer_build;

	VIPS_ARG_BOXED( class, "buffer", 1,
		_( "Buffer" ),
		_( "Buffer to save to" ),
		VIPS_ARGUMENT_REQUIRED_OUTPUT,
		G_STRUCT_OFFSET( VipsForeignSaveMagickBuffer, buf ),
		VIPS_TYPE_BLOB );

	VIPS_ARG_STRING( class, "format", 2,
		_( "Format" ),
		_( "Format to save in" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveMagickBuffer, format ),
		NULL );

	VIPS_ARG_INT( class, "quality", 3,
		_( "Quality" ),
		_( "Quality to use" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveMagickBuffer, quality ),
		0, 100, 0 );
}

static void
vips_foreign_save_magick_buffer_init( VipsForeignSaveMagickBuffer *buffer )
{
}

#endif /*HAVE_MAGICKSAVE*/
