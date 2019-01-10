/* save with libMagick
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

#ifdef ENABLE_MAGICKSAVE

#include "pforeign.h"
#include "magick.h"

typedef struct _VipsForeignSaveMagick {
	VipsForeignSave parent_object;

	/* Parameters.
	 */
	char *filename;		/* NULL during buffer output */
	char *format;
	int quality;

	Image *images;
	ImageInfo *image_info;
	ExceptionInfo *exception;

	Image *current_image;
	char *map;
	StorageType storage_type;
} VipsForeignSaveMagick;

typedef VipsForeignSaveClass VipsForeignSaveMagickClass;

G_DEFINE_ABSTRACT_TYPE( VipsForeignSaveMagick, vips_foreign_save_magick,
	VIPS_TYPE_FOREIGN_SAVE );

static void
vips_foreign_save_magick_dispose( GObject *gobject )
{
	VipsForeignSaveMagick *magick = (VipsForeignSaveMagick *) gobject;

#ifdef DEBUG
	printf( "vips_foreign_save_magick_dispose: %p\n", gobject ); 
#endif /*DEBUG*/

	VIPS_FREE( magick->map );
	VIPS_FREEF( DestroyImageList, magick->images );
	VIPS_FREEF( DestroyImageInfo, magick->image_info );
	VIPS_FREEF( magick_destroy_exception, magick->exception );

	G_OBJECT_CLASS( vips_foreign_save_magick_parent_class )->
		dispose( gobject );
}

static void
vips_foreign_save_magick_set_properties( VipsForeignSaveMagick *magick, 
	Image *image, VipsImage *im )
{
	int number;
	const char *str;

	if( vips_image_get_typeof( im, "gif-delay" ) &&
		!vips_image_get_int( im, "gif-delay", &number ) )
		image->delay = (size_t) number;

	if( vips_image_get_typeof( im, "gif-loop" ) &&
		!vips_image_get_int( im, "gif-loop", &number ) )
		image->iterations = (size_t) number;

	if( vips_image_get_typeof( im, "gif-comment" ) &&
		!vips_image_get_string( im, "gif-comment", &str ) )
		magick_set_property( image, "comment", str, magick->exception );
}

static int
magick_write_block( VipsRegion *region, VipsRect *area, void *a )
{
	VipsForeignSaveMagick *magick = (VipsForeignSaveMagick *) a;

	MagickBooleanType status;
	void *p;

	p = VIPS_REGION_ADDR( region, area->left, area->top );

	status = magick_import_pixels( magick->current_image, 
		area->left, area->top, area->width, area->height, 
		magick->map, magick->storage_type, 
		p,
		magick->exception );

	return( status == MagickFalse ? -1 : 0 );
}

static int
vips_foreign_save_magick_create_one( VipsForeignSaveMagick *magick, 
	VipsImage *im )
{
	Image *image;
	int status;

	if( magick->images == NULL ) {
		if( !(image = magick_acquire_image( magick->image_info, 
			magick->exception )) )
			return( -1 );

		magick->images = image;
	}
	else {
		image = GetLastImageInList( magick->images );
		magick_acquire_next_image( magick->image_info, image, 
			magick->exception );
		if( GetNextImageInList( image ) == NULL )
			return( -1 );

		image = SyncNextImageInList( image );
	}

	if( !magick_set_image_size( image, im->Xsize, im->Ysize, 
		magick->exception ) )
		return( -1 );
	vips_foreign_save_magick_set_properties( magick, image, im );

	magick->current_image = image;
	status = vips_sink_disc( im, magick_write_block, magick );

	magick_inherit_exception( magick->exception, image );

	return( status );
}

static int
vips_foreign_save_magick_create( VipsForeignSaveMagick *magick, VipsImage *im )
{
	int page_height;
	int status;
	int top;

	page_height = 0;
	if( vips_image_get_typeof( im, VIPS_META_PAGE_HEIGHT ) &&
		vips_image_get_int( im, VIPS_META_PAGE_HEIGHT, &page_height ) )
		;
	if( page_height <= 0 )
		page_height = im->Ysize;

	status = 0;
	for( top = 0; top < im->Ysize; top += page_height ) {
		VipsImage *x;

		if( vips_crop( im, &x, 0, top, im->Xsize, page_height, NULL ) )
			return( -1 );

		status = vips_foreign_save_magick_create_one( magick, x );

		g_object_unref( x );

		if( status )
			break;
	}

	return( status );
}

static int
vips_foreign_save_magick_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object ); 
	VipsForeignSave *save = (VipsForeignSave *) object;
	VipsForeignSaveMagick *magick = (VipsForeignSaveMagick *) object;

	VipsImage *im;

#ifdef DEBUG
	printf( "vips_foreign_save_magick_build: %p\n", object ); 
#endif /*DEBUG*/

	if( VIPS_OBJECT_CLASS( vips_foreign_save_magick_parent_class )->
		build( object ) )
		return( -1 );

	magick_genesis();

	/* The image to save.
	 */
	im = save->ready;

	magick->exception = magick_acquire_exception();
	magick->image_info = CloneImageInfo( NULL );

	magick->storage_type = UndefinedPixel;
	switch( im->BandFmt ) {
	case VIPS_FORMAT_UCHAR:
		magick->storage_type = CharPixel;
		break;

	case VIPS_FORMAT_USHORT:
		magick->storage_type = ShortPixel;
		break;

	case VIPS_FORMAT_UINT:
		magick->storage_type = LongPixel;
		break;

	case VIPS_FORMAT_FLOAT:
		magick->storage_type = FloatPixel;
		break;

	case VIPS_FORMAT_DOUBLE:
		magick->storage_type = DoublePixel;
		break;

	default:
		vips_error( class->nickname, 
			"%s", _( "unsupported image format" ) );
		return( -1 );
	}

	magick->map = NULL;
	switch( im->Bands ) {
	case 1:
		magick->map = g_strdup( "I" );
		break;

	case 2:
		magick->map = g_strdup( "IA" );
		break;

	case 3:
		magick->map = g_strdup( "RGB" );
		break;

	case 4:
		if( im->Type == VIPS_INTERPRETATION_CMYK )
			magick->map = g_strdup( "CMYK" );
		else
			magick->map = g_strdup( "RGBA" );
		break;

	case 5:
		magick->map = g_strdup( "CMYKA" );
		break;

	default:
		vips_error( class->nickname, 
			"%s", _( "unsupported number of image bands" ) );
		return( -1 );
	}

	if( magick->format ) {
		vips_strncpy( magick->image_info->magick,
			magick->format, MaxPathExtent );
		if( magick->filename ) 
			(void) vips_snprintf( magick->image_info->filename,
				MaxPathExtent, "%s:%s", 
				magick->format, magick->filename );
	}
	else if( magick->filename ) {
		vips_strncpy( magick->image_info->filename,
			magick->filename, MaxPathExtent );
	}

	if( magick->quality > 0 ) 
		magick->image_info->quality = magick->quality;

	if( vips_foreign_save_magick_create( magick, im ) ) {
		magick_vips_error( class->nickname, magick->exception ); 
		return( -1 ); 
	}

	return( 0 );
}

/* We could call into libMagick and discover what save formats it supports, but
 * that would mean starting up libMagick on libvips init, and that would add a
 * lot of time.
 *
 * Instead, just list the commonly-used formats that all libMagicks support and 
 * that libvips does not.
 */
static const char *vips__save_magick_suffs[] = { ".gif", ".bmp", NULL };

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

	gobject_class->dispose = vips_foreign_save_magick_dispose;
	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "magicksave_base";
	object_class->description = _( "save with ImageMagick" );
	object_class->build = vips_foreign_save_magick_build;

	/* We need to be well to the back of the queue since vips's
	 * dedicated savers are usually preferable.
	 */
	foreign_class->priority = -100;
	foreign_class->suffs = vips__save_magick_suffs;

	save_class->saveable = VIPS_SAVEABLE_ANY;
	save_class->format_table = bandfmt_magick;

	VIPS_ARG_STRING( class, "format", 2,
		_( "Format" ),
		_( "Format to save in" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveMagick, format ),
		NULL );

	VIPS_ARG_INT( class, "quality", 3,
		_( "Quality" ),
		_( "Quality to use" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveMagick, quality ),
		0, 100, 0 );
}

static void
vips_foreign_save_magick_init( VipsForeignSaveMagick *magick )
{
}

typedef struct _VipsForeignSaveMagickFile {
	VipsForeignSaveMagick parent_object;

	char *filename;

} VipsForeignSaveMagickFile;

typedef VipsForeignSaveMagickClass VipsForeignSaveMagickFileClass;

G_DEFINE_TYPE( VipsForeignSaveMagickFile, vips_foreign_save_magick_file,
	vips_foreign_save_magick_get_type() );

static int
vips_foreign_save_magick_file_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object ); 
	VipsForeignSaveMagick *magick = (VipsForeignSaveMagick *) object;
	VipsForeignSaveMagickFile *file = (VipsForeignSaveMagickFile *) object;

	magick->filename = file->filename;

	if( VIPS_OBJECT_CLASS( vips_foreign_save_magick_file_parent_class )->
		build( object ) )
		return( -1 );

	if( !WriteImages( magick->image_info, magick->images,
		magick->image_info->filename, magick->exception ) ) {
		magick_inherit_exception( magick->exception, magick->images );
		magick_vips_error( class->nickname, magick->exception );

		return( -1 );
	}

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

} VipsForeignSaveMagickBuffer;

typedef VipsForeignSaveMagickClass VipsForeignSaveMagickBufferClass;

G_DEFINE_TYPE( VipsForeignSaveMagickBuffer, vips_foreign_save_magick_buffer, 
	vips_foreign_save_magick_get_type() );

static int
vips_foreign_save_magick_buffer_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object ); 
	VipsForeignSaveMagick *magick = (VipsForeignSaveMagick *) object;
	VipsForeignSaveMagickBuffer *buffer = 
		(VipsForeignSaveMagickBuffer *) object;

	void *obuf;
	size_t olen;
	VipsBlob *blob;

	if( VIPS_OBJECT_CLASS( vips_foreign_save_magick_buffer_parent_class )->
		build( object ) )
		return( -1 );

	if( !(obuf = ImagesToBlob( magick->image_info, magick->images, 
		&olen, magick->exception )) ) { 
		magick_inherit_exception( magick->exception, magick->images );
		magick_vips_error( class->nickname, magick->exception );

		return( -1 );
	}

	/* obuf is a g_free() buffer, not vips_free().
	 */
	blob = vips_blob_new( (VipsCallbackFn) g_free, obuf, olen );
	g_object_set( buffer, "buffer", blob, NULL );
	vips_area_unref( VIPS_AREA( blob ) );

	return( 0 );
}

static void
vips_foreign_save_magick_buffer_class_init( 
	VipsForeignSaveMagickBufferClass *class )
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

}

static void
vips_foreign_save_magick_buffer_init( VipsForeignSaveMagickBuffer *buffer )
{
}

#endif /*ENABLE_MAGICKSAVE*/

/**
 * vips_magicksave: (method)
 * @in: image to save 
 * @filename: file to write to 
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @quality: %gint, quality factor
 * * @format: %gchararray, format to save as
 *
 * Write an image using libMagick.
 *
 * Use @quality to set the quality factor. Default 0.
 *
 * Use @format to explicitly set the save format, for example, "BMP". Otherwise
 * the format is guessed from the filename suffix.
 *
 * See also: vips_magicksave_buffer(), vips_magickload().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_magicksave( VipsImage *in, const char *filename, ... )
{
	va_list ap;
	int result;

	va_start( ap, filename );
	result = vips_call_split( "magicksave", ap, in, filename );
	va_end( ap );

	return( result );
}

/**
 * vips_magicksave_buffer: (method)
 * @in: image to save 
 * @buf: (array length=len) (element-type guint8): return output buffer here
 * @len: (type gsize): return output length here
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @quality: %gint, quality factor
 * * @format: %gchararray, format to save as
 *
 * As vips_magicksave(), but save to a memory buffer. 
 *
 * The address of the buffer is returned in @obuf, the length of the buffer in
 * @olen. You are responsible for freeing the buffer with g_free() when you
 * are done with it.
 *
 * See also: vips_magicksave(), vips_image_write_to_file().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_magicksave_buffer( VipsImage *in, void **buf, size_t *len, ... )
{
	va_list ap;
	VipsArea *area;
	int result;

	area = NULL; 

	va_start( ap, len );
	result = vips_call_split( "magicksave_buffer", ap, in, &area );
	va_end( ap );

	if( !result &&
		area ) { 
		if( buf ) {
			*buf = area->data;
			area->free_fn = NULL;
		}
		if( len ) 
			*len = area->length;

		vips_area_unref( area );
	}

	return( result );
}
