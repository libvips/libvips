/* save with libMagick
 *
 * 22/12/17 dlemstra 
 * 6/2/19 DarthSim
 * 	- fix GraphicsMagick support
 * 17/2/19
 * 	- support ICC, XMP, EXIF, IPTC metadata
 * 	- write with a single call to vips_sink_disc()
 * 29/6/19
 * 	- support "strip" option
 * 6/7/19 [deftomat]
 * 	- support array of delays 
 * 5/8/19 DarthSim
 * 	- support GIF optimization
 * 21/4/21 kleisauke
 * 	- include GObject part from magicksave.c
 * 9/12/21 [erik-frontify]
 * 	- add gif save subclass
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
	int bitdepth;
	gboolean optimize_gif_frames;
	gboolean optimize_gif_transparency;

	ImageInfo *image_info;
	ExceptionInfo *exception;
	char *map;
	StorageType storage_type;
	Image *images;
	Image *current_image;

	int page_height;
	GValue delay_gvalue;
	int *delays;
	int delays_length;

	/* The position of current_image in the output.
	 */
	VipsRect position;

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

	VIPS_FREE( magick->filename );
	VIPS_FREE( magick->map );
	VIPS_FREEF( DestroyImageList, magick->images );
	VIPS_FREEF( DestroyImageInfo, magick->image_info );
	VIPS_FREEF( magick_destroy_exception, magick->exception );
	g_value_unset( &magick->delay_gvalue );

	G_OBJECT_CLASS( vips_foreign_save_magick_parent_class )->
		dispose( gobject );
}

/* Move current_image on to the next image we will write.
 */
static int
vips_foreign_save_magick_next_image( VipsForeignSaveMagick *magick ) 
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( magick );
	VipsForeignSave *save = (VipsForeignSave *) magick;
	VipsImage *im = save->ready;

	Image *image;
	int number;
	const char *str;
	int page_index;

	g_assert( !magick->current_image );

	if( magick->images == NULL ) {
		if( !(image = magick_acquire_image( magick->image_info, 
			magick->exception )) )
			return( -1 );

		magick->images = image;
		magick->position.top = 0;
		magick->position.left = 0;
		magick->position.width = im->Xsize;
		magick->position.height = magick->page_height;
	}
	else {
		image = GetLastImageInList( magick->images );
		magick_acquire_next_image( magick->image_info, image, 
			magick->exception );
		if( GetNextImageInList( image ) == NULL )
			return( -1 );

		image = SyncNextImageInList( image );
		magick->position.top += magick->page_height;
	}

	if( !magick_set_image_size( image, 
		im->Xsize, magick->page_height, magick->exception ) ) {
		magick_vips_error( class->nickname, magick->exception ); 
		return( -1 );
	}

	/* Delay must be converted from milliseconds into centiseconds
	 * as GIF image requires centiseconds.
	 */
	if( magick->delays ) {
		page_index = magick->position.top / magick->page_height;
		if( page_index < magick->delays_length ) 
			image->delay = 
				VIPS_RINT( magick->delays[page_index] / 10.0 );
	}

	/* ImageMagick uses iterations like this (at least in gif save):
	 * 	0 - set 0 loops (infinite)
	 * 	1 - don't write the netscape extension block
	 * 	2 - loop once
	 * 	3 - loop twice etc.
	 */
	if( vips_image_get_typeof( im, "loop" ) &&
		!vips_image_get_int( im, "loop", &number ) ) {
		image->iterations = (size_t) number;
	}
	else {
		/* DEPRECATED "gif-loop"
		 *
		 * We have the simple gif meaning, so we must add one unless 
		 * it's zero.
		 */
		if( vips_image_get_typeof( im, "gif-loop" ) &&
			!vips_image_get_int( im, "gif-loop", &number ) )
			image->iterations = (size_t) (number ? number + 1 : 0);
	}

	if( vips_image_get_typeof( im, "gif-comment" ) &&
		!vips_image_get_string( im, "gif-comment", &str ) )
		magick_set_property( image, "comment", str, magick->exception );

	/* libvips keeps animations as a set of independent frames, so we want
	 * to clear to the background between each one.
	 */
	image->dispose = BackgroundDispose;

	if( !save->strip &&
		magick_set_magick_profile( image, im, magick->exception ) ) {
		magick_vips_error( class->nickname, magick->exception ); 
		return( -1 );
	}

	magick->current_image = image;
	
	return( 0 );
}

/* We've written all the pixels to current_image ... finish it off ready to
 * move on.
 */
static void
vips_foreign_save_magick_end_image( VipsForeignSaveMagick *magick )
{
	if( magick->current_image ) { 
		magick_inherit_exception( magick->exception, 
			magick->current_image );
		magick->current_image = NULL;
	}
}

/* Another block of pixels have arrived from libvips. 
 */
static int
vips_foreign_save_magick_write_block( VipsRegion *region, VipsRect *area, 
	void *a )
{
	VipsForeignSaveMagick *magick = (VipsForeignSaveMagick *) a;
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( magick ); 

	VipsRect pixels;

	pixels = region->valid;
	do {
		VipsRect hit;
		void *p;

		if( !magick->current_image &&
			vips_foreign_save_magick_next_image( magick ) )
			return( -1 );

		vips_rect_intersectrect( &pixels, &magick->position, &hit );
		p = VIPS_REGION_ADDR( region, hit.left, hit.top );
		if( !magick_import_pixels( magick->current_image, 
			hit.left, hit.top - magick->position.top, 
			hit.width, hit.height, 
			magick->map, magick->storage_type, 
			p, 
			magick->exception ) ) {
			magick_vips_error( class->nickname, 
				magick->exception ); 
			return( -1 );
		}

		/* Have we filled the page.
		 */
		if( VIPS_RECT_BOTTOM( &hit ) == 
			VIPS_RECT_BOTTOM( &magick->position ) ) 
			vips_foreign_save_magick_end_image( magick );

		pixels.top += hit.height;
		pixels.height -= hit.height;
	} while( pixels.height > 0 );

	return( 0 );
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

	magick->page_height = vips_image_get_page_height( im );

	/* Get as a gvalue so we can keep a ref to the delay array while we
	 * need it.
	 */
	if( vips_image_get_typeof( im, "delay" ) ) {
		g_value_unset( &magick->delay_gvalue );
		if( vips_image_get( im, "delay", &magick->delay_gvalue ) ) 
			return( -1 );
		magick->delays = vips_value_get_array_int( 
			&magick->delay_gvalue, &magick->delays_length );
	}

	if( vips_sink_disc( im, 
		vips_foreign_save_magick_write_block, magick ) ) 
		return( -1 );

	if( magick->optimize_gif_frames ) {
		if( !magick_optimize_image_layers( &magick->images, 
			magick->exception ) ) {
			magick_inherit_exception( magick->exception, 
				magick->images );
			magick_vips_error( class->nickname, magick->exception );

			return( -1 );
		}
	}

	if( magick->optimize_gif_transparency ) {
		if( !magick_optimize_image_transparency( magick->images, 
			magick->exception ) ) {
			magick_inherit_exception( magick->exception, 
				magick->images );
			magick_vips_error( class->nickname, magick->exception );

			return( -1 );
		}
	}
	
	/* Bitdepth <= 8 requested? Quantize/Dither images.
	 * ImageMagick then selects the appropriate bit depth when writing
	 * the actual image (e.g. BMP or GIF).
	 */
	if( magick->bitdepth ) {
		if ( !magick_quantize_images( magick->images,
			magick->bitdepth, magick->exception ) ) {
			magick_inherit_exception( magick->exception,
				magick->images );
			magick_vips_error( class->nickname, magick->exception );

			return( -1 );
		}
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
static const char *vips__save_magick_suffs[] = { NULL };
static const char *vips__save_magick_bmp_suffs[] = { ".bmp", NULL };
static const char *vips__save_magick_gif_suffs[] = { ".gif", NULL };

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
	VipsOperationClass *operation_class = (VipsOperationClass *) class;
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;
	VipsForeignSaveClass *save_class = (VipsForeignSaveClass *) class;

	gobject_class->dispose = vips_foreign_save_magick_dispose;
	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "magicksave_base";
	object_class->description = _( "save with ImageMagick" );
	object_class->build = vips_foreign_save_magick_build;

	/* *magick is fuzzed, but it's such a huge thing it's safer to
	 * disable it.
	 */
	operation_class->flags |= VIPS_OPERATION_UNTRUSTED;

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

	VIPS_ARG_BOOL( class, "optimize_gif_frames", 4,
		_( "Optimize_gif_frames" ),
		_( "Apply GIF frames optimization" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveMagick, optimize_gif_frames ),
		FALSE );

	VIPS_ARG_BOOL( class, "optimize_gif_transparency", 5,
		_( "Optimize_gif_transparency" ),
		_( "Apply GIF transparency optimization" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveMagick, 
			optimize_gif_transparency ),
		FALSE );
		
	VIPS_ARG_INT( class, "bitdepth", 6,
		_( "Bit depth" ),
		_( "Number of bits per pixel" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveMagick, bitdepth ),
		0, 8, 0);
}

static void
vips_foreign_save_magick_init( VipsForeignSaveMagick *magick )
{
	/* Init to an int just to have something there. It is swapped for an
	 * int array later.
	 */
	g_value_init( &magick->delay_gvalue, G_TYPE_INT );
	magick->bitdepth = 0;
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

	magick->filename = g_strdup( file->filename );

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

	if( !(obuf = magick_images_to_blob( magick->image_info, magick->images, 
		&olen, magick->exception )) ) {
		magick_inherit_exception( magick->exception, magick->images );
		magick_vips_error( class->nickname, magick->exception );

		return( -1 );
	}

	blob = vips_blob_new( (VipsCallbackFn) vips_area_free_cb, obuf, olen );
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

typedef VipsForeignSaveMagickFile VipsForeignSaveMagickBmpFile;
typedef VipsForeignSaveMagickFileClass VipsForeignSaveMagickBmpFileClass;

G_DEFINE_TYPE( VipsForeignSaveMagickBmpFile, vips_foreign_save_magick_bmp_file, 
	vips_foreign_save_magick_file_get_type() );

static void
vips_foreign_save_magick_bmp_file_class_init( 
	VipsForeignSaveMagickBmpFileClass *class )
{
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;
	VipsOperationClass *operation_class = (VipsOperationClass *) class;

	object_class->nickname = "magicksave_bmp";
	object_class->description = _( "save bmp image with ImageMagick" );

	foreign_class->suffs = vips__save_magick_bmp_suffs;

	/* Hide from UI.
	 */
	operation_class->flags |= VIPS_OPERATION_DEPRECATED;
}

static void
vips_foreign_save_magick_bmp_file_init( VipsForeignSaveMagickBmpFile *file )
{
	VipsForeignSaveMagick *magick = (VipsForeignSaveMagick *) file;

	VIPS_SETSTR( magick->format, "bmp" );
}

typedef VipsForeignSaveMagickBuffer VipsForeignSaveMagickBmpBuffer;
typedef VipsForeignSaveMagickBufferClass VipsForeignSaveMagickBmpBufferClass;

G_DEFINE_TYPE( VipsForeignSaveMagickBmpBuffer, 
	vips_foreign_save_magick_bmp_buffer, 
	vips_foreign_save_magick_buffer_get_type() );

static void
vips_foreign_save_magick_bmp_buffer_class_init(
	VipsForeignSaveMagickBmpBufferClass *class )
{
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;
	VipsOperationClass *operation_class = (VipsOperationClass *) class;

	object_class->nickname = "magicksave_bmp_buffer";
	object_class->description = _( "save bmp image to magick buffer" );

	foreign_class->suffs = vips__save_magick_bmp_suffs;

	/* Hide from UI.
	 */
	operation_class->flags |= VIPS_OPERATION_DEPRECATED;
}

static void
vips_foreign_save_magick_bmp_buffer_init( 
	VipsForeignSaveMagickBmpBuffer *buffer )
{
	VipsForeignSaveMagick *magick = (VipsForeignSaveMagick *) buffer;

	VIPS_SETSTR( magick->format, "bmp" );
}

typedef VipsForeignSaveMagickFile VipsForeignSaveMagickGifFile;
typedef VipsForeignSaveMagickFileClass VipsForeignSaveMagickGifFileClass;

G_DEFINE_TYPE( VipsForeignSaveMagickGifFile, vips_foreign_save_magick_gif_file, 
	vips_foreign_save_magick_file_get_type() );

static void
vips_foreign_save_magick_gif_file_class_init( 
	VipsForeignSaveMagickGifFileClass *class )
{
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;
	VipsOperationClass *operation_class = (VipsOperationClass *) class;

	object_class->nickname = "magicksave_gif";
	object_class->description = _( "save gif image with ImageMagick" );

	foreign_class->suffs = vips__save_magick_gif_suffs;

	/* Hide from UI.
	 */
	operation_class->flags |= VIPS_OPERATION_DEPRECATED;
}

static void
vips_foreign_save_magick_gif_file_init( VipsForeignSaveMagickGifFile *file )
{
	VipsForeignSaveMagick *magick = (VipsForeignSaveMagick *) file;

	VIPS_SETSTR( magick->format, "gif" );
}

typedef VipsForeignSaveMagickBuffer VipsForeignSaveMagickGifBuffer;
typedef VipsForeignSaveMagickBufferClass VipsForeignSaveMagickGifBufferClass;

G_DEFINE_TYPE( VipsForeignSaveMagickGifBuffer, 
	vips_foreign_save_magick_gif_buffer, 
	vips_foreign_save_magick_buffer_get_type() );

static void
vips_foreign_save_magick_gif_buffer_class_init(
	VipsForeignSaveMagickGifBufferClass *class )
{
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;
	VipsOperationClass *operation_class = (VipsOperationClass *) class;

	object_class->nickname = "magicksave_gif_buffer";
	object_class->description = _( "save gif image to magick buffer" );

	foreign_class->suffs = vips__save_magick_gif_suffs;

	/* Hide from UI.
	 */
	operation_class->flags |= VIPS_OPERATION_DEPRECATED;
}

static void
vips_foreign_save_magick_gif_buffer_init( 
	VipsForeignSaveMagickGifBuffer *buffer )
{
	VipsForeignSaveMagick *magick = (VipsForeignSaveMagick *) buffer;

	VIPS_SETSTR( magick->format, "gif" );
}

#endif /*ENABLE_MAGICKSAVE*/
