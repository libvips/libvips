/* save to tiff
 *
 * 2/12/11
 * 	- wrap a class around the tiff writer
 * 17/3/12
 * 	- argh xres/yres macro was wrong
 * 26/1/14
 * 	- add rgbjpeg flag
 * 21/12/15
 * 	- add properties flag
 * 31/5/16
 * 	- convert for jpg if jpg compression is on
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

/*
#define DEBUG_VERBOSE
#define DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vips/vips.h>
#include <vips/internal.h>

#include "pforeign.h"

#ifdef HAVE_TIFF

#include "tiff.h"

typedef struct _VipsForeignSaveTiff {
	VipsForeignSave parent_object;

	/* Many options argh.
	 */
	VipsForeignTiffCompression compression;
	int Q;
	VipsForeignTiffPredictor predictor;
	char *profile; 
	gboolean tile;
	int tile_width;
	int tile_height;
	gboolean pyramid;
	gboolean squash;
	gboolean miniswhite;
	VipsForeignTiffResunit resunit;
	double xres;
	double yres;
	gboolean bigtiff;
	gboolean rgbjpeg;
	gboolean properties;
} VipsForeignSaveTiff;

typedef VipsForeignSaveClass VipsForeignSaveTiffClass;

G_DEFINE_ABSTRACT_TYPE( VipsForeignSaveTiff, vips_foreign_save_tiff, 
	VIPS_TYPE_FOREIGN_SAVE );

#define UC VIPS_FORMAT_UCHAR

/* Type promotion for save ... just always go to uchar.
 */
static int bandfmt_jpeg[10] = {
/* UC  C   US  S   UI  I   F   X   D   DX */
   UC, UC, UC, UC, UC, UC, UC, UC, UC, UC
};

static int
vips_foreign_save_tiff_build( VipsObject *object )
{
	VipsForeignSaveClass *class = VIPS_FOREIGN_SAVE_GET_CLASS( object );

	VipsForeignSave *save = (VipsForeignSave *) object;
	VipsForeignSaveTiff *tiff = (VipsForeignSaveTiff *) object;

	const char *p;

	/* If we are saving jpeg-in-tiff, we need a different convert_saveable
	 * path. The regular tiff one will let through things like float and
	 * 16-bit and alpha for example, which will make the jpeg saver choke.
	 */
	if( save->in &&
		tiff->compression == VIPS_FOREIGN_TIFF_COMPRESSION_JPEG ) {
		VipsImage *x;

		/* See also vips_foreign_save_jpeg_class_init().
		 */
		if( vips__foreign_convert_saveable( save->in, &x,
			VIPS_SAVEABLE_RGB_CMYK, bandfmt_jpeg, class->coding,
			save->background ) )
			return( -1 );

		g_object_set( object, "in", x, NULL );
		g_object_unref( x );
	}

	if( VIPS_OBJECT_CLASS( vips_foreign_save_tiff_parent_class )->
		build( object ) )
		return( -1 );

	/* Default xres/yres to the values from the image.
	 */
	if( !vips_object_argument_isset( object, "xres" ) )
		tiff->xres = save->ready->Xres * 10.0;
	if( !vips_object_argument_isset( object, "yres" ) )
		tiff->yres = save->ready->Yres * 10.0;

	/* resunit param overrides resunit metadata.
	 */
	if( !vips_object_argument_isset( object, "resunit" ) &&
		vips_image_get_typeof( save->ready, 
			VIPS_META_RESOLUTION_UNIT ) &&
		!vips_image_get_string( save->ready, 
			VIPS_META_RESOLUTION_UNIT, &p ) &&
		vips_isprefix( "in", p ) ) 
		tiff->resunit = VIPS_FOREIGN_TIFF_RESUNIT_INCH;

	if( tiff->resunit == VIPS_FOREIGN_TIFF_RESUNIT_INCH ) {
		tiff->xres *= 2.54;
		tiff->yres *= 2.54;
	}

	return( 0 );
}

static void
vips_foreign_save_tiff_class_init( VipsForeignSaveTiffClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;
	VipsForeignSaveClass *save_class = (VipsForeignSaveClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "tiffsave_base";
	object_class->description = _( "save image to tiff file" );
	object_class->build = vips_foreign_save_tiff_build;

	foreign_class->suffs = vips__foreign_tiff_suffs;

	save_class->saveable = VIPS_SAVEABLE_ANY;
	save_class->coding[VIPS_CODING_LABQ] = TRUE;

	VIPS_ARG_ENUM( class, "compression", 6, 
		_( "Compression" ), 
		_( "Compression for this file" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveTiff, compression ),
		VIPS_TYPE_FOREIGN_TIFF_COMPRESSION, 
			VIPS_FOREIGN_TIFF_COMPRESSION_NONE ); 

	VIPS_ARG_INT( class, "Q", 7, 
		_( "Q" ), 
		_( "Q factor" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveTiff, Q ),
		1, 100, 75 );

	VIPS_ARG_ENUM( class, "predictor", 8, 
		_( "predictor" ), 
		_( "Compression prediction" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveTiff, predictor ),
		VIPS_TYPE_FOREIGN_TIFF_PREDICTOR, 
			VIPS_FOREIGN_TIFF_PREDICTOR_NONE ); 

	VIPS_ARG_STRING( class, "profile", 9, 
		_( "profile" ), 
		_( "ICC profile to embed" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveTiff, profile ),
		NULL );

	VIPS_ARG_BOOL( class, "tile", 10, 
		_( "Tile" ), 
		_( "Write a tiled tiff" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveTiff, tile ),
		FALSE );

	VIPS_ARG_INT( class, "tile_width", 11, 
		_( "Tile width" ), 
		_( "Tile width in pixels" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveTiff, tile_width ),
		1, 1024, 128 );

	VIPS_ARG_INT( class, "tile_height", 12, 
		_( "Tile height" ), 
		_( "Tile height in pixels" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveTiff, tile_height ),
		1, 1024, 128 );

	VIPS_ARG_BOOL( class, "pyramid", 13, 
		_( "Pyramid" ), 
		_( "Write a pyramidal tiff" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveTiff, pyramid ),
		FALSE );

	VIPS_ARG_BOOL( class, "squash", 14, 
		_( "Squash" ), 
		_( "Squash images down to 1 bit" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveTiff, squash ),
		FALSE );

	VIPS_ARG_BOOL( class, "miniswhite", 14, 
		_( "Miniswhite" ), 
		_( "Use 0 for white in 1-bit images" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveTiff, miniswhite ),
		FALSE );

	VIPS_ARG_ENUM( class, "resunit", 15, 
		_( "Resolution unit" ), 
		_( "Resolution unit" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveTiff, resunit ),
		VIPS_TYPE_FOREIGN_TIFF_RESUNIT, VIPS_FOREIGN_TIFF_RESUNIT_CM ); 

	VIPS_ARG_DOUBLE( class, "xres", 16, 
		_( "Xres" ), 
		_( "Horizontal resolution in pixels/mm" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveTiff, xres ),
		0.001, 1000000, 1 );

	VIPS_ARG_DOUBLE( class, "yres", 17, 
		_( "Yres" ), 
		_( "Vertical resolution in pixels/mm" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveTiff, yres ),
		0.001, 1000000, 1 );

	VIPS_ARG_BOOL( class, "bigtiff", 18, 
		_( "Bigtiff" ), 
		_( "Write a bigtiff image" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveTiff, bigtiff ),
		FALSE );

	VIPS_ARG_BOOL( class, "rgbjpeg", 20, 
		_( "RGB JPEG" ),
		_( "Output RGB JPEG rather than YCbCr" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT | VIPS_ARGUMENT_DEPRECATED, 
		G_STRUCT_OFFSET( VipsForeignSaveTiff, rgbjpeg ),
		FALSE );

	VIPS_ARG_BOOL( class, "properties", 21, 
		_( "Properties" ), 
		_( "Write a properties document to IMAGEDESCRIPTION" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveTiff, properties ),
		FALSE );

}

static void
vips_foreign_save_tiff_init( VipsForeignSaveTiff *tiff )
{
	tiff->compression = VIPS_FOREIGN_TIFF_COMPRESSION_NONE;
	tiff->Q = 75;
	tiff->predictor = VIPS_FOREIGN_TIFF_PREDICTOR_NONE;
	tiff->tile_width = 128;
	tiff->tile_height = 128;
	tiff->resunit = VIPS_FOREIGN_TIFF_RESUNIT_CM;
	tiff->xres = 1.0;
	tiff->yres = 1.0;
}

typedef struct _VipsForeignSaveTiffFile {
	VipsForeignSaveTiff parent_object;

	char *filename; 
} VipsForeignSaveTiffFile;

typedef VipsForeignSaveTiffClass VipsForeignSaveTiffFileClass;

G_DEFINE_TYPE( VipsForeignSaveTiffFile, vips_foreign_save_tiff_file, 
	vips_foreign_save_tiff_get_type() );

static int
vips_foreign_save_tiff_file_build( VipsObject *object )
{
	VipsForeignSave *save = (VipsForeignSave *) object;
	VipsForeignSaveTiff *tiff = (VipsForeignSaveTiff *) object;
	VipsForeignSaveTiffFile *file = (VipsForeignSaveTiffFile *) object;

	if( VIPS_OBJECT_CLASS( vips_foreign_save_tiff_file_parent_class )->
		build( object ) )
		return( -1 );

	if( vips__tiff_write( save->ready, file->filename,
		tiff->compression, tiff->Q, tiff->predictor,
		tiff->profile,
		tiff->tile, tiff->tile_width, tiff->tile_height,
		tiff->pyramid,
		tiff->squash,
		tiff->miniswhite,
		tiff->resunit, tiff->xres, tiff->yres,
		tiff->bigtiff,
		tiff->rgbjpeg,
		tiff->properties,
		save->strip ) )
		return( -1 );

	return( 0 );
}

static void
vips_foreign_save_tiff_file_class_init( VipsForeignSaveTiffFileClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "tiffsave";
	object_class->description = _( "save image to tiff file" );
	object_class->build = vips_foreign_save_tiff_file_build;

	VIPS_ARG_STRING( class, "filename", 1, 
		_( "Filename" ),
		_( "Filename to save to" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignSaveTiffFile, filename ),
		NULL );
}

static void
vips_foreign_save_tiff_file_init( VipsForeignSaveTiffFile *file )
{
}

typedef struct _VipsForeignSaveTiffBuffer {
	VipsForeignSaveTiff parent_object;

	VipsArea *buf;
} VipsForeignSaveTiffBuffer;

typedef VipsForeignSaveTiffClass VipsForeignSaveTiffBufferClass;

G_DEFINE_TYPE( VipsForeignSaveTiffBuffer, vips_foreign_save_tiff_buffer, 
	vips_foreign_save_tiff_get_type() );

static int
vips_foreign_save_tiff_buffer_build( VipsObject *object )
{
	VipsForeignSave *save = (VipsForeignSave *) object;
	VipsForeignSaveTiff *tiff = (VipsForeignSaveTiff *) object;

	void *obuf;
	size_t olen;
	VipsBlob *blob;

	if( VIPS_OBJECT_CLASS( vips_foreign_save_tiff_buffer_parent_class )->
		build( object ) )
		return( -1 );

	if( vips__tiff_write_buf( save->ready, &obuf, &olen,
		tiff->compression, tiff->Q, tiff->predictor,
		tiff->profile,
		tiff->tile, tiff->tile_width, tiff->tile_height,
		tiff->pyramid,
		tiff->squash,
		tiff->miniswhite,
		tiff->resunit, tiff->xres, tiff->yres,
		tiff->bigtiff,
		tiff->rgbjpeg,
		tiff->properties,
		save->strip ) )
		return( -1 );

	/* vips__tiff_write_buf() makes a buffer that needs g_free(), not
	 * vips_free().
	 */
	blob = vips_blob_new( (VipsCallbackFn) g_free, obuf, olen );
	g_object_set( object, "buffer", blob, NULL );
	vips_area_unref( VIPS_AREA( blob ) );

	return( 0 );
}

static void
vips_foreign_save_tiff_buffer_class_init( VipsForeignSaveTiffBufferClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "tiffsave_buffer";
	object_class->description = _( "save image to tiff buffer" );
	object_class->build = vips_foreign_save_tiff_buffer_build;

	VIPS_ARG_BOXED( class, "buffer", 1, 
		_( "Buffer" ),
		_( "Buffer to save to" ),
		VIPS_ARGUMENT_REQUIRED_OUTPUT, 
		G_STRUCT_OFFSET( VipsForeignSaveTiffBuffer, buf ),
		VIPS_TYPE_BLOB );
}

static void
vips_foreign_save_tiff_buffer_init( VipsForeignSaveTiffBuffer *buffer )
{
}

#endif /*HAVE_TIFF*/

/**
 * vips_tiffsave:
 * @in: image to save 
 * @filename: file to write to 
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @compression: use this #VipsForeignTiffCompression
 * * @Q: %gint quality factor
 * * @predictor: use this #VipsForeignTiffPredictor
 * * @profile: filename of ICC profile to attach
 * * @tile: set %TRUE to write a tiled tiff
 * * @tile_width: %gint for tile size
 * * @tile_height: %gint for tile size
 * * @pyramid: set %TRUE to write an image pyramid
 * * @squash: set %TRUE to squash 8-bit images down to 1 bit
 * * @miniswhite: set %TRUE to write 1-bit images as MINISWHITE
 * * @resunit: #VipsForeignTiffResunit for resolution unit
 * * @xres: %gdouble horizontal resolution in pixels/mm
 * * @yres: %gdouble vertical resolution in pixels/mm
 * * @bigtiff: set %TRUE to write a BigTiff file
 * * @properties: set %TRUE to write an IMAGEDESCRIPTION tag
 * * @strip: set %TRUE to block metadata save
 *
 * Write a VIPS image to a file as TIFF.
 *
 * If @in has the #VIPS_META_PAGE_HEIGHT metadata item, this is assumed to be a
 * "toilet roll" image. It will be
 * written as series of pages, each #VIPS_META_PAGE_HEIGHT pixels high. 
 *
 * Use @compression to set the tiff compression. Currently jpeg, packbits,
 * fax4, lzw, none and deflate are supported. The default is no compression.
 * JPEG compression is a good lossy compressor for photographs, packbits is 
 * good for 1-bit images, and deflate is the best lossless compression TIFF 
 * can do. 
 *
 * Use @Q to set the JPEG compression factor. Default 75.
 *
 * Use @predictor to set the predictor for lzw and deflate compression. 
 *
 * Predictor is not set by default. There are three predictor values recognised
 * at the moment (2007, July): 1 is no prediction, 2 is a horizontal 
 * differencing and 3 is a floating point predictor. Refer to the libtiff 
 * specifications for further discussion of various predictors. In short, 
 * predictor helps to better compress image, especially in case of digital 
 * photos or scanned images and bit depths > 8. Try it to find whether it 
 * works for your images.
 *
 * Use @profile to give the filename of a profile to be embedded in the TIFF.
 * This does not affect the pixels which are written, just the way 
 * they are tagged. You can use the special string "none" to mean 
 * "don't attach a profile".
 *
 * If no profile is specified and the VIPS header 
 * contains an ICC profile named #VIPS_META_ICC_NAME, the
 * profile from the VIPS header will be attached.
 *
 * Set @tile to TRUE to write a tiled tiff.  By default tiff are written in
 * strips. Use @tile_width and @tile_height to set the tile size. The defaiult
 * is 128 by 128.
 *
 * Set @pyramid to write the image as a set of images, one per page, of
 * decreasing size. 
 *
 * Set @squash to make 8-bit uchar images write as 1-bit TIFFs. Values >128
 * are written as white, values <=128 as black. Normally vips will write
 * MINISBLACK TIFFs where black is a 0 bit, but if you set @miniswhite, it
 * will use 0 for a white bit. Many pre-press applications only work with
 * images which use this sense. @miniswhite only affects one-bit images, it
 * does nothing for greyscale images. 
 *
 * Use @resunit to override the default resolution unit.  
 * The default 
 * resolution unit is taken from the header field 
 * #VIPS_META_RESOLUTION_UNIT. If this field is not set, then 
 * VIPS defaults to cm.
 *
 * Use @xres and @yres to override the default horizontal and vertical
 * resolutions. By default these values are taken from the VIPS image header. 
 * libvips resolution is always in pixels per millimetre.
 *
 * Set @bigtiff to attempt to write a bigtiff. 
 * Bigtiff is a variant of the TIFF
 * format that allows more than 4GB in a file.
 *
 * Set @properties to write all vips metadata to the IMAGEDESCRIPTION tag as
 * xml. If @properties is not set, the value of #VIPS_META_IMAGEDESCRIPTION is
 * used instead.
 *
 * The value of #VIPS_META_XMP_NAME is written to
 * the XMP tag. #VIPS_META_ORIENTATION (if set) is used to set the value of 
 * the orientation
 * tag. #VIPS_META_IPCT (if set) is used to set the value of the IPCT tag.  
 * #VIPS_META_PHOTOSHOP_NAME (if set) is used to set the value of the PHOTOSHOP
 * tag.
 *
 * See also: vips_tiffload(), vips_image_write_to_file().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_tiffsave( VipsImage *in, const char *filename, ... )
{
	va_list ap;
	int result;

	va_start( ap, filename );
	result = vips_call_split( "tiffsave", ap, in, filename );
	va_end( ap );

	return( result );
}

/**
 * vips_tiffsave_buffer:
 * @in: image to save 
 * @buf: return output buffer here
 * @len: return output length here
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @compression: use this #VipsForeignTiffCompression
 * * @Q: %gint quality factor
 * * @predictor: use this #VipsForeignTiffPredictor
 * * @profile: filename of ICC profile to attach
 * * @tile: set %TRUE to write a tiled tiff
 * * @tile_width: %gint for tile size
 * * @tile_height: %gint for tile size
 * * @pyramid: set %TRUE to write an image pyramid
 * * @squash: set %TRUE to squash 8-bit images down to 1 bit
 * * @miniswhite: set %TRUE to write 1-bit images as MINISWHITE
 * * @resunit: #VipsForeignTiffResunit for resolution unit
 * * @xres: %gdouble horizontal resolution in pixels/mm
 * * @yres: %gdouble vertical resolution in pixels/mm
 * * @bigtiff: set %TRUE to write a BigTiff file
 * * @properties: set %TRUE to write an IMAGEDESCRIPTION tag
 * * @strip: set %TRUE to block metadata save
 *
 * As vips_tiffsave(), but save to a memory buffer. 
 *
 * The address of the buffer is returned in @buf, the length of the buffer in
 * @len. You are responsible for freeing the buffer with g_free() when you
 * are done with it.
 *
 * See also: vips_tiffsave(), vips_image_write_to_file().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_tiffsave_buffer( VipsImage *in, void **buf, size_t *len, ... )
{
	va_list ap;
	VipsArea *area;
	int result;

	area = NULL; 

	va_start( ap, len );
	result = vips_call_split( "tiffsave_buffer", ap, in, &area );
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
