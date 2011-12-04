/* save to tiff
 *
 * 2/12/11
 * 	- wrap a class around the tiff writer
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
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

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

typedef struct _VipsForeignSaveTiff {
	VipsForeignSave parent_object;

	/* Filename for save.
	 */
	char *filename; 

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
	VipsForeignTiffResunit resunit;
	double xres;
	double yres;
	gboolean bigtiff;
} VipsForeignSaveTiff;

int vips__tiff_write( VipsImage *in, const char *filename, 
	VipsForeignTiffCompression compression, int Q, 
		VipsForeignTiffPredictor predictor,
	char *profile,
	gboolean tile, int tile_width, int tile_height,
	gboolean pyramid,
	gboolean squash,
	VipsForeignTiffResunit resunit, double xres, double yres,
	gboolean bigtiff );

typedef VipsForeignSaveClass VipsForeignSaveTiffClass;

G_DEFINE_TYPE( VipsForeignSaveTiff, vips_foreign_save_tiff, 
	VIPS_TYPE_FOREIGN_SAVE );

static int
vips_foreign_save_tiff_build( VipsObject *object )
{
	VipsForeignSave *save = (VipsForeignSave *) object;
	VipsForeignSaveTiff *tiff = (VipsForeignSaveTiff *) object;

	char *p;

	if( VIPS_OBJECT_CLASS( vips_foreign_save_tiff_parent_class )->
		build( object ) )
		return( -1 );

	/* Default xres/yres to the values from the image.
	 */
	if( !vips_argument_get_assigned( object, "xres" ) )
		tiff->xres = save->ready->Xres * 10.0;
	if( !vips_argument_get_assigned( object, "yres" ) )
		tiff->yres = save->ready->Yres * 10.0;

	/* resunit param overrides resunit metadata.
	 */
	if( !vips_argument_get_assigned( object, "resunit" ) &&
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

	if( vips__tiff_write( save->ready, tiff->filename,
		tiff->compression, tiff->Q, tiff->predictor,
		tiff->profile,
		tiff->tile, tiff->tile_width, tiff->tile_height,
		tiff->pyramid,
		tiff->squash,
		tiff->resunit, tiff->xres, tiff->yres,
		tiff->bigtiff ) )
		return( -1 );

	return( 0 );
}

static const char *tiff_suffs[] = { ".tif", ".tiff", NULL };

/* Save a bit of typing.
 */
#define UC VIPS_FORMAT_UCHAR
#define C VIPS_FORMAT_CHAR
#define US VIPS_FORMAT_USHORT
#define S VIPS_FORMAT_SHORT
#define UI VIPS_FORMAT_UINT
#define I VIPS_FORMAT_INT
#define F VIPS_FORMAT_FLOAT
#define X VIPS_FORMAT_COMPLEX
#define D VIPS_FORMAT_DOUBLE
#define DX VIPS_FORMAT_DPCOMPLEX

static int bandfmt_tiff[10] = {
/* UC  C   US  S   UI  I   F   X   D   DX */
   UC, UC, US, S,  US, US, F,  F,  F,  F
};

static void
vips_foreign_save_tiff_class_init( VipsForeignSaveTiffClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;
	VipsForeignSaveClass *save_class = (VipsForeignSaveClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "tiffsave";
	object_class->description = _( "save image to tiff file" );
	object_class->build = vips_foreign_save_tiff_build;

	foreign_class->suffs = tiff_suffs;

	save_class->saveable = VIPS_SAVEABLE_ANY;
	save_class->format_table = bandfmt_tiff;

	VIPS_ARG_STRING( class, "filename", 1, 
		_( "Filename" ),
		_( "Filename to save to" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignSaveTiff, filename ),
		NULL );

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

	VIPS_ARG_ENUM( class, "resunit", 15, 
		_( "Resolution unit" ), 
		_( "Resolution unit" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveTiff, resunit ),
		VIPS_TYPE_FOREIGN_TIFF_RESUNIT, 
			VIPS_FOREIGN_TIFF_RESUNIT_CM ); 

	VIPS_ARG_DOUBLE( class, "xres", 16, 
		_( "Xres" ), 
		_( "Horizontal resolution in pixels/mm" ),
		VIPS_ARGUMENT_NONE,
		G_STRUCT_OFFSET( VipsImage, Xres ),
		0, 1000000, 0 );

	VIPS_ARG_DOUBLE( class, "yres", 17, 
		_( "Yres" ), 
		_( "Vertical resolution in pixels/mm" ),
		VIPS_ARGUMENT_NONE,
		G_STRUCT_OFFSET( VipsImage, Yres ),
		0, 1000000, 0 );

	VIPS_ARG_BOOL( class, "bigtiff", 18, 
		_( "Bigtiff" ), 
		_( "Write a bigtiff image" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveTiff, bigtiff ),
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

/**
 * vips_tiffsave:
 * @in: image to save 
 * @filename: file to write to 
 * @compression; use this compression scheme
 * @Q: quality factor
 * @predictor; compress with this prediction
 * @profile: attach this ICC profile
 * @tile; set %TRUE to write a tiled tiff
 * @tile_width; set tile size
 * @tile_height; set tile size
 * @pyramid; set %TRUE to write an image pyramid
 * @squash; squash 8-bit images down to 1 bit
 * @resunit; use pixels per inch or cm for the resolution
 * @xres; horizontal resolution
 * @yres; vertical resolution
 * @bigtiff; write a BigTiff file
 *
 * Write a VIPS image to a file as TIFF.
 *
 * Use @Q to set the JPEG compression factor. Default 75.
 *
 * Use @profile to give the filename of a profile to be em,bedded in the TIFF.
 * This does not affect the pixels which are written, just the way 
 * they are tagged. You can use the special string "none" to mean 
 * "don't attach a profile".
 *
 * If no profile is specified and the VIPS header 
 * contains an ICC profile named VIPS_META_ICC_NAME ("icc-profile-data"), the
 * profile from the VIPS header will be attached.
 *
 * You can embed options in the filename. They have the form:
 *
 * |[
 * filename.tif:<emphasis>compression</emphasis>,<emphasis>layout</emphasis>,<emphasis>multi-res</emphasis>,<emphasis>format</emphasis>,<emphasis>resolution</emphasis>,<emphasis>icc</emphasis>, <emphasis>bigtiff</emphasis>
 * ]|
 *
 * <itemizedlist>
 *   <listitem>
 *     <para>
 * <emphasis>compression</emphasis> 
 * should be one of "none" (no compression), "jpeg" (JPEG compression), 
 * "deflate" (ZIP compression), "packbits" (TIFF packbits compression),
 * "ccittfax4" (CCITT Group 4 fax encoding), "lzw"  (Lempel-Ziv compression).
 *
 * "jpeg" compression can be followed by a ":" character and a JPEG quality
 * level; "lzw" and "deflate" can be followed by a ":" and predictor value. 
 * The default compression type is "none", the default JPEG quality factor 
 * is 75.
 *
 * Predictor is not set by default. There are three predictor values recognised
 * at the moment (2007, July): 1 is no prediction, 2 is a horizontal 
 * differencing and 3 is a floating point predictor. Refer to the libtiff 
 * specifications for further discussion of various predictors. In short, 
 * predictor helps to better compress image, especially in case of digital 
 * photos or scanned images and bit depths > 8. Try it to find whether it 
 * works for your images.
 *
 * JPEG compression is a good lossy compressor for photographs, packbits is 
 * good for 1-bit images, and deflate is the best lossless compression TIFF 
 * can do. LZW has patent problems and is no longer recommended.
 *     </para>
 *   </listitem>
 *   <listitem>
 *     <para>
 * <emphasis>layout</emphasis> 
 * should be "strip" (strip layout) or "tile" (tiled layout).
 *
 * "tile" layout can be followed by a ":" character and the horizontal and
 * vertical tile size, separated by a "x" character. The default layout is
 * "strip", and the default tile size is 128 by 128 pixels.
 *     </para>
 *   </listitem>
 *   <listitem>
 *     <para>
 * <emphasis>multi-res</emphasis> 
 * should be "flat" (single image) or "pyramid" (many images arranged in a 
 * pyramid). The default multi-res mode is "flat".
 *     </para>
 *   </listitem>
 *   <listitem>
 *     <para>
 * <emphasis>format</emphasis> 
 * shoiuld be "manybit" (don't bit-reduce images) or "onebit" (one band 8 
 * bit images are saved as 1 bit). The default format is "multibit". 
 *     </para>
 *   </listitem>
 *   <listitem>
 *     <para>
 * <emphasis>resolution</emphasis> 
 * should be "res_cm"  (output resolution unit is pixels per centimetre) or 
 * "res_inch"  (output resolution unit is pixels per inch). The default 
 * resolution unit is taken from the header field "resolution-unit"
 * (#IM_META_RESOLUTION_UNIT in C). If this field is not set, then 
 * VIPS defaults to cm.
 *
 * The unit can optionally be followed by a ":" character and the 
 * horizontal and vertical resolution, separated by a "x" character. 
 * You can have a single number with no "x" and set the horizontal and 
 * vertical resolutions together. 
 *     </para>
 *   </listitem>
 *   <listitem>
 *     <para>
 * <emphasis>icc</emphasis> 
 * Attach this ICC profile. 
 * This does not affect the pixels which are written, just the way 
 * they are tagged. 
 *     </para>
 *   </listitem>
 *   <listitem>
 *     <para>
 * <emphasis>bigtiff</emphasis> 
 * Set this to 8 to enable bigtiff output. Bigtiff is a variant of the TIFF
 * format that allows more than 4GB in a file.
 *     </para>
 *   </listitem>
 * </itemizedlist>
 *
 * Example:
 *
 * |[
 * im_vips2jpeg( in, "fred.tif:jpeg,tile,pyramid" );
 * ]|
 *
 * Will write "fred.tif" as a tiled jpeg-compressed pyramid.
 *
 * |[
 * im_vips2jpeg( in, "fred.tif:packbits,tile,,onebit" ); 
 * ]|
 *
 * Writes a tiled one bit TIFF image (provided fred.v is a one band 8 bit 
 * image) compressed with packbits.
 *
 * See also: vips_tiffload(), vips_image_write_file().
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
