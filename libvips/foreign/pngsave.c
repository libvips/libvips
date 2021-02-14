/* save to png
 *
 * 2/12/11
 * 	- wrap a class around the png writer
 * 16/7/12
 * 	- compression should be 0-9, not 1-10
 * 20/6/18 [felixbuenemann]
 * 	- support png8 palette write with palette, colours, Q, dither
 * 24/6/20
 * 	- add @bitdepth, deprecate @colours
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

#include "pforeign.h"

#ifdef HAVE_PNG

typedef struct _VipsForeignSavePng {
	VipsForeignSave parent_object;

	int compression;
	gboolean interlace;
	char *profile;
	VipsForeignPngFilter filter;
	gboolean palette;
	int Q;
	double dither;
	int bitdepth;

	/* Set by subclasses.
	 */
	VipsTarget *target;

	/* Deprecated.
	 */
	int colours;
} VipsForeignSavePng;

typedef VipsForeignSaveClass VipsForeignSavePngClass;

G_DEFINE_ABSTRACT_TYPE( VipsForeignSavePng, vips_foreign_save_png, 
	VIPS_TYPE_FOREIGN_SAVE );

static void
vips_foreign_save_png_dispose( GObject *gobject )
{
	VipsForeignSavePng *png = (VipsForeignSavePng *) gobject;

	if( png->target ) 
		vips_target_finish( png->target );
	VIPS_UNREF( png->target );

	G_OBJECT_CLASS( vips_foreign_save_png_parent_class )->
		dispose( gobject );
}

static int
vips_foreign_save_png_build( VipsObject *object )
{
	VipsForeignSave *save = (VipsForeignSave *) object;
	VipsForeignSavePng *png = (VipsForeignSavePng *) object;

	VipsImage *in;

	if( VIPS_OBJECT_CLASS( vips_foreign_save_png_parent_class )->
		build( object ) )
		return( -1 );

	in = save->ready;
	g_object_ref( in );

	/* save->ready will have been converted to uint16 for high-bitdepth
	 * formats (eg. float) ... we need to check Type to see if we want 
	 * to save as 8 or 16-bits. Eg. imagine a float image tagged as sRGB.
	 */
	if( in->Type == VIPS_INTERPRETATION_sRGB ||
		in->Type == VIPS_INTERPRETATION_B_W ) {
		VipsImage *x;

		if( vips_cast( in, &x, VIPS_FORMAT_UCHAR, NULL ) ) {
			g_object_unref( in );
			return( -1 );
		}
		g_object_unref( in );
		in = x;
	}

	/* Deprecated "colours" arg just sets bitdepth large enough to hold
	 * that many colours.
	 */
        if( vips_object_argument_isset( object, "colours" ) ) 
		png->bitdepth = ceil( log2( png->colours ) );

        if( !vips_object_argument_isset( object, "bitdepth" ) ) 
		png->bitdepth = in->BandFmt == VIPS_FORMAT_UCHAR ? 8 : 16;

	/* Filtering usually reduces the compression ratio for palette images,
	 * so default off.
	 */
        if( !vips_object_argument_isset( object, "filter" ) &&
		png->palette )
		png->filter = VIPS_FOREIGN_PNG_FILTER_NONE;

	/* If this is a RGB or RGBA image and a low bit depth has been
	 * requested, enable palettization.
	 */
        if( in->Bands > 2 &&
		png->bitdepth < 8 )
		png->palette = TRUE;

	if( vips__png_write_target( in, png->target,
		png->compression, png->interlace, png->profile, png->filter,
		save->strip, png->palette, png->Q, png->dither,
		png->bitdepth ) ) {
		g_object_unref( in );
		return( -1 );
	}

	g_object_unref( in );

	return( 0 );
}

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

/* Except for 8-bit inputs, we send everything else to 16. We decide on png8
 * vs. png16 based on Type in_build(), see above.
 */
static int bandfmt_png[10] = {
/* UC  C   US  S   UI  I   F   X   D   DX */
   UC, UC, US, US, US, US, US, US, US, US
};

static void
vips_foreign_save_png_class_init( VipsForeignSavePngClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;
	VipsForeignSaveClass *save_class = (VipsForeignSaveClass *) class;

	gobject_class->dispose = vips_foreign_save_png_dispose;
	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "pngsave_base";
	object_class->description = _( "save png" );
	object_class->build = vips_foreign_save_png_build;

	foreign_class->suffs = vips__png_suffs;

	save_class->saveable = VIPS_SAVEABLE_RGBA;
	save_class->format_table = bandfmt_png;

	VIPS_ARG_INT( class, "compression", 6, 
		_( "Compression" ), 
		_( "Compression factor" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSavePng, compression ),
		0, 9, 6 );

	VIPS_ARG_BOOL( class, "interlace", 7, 
		_( "Interlace" ), 
		_( "Interlace image" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSavePng, interlace ),
		FALSE );

	VIPS_ARG_STRING( class, "profile", 11, 
		_( "Profile" ), 
		_( "ICC profile to embed" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSavePng, profile ),
		NULL );

	VIPS_ARG_FLAGS( class, "filter", 12,
		_( "Filter" ),
		_( "libpng row filter flag(s)" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSavePng, filter ),
		VIPS_TYPE_FOREIGN_PNG_FILTER,
		VIPS_FOREIGN_PNG_FILTER_ALL );

	VIPS_ARG_BOOL( class, "palette", 13,
		_( "Palette" ),
		_( "Quantise to 8bpp palette" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSavePng, palette ),
		FALSE );

	VIPS_ARG_INT( class, "Q", 15,
		_( "Quality" ),
		_( "Quantisation quality" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSavePng, Q ),
		0, 100, 100 );

	VIPS_ARG_DOUBLE( class, "dither", 16,
		_( "Dithering" ),
		_( "Amount of dithering" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSavePng, dither ),
		0.0, 1.0, 1.0 );

	VIPS_ARG_INT( class, "bitdepth", 17,
		_( "Bit depth" ),
		_( "Write as a 1, 2, 4 or 8 bit image" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSavePng, bitdepth ),
		0, 8, 0 );

	VIPS_ARG_INT( class, "colours", 14,
		_( "Colours" ),
		_( "Max number of palette colours" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT | VIPS_ARGUMENT_DEPRECATED,
		G_STRUCT_OFFSET( VipsForeignSavePng, colours ),
		2, 256, 256 );

}

static void
vips_foreign_save_png_init( VipsForeignSavePng *png )
{
	png->compression = 6;
	png->filter = VIPS_FOREIGN_PNG_FILTER_ALL;
	png->Q = 100;
	png->dither = 1.0;
}

typedef struct _VipsForeignSavePngTarget {
	VipsForeignSavePng parent_object;

	VipsTarget *target;
} VipsForeignSavePngTarget;

typedef VipsForeignSavePngClass VipsForeignSavePngTargetClass;

G_DEFINE_TYPE( VipsForeignSavePngTarget, vips_foreign_save_png_target, 
	vips_foreign_save_png_get_type() );

static int
vips_foreign_save_png_target_build( VipsObject *object )
{
	VipsForeignSavePng *png = (VipsForeignSavePng *) object;
	VipsForeignSavePngTarget *target = (VipsForeignSavePngTarget *) object;

	png->target = target->target;
	g_object_ref( png->target );

	if( VIPS_OBJECT_CLASS( vips_foreign_save_png_target_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

static void
vips_foreign_save_png_target_class_init( VipsForeignSavePngTargetClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "pngsave_target";
	object_class->description = _( "save image to target as PNG" );
	object_class->build = vips_foreign_save_png_target_build;

	VIPS_ARG_OBJECT( class, "target", 1,
		_( "Target" ),
		_( "Target to save to" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignSavePngTarget, target ),
		VIPS_TYPE_TARGET );

}

static void
vips_foreign_save_png_target_init( VipsForeignSavePngTarget *target )
{
}

typedef struct _VipsForeignSavePngFile {
	VipsForeignSavePng parent_object;

	char *filename; 
} VipsForeignSavePngFile;

typedef VipsForeignSavePngClass VipsForeignSavePngFileClass;

G_DEFINE_TYPE( VipsForeignSavePngFile, vips_foreign_save_png_file, 
	vips_foreign_save_png_get_type() );

static int
vips_foreign_save_png_file_build( VipsObject *object )
{
	VipsForeignSavePng *png = (VipsForeignSavePng *) object;
	VipsForeignSavePngFile *file = (VipsForeignSavePngFile *) object;

	if( !(png->target = vips_target_new_to_file( file->filename )) )
		return( -1 );

	if( VIPS_OBJECT_CLASS( vips_foreign_save_png_file_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

static void
vips_foreign_save_png_file_class_init( VipsForeignSavePngFileClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "pngsave";
	object_class->description = _( "save image to png file" );
	object_class->build = vips_foreign_save_png_file_build;

	VIPS_ARG_STRING( class, "filename", 1, 
		_( "Filename" ),
		_( "Filename to save to" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignSavePngFile, filename ),
		NULL );
}

static void
vips_foreign_save_png_file_init( VipsForeignSavePngFile *file )
{
}

typedef struct _VipsForeignSavePngBuffer {
	VipsForeignSavePng parent_object;

	VipsArea *buf;
} VipsForeignSavePngBuffer;

typedef VipsForeignSavePngClass VipsForeignSavePngBufferClass;

G_DEFINE_TYPE( VipsForeignSavePngBuffer, vips_foreign_save_png_buffer, 
	vips_foreign_save_png_get_type() );

static int
vips_foreign_save_png_buffer_build( VipsObject *object )
{
	VipsForeignSavePng *png = (VipsForeignSavePng *) object;
	VipsForeignSavePngBuffer *buffer = (VipsForeignSavePngBuffer *) object;

	VipsBlob *blob;

	if( !(png->target = vips_target_new_to_memory()) )
		return( -1 );

	if( VIPS_OBJECT_CLASS( vips_foreign_save_png_buffer_parent_class )->
		build( object ) )
		return( -1 );

	g_object_get( png->target, "blob", &blob, NULL );
	g_object_set( buffer, "buffer", blob, NULL );
	vips_area_unref( VIPS_AREA( blob ) );

	return( 0 );
}

static void
vips_foreign_save_png_buffer_class_init( VipsForeignSavePngBufferClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "pngsave_buffer";
	object_class->description = _( "save image to png buffer" );
	object_class->build = vips_foreign_save_png_buffer_build;

	VIPS_ARG_BOXED( class, "buffer", 1, 
		_( "Buffer" ),
		_( "Buffer to save to" ),
		VIPS_ARGUMENT_REQUIRED_OUTPUT, 
		G_STRUCT_OFFSET( VipsForeignSavePngBuffer, buf ),
		VIPS_TYPE_BLOB );
}

static void
vips_foreign_save_png_buffer_init( VipsForeignSavePngBuffer *buffer )
{
}

#endif /*HAVE_PNG*/

/**
 * vips_pngsave: (method)
 * @in: image to save 
 * @filename: file to write to 
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @compression: %gint, compression level
 * * @interlace: %gboolean, interlace image
 * * @profile: %gchararray, ICC profile to embed
 * * @filter: #VipsForeignPngFilter row filter flag(s)
 * * @palette: %gboolean, enable quantisation to 8bpp palette
 * * @Q: %gint, quality for 8bpp quantisation 
 * * @dither: %gdouble, amount of dithering for 8bpp quantization
 * * @bitdepth: %int, set write bit depth to 1, 2, 4 or 8
 *
 * Write a VIPS image to a file as PNG.
 *
 * @compression means compress with this much effort (0 - 9). Default 6.
 *
 * Set @interlace to %TRUE to interlace the image with ADAM7 
 * interlacing. Beware
 * than an interlaced PNG can be up to 7 times slower to write than a
 * non-interlaced image.
 *
 * Use @profile to give the filename of a profile to be embedded in the PNG.
 * This does not affect the pixels which are written, just the way 
 * they are tagged. See vips_profile_load() for details on profile naming. 
 *
 * If @profile is specified and the VIPS header 
 * contains an ICC profile named VIPS_META_ICC_NAME ("icc-profile-data"), the
 * profile from the VIPS header will be attached.
 *
 * Use @filter to specify one or more filters (instead of adaptive filtering),
 * see #VipsForeignPngFilter. @filter defaults to NONE for palette images, 
 * since they generally have very low local correlation.
 *
 * The image is automatically converted to RGB, RGBA, Monochrome or Mono +
 * alpha before saving. Images with more than one byte per band element are
 * saved as 16-bit PNG, others are saved as 8-bit PNG.
 *
 * Set @palette to %TRUE to enable palette mode for RGB or RGBA images. A
 * palette will be computed with enough space for @bitdepth (1, 2, 4 or 8) 
 * bits. Use @Q to set the optimisation effort, and @dither to set the degree of
 * Floyd-Steinberg dithering.
 * This feature requires libvips to be compiled with libimagequant.
 *
 * You can also set @bitdepth for mono and mono + alpha images, and the image
 * will be quantized.
 *
 * XMP metadata is written to the XMP chunk. PNG comments are written to
 * separate text chunks.
 *
 * See also: vips_image_new_from_file().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_pngsave( VipsImage *in, const char *filename, ... )
{
	va_list ap;
	int result;

	va_start( ap, filename );
	result = vips_call_split( "pngsave", ap, in, filename );
	va_end( ap );

	return( result );
}

/**
 * vips_pngsave_buffer: (method)
 * @in: image to save 
 * @buf: (array length=len) (element-type guint8): return output buffer here
 * @len: (type gsize): return output length here
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @compression: %gint, compression level
 * * @interlace: %gboolean, interlace image
 * * @profile: %gchararray, ICC profile to embed
 * * @filter: #VipsForeignPngFilter row filter flag(s)
 * * @palette: %gboolean, enable quantisation to 8bpp palette
 * * @Q: %gint, quality for 8bpp quantisation 
 * * @dither: %gdouble, amount of dithering for 8bpp quantization
 * * @bitdepth: %int, set write bit depth to 1, 2, 4 or 8
 *
 * As vips_pngsave(), but save to a memory buffer. 
 *
 * The address of the buffer is returned in @buf, the length of the buffer in
 * @len. You are responsible for freeing the buffer with g_free() when you
 * are done with it.
 *
 * See also: vips_pngsave(), vips_image_write_to_file().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_pngsave_buffer( VipsImage *in, void **buf, size_t *len, ... )
{
	va_list ap;
	VipsArea *area;
	int result;

	area = NULL; 

	va_start( ap, len );
	result = vips_call_split( "pngsave_buffer", ap, in, &area );
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

/**
 * vips_pngsave_target: (method)
 * @in: image to save 
 * @target: save image to this target
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @compression: compression level
 * * @interlace: interlace image
 * * @profile: ICC profile to embed
 * * @filter: libpng row filter flag(s)
 * * @palette: enable quantisation to 8bpp palette
 * * @Q: quality for 8bpp quantisation 
 * * @dither: amount of dithering for 8bpp quantization
 * * @bitdepth: %int, set write bit depth to 1, 2, 4 or 8
 *
 * As vips_pngsave(), but save to a target.
 *
 * See also: vips_pngsave(), vips_image_write_to_target().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_pngsave_target( VipsImage *in, VipsTarget *target, ... )
{
	va_list ap;
	int result;

	va_start( ap, target );
	result = vips_call_split( "pngsave_target", ap, in, target );
	va_end( ap );

	return( result );
}
