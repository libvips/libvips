/* save as GIF
 *
 * 22/8/21 lovell
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

#ifdef HAVE_CGIF

#include <cgif.h>

typedef struct _VipsForeignSaveCgif {
	VipsForeignSave parent_object;

	double dither;
	int effort;
	int bitdepth;

	VipsTarget *target;
} VipsForeignSaveCgif;

typedef VipsForeignSaveClass VipsForeignSaveCgifClass;

G_DEFINE_ABSTRACT_TYPE( VipsForeignSaveCgif, vips_foreign_save_cgif,
	VIPS_TYPE_FOREIGN_SAVE );

static void
vips_foreign_save_cgif_dispose( GObject *gobject )
{
	VipsForeignSaveCgif *cgif = (VipsForeignSaveCgif *) gobject;

	VIPS_UNREF( cgif->target );

	G_OBJECT_CLASS( vips_foreign_save_cgif_parent_class )->
		dispose( gobject );
}

/* Minimal callback wrapper around vips_target_write
 */
static int vips__cgif_write( void *target, const uint8_t *buffer,
	const size_t length ) {
	return vips_target_write( (VipsTarget *) target,
		(const void *) buffer, (size_t) length );
}

static int
vips_foreign_save_cgif_build( VipsObject *object )
{
	VipsForeignSave *save = (VipsForeignSave *) object;
	VipsForeignSaveCgif *cgif = (VipsForeignSaveCgif *) object;
	VipsImage **t = (VipsImage **) 
		vips_object_local_array( VIPS_OBJECT( cgif ), 2 );

	int rgb;
	int rgba;
	gboolean has_transparency;
	int page_height;
	int *delay;
	int delay_length;
	int loop;
	int top;
	uint8_t * restrict paletteRgba;
	uint8_t * restrict paletteRgb;

	CGIF *cgif_context;
	CGIF_Config cgif_config;
	CGIF_FrameConfig cgif_frame_config;

	if( VIPS_OBJECT_CLASS( vips_foreign_save_cgif_parent_class )->
		build( object ) )
		return( -1 );

	/* Animation properties
	 */
	page_height = vips_image_get_page_height( save->ready );
	delay = NULL;
	if( vips_image_get_typeof( save->ready, "delay" ) )
		vips_image_get_array_int( save->ready, "delay",
			&delay, &delay_length );
	if( vips_image_get_typeof( save->ready, "loop" ) )
		vips_image_get_int( save->ready, "loop", &loop );

	/* Generate indexed image (t[0]) and palette (t[1])
	 */
	if( vips__quantise_image( save->ready, &t[0], &t[1],
		(1 << cgif->bitdepth) - 1, 100, cgif->dither,
		cgif->effort, TRUE ) )
		return( -1 );

	/* Convert palette to RGB
	 */
	paletteRgba = (uint8_t *) VIPS_IMAGE_ADDR( t[1], 0, 0 );
	paletteRgb = g_malloc0( t[1]->Xsize * 3 );
	for( rgb = 0, rgba = 0; rgb < t[1]->Xsize * 3; rgb += 3 ) {
		paletteRgb[rgb] = paletteRgba[rgba];
		paletteRgb[rgb + 1] = paletteRgba[rgba + 1];
		paletteRgb[rgb + 2] = paletteRgba[rgba + 2];
		rgba += 4;
	}

	/* Does the palette contain a transparent pixel value? This will 
	 * always the first entry, if any.
	 */
	has_transparency = paletteRgba[3] == 255 ? FALSE : TRUE;

	/* Initiialise cgif
	 */
	memset( &cgif_config, 0, sizeof( CGIF_Config ) );
	cgif_config.width = t[0]->Xsize;
	cgif_config.height = page_height;
	cgif_config.pGlobalPalette = paletteRgb;
	cgif_config.numGlobalPaletteEntries = t[1]->Xsize;
	cgif_config.numLoops = loop;
	cgif_config.attrFlags = CGIF_ATTR_IS_ANIMATED;
	if( has_transparency ) 
		cgif_config.attrFlags |= CGIF_ATTR_HAS_TRANSPARENCY;
	cgif_config.pWriteFn = vips__cgif_write;
	cgif_config.pContext = (void *) cgif->target;
	cgif_context = cgif_newgif( &cgif_config );
	g_free( paletteRgb );

	/* Add each vips page as a cgif frame
	 */
	for( top = 0; top < t[0]->Ysize; top += page_height ) {
		int page_index = top / page_height;

		memset( &cgif_frame_config, 0, sizeof( CGIF_FrameConfig ) );
		cgif_frame_config.pImageData = (uint8_t *)
			VIPS_IMAGE_ADDR( t[0], 0, top );
		if( delay &&
			page_index < delay_length )
			cgif_frame_config.delay =
				VIPS_RINT( delay[page_index] / 10.0 );
		if( !has_transparency ) 
			/* Allow cgif to optimise by adding transparency
			 */
			cgif_frame_config.genFlags = 
				CGIF_FRAME_GEN_USE_TRANSPARENCY |
				CGIF_FRAME_GEN_USE_DIFF_WINDOW;
		cgif_addframe( cgif_context, &cgif_frame_config );
	}

	cgif_close( cgif_context );
	vips_target_finish( cgif->target );

	return( 0 );
}

static const char *vips__save_cgif_suffs[] = { ".gif", NULL };

#define UC VIPS_FORMAT_UCHAR
static int bandfmt_gif[10] = {
	UC, UC, UC, UC, UC, UC, UC, UC, UC, UC
};

static void
vips_foreign_save_cgif_class_init( VipsForeignSaveCgifClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;
	VipsForeignSaveClass *save_class = (VipsForeignSaveClass *) class;

	gobject_class->dispose = vips_foreign_save_cgif_dispose;
	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "gifsave_base";
	object_class->description = _( "save as gif" );
	object_class->build = vips_foreign_save_cgif_build;

	foreign_class->suffs = vips__save_cgif_suffs;

	save_class->saveable = VIPS_SAVEABLE_RGBA_ONLY;
	save_class->format_table = bandfmt_gif;

	VIPS_ARG_DOUBLE( class, "dither", 10,
		_( "Dithering" ),
		_( "Amount of dithering" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveCgif, dither ),
		0.0, 1.0, 1.0 );

	VIPS_ARG_INT( class, "effort", 11,
		_( "Effort" ),
		_( "Quantisation effort" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveCgif, effort ),
		1, 10, 7 );

	VIPS_ARG_INT( class, "bitdepth", 12,
		_( "Bit depth" ),
		_( "Number of bits per pixel" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveCgif, bitdepth ),
		1, 8, 8 );

}

static void
vips_foreign_save_cgif_init( VipsForeignSaveCgif *gif )
{
	gif->dither = 1.0;
	gif->effort = 7;
	gif->bitdepth = 8;
}

typedef struct _VipsForeignSaveCgifTarget {
	VipsForeignSaveCgif parent_object;

	VipsTarget *target;
} VipsForeignSaveCgifTarget;

typedef VipsForeignSaveCgifClass VipsForeignSaveCgifTargetClass;

G_DEFINE_TYPE( VipsForeignSaveCgifTarget, vips_foreign_save_cgif_target,
	vips_foreign_save_cgif_get_type() );

static int
vips_foreign_save_cgif_target_build( VipsObject *object )
{
	VipsForeignSaveCgif *gif = (VipsForeignSaveCgif *) object;
	VipsForeignSaveCgifTarget *target = 
		(VipsForeignSaveCgifTarget *) object;

	gif->target = target->target;
	g_object_ref( gif->target );

	if( VIPS_OBJECT_CLASS( vips_foreign_save_cgif_target_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

static void
vips_foreign_save_cgif_target_class_init( 
	VipsForeignSaveCgifTargetClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "gifsave_target";
	object_class->build = vips_foreign_save_cgif_target_build;

	VIPS_ARG_OBJECT( class, "target", 1,
		_( "Target" ),
		_( "Target to save to" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveCgifTarget, target ),
		VIPS_TYPE_TARGET );

}

static void
vips_foreign_save_cgif_target_init( VipsForeignSaveCgifTarget *target )
{
}

typedef struct _VipsForeignSaveCgifFile {
	VipsForeignSaveCgif parent_object;
	char *filename;
} VipsForeignSaveCgifFile;

typedef VipsForeignSaveCgifClass VipsForeignSaveCgifFileClass;

G_DEFINE_TYPE( VipsForeignSaveCgifFile, vips_foreign_save_cgif_file,
	vips_foreign_save_cgif_get_type() );

static int
vips_foreign_save_cgif_file_build( VipsObject *object )
{
	VipsForeignSaveCgif *gif = (VipsForeignSaveCgif *) object;
	VipsForeignSaveCgifFile *file = (VipsForeignSaveCgifFile *) object;

	if( !(gif->target = vips_target_new_to_file( file->filename )) )
		return( -1 );

	if( VIPS_OBJECT_CLASS( vips_foreign_save_cgif_file_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

static void
vips_foreign_save_cgif_file_class_init( VipsForeignSaveCgifFileClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "gifsave";
	object_class->build = vips_foreign_save_cgif_file_build;

	VIPS_ARG_STRING( class, "filename", 1,
		_( "Filename" ),
		_( "Filename to save to" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveCgifFile, filename ),
		NULL );
}

static void
vips_foreign_save_cgif_file_init( VipsForeignSaveCgifFile *file )
{
}

typedef struct _VipsForeignSaveCgifBuffer {
	VipsForeignSaveCgif parent_object;
	VipsArea *buf;
} VipsForeignSaveCgifBuffer;

typedef VipsForeignSaveCgifClass VipsForeignSaveCgifBufferClass;

G_DEFINE_TYPE( VipsForeignSaveCgifBuffer, vips_foreign_save_cgif_buffer,
	vips_foreign_save_cgif_get_type() );

static int
vips_foreign_save_cgif_buffer_build( VipsObject *object )
{
	VipsForeignSaveCgif *gif = (VipsForeignSaveCgif *) object;
	VipsForeignSaveCgifBuffer *buffer = 
		(VipsForeignSaveCgifBuffer *) object;

	VipsBlob *blob;

	if( !(gif->target = vips_target_new_to_memory()) )
		return( -1 );

	if( VIPS_OBJECT_CLASS( vips_foreign_save_cgif_buffer_parent_class )->
		build( object ) )
		return( -1 );

	g_object_get( gif->target, "blob", &blob, NULL );
	g_object_set( buffer, "buffer", blob, NULL );
	vips_area_unref( VIPS_AREA( blob ) );

	return( 0 );
}

static void
vips_foreign_save_cgif_buffer_class_init( 
	VipsForeignSaveCgifBufferClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "gifsave_buffer";
	object_class->build = vips_foreign_save_cgif_buffer_build;

	VIPS_ARG_BOXED( class, "buffer", 1,
		_( "Buffer" ),
		_( "Buffer to save to" ),
		VIPS_ARGUMENT_REQUIRED_OUTPUT,
		G_STRUCT_OFFSET( VipsForeignSaveCgifBuffer, buf ),
		VIPS_TYPE_BLOB );
}

static void
vips_foreign_save_cgif_buffer_init( VipsForeignSaveCgifBuffer *buffer )
{
}

#endif /*HAVE_CGIF*/

/**
 * vips_gifsave: (method)
 * @in: image to save
 * @filename: file to write to
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @dither: %double, quantisation dithering level
 * * @effort: %int, quantisation CPU effort
 * * @bitdepth: %int, number of bits per pixel
 *
 * Write a VIPS image to a file as GIF.
 *
 * Use @dither to set the degree of Floyd-Steinberg dithering
 * and @effort to control the CPU effort (1 is the fastest,
 * 10 is the slowest, 7 is the default).
 *
 * Use @bitdepth (from 1 to 8, default 8) to control the number
 * of colours in the palette. The first entry in the palette is
 * always reserved for transparency. For example, a bitdepth of
 * 4 will allow the output to contain up to 15 colours.
 *
 * See also: vips_image_new_from_file().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_gifsave( VipsImage *in, const char *filename, ... )
{
	va_list ap;
	int result;

	va_start( ap, filename );
	result = vips_call_split( "gifsave", ap, in, filename );
	va_end( ap );

	return( result );
}

/**
 * vips_gifsave_buffer: (method)
 * @in: image to save
 * @buf: (array length=len) (element-type guint8): return output buffer here
 * @len: (type gsize): return output length here
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @dither: %double, quantisation dithering level
 * * @effort: %int, quantisation CPU effort
 * * @bitdepth: %int, number of bits per pixel
 *
 * As vips_gifsave(), but save to a memory buffer.
 *
 * The address of the buffer is returned in @buf, the length of the buffer in
 * @len. You are responsible for freeing the buffer with g_free() when you
 * are done with it.
 *
 * See also: vips_gifsave(), vips_image_write_to_file().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_gifsave_buffer( VipsImage *in, void **buf, size_t *len, ... )
{
	va_list ap;
	VipsArea *area;
	int result;

	area = NULL;

	va_start( ap, len );
	result = vips_call_split( "gifsave_buffer", ap, in, &area );
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
 * vips_gifsave_target: (method)
 * @in: image to save
 * @target: save image to this target
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @dither: %double, quantisation dithering level
 * * @effort: %int, quantisation CPU effort
 * * @bitdepth: %int, number of bits per pixel
 *
 * As vips_gifsave(), but save to a target.
 *
 * See also: vips_gifsave(), vips_image_write_to_target().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_gifsave_target( VipsImage *in, VipsTarget *target, ... )
{
	va_list ap;
	int result;

	va_start( ap, target );
	result = vips_call_split( "gifsave_target", ap, in, target );
	va_end( ap );

	return( result );
}
