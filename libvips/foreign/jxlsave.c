/* save as jpeg2000
 *
 * 18/3/20
 * 	- from jxlload.c
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

#ifdef HAVE_LIBJXL

#include <jxl/encode.h>
#include <jxl/thread_parallel_runner.h>

#include "pforeign.h"

typedef struct _VipsForeignSaveJp2k {
	VipsForeignSave parent_object;

	/* Where to write (set by subclasses).
	 */
	VipsTarget *target;

	/* Base image properties.
	 */
	JxlBasicInfo info;
	size_t icc_size;
	uint8_t *icc_data;

	/* Encoder state.
	 */
	void *runner;
	JxlEncoder *encoder;

} VipsForeignSaveJp2k;

typedef VipsForeignSaveClass VipsForeignSaveJp2kClass;

G_DEFINE_ABSTRACT_TYPE( VipsForeignSaveJp2k, vips_foreign_save_jxl, 
	VIPS_TYPE_FOREIGN_SAVE );

static void
vips_foreign_save_jxl_dispose( GObject *gobject )
{
	VipsForeignSaveJp2k *jxl = (VipsForeignSaveJp2k *) gobject;

	VIPS_FREEF( JxlThreadParallelRunnerDestroy, jxl->runner );
	VIPS_FREEF( JxlEncoderDestroy, jxl->encoder );

	G_OBJECT_CLASS( vips_foreign_save_jxl_parent_class )->
		dispose( gobject );
}

static int
vips_foreign_save_jxl_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsForeignSave *save = (VipsForeignSave *) object;
	VipsForeignSaveJp2k *jxl = (VipsForeignSaveJp2k *) object;

	OPJ_COLOR_SPACE color_space;
	int expected_bands;
	int bits_per_pixel;
	int i;
	size_t sizeof_tile;
	size_t sizeof_line;
	VipsRect strip_position;

	if( VIPS_OBJECT_CLASS( vips_foreign_save_jxl_parent_class )->
		build( object ) )
		return( -1 );

	opj_set_default_encoder_parameters( &jxl->parameters );

	/* Analyze our arguments.
	 */

	if( !vips_band_format_isint( save->ready->BandFmt ) ) {
		vips_error( class->nickname,
			"%s", _( "not an integer format" ) );
		return( -1 );
	}

	switch( jxl->subsample_mode ) {
	case VIPS_FOREIGN_SUBSAMPLE_AUTO:
		jxl->downsample =
			!jxl->lossless &&
			jxl->Q < 90 &&
			save->ready->Xsize % 2 == 0 &&
			save->ready->Ysize % 2 == 0 &&
			(save->ready->Type == VIPS_INTERPRETATION_sRGB ||
			 save->ready->Type == VIPS_INTERPRETATION_RGB16) &&
			save->ready->Bands == 3;
		break;

	case VIPS_FOREIGN_SUBSAMPLE_ON:
		jxl->downsample = TRUE;
		break;

	case VIPS_FOREIGN_SUBSAMPLE_OFF:
		jxl->downsample = FALSE;
		break;

	default:
		g_assert_not_reached();
		break;
	}

	if( jxl->downsample ) 
		jxl->save_as_ycc = TRUE;

	/* CIELAB etc. do not seem to be well documented.
	 */
	switch( save->ready->Type ) {
	case VIPS_INTERPRETATION_B_W:
	case VIPS_INTERPRETATION_GREY16:
		color_space = OPJ_CLRSPC_GRAY;
		expected_bands = 1;
		break;

	case VIPS_INTERPRETATION_sRGB:
	case VIPS_INTERPRETATION_RGB16:
		color_space = jxl->save_as_ycc ? 
			OPJ_CLRSPC_SYCC : OPJ_CLRSPC_SRGB;
		expected_bands = 3;
		break;

	case VIPS_INTERPRETATION_CMYK:
		color_space = OPJ_CLRSPC_CMYK;
		expected_bands = 4;
		break;

	default:
		color_space = OPJ_CLRSPC_UNSPECIFIED;
		expected_bands = save->ready->Bands;
		break;
	}

	switch( save->ready->BandFmt ) {
	case VIPS_FORMAT_CHAR:
	case VIPS_FORMAT_UCHAR:
		bits_per_pixel = 8;
		break;

	case VIPS_FORMAT_SHORT:
	case VIPS_FORMAT_USHORT:
		bits_per_pixel = 16;
		break;

	case VIPS_FORMAT_INT:
	case VIPS_FORMAT_UINT:
		/* OpenJPEG only supports up to 31.
		 */
		bits_per_pixel = 31;
		break;

	default:
		g_assert_not_reached();
		break;
	}

	/* Set parameters for compressor.
	 */ 

	/* Always tile.
	 */
	jxl->parameters.tile_size_on = OPJ_TRUE;
	jxl->parameters.cp_tdx = jxl->tile_width;
	jxl->parameters.cp_tdy = jxl->tile_height;

	/* Number of layers to write. Smallest layer is c. 2^5 on the smallest
	 * axis.
	 */
	jxl->parameters.numresolution = VIPS_MAX( 1, 
		log( VIPS_MIN( save->ready->Xsize, save->ready->Ysize ) ) / 
		log( 2 ) - 4 );
#ifdef DEBUG
	printf( "vips_foreign_save_jxl_build: numresolutions = %d\n", 
		jxl->parameters.numresolution );
#endif /*DEBUG*/

	for( i = 0; i < save->ready->Bands; i++ ) {
		jxl->comps[i].dx = (jxl->downsample && i > 0) ? 2 : 1;
		jxl->comps[i].dy = (jxl->downsample && i > 0) ? 2 : 1;
		jxl->comps[i].w = save->ready->Xsize;
		jxl->comps[i].h = save->ready->Ysize;
		jxl->comps[i].x0 = 0;
		jxl->comps[i].y0 = 0;
		jxl->comps[i].prec = bits_per_pixel;
		jxl->comps[i].bpp = bits_per_pixel;
		jxl->comps[i].sgnd = 
			!vips_band_format_isuint( save->ready->BandFmt );
	}

	/* Makes three band images smaller, somehow.
	 */
	jxl->parameters.tcp_mct = 
		(save->ready->Bands == 3 && !jxl->downsample) ? 1 : 0;

	/* Lossy mode.
	 */
	if( !jxl->lossless ) {
		jxl->parameters.irreversible = TRUE;

		/* Map Q to allowed distortion.
		 */
		jxl->parameters.cp_disto_alloc = 1;
		jxl->parameters.cp_fixed_quality = TRUE;
		jxl->parameters.tcp_distoratio[0] = jxl->Q;
		jxl->parameters.tcp_numlayers = 1;
	}

	/* Create output image.
	 */

	jxl->image = opj_image_create( save->ready->Bands, 
		jxl->comps, color_space );
	jxl->image->x1 = save->ready->Xsize;
	jxl->image->y1 = save->ready->Ysize;

	/* Tag alpha channels.
	 */
	for( i = 0; i < save->ready->Bands; i++ )
		jxl->image->comps[i].alpha = i >= expected_bands;

	/* Set up compressor.
	 */

	jxl->codec = opj_create_compress( OPJ_CODEC_J2K );
	vips_foreign_save_jxl_attach_handlers( jxl, jxl->codec );
        if( !opj_setup_encoder( jxl->codec, &jxl->parameters, jxl->image ) ) 
		return( -1 );

#ifdef HAVE_LIBOPENJP2_THREADING
	/* Use eg. VIPS_CONCURRENCY etc. to set n-cpus, if this openjpeg has
	 * stable support. 
	 */
	opj_codec_set_threads( jxl->codec, vips_concurrency_get() );
#endif /*HAVE_LIBOPENJP2_THREADING*/

	if( !(jxl->stream = vips_foreign_save_jxl_target( jxl->target )) )
		return( -1 );

	if( !opj_start_compress( jxl->codec, jxl->image,  jxl->stream ) )
		return( -1 );

	/* The buffer we repack tiles to for write. Large enough for one
	 * complete tile.
	 */
	sizeof_tile = VIPS_IMAGE_SIZEOF_PEL( save->ready ) *
		jxl->tile_width * jxl->tile_height;
	if( !(jxl->tile_buffer = VIPS_ARRAY( NULL, sizeof_tile, VipsPel )) )
		return( -1 );

	/* We need a line of sums for chroma subsample. At worst, gint64.
	 */
	sizeof_line = sizeof( gint64 ) * jxl->tile_width;
	if( !(jxl->accumulate = VIPS_ARRAY( NULL, sizeof_line, VipsPel )) )
		return( -1 );

	/* The line of tiles we are building.
	 */
	jxl->strip = vips_region_new( save->ready );

	/* Position strip at the top of the image, the height of a row of
	 * tiles.
	 */
	strip_position.left = 0;
	strip_position.top = 0;
	strip_position.width = save->ready->Xsize;
	strip_position.height = jxl->tile_height;
	if( vips_region_buffer( jxl->strip, &strip_position ) ) 
		return( -1 );

	/* Write data. 
	 */
	if( vips_sink_disc( save->ready,
		vips_foreign_save_jxl_write_block, jxl ) )
		return( -1 );

	opj_end_compress( jxl->codec, jxl->stream );

	vips_target_finish( jxl->target );

	return( 0 );
}

static void
vips_foreign_save_jxl_class_init( VipsForeignSaveJp2kClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;
	VipsForeignSaveClass *save_class = (VipsForeignSaveClass *) class;

	gobject_class->dispose = vips_foreign_save_jxl_dispose;
	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "jxlsave_base";
	object_class->description = _( "save image in JPEG-XL format" );
	object_class->build = vips_foreign_save_jxl_build;

	foreign_class->suffs = vips__jxl_suffs;

	save_class->saveable = VIPS_SAVEABLE_ANY;

}

static void
vips_foreign_save_jxl_init( VipsForeignSaveJp2k *jxl )
{
}

typedef struct _VipsForeignSaveJp2kFile {
	VipsForeignSaveJp2k parent_object;

	/* Filename for save.
	 */
	char *filename; 

} VipsForeignSaveJp2kFile;

typedef VipsForeignSaveJp2kClass VipsForeignSaveJp2kFileClass;

G_DEFINE_TYPE( VipsForeignSaveJp2kFile, vips_foreign_save_jxl_file, 
	vips_foreign_save_jxl_get_type() );

static int
vips_foreign_save_jxl_file_build( VipsObject *object )
{
	VipsForeignSaveJp2k *jxl = (VipsForeignSaveJp2k *) object;
	VipsForeignSaveJp2kFile *file = (VipsForeignSaveJp2kFile *) object;

	if( !(jxl->target = vips_target_new_to_file( file->filename )) )
		return( -1 );

	if( VIPS_OBJECT_CLASS( vips_foreign_save_jxl_file_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

static void
vips_foreign_save_jxl_file_class_init( VipsForeignSaveJp2kFileClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "jxlsave";
	object_class->build = vips_foreign_save_jxl_file_build;

	VIPS_ARG_STRING( class, "filename", 1, 
		_( "Filename" ),
		_( "Filename to load from" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignSaveJp2kFile, filename ),
		NULL );

}

static void
vips_foreign_save_jxl_file_init( VipsForeignSaveJp2kFile *file )
{
}

typedef struct _VipsForeignSaveJp2kBuffer {
	VipsForeignSaveJp2k parent_object;

	/* Save to a buffer.
	 */
	VipsArea *buf;

} VipsForeignSaveJp2kBuffer;

typedef VipsForeignSaveJp2kClass VipsForeignSaveJp2kBufferClass;

G_DEFINE_TYPE( VipsForeignSaveJp2kBuffer, vips_foreign_save_jxl_buffer, 
	vips_foreign_save_jxl_get_type() );

static int
vips_foreign_save_jxl_buffer_build( VipsObject *object )
{
	VipsForeignSaveJp2k *jxl = (VipsForeignSaveJp2k *) object;
	VipsForeignSaveJp2kBuffer *buffer = 
		(VipsForeignSaveJp2kBuffer *) object;

	VipsBlob *blob;

	if( !(jxl->target = vips_target_new_to_memory()) )
		return( -1 );

	if( VIPS_OBJECT_CLASS( vips_foreign_save_jxl_buffer_parent_class )->
		build( object ) )
		return( -1 );

	g_object_get( jxl->target, "blob", &blob, NULL );
	g_object_set( buffer, "buffer", blob, NULL );
	vips_area_unref( VIPS_AREA( blob ) );

	return( 0 );
}

static void
vips_foreign_save_jxl_buffer_class_init( 
	VipsForeignSaveJp2kBufferClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "jxlsave_buffer";
	object_class->build = vips_foreign_save_jxl_buffer_build;

	VIPS_ARG_BOXED( class, "buffer", 1, 
		_( "Buffer" ),
		_( "Buffer to save to" ),
		VIPS_ARGUMENT_REQUIRED_OUTPUT, 
		G_STRUCT_OFFSET( VipsForeignSaveJp2kBuffer, buf ),
		VIPS_TYPE_BLOB );

}

static void
vips_foreign_save_jxl_buffer_init( VipsForeignSaveJp2kBuffer *buffer )
{
}

typedef struct _VipsForeignSaveJp2kTarget {
	VipsForeignSaveJp2k parent_object;

	VipsTarget *target;
} VipsForeignSaveJp2kTarget;

typedef VipsForeignSaveJp2kClass VipsForeignSaveJp2kTargetClass;

G_DEFINE_TYPE( VipsForeignSaveJp2kTarget, vips_foreign_save_jxl_target, 
	vips_foreign_save_jxl_get_type() );

static int
vips_foreign_save_jxl_target_build( VipsObject *object )
{
	VipsForeignSaveJp2k *jxl = (VipsForeignSaveJp2k *) object;
	VipsForeignSaveJp2kTarget *target = 
		(VipsForeignSaveJp2kTarget *) object;

	if( target->target ) {
		jxl->target = target->target;
		g_object_ref( jxl->target );
	}

	if( VIPS_OBJECT_CLASS( vips_foreign_save_jxl_target_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

static void
vips_foreign_save_jxl_target_class_init( 
	VipsForeignSaveJp2kTargetClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "jxlsave_target";
	object_class->build = vips_foreign_save_jxl_target_build;

	VIPS_ARG_OBJECT( class, "target", 1,
		_( "Target" ),
		_( "Target to save to" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignSaveJp2kTarget, target ),
		VIPS_TYPE_TARGET );

}

static void
vips_foreign_save_jxl_target_init( VipsForeignSaveJp2kTarget *target )
{
}

#endif /*HAVE_LIBOPENJXL*/

/**
 * vips_jxlsave: (method)
 * @in: image to save 
 * @filename: file to write to 
 * @...: %NULL-terminated list of optional named arguments
 *
 * Write a VIPS image to a file in JPEG-XL format. 
 *
 * See also: vips_image_write_to_file(), vips_jxlload().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_jxlsave( VipsImage *in, const char *filename, ... )
{
	va_list ap;
	int result;

	va_start( ap, filename );
	result = vips_call_split( "jxlsave", ap, in, filename );
	va_end( ap );

	return( result );
}

/**
 * vips_jxlsave_buffer: (method)
 * @in: image to save 
 * @buf: (array length=len) (element-type guint8): return output buffer here
 * @len: (type gsize): return output length here
 * @...: %NULL-terminated list of optional named arguments
 *
 * As vips_jxlsave(), but save to a memory buffer.
 *
 * See also: vips_jxlsave(), vips_image_write_to_target().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_jxlsave_buffer( VipsImage *in, void **buf, size_t *len, ... )
{
	va_list ap;
	VipsArea *area;
	int result;

	area = NULL; 

	va_start( ap, len );
	result = vips_call_split( "jxlsave_buffer", ap, in, &area );
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
 * vips_jxlsave_target: (method)
 * @in: image to save 
 * @target: save image to this target
 * @...: %NULL-terminated list of optional named arguments
 *
 * As vips_jxlsave(), but save to a target.
 *
 * See also: vips_jxlsave(), vips_image_write_to_target().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_jxlsave_target( VipsImage *in, VipsTarget *target, ... )
{
	va_list ap;
	int result;

	va_start( ap, target );
	result = vips_call_split( "jxlsave_target", ap, in, target );
	va_end( ap );

	return( result );
}
