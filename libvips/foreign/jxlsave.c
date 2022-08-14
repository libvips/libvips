/* save as jpeg-xl
 *
 * 18/3/20
 * 	- from heifload.c
 * 21/5/22
 * 	- add ICC profile support
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
#define DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <glib/gi18n-lib.h>

#ifdef HAVE_LIBJXL

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vips/vips.h>
#include <vips/internal.h>

#include <jxl/encode.h>
#include <jxl/thread_parallel_runner.h>

#include "pforeign.h"

/* TODO:
 *
 * - libjxl encode only works in one shot mode, so there's no way to write in
 *   chunks
 *
 * - add metadata support EXIF, XMP, etc. api for this is on the way
 *
 * - add animation support
 *
 * - libjxl is currently missing error messages (I think)
 */

#define OUTPUT_BUFFER_SIZE (4096)

typedef struct _VipsForeignSaveJxl {
	VipsForeignSave parent_object;

	/* Where to write (set by subclasses).
	 */
	VipsTarget *target;

	/* Encoder options.
	 */
	int tier;
	double distance;
	int effort;
	gboolean lossless;
	int Q;

	/* Base image properties.
	 */
	JxlBasicInfo info;
	JxlColorEncoding color_encoding;
	JxlPixelFormat format;

	/* Encoder state.
	 */
	void *runner;
	JxlEncoder *encoder;

	/* Write buffer.
	 */
	uint8_t output_buffer[OUTPUT_BUFFER_SIZE];

} VipsForeignSaveJxl;

typedef VipsForeignSaveClass VipsForeignSaveJxlClass;

G_DEFINE_ABSTRACT_TYPE( VipsForeignSaveJxl, vips_foreign_save_jxl, 
	VIPS_TYPE_FOREIGN_SAVE );

static void
vips_foreign_save_jxl_dispose( GObject *gobject )
{
	VipsForeignSaveJxl *jxl = (VipsForeignSaveJxl *) gobject;

	VIPS_FREEF( JxlThreadParallelRunnerDestroy, jxl->runner );
	VIPS_FREEF( JxlEncoderDestroy, jxl->encoder );
	VIPS_UNREF( jxl->target );

	G_OBJECT_CLASS( vips_foreign_save_jxl_parent_class )->
		dispose( gobject );
}

static void
vips_foreign_save_jxl_error( VipsForeignSaveJxl *jxl, const char *details )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( jxl );

	/* TODO ... jxl has no way to get error messages at the moment.
	 */
	vips_error( class->nickname, "error %s", details );
}

#ifdef DEBUG
static void
vips_foreign_save_jxl_print_info( JxlBasicInfo *info )
{
	printf( "JxlBasicInfo:\n" );
	printf( "    have_container = %d\n", info->have_container );
	printf( "    xsize = %d\n", info->xsize );
	printf( "    ysize = %d\n", info->ysize );
	printf( "    bits_per_sample = %d\n", info->bits_per_sample );
	printf( "    exponent_bits_per_sample = %d\n", 
		info->exponent_bits_per_sample );
	printf( "    intensity_target = %g\n", info->intensity_target );
	printf( "    min_nits = %g\n", info->min_nits );
	printf( "    relative_to_max_display = %d\n", 
		info->relative_to_max_display );
	printf( "    linear_below = %g\n", info->linear_below );
	printf( "    uses_original_profile = %d\n", 
		info->uses_original_profile );
	printf( "    have_preview = %d\n", info->have_preview );
	printf( "    have_animation = %d\n", info->have_animation );
	printf( "    orientation = %d\n", info->orientation );
	printf( "    num_color_channels = %d\n", info->num_color_channels );
	printf( "    num_extra_channels = %d\n", info->num_extra_channels );
	printf( "    alpha_bits = %d\n", info->alpha_bits );
	printf( "    alpha_exponent_bits = %d\n", info->alpha_exponent_bits );
	printf( "    alpha_premultiplied = %d\n", info->alpha_premultiplied );
	printf( "    preview.xsize = %d\n", info->preview.xsize );
	printf( "    preview.ysize = %d\n", info->preview.ysize );
	printf( "    animation.tps_numerator = %d\n", 
		info->animation.tps_numerator );
	printf( "    animation.tps_denominator = %d\n", 
		info->animation.tps_denominator );
	printf( "    animation.num_loops = %d\n", info->animation.num_loops );
	printf( "    animation.have_timecodes = %d\n", 
		info->animation.have_timecodes );
}

static void
vips_foreign_save_jxl_print_format( JxlPixelFormat *format )
{
	printf( "JxlPixelFormat:\n" );
	printf( "    num_channels = %d\n", format->num_channels );
	printf( "    data_type = " );
	switch( format->data_type ) {
	case JXL_TYPE_UINT8: 
		printf( "JXL_TYPE_UINT8" );
		break;

	case JXL_TYPE_UINT16: 
		printf( "JXL_TYPE_UINT16" );
		break;

	case JXL_TYPE_FLOAT: 
		printf( "JXL_TYPE_FLOAT" );
		break;

	default:
		printf( "(unknown)" );
		break;
	}
	printf( "\n" );
	printf( "    endianness = %d\n", format->endianness );
	printf( "    align = %zd\n", format->align );
}

static void
vips_foreign_save_jxl_print_status( JxlEncoderStatus status )
{
	switch( status ) {
	case JXL_ENC_SUCCESS:
		printf( "JXL_ENC_SUCCESS\n" );
		break;

	case JXL_ENC_ERROR:
		printf( "JXL_ENC_ERROR\n" );
		break;

	case JXL_ENC_NEED_MORE_OUTPUT:
		printf( "JXL_ENC_NEED_MORE_OUTPUT\n" );
		break;

	case JXL_ENC_NOT_SUPPORTED:
		printf( "JXL_ENC_NOT_SUPPORTED\n" );
		break;

	default:
		printf( "JXL_ENC_<unknown>\n" );
		break;
	}
}
#endif /*DEBUG*/

static int
vips_foreign_save_jxl_build( VipsObject *object )
{
	VipsForeignSave *save = (VipsForeignSave *) object;
	VipsForeignSaveJxl *jxl = (VipsForeignSaveJxl *) object;
	VipsImage **t = (VipsImage **) vips_object_local_array( object, 5 );

	JxlEncoderFrameSettings *frame_settings;
	JxlEncoderStatus status;
	VipsImage *in;
	VipsBandFormat format;

	if( VIPS_OBJECT_CLASS( vips_foreign_save_jxl_parent_class )->
		build( object ) )
		return( -1 );

	/* If Q is set and distance is not, use Q to set a rough distance
	 * value. Formula stolen from cjxl.c and very roughly approximates
	 * libjpeg values.
	 */
	if( !vips_object_argument_isset( object, "distance" ) ) 
		jxl->distance = jxl->Q >= 30 ?
			0.1 + (100 - jxl->Q) * 0.09 :
			6.4 + pow(2.5, (30 - jxl->Q) / 5.0f) / 6.25f;

	/* Distance 0 is lossless. libjxl will fail for lossy distance 0.
	 */
	if( jxl->distance == 0 )
		jxl->lossless = TRUE;

	jxl->runner = JxlThreadParallelRunnerCreate( NULL, 
		vips_concurrency_get() );
	jxl->encoder = JxlEncoderCreate( NULL );

	if( JxlEncoderSetParallelRunner( jxl->encoder, 
		JxlThreadParallelRunner, jxl->runner ) ) {
		vips_foreign_save_jxl_error( jxl, 
			"JxlDecoderSetParallelRunner" );
		return( -1 );
	}

	in = save->ready;

	/* Fix the input image format. JXL uses float for 0-1 linear (ie.
	 * scRGB) only. We must convert eg. sRGB float to 8-bit for save.
	 */
	if( in->Type == VIPS_INTERPRETATION_scRGB )
		format = VIPS_FORMAT_FLOAT;
	else if( in->Type == VIPS_INTERPRETATION_RGB16 ||
		in->Type == VIPS_INTERPRETATION_GREY16 )
		format = VIPS_FORMAT_USHORT;
	else
		format = VIPS_FORMAT_UCHAR;

	if( vips_cast( in, &t[0], format, NULL ) )
		return( -1 );
	in = t[0];

	JxlEncoderInitBasicInfo( &jxl->info );

	switch( in->BandFmt ) {
	case VIPS_FORMAT_UCHAR:
		jxl->info.bits_per_sample = 8;
		jxl->info.exponent_bits_per_sample = 0;
		jxl->format.data_type = JXL_TYPE_UINT8;
		break;

	case VIPS_FORMAT_USHORT:
		jxl->info.bits_per_sample = 16;
		jxl->info.exponent_bits_per_sample = 0;
		jxl->format.data_type = JXL_TYPE_UINT16;
		break;

	case VIPS_FORMAT_FLOAT:
		jxl->info.bits_per_sample = 32;
		jxl->info.exponent_bits_per_sample = 8;
		jxl->format.data_type = JXL_TYPE_FLOAT;
		break;

	default:
		g_assert_not_reached();
		break;
	}

	switch( in->Type ) {
	case VIPS_INTERPRETATION_B_W:
	case VIPS_INTERPRETATION_GREY16:
		jxl->info.num_color_channels = 1;
		break;

	case VIPS_INTERPRETATION_sRGB:
	case VIPS_INTERPRETATION_scRGB:
	case VIPS_INTERPRETATION_RGB16:
		jxl->info.num_color_channels = 3;
		break;

	default:
		jxl->info.num_color_channels = in->Bands;
	}
	jxl->info.num_extra_channels = VIPS_MAX( 0, 
		in->Bands - jxl->info.num_color_channels );

	jxl->info.xsize = in->Xsize;
	jxl->info.ysize = in->Ysize;
	jxl->format.num_channels = in->Bands;
	jxl->format.endianness = JXL_NATIVE_ENDIAN;
	jxl->format.align = 0;

	if( vips_image_hasalpha( in ) ) {
		jxl->info.alpha_bits = jxl->info.bits_per_sample;
		jxl->info.alpha_exponent_bits = 
			jxl->info.exponent_bits_per_sample;
	}
	else {
		jxl->info.alpha_exponent_bits = 0;
		jxl->info.alpha_bits = 0;
	}

	if( vips_image_get_typeof( in, "stonits" ) ) {
		double stonits;

		if( vips_image_get_double( in, "stonits", &stonits ) )
			return( -1 );
		jxl->info.intensity_target = stonits;
	}

	/* uses_original_profile forces libjxl to not use lossy XYB
	 * colourspace. The name is very confusing.
	 */
	jxl->info.uses_original_profile = jxl->lossless;

	if( JxlEncoderSetBasicInfo( jxl->encoder, &jxl->info ) ) {
		vips_foreign_save_jxl_error( jxl, "JxlEncoderSetBasicInfo" );
		return( -1 );
	}

	/* Set any ICC profile.
	 */
	if( vips_image_get_typeof( in, VIPS_META_ICC_NAME ) ) {
		const void *data;
		size_t length;

		if( vips_image_get_blob( in, 
			VIPS_META_ICC_NAME, &data, &length ) )
			return( -1 );

#ifdef DEBUG
		printf( "attaching %zd bytes of ICC\n", length );
#endif /*DEBUG*/
		if( JxlEncoderSetICCProfile( jxl->encoder,
			(guint8 *) data, length ) ) {
			vips_foreign_save_jxl_error( jxl, 
				"JxlEncoderSetColorEncoding" );
			return( -1 );
		}
	}
	else {
		/* If there's no ICC profile, we must set the colour encoding
		 * ourselves.
		 */
		if( in->Type == VIPS_INTERPRETATION_scRGB ) {
#ifdef DEBUG
			printf( "setting scRGB colourspace\n" );
#endif /*DEBUG*/

			JxlColorEncodingSetToLinearSRGB( &jxl->color_encoding,
				jxl->format.num_channels < 3 );
		}
		else {
#ifdef DEBUG
			printf( "setting sRGB colourspace\n" );
#endif /*DEBUG*/

			JxlColorEncodingSetToSRGB( &jxl->color_encoding,
				jxl->format.num_channels < 3 );
		}

		if( JxlEncoderSetColorEncoding( jxl->encoder, 
			&jxl->color_encoding ) ) {
			vips_foreign_save_jxl_error( jxl,
				"JxlEncoderSetColorEncoding" );
			return( -1 );
		}
	}

	/* Render the entire image in memory. libjxl seems to be missing
	 * tile-based write at the moment.
	 */
	if( vips_image_wio_input( in ) )
		return( -1 );

	frame_settings = JxlEncoderFrameSettingsCreate( jxl->encoder, NULL );
	JxlEncoderFrameSettingsSetOption( frame_settings, 
		JXL_ENC_FRAME_SETTING_DECODING_SPEED, jxl->tier );
	JxlEncoderSetFrameDistance( frame_settings, jxl->distance );
	JxlEncoderFrameSettingsSetOption( frame_settings, 
		JXL_ENC_FRAME_SETTING_EFFORT, jxl->effort );
	JxlEncoderSetFrameLossless( frame_settings, jxl->lossless );

#ifdef DEBUG
	vips_foreign_save_jxl_print_info( &jxl->info );
	vips_foreign_save_jxl_print_format( &jxl->format );
	printf( "JxlEncoderFrameSettings:\n" );
	printf( "    tier = %d\n", jxl->tier );
	printf( "    distance = %g\n", jxl->distance );
	printf( "    effort = %d\n", jxl->effort );
	printf( "    lossless = %d\n", jxl->lossless );
#endif /*DEBUG*/

	if( JxlEncoderAddImageFrame( frame_settings, &jxl->format, 
		VIPS_IMAGE_ADDR( in, 0, 0 ),
		VIPS_IMAGE_SIZEOF_IMAGE( in ) ) ) { 
		vips_foreign_save_jxl_error( jxl, "JxlEncoderAddImageFrame" );
		return( -1 );
	}

	/* This function must be called after the final frame and/or box,
	 * otherwise the codestream will not be encoded correctly.
	 */
	JxlEncoderCloseInput( jxl->encoder );

	do {
		uint8_t *out;
		size_t avail_out;

		out = jxl->output_buffer;
		avail_out = OUTPUT_BUFFER_SIZE;
		status = JxlEncoderProcessOutput( jxl->encoder,
			&out, &avail_out );
		switch( status ) {
		case JXL_ENC_SUCCESS:
		case JXL_ENC_NEED_MORE_OUTPUT:
			if( vips_target_write( jxl->target,
				jxl->output_buffer, 
				OUTPUT_BUFFER_SIZE - avail_out ) )
				return( -1 );
			break;

		default:
			vips_foreign_save_jxl_error( jxl, 
				"JxlEncoderProcessOutput" );
#ifdef DEBUG
			vips_foreign_save_jxl_print_status( status );
#endif /*DEBUG*/
			return( -1 );
		}
	} while( status != JXL_ENC_SUCCESS );

	if( vips_target_end( jxl->target ) )
		return( -1 );

	return( 0 );
}

/* Save a bit of typing.
 */
#define UC VIPS_FORMAT_UCHAR
#define US VIPS_FORMAT_USHORT
#define F VIPS_FORMAT_FLOAT

/* Type promotion for save ... unsigned ints + float + double.
 */
static int bandfmt_jxl[10] = {
     /* UC   C  US   S  UI   I  F  X  D DX */
	UC, UC, US, US,  F,  F, F, F, F, F
};

static void
vips_foreign_save_jxl_class_init( VipsForeignSaveJxlClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsOperationClass *operation_class = VIPS_OPERATION_CLASS( class );
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;
	VipsForeignSaveClass *save_class = (VipsForeignSaveClass *) class;

	gobject_class->dispose = vips_foreign_save_jxl_dispose;
	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "jxlsave_base";
	object_class->description = _( "save image in JPEG-XL format" );
	object_class->build = vips_foreign_save_jxl_build;

	/* libjxl is fuzzed, but it's still relatively young and bugs are
	 * still being found in jan 2022. Revise this status soon.
	 */
	operation_class->flags |= VIPS_OPERATION_UNTRUSTED;

	foreign_class->suffs = vips__jxl_suffs;

	/* This lets throuigh scRGB too, which we then save as jxl float.
	 */
	save_class->saveable = VIPS_SAVEABLE_RGBA;
	save_class->format_table = bandfmt_jxl;

	VIPS_ARG_INT( class, "tier", 10, 
		_( "Tier" ), 
		_( "Decode speed tier" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveJxl, tier ),
		0, 4, 0 );

	VIPS_ARG_DOUBLE( class, "distance", 11, 
		_( "Distance" ), 
		_( "Target butteraugli distance" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveJxl, distance ),
		0, 15, 1.0 );

	VIPS_ARG_INT( class, "effort", 12, 
		_( "Effort" ), 
		_( "Encoding effort" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveJxl, effort ),
		3, 9, 7 );

	VIPS_ARG_BOOL( class, "lossless", 13, 
		_( "Lossless" ), 
		_( "Enable lossless compression" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveJxl, lossless ),
		FALSE ); 

	VIPS_ARG_INT( class, "Q", 14, 
		_( "Q" ), 
		_( "Quality factor" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveJxl, Q ),
		0, 100, 75 );

}

static void
vips_foreign_save_jxl_init( VipsForeignSaveJxl *jxl )
{
	jxl->tier = 0;
	jxl->distance = 1.0;
	jxl->effort = 7;
	jxl->lossless = FALSE;
	jxl->Q = 75;
}

typedef struct _VipsForeignSaveJxlFile {
	VipsForeignSaveJxl parent_object;

	/* Filename for save.
	 */
	char *filename; 

} VipsForeignSaveJxlFile;

typedef VipsForeignSaveJxlClass VipsForeignSaveJxlFileClass;

G_DEFINE_TYPE( VipsForeignSaveJxlFile, vips_foreign_save_jxl_file, 
	vips_foreign_save_jxl_get_type() );

static int
vips_foreign_save_jxl_file_build( VipsObject *object )
{
	VipsForeignSaveJxl *jxl = (VipsForeignSaveJxl *) object;
	VipsForeignSaveJxlFile *file = (VipsForeignSaveJxlFile *) object;

	if( !(jxl->target = vips_target_new_to_file( file->filename )) )
		return( -1 );

	if( VIPS_OBJECT_CLASS( vips_foreign_save_jxl_file_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

static void
vips_foreign_save_jxl_file_class_init( VipsForeignSaveJxlFileClass *class )
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
		G_STRUCT_OFFSET( VipsForeignSaveJxlFile, filename ),
		NULL );

}

static void
vips_foreign_save_jxl_file_init( VipsForeignSaveJxlFile *file )
{
}

typedef struct _VipsForeignSaveJxlBuffer {
	VipsForeignSaveJxl parent_object;

	/* Save to a buffer.
	 */
	VipsArea *buf;

} VipsForeignSaveJxlBuffer;

typedef VipsForeignSaveJxlClass VipsForeignSaveJxlBufferClass;

G_DEFINE_TYPE( VipsForeignSaveJxlBuffer, vips_foreign_save_jxl_buffer, 
	vips_foreign_save_jxl_get_type() );

static int
vips_foreign_save_jxl_buffer_build( VipsObject *object )
{
	VipsForeignSaveJxl *jxl = (VipsForeignSaveJxl *) object;
	VipsForeignSaveJxlBuffer *buffer = 
		(VipsForeignSaveJxlBuffer *) object;

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
	VipsForeignSaveJxlBufferClass *class )
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
		G_STRUCT_OFFSET( VipsForeignSaveJxlBuffer, buf ),
		VIPS_TYPE_BLOB );

}

static void
vips_foreign_save_jxl_buffer_init( VipsForeignSaveJxlBuffer *buffer )
{
}

typedef struct _VipsForeignSaveJxlTarget {
	VipsForeignSaveJxl parent_object;

	VipsTarget *target;
} VipsForeignSaveJxlTarget;

typedef VipsForeignSaveJxlClass VipsForeignSaveJxlTargetClass;

G_DEFINE_TYPE( VipsForeignSaveJxlTarget, vips_foreign_save_jxl_target, 
	vips_foreign_save_jxl_get_type() );

static int
vips_foreign_save_jxl_target_build( VipsObject *object )
{
	VipsForeignSaveJxl *jxl = (VipsForeignSaveJxl *) object;
	VipsForeignSaveJxlTarget *target = 
		(VipsForeignSaveJxlTarget *) object;

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
	VipsForeignSaveJxlTargetClass *class )
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
		G_STRUCT_OFFSET( VipsForeignSaveJxlTarget, target ),
		VIPS_TYPE_TARGET );

}

static void
vips_foreign_save_jxl_target_init( VipsForeignSaveJxlTarget *target )
{
}

#endif /*HAVE_LIBJXL*/

/* The C API wrappers are defined in foreign.c.
 */
