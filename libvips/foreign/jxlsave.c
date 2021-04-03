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

#define OUTPUT_BUFFER_SIZE (4096)

typedef struct _VipsForeignSaveJxl {
	VipsForeignSave parent_object;

	/* Where to write (set by subclasses).
	 */
	VipsTarget *target;

	/* Base image properties.
	 */
	JxlBasicInfo info;
	JxlColorEncoding color_encoding;
	size_t icc_size;
	uint8_t *icc_data;

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

	G_OBJECT_CLASS( vips_foreign_save_jxl_parent_class )->
		dispose( gobject );
}

static void
vips_foreign_save_jxl_error( VipsForeignSaveJxl *jxl, const char *details )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( jxl );

	/* TODO ... jxl has no way to get error messages at the moemnt.
	 */
	vips_error( class->nickname, "%s", details );
}

static JxlPixelFormat vips_foreign_save_jxl_format = 
	{3, JXL_TYPE_FLOAT, JXL_NATIVE_ENDIAN, 0};

static int
vips_foreign_save_jxl_build( VipsObject *object )
{
	VipsForeignSave *save = (VipsForeignSave *) object;
	VipsForeignSaveJxl *jxl = (VipsForeignSaveJxl *) object;

	JxlEncoderOptions *encoder_options;
	JxlEncoderStatus status;

	if( VIPS_OBJECT_CLASS( vips_foreign_save_jxl_parent_class )->
		build( object ) )
		return( -1 );

	jxl->runner = JxlThreadParallelRunnerCreate( NULL, 
		vips_concurrency_get() );
	jxl->encoder = JxlEncoderCreate( NULL );

	if( JxlEncoderSetParallelRunner( jxl->encoder, 
		JxlThreadParallelRunner, jxl->runner ) ) {
		vips_foreign_save_jxl_error( jxl, 
			"JxlDecoderSetParallelRunner" );
		return( -1 );
	}

	jxl->info.xsize = save->ready->Xsize;
	jxl->info.ysize = save->ready->Ysize;
	jxl->info.bits_per_sample = 32;
	jxl->info.exponent_bits_per_sample = 8;
	jxl->info.alpha_exponent_bits = 0;
	jxl->info.alpha_bits = 0;
	jxl->info.uses_original_profile = JXL_FALSE;
	if( JxlEncoderSetBasicInfo( jxl->encoder, &jxl->info ) ) {
		vips_foreign_save_jxl_error( jxl, "JxlEncoderSetBasicInfo" );
		return( -1 );
	}

	JxlColorEncodingSetToSRGB( &jxl->color_encoding, 
		vips_foreign_save_jxl_format.num_channels < 3 );
	if( JxlEncoderSetColorEncoding( jxl->encoder, &jxl->color_encoding ) ) {
		vips_foreign_save_jxl_error( jxl, 
			"JxlEncoderSetColorEncoding" );
		return( -1 );
	}

	if( vips_image_wio_input( save->ready ) )
		return( -1 );
	
	encoder_options = JxlEncoderOptionsCreate( jxl->encoder, NULL );
	if( JxlEncoderAddImageFrame( encoder_options, 
		&vips_foreign_save_jxl_format, 
		VIPS_IMAGE_ADDR( save->ready, 0, 0 ),
		VIPS_IMAGE_SIZEOF_IMAGE( save->ready ) ) ) { 
		vips_foreign_save_jxl_error( jxl, "JxlEncoderAddImageFrame" );
		return( -1 );
	}

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
			return( -1 );
		}
	} while( status != JXL_ENC_SUCCESS );

	vips_target_finish( jxl->target );

	return( 0 );
}

#define F VIPS_FORMAT_FLOAT

/* Type promotion for save ... just always go to uchar.
 */
static int bandfmt_jpeg[10] = {
     /* UC  C US  S UI  I  F  X  D DX */
	 F, F, F, F, F, F, F, F, F, F
};

static void
vips_foreign_save_jxl_class_init( VipsForeignSaveJxlClass *class )
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
	save_class->format_table = bandfmt_jpeg;

}

static void
vips_foreign_save_jxl_init( VipsForeignSaveJxl *jxl )
{
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
