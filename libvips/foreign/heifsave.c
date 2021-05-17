/* save to heif
 *
 * 5/7/18
 * 	- from niftisave.c
 * 3/7/19 [lovell]
 * 	- add "compression" option
 * 1/9/19 [meyermarcel]
 * 	- save alpha when necessary
 * 15/3/20
 * 	- revise for new VipsTarget API
 * 14/2/21 kleisauke
 * 	- move GObject part to vips2heif.c
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

#ifdef HAVE_HEIF_ENCODER

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vips/vips.h>
#include <vips/internal.h>

#include "pforeign.h"

#include <libheif/heif.h>

typedef struct _VipsForeignSaveHeif {
	VipsForeignSave parent_object;

	/* Where to write (set by subclasses).
	 */
	VipsTarget *target;

	/* Coding quality factor (1-100).
	 */
	int Q;

	/* Lossless compression.
	 */
	gboolean lossless;

	/* Compression format
	 */
	VipsForeignHeifCompression compression;

	/* CPU effort (0-8).
	 */
	int speed;

	/* Chroma subsampling.
	 */
	VipsForeignSubsample subsample_mode;

	/* The image we save. This is a copy of save->ready since we need to
	 * be able to update the metadata.
	 */
	VipsImage *image;

	int page_width;
	int page_height;
	int n_pages;

	struct heif_context *ctx;
	struct heif_encoder *encoder;

	/* The current page we are writing.
	 */
	struct heif_image_handle *handle;

	/* The current page in memory which we build as we scan down the
	 * image.
	 */
	struct heif_image *img;

	/* The libheif memory area we fill with pixels from the libvips 
	 * pipe.
	 */
	uint8_t *data;
	int stride;

} VipsForeignSaveHeif;

typedef VipsForeignSaveClass VipsForeignSaveHeifClass;

/* Defined in heif2vips.c
 */
void vips__heif_error( struct heif_error *error );
void vips__heif_image_print( struct heif_image *img );

G_DEFINE_ABSTRACT_TYPE( VipsForeignSaveHeif, vips_foreign_save_heif, 
	VIPS_TYPE_FOREIGN_SAVE );

static void
vips_foreign_save_heif_dispose( GObject *gobject )
{
	VipsForeignSaveHeif *heif = (VipsForeignSaveHeif *) gobject;

	VIPS_UNREF( heif->target );
	VIPS_UNREF( heif->image );
	VIPS_FREEF( heif_image_release, heif->img );
	VIPS_FREEF( heif_image_handle_release, heif->handle );
	VIPS_FREEF( heif_encoder_release, heif->encoder );
	VIPS_FREEF( heif_context_free, heif->ctx );

	G_OBJECT_CLASS( vips_foreign_save_heif_parent_class )->
		dispose( gobject );
}

typedef struct heif_error (*libheif_metadata_fn)( struct heif_context *,
	 const struct heif_image_handle *,
	 const void *, int );

struct _VipsForeignSaveHeifMetadata {
	const char *name;
	libheif_metadata_fn saver;
} libheif_metadata[] = {
	{ VIPS_META_EXIF_NAME, heif_context_add_exif_metadata },
	{ VIPS_META_XMP_NAME, heif_context_add_XMP_metadata }
};

static int
vips_foreign_save_heif_write_metadata( VipsForeignSaveHeif *heif )
{
	int i;
	struct heif_error error;

	/* Rebuild exif from tags, if we'll be saving it.
	 */
	if( vips_image_get_typeof( heif->image, VIPS_META_EXIF_NAME ) ) 
		if( vips__exif_update( heif->image ) )
			return( -1 );

	for( i = 0; i < VIPS_NUMBER( libheif_metadata ); i++ )  
		if( vips_image_get_typeof( heif->image, 
			libheif_metadata[i].name ) ) {
			const void *data;
			size_t length;

#ifdef DEBUG
			printf( "attaching %s ..\n", 
				libheif_metadata[i].name ); 
#endif /*DEBUG*/

			if( vips_image_get_blob( heif->image, 
				libheif_metadata[i].name, &data, &length ) )
				return( -1 );

			error = libheif_metadata[i].saver( heif->ctx, 
				heif->handle, data, length );
			if( error.code ) {
				vips__heif_error( &error );
				return( -1 );
			}
		}

	return( 0 );
}

static int
vips_foreign_save_heif_write_page( VipsForeignSaveHeif *heif, int page )
{
	VipsForeignSave *save = (VipsForeignSave *) heif;

	struct heif_error error;
	struct heif_encoding_options *options;

#ifdef HAVE_HEIF_COLOR_PROFILE
	if( !save->strip &&
		vips_image_get_typeof( heif->image, VIPS_META_ICC_NAME ) ) {
		const void *data;
		size_t length;

#ifdef DEBUG
		printf( "attaching profile ..\n" ); 
#endif /*DEBUG*/

		if( vips_image_get_blob( heif->image, 
			VIPS_META_ICC_NAME, &data, &length ) )
			return( -1 );

		/* FIXME .. also see heif_image_set_nclx_color_profile()
		 */
		error = heif_image_set_raw_color_profile( heif->img, 
			"rICC", data, length );
		if( error.code ) {
			vips__heif_error( &error );
			return( -1 );
		}
	}
#endif /*HAVE_HEIF_COLOR_PROFILE*/

	options = heif_encoding_options_alloc();
	if( vips_image_hasalpha( heif->image ) )
		options->save_alpha_channel = 1;

#ifdef DEBUG
	printf( "encoding ..\n" ); 
#endif /*DEBUG*/
	error = heif_context_encode_image( heif->ctx, 
		heif->img, heif->encoder, options, &heif->handle );

	heif_encoding_options_free( options );

	if( error.code ) {
		vips__heif_error( &error );
		return( -1 );
	}

	if( vips_image_get_typeof( heif->image, "heif-primary" ) ) { 
		int primary;

		if( vips_image_get_int( heif->image, 
			"heif-primary", &primary ) ) 
			return( -1 ); 	

		if( page == primary ) { 
			error = heif_context_set_primary_image( heif->ctx, 
				heif->handle );
			if( error.code ) {
				vips__heif_error( &error );
				return( -1 );
			}
		}
	}

	if( !save->strip &&
		vips_foreign_save_heif_write_metadata( heif ) )
		return( -1 );

	VIPS_FREEF( heif_image_handle_release, heif->handle );

	return( 0 );
}

static int
vips_foreign_save_heif_write_block( VipsRegion *region, VipsRect *area, 
	void *a )
{
	VipsForeignSaveHeif *heif = (VipsForeignSaveHeif *) a;

	int y;

#ifdef DEBUG
	printf( "vips_foreign_save_heif_write_block: y = %d\n", area->top );
#endif /*DEBUG*/

	/* Copy a line at a time into our output image, write each time the 
	 * image fills.
	 */
	for( y = 0; y < area->height; y++ ) {
		/* Y in page.
		 */
		int page = (area->top + y) / heif->page_height;
		int line = (area->top + y) % heif->page_height;

		VipsPel *p = VIPS_REGION_ADDR( region, 0, area->top + y );
		VipsPel *q = heif->data + line * heif->stride;

		memcpy( q, p, VIPS_IMAGE_SIZEOF_LINE( region->im ) );

		/* Did we just write the final line? Write as a new page 
		 * into the output.
		 */
		if( line == heif->page_height - 1 )
			if( vips_foreign_save_heif_write_page( heif, page ) )
				return( -1 );
	}

	return( 0 );
}

struct heif_error 
vips_foreign_save_heif_write( struct heif_context *ctx, 
	const void *data, size_t length, void *userdata )
{
	VipsForeignSaveHeif *heif = (VipsForeignSaveHeif *) userdata;

	struct heif_error error;

	error.code = 0;
	if( vips_target_write( heif->target, data, length ) )
		error.code = -1;

	return( error );
}

static int
vips_foreign_save_heif_build( VipsObject *object )
{
	VipsForeignSave *save = (VipsForeignSave *) object;
	VipsForeignSaveHeif *heif = (VipsForeignSaveHeif *) object;

	const char *filename;
	struct heif_error error;
	struct heif_writer writer;
	char *chroma;

	if( VIPS_OBJECT_CLASS( vips_foreign_save_heif_parent_class )->
		build( object ) )
		return( -1 );

	/* Make a copy of the image in case we modify the metadata eg. for
	 * exif_update.
	 */
	if( vips_copy( save->ready, &heif->image, NULL ) ) 
		return( -1 );

	/* Compression defaults to VIPS_FOREIGN_HEIF_COMPRESSION_AV1 for .avif
	 * suffix.
	 */
	filename = vips_connection_filename( VIPS_CONNECTION( heif->target ) );
	if( !vips_object_argument_isset( object, "compression" ) &&
		filename &&
		vips_iscasepostfix( filename, ".avif" ) )
		heif->compression = VIPS_FOREIGN_HEIF_COMPRESSION_AV1;

	error = heif_context_get_encoder_for_format( heif->ctx, 
		(enum heif_compression_format) heif->compression, 
		&heif->encoder );
	if( error.code ) {
		if( error.code == heif_error_Unsupported_filetype ) 
			vips_error( "heifsave", 
				"%s", _( "Unsupported compression" ) );
		else 
			vips__heif_error( &error );

		return( -1 );
	}

	error = heif_encoder_set_lossy_quality( heif->encoder, heif->Q );
	if( error.code ) {
		vips__heif_error( &error );
		return( -1 );
	}

	error = heif_encoder_set_lossless( heif->encoder, heif->lossless );
	if( error.code ) {
		vips__heif_error( &error );
		return( -1 );
	}

	error = heif_encoder_set_parameter_integer( heif->encoder,
		"speed", heif->speed );
	if( error.code &&
		error.subcode != heif_suberror_Unsupported_parameter ) {
		vips__heif_error( &error );
		return( -1 );
	}

	chroma = heif->subsample_mode == VIPS_FOREIGN_SUBSAMPLE_OFF ||
		( heif->subsample_mode == VIPS_FOREIGN_SUBSAMPLE_AUTO &&
			heif->Q >= 90 ) ? "444" : "420";
	error = heif_encoder_set_parameter_string( heif->encoder,
		"chroma", chroma );
	if( error.code &&
		error.subcode != heif_suberror_Unsupported_parameter ) {
		vips__heif_error( &error );
		return( -1 );
	}

	/* TODO .. support extra per-encoder params with 
	 * heif_encoder_list_parameters().
	 */

	heif->page_width = heif->image->Xsize;
	heif->page_height = vips_image_get_page_height( heif->image );
	heif->n_pages = heif->image->Ysize / heif->page_height;

	/* Make a heif image the size of a page. We send sink_disc() output 
	 * here and write a frame each time it fills.
	 */
#ifdef DEBUG
	printf( "vips_foreign_save_heif_build:\n" );
	printf( "\twidth = %d\n", heif->page_width );
	printf( "\theight = %d\n", heif->page_height );
	printf( "\talpha = %d\n", vips_image_hasalpha( heif->image ) );
#endif /*DEBUG*/
	error = heif_image_create( heif->page_width, heif->page_height, 
		heif_colorspace_RGB, 
		vips_image_hasalpha( heif->image ) ?
			heif_chroma_interleaved_RGBA : 
			heif_chroma_interleaved_RGB,
		&heif->img );
	if( error.code ) {
		vips__heif_error( &error );
		return( -1 );
	}

	error = heif_image_add_plane( heif->img, heif_channel_interleaved, 
		heif->page_width, heif->page_height, 
		vips_image_hasalpha( heif->image ) ? 32 : 24 );
	if( error.code ) {
		vips__heif_error( &error );
		return( -1 );
	}

#ifdef DEBUG
	vips__heif_image_print( heif->img );
#endif /*DEBUG*/

	heif->data = heif_image_get_plane( heif->img, 
		heif_channel_interleaved, &heif->stride );

	/* Write data. 
	 */
	if( vips_sink_disc( heif->image, 
		vips_foreign_save_heif_write_block, heif ) )
		return( -1 );

	/* This has to come right at the end :-( so there's no support for
	 * incremental writes.
	 */
	writer.writer_api_version = 1;
	writer.write = vips_foreign_save_heif_write;
	error = heif_context_write( heif->ctx, &writer, heif );
	if( error.code ) {
		vips__heif_error( &error );
		return( -1 );
	}

	vips_target_finish( heif->target );

	return( 0 );
}

/* Save a bit of typing.
 */
#define UC VIPS_FORMAT_UCHAR

static int vips_heif_bandfmt[10] = {
/* UC  C   US  S   UI  I   F   X   D   DX */
   UC, UC, UC, UC, UC, UC, UC, UC, UC, UC
};

static void
vips_foreign_save_heif_class_init( VipsForeignSaveHeifClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;
	VipsForeignSaveClass *save_class = (VipsForeignSaveClass *) class;

	gobject_class->dispose = vips_foreign_save_heif_dispose;
	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "heifsave_base";
	object_class->description = _( "save image in HEIF format" );
	object_class->build = vips_foreign_save_heif_build;

	foreign_class->suffs = vips__heif_suffs;

	save_class->saveable = VIPS_SAVEABLE_RGBA_ONLY;
	save_class->format_table = vips_heif_bandfmt;

	VIPS_ARG_INT( class, "Q", 10, 
		_( "Q" ), 
		_( "Q factor" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveHeif, Q ),
		1, 100, 50 );

	VIPS_ARG_BOOL( class, "lossless", 13,
		_( "Lossless" ),
		_( "Enable lossless compression" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveHeif, lossless ),
		FALSE );

	VIPS_ARG_ENUM( class, "compression", 14,
		_( "compression" ),
		_( "Compression format" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveHeif, compression ),
		VIPS_TYPE_FOREIGN_HEIF_COMPRESSION,
		VIPS_FOREIGN_HEIF_COMPRESSION_HEVC );

	VIPS_ARG_INT( class, "speed", 15,
		_( "speed" ),
		_( "CPU effort" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveHeif, speed ),
		0, 9, 5 );

	VIPS_ARG_ENUM( class, "subsample_mode", 16,
		_( "Subsample mode" ),
		_( "Select chroma subsample operation mode" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveHeif, subsample_mode ),
		VIPS_TYPE_FOREIGN_SUBSAMPLE,
		VIPS_FOREIGN_SUBSAMPLE_AUTO );
}

static void
vips_foreign_save_heif_init( VipsForeignSaveHeif *heif )
{
	heif->ctx = heif_context_alloc();
	heif->Q = 50;
	heif->compression = VIPS_FOREIGN_HEIF_COMPRESSION_HEVC;
	heif->speed = 5;
	heif->subsample_mode = VIPS_FOREIGN_SUBSAMPLE_AUTO;
}

typedef struct _VipsForeignSaveHeifFile {
	VipsForeignSaveHeif parent_object;

	/* Filename for save.
	 */
	char *filename; 

} VipsForeignSaveHeifFile;

typedef VipsForeignSaveHeifClass VipsForeignSaveHeifFileClass;

G_DEFINE_TYPE( VipsForeignSaveHeifFile, vips_foreign_save_heif_file, 
	vips_foreign_save_heif_get_type() );

static int
vips_foreign_save_heif_file_build( VipsObject *object )
{
	VipsForeignSaveHeif *heif = (VipsForeignSaveHeif *) object;
	VipsForeignSaveHeifFile *file = (VipsForeignSaveHeifFile *) object;

	if( !(heif->target = vips_target_new_to_file( file->filename )) )
		return( -1 );

	if( VIPS_OBJECT_CLASS( vips_foreign_save_heif_file_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

static void
vips_foreign_save_heif_file_class_init( VipsForeignSaveHeifFileClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "heifsave";
	object_class->build = vips_foreign_save_heif_file_build;

	VIPS_ARG_STRING( class, "filename", 1, 
		_( "Filename" ),
		_( "Filename to save to" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignSaveHeifFile, filename ),
		NULL );

}

static void
vips_foreign_save_heif_file_init( VipsForeignSaveHeifFile *file )
{
}

typedef struct _VipsForeignSaveHeifBuffer {
	VipsForeignSaveHeif parent_object;

	/* Save to a buffer.
	 */
	VipsArea *buf;

} VipsForeignSaveHeifBuffer;

typedef VipsForeignSaveHeifClass VipsForeignSaveHeifBufferClass;

G_DEFINE_TYPE( VipsForeignSaveHeifBuffer, vips_foreign_save_heif_buffer, 
	vips_foreign_save_heif_get_type() );

static int
vips_foreign_save_heif_buffer_build( VipsObject *object )
{
	VipsForeignSaveHeif *heif = (VipsForeignSaveHeif *) object;
	VipsForeignSaveHeifBuffer *buffer = 
		(VipsForeignSaveHeifBuffer *) object;

	VipsBlob *blob;

	if( !(heif->target = vips_target_new_to_memory()) )
		return( -1 );

	if( VIPS_OBJECT_CLASS( vips_foreign_save_heif_buffer_parent_class )->
		build( object ) )
		return( -1 );

	g_object_get( heif->target, "blob", &blob, NULL );
	g_object_set( buffer, "buffer", blob, NULL );
	vips_area_unref( VIPS_AREA( blob ) );

	return( 0 );
}

static void
vips_foreign_save_heif_buffer_class_init( 
	VipsForeignSaveHeifBufferClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "heifsave_buffer";
	object_class->build = vips_foreign_save_heif_buffer_build;

	VIPS_ARG_BOXED( class, "buffer", 1, 
		_( "Buffer" ),
		_( "Buffer to save to" ),
		VIPS_ARGUMENT_REQUIRED_OUTPUT, 
		G_STRUCT_OFFSET( VipsForeignSaveHeifBuffer, buf ),
		VIPS_TYPE_BLOB );

}

static void
vips_foreign_save_heif_buffer_init( VipsForeignSaveHeifBuffer *buffer )
{
}

typedef struct _VipsForeignSaveHeifTarget {
	VipsForeignSaveHeif parent_object;

	VipsTarget *target;
} VipsForeignSaveHeifTarget;

typedef VipsForeignSaveHeifClass VipsForeignSaveHeifTargetClass;

G_DEFINE_TYPE( VipsForeignSaveHeifTarget, vips_foreign_save_heif_target, 
	vips_foreign_save_heif_get_type() );

static int
vips_foreign_save_heif_target_build( VipsObject *object )
{
	VipsForeignSaveHeif *heif = (VipsForeignSaveHeif *) object;
	VipsForeignSaveHeifTarget *target = 
		(VipsForeignSaveHeifTarget *) object;

	if( target->target ) {
		heif->target = target->target;
		g_object_ref( heif->target );
	}

	if( VIPS_OBJECT_CLASS( vips_foreign_save_heif_target_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

static void
vips_foreign_save_heif_target_class_init( 
	VipsForeignSaveHeifTargetClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "heifsave_target";
	object_class->build = vips_foreign_save_heif_target_build;

	VIPS_ARG_OBJECT( class, "target", 1,
		_( "Target" ),
		_( "Target to save to" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignSaveHeifTarget, target ),
		VIPS_TYPE_TARGET );

}

static void
vips_foreign_save_heif_target_init( VipsForeignSaveHeifTarget *target )
{
}

#endif /*HAVE_HEIF_ENCODER*/

/* The C API wrappers are defined in foreign.c.
 */
