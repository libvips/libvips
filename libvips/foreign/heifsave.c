/* save to heif
 *
 * 5/7/18
 * 	- from niftisave.c
 * 3/7/19 [lovell]
 * 	- add "compression" option
 * 1/9/19 [meyermarcel]
 * 	- save alpha when necessary
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

#ifdef HAVE_HEIF_ENCODER

#include <libheif/heif.h>

#include "pforeign.h"

typedef struct _VipsForeignSaveHeif {
	VipsForeignSave parent_object;

	/* Coding quality factor (1-100).
	 */
	int Q;

	/* Lossless compression.
	 */
	gboolean lossless;

	/* Compression format
	 */
	VipsForeignHeifCompression compression;

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

G_DEFINE_ABSTRACT_TYPE( VipsForeignSaveHeif, vips_foreign_save_heif, 
	VIPS_TYPE_FOREIGN_SAVE );

static void
vips_foreign_save_heif_dispose( GObject *gobject )
{
	VipsForeignSaveHeif *heif = (VipsForeignSaveHeif *) gobject;

	VIPS_UNREF( heif->image );
	VIPS_FREEF( heif_image_release, heif->img );
	VIPS_FREEF( heif_image_handle_release, heif->handle );
	VIPS_FREEF( heif_encoder_release, heif->encoder );
	VIPS_FREEF( heif_context_free, heif->ctx );

	G_OBJECT_CLASS( vips_foreign_save_heif_parent_class )->
		dispose( gobject );
}

#ifdef HAVE_HEIF_CONTEXT_ADD_EXIF_METADATA
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
#endif /*HAVE_HEIF_CONTEXT_ADD_EXIF_METADATA*/

static int
vips_foreign_save_heif_write_metadata( VipsForeignSaveHeif *heif )
{
#ifdef HAVE_HEIF_CONTEXT_ADD_EXIF_METADATA

	int i;
	struct heif_error error;

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
				VIPS_META_EXIF_NAME, &data, &length ) )
				return( -1 );

			error = libheif_metadata[i].saver( heif->ctx, 
				heif->handle, data, length );
			if( error.code ) {
				vips__heif_error( &error );
				return( -1 );
			}
		}
#endif /*HAVE_HEIF_CONTEXT_ADD_EXIF_METADATA*/

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

#ifdef HAVE_HEIF_ENCODING_OPTIONS_ALLOC
	options = heif_encoding_options_alloc();
	if( vips_image_hasalpha( heif->image ) )
		options->save_alpha_channel = 1;
#else /*!HAVE_HEIF_ENCODING_OPTIONS_ALLOC*/
	options = NULL;
#endif /*HAVE_HEIF_ENCODING_OPTIONS_ALLOC*/

#ifdef DEBUG
	printf( "encoding ..\n" ); 
#endif /*DEBUG*/
	error = heif_context_encode_image( heif->ctx, 
		heif->img, heif->encoder, options, &heif->handle );

#ifdef HAVE_HEIF_ENCODING_OPTIONS_ALLOC
	heif_encoding_options_free( options );
#endif /*HAVE_HEIF_ENCODING_OPTIONS_ALLOC*/

	if( error.code ) {
		vips__heif_error( &error );
		return( -1 );
	}

#ifdef HAVE_HEIF_CONTEXT_SET_PRIMARY_IMAGE
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
#endif /*HAVE_HEIF_CONTEXT_SET_PRIMARY_IMAGE*/

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

static int
vips_foreign_save_heif_build( VipsObject *object )
{
	VipsForeignSave *save = (VipsForeignSave *) object;
	VipsForeignSaveHeif *heif = (VipsForeignSaveHeif *) object;

	struct heif_error error;

	if( VIPS_OBJECT_CLASS( vips_foreign_save_heif_parent_class )->
		build( object ) )
		return( -1 );

	/* Only rebuild exif if there's an EXIF block or we'll make a
	 * default set of tags. EXIF is not required for heif.
	 */
	if( vips_copy( save->ready, &heif->image, NULL ) ) 
		return( -1 );
	if( vips_image_get_typeof( heif->image, VIPS_META_EXIF_NAME ) ) 
		if( vips__exif_update( heif->image ) )
			return( -1 );

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

	/* TODO .. support extra per-encoder params with 
	 * heif_encoder_list_parameters().
	 */

	heif->page_width = heif->image->Xsize;
	heif->page_height = vips_image_get_page_height( heif->image );
	heif->n_pages = heif->image->Ysize / heif->page_height;

	/* Make a heif image the size of a page. We send sink_disc() output 
	 * here and write a frame each time it fills.
	 */
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

	heif->data = heif_image_get_plane( heif->img, 
		heif_channel_interleaved, &heif->stride );

	/* Write data. 
	 */
	if( vips_sink_disc( heif->image, 
		vips_foreign_save_heif_write_block, heif ) )
		return( -1 );

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

}

static void
vips_foreign_save_heif_init( VipsForeignSaveHeif *heif )
{
	heif->ctx = heif_context_alloc();
	heif->Q = 50;
	heif->compression = VIPS_FOREIGN_HEIF_COMPRESSION_HEVC;
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

	struct heif_error error;

	if( VIPS_OBJECT_CLASS( vips_foreign_save_heif_file_parent_class )->
		build( object ) )
		return( -1 );

	/* This has to come right at the end :-( so there's no support for
	 * incremental writes.
	 */
	error = heif_context_write_to_file( heif->ctx, file->filename );
	if( error.code ) {
		vips__heif_error( &error );
		return( -1 );
	}

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
		_( "Filename to load from" ),
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

struct heif_error 
vips_foreign_save_heif_buffer_write( struct heif_context *ctx, 
	const void *data, size_t length, void *userdata )
{
	VipsForeignSaveHeif *heif = (VipsForeignSaveHeif *) userdata;

	VipsBlob *blob;
	struct heif_error error;
	void *data_copy;

	/* FIXME .. we have to memcpy()!
	 */
	data_copy = vips_malloc( NULL, length );
	memcpy( data_copy, data, length );

	blob = vips_blob_new( (VipsCallbackFn) vips_free, data_copy, length );
	g_object_set( heif, "buffer", blob, NULL );
	vips_area_unref( VIPS_AREA( blob ) );

	error.code = 0;

	return( error );
}

static int
vips_foreign_save_heif_buffer_build( VipsObject *object )
{
	VipsForeignSaveHeif *heif = (VipsForeignSaveHeif *) object;

	/* FIXME ... argh, allocating on the stack! But the example code does
	 * this too.
	 */
	struct heif_writer writer;
	struct heif_error error;

	if( VIPS_OBJECT_CLASS( vips_foreign_save_heif_buffer_parent_class )->
		build( object ) )
		return( -1 );

	/* This has to come right at the end :-( so there's no support for
	 * incremental writes.
	 */
	writer.writer_api_version = 1;
	writer.write = vips_foreign_save_heif_buffer_write;
	error = heif_context_write( heif->ctx, &writer, heif );
	if( error.code ) {
		vips__heif_error( &error );
		return( -1 );
	}

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

#endif /*HAVE_HEIF_ENCODER*/

/**
 * vips_heifsave: (method)
 * @in: image to save 
 * @filename: file to write to 
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @Q: %gint, quality factor
 * * @lossless: %gboolean, enable lossless encoding
 * * @compression: #VipsForeignHeifCompression, write with this compression
 *
 * Write a VIPS image to a file in HEIF format. 
 *
 * Use @Q to set the compression factor. Default 50, which seems to be roughly
 * what the iphone uses. Q 30 gives about the same quality as JPEG Q 75.
 *
 * Set @lossless %TRUE to switch to lossless compression.
 *
 * Use @compression to set the encoder e.g. HEVC, AVC, AV1
 *
 * See also: vips_image_write_to_file(), vips_heifload().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_heifsave( VipsImage *in, const char *filename, ... )
{
	va_list ap;
	int result;

	va_start( ap, filename );
	result = vips_call_split( "heifsave", ap, in, filename );
	va_end( ap );

	return( result );
}

/**
 * vips_heifsave_buffer: (method)
 * @in: image to save 
 * @buf: (array length=len) (element-type guint8): return output buffer here
 * @len: (type gsize): return output length here
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @Q: %gint, quality factor
 * * @lossless: %gboolean, enable lossless encoding
 * * @compression: #VipsForeignHeifCompression, write with this compression
 *
 * As vips_heifsave(), but save to a memory buffer. 
 *
 * The address of the buffer is returned in @obuf, the length of the buffer in
 * @olen. You are responsible for freeing the buffer with g_free() when you
 * are done with it.
 *
 * See also: vips_heifsave(), vips_image_write_to_file().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_heifsave_buffer( VipsImage *in, void **buf, size_t *len, ... )
{
	va_list ap;
	VipsArea *area;
	int result;

	area = NULL; 

	va_start( ap, len );
	result = vips_call_split( "heifsave_buffer", ap, in, &area );
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
