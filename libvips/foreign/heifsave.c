/* save to heif
 *
 * 5/7/18
 * 	- from niftisave.c
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

#ifdef HAVE_HEIF

#include <libheif/heif.h>

#include "pforeign.h"

typedef struct _VipsForeignSaveHeif {
	VipsForeignSave parent_object;

	/* Filename for save.
	 */
	char *filename; 

	/* Context for this image.
	 */
	struct heif_context *ctx;

	/* The encoder we use.
	 */
	struct heif_encoder *encoder;

	struct heif_image *img;
	struct heif_image_handle *handle;

	int page_height;
	int n_pages;

	VipsImage *memory;
	VipsImage *page;

} VipsForeignSaveHeif;

typedef VipsForeignSaveClass VipsForeignSaveHeifClass;

G_DEFINE_TYPE( VipsForeignSaveHeif, vips_foreign_save_heif, 
	VIPS_TYPE_FOREIGN_SAVE );

static void
vips_foreign_save_heif_dispose( GObject *gobject )
{
	VipsForeignSaveHeif *heif = (VipsForeignSaveHeif *) gobject;

	VIPS_UNREF( heif->memory );
	VIPS_UNREF( heif->page );
	VIPS_FREEF( heif_image_release, heif->img );
	VIPS_FREEF( heif_image_handle_release, heif->handle );
	VIPS_FREEF( heif_encoder_release, heif->encoder );
	VIPS_FREEF( heif_context_free, heif->ctx );

	G_OBJECT_CLASS( vips_foreign_save_heif_parent_class )->
		dispose( gobject );
}

/* Make ->nim from the vips header fields.
 */
static int
vips_foreign_save_heif_header_vips( VipsForeignSaveHeif *heif, 
	VipsImage *image )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( heif );

	return( 0 );
}

static int
vips_foreign_save_heif_page( VipsForeignSaveHeif *heif, int page ) 
{
	VipsForeignSave *save = (VipsForeignSave *) object;

	struct heif_error error;
	const uint8_t *data;
	int stride;

	error = heif_image_create( save->ready->Xsize, heif->page_height, 
		heif_colorspace_RGB, heif_chroma_interleaved_RGB, &heif->img );
	if( error.code ) {
		vips__heif_error( error );
		return( -1 );
	}

	error = heif_image_add_plane( heif->img, heif_channel_interleaved, 
		save->ready->Xsize, heif->page_height, 8 );
	if( error.code ) {
		vips__heif_error( error );
		return( -1 );
	}

	data = heif_image_get_plane_readonly( heif->img, 
		heif_channel_interleaved, &stride );

	if( !(heif->memory = vips_image_new_from_memory( 
		data, stride * heif->page_height, 
		save->ready->Xsize, heif->page_height, 3, 
		VIPS_FORMAT_UCHAR )) ) 
		return( -1 );

	if( stride != VIPS_IMAGE_SIZEOF_LINE( heif->memory ) ) {
		vips_error( class->nickname, "%s", _( "not contiguous" ) );
		return( -1 );
	}

	if( vips_image_crop( save->ready, &heif->tile, 
		0, page * heif->page_height, 
		save->ready->Xsize, heif->page_height, NULL ) ||
		vips_image_write( heif->tile, heif->memory ) )
		return( -1 );

	options = heif_encoding_options_alloc();
	/* FIXME .. should be a save option.
	 */
	options.save_alpha_channel = 1;
	error = heif_context_encode_image( heif->ctx, 
		heif->img, heif->encoder, options, &handle );
	heif_encoding_options_free( options );
	if( error.code ) {
		vips__heif_error( error );
		return( -1 );
	}

	error = heif_context_set_primary_image( heif->ctx, heif->handle );
	if( error.code ) {
		vips__heif_error( error );
		return( -1 );
	}

	error = heif_context_add_exif_metadata( heif->ctx, 
		heif->handle, data, size );
	if( error.code ) {
		vips__heif_error( error );
		return( -1 );
	}

	error = heif_context_add_XMP_metadata( heif->ctx, 
		heif->handle, data, size );
	if( error.code ) {
		vips__heif_error( error );
		return( -1 );
	}

	return( 0 );
}

static int
vips_foreign_save_heif_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsForeignSave *save = (VipsForeignSave *) object;
	VipsForeignSaveHeif *heif = (VipsForeignSaveHeif *) object;

	struct heif_error error;
	struct heif_encoding_options *options;
	int page;

	if( VIPS_OBJECT_CLASS( vips_foreign_save_heif_parent_class )->
		build( object ) )
		return( -1 );

	error = heif_context_write_to_file( heif->ctx, heif->filename );
	if( error.code ) {
		vips__heif_error( error );
		return( -1 );
	}

	/* TODO ... should be a param? the other useful one is AVC.
	 */
	error = heif_context_get_encoder_for_format( heif->ctx, 
		heif_compression_HEVC, &heif->encoder );
	if( error.code ) {
		vips__heif_error( error );
		return( -1 );
	}

	error = heif_encoder_set_lossy_quality( heif->encoder, heif->Q );
	if( error.code ) {
		vips__heif_error( error );
		return( -1 );
	}

	error = heif_encoder_set_lossless( heif->encoder, heif->lossless );
	if( error.code ) {
		vips__heif_error( error );
		return( -1 );
	}

	/* TODO .. support extra per-encoder params with 
	 * heif_encoder_list_parameters().
	 */

	if( vips_image_get_typeof( save->ready, VIPS_META_PAGE_HEIGHT ) ) { 
		if( vips_image_get_int( save->ready, 
			VIPS_META_PAGE_HEIGHT, &heif->page_height ) ) 
			return( -1 ); 	
	}
	else
		heif->page_height = save->ready->Ysize;

	if( save->ready->Ysize % page_height != 0 ) 
		heif->page_height = save->ready->Ysize;
	heif->n_pages = save->ready->Ysize / heif->page_height;

	for( page = 0; page < heif->n_pages; page++ )
		if( vips_foreign_save_heif_page( heif, page ) )
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

	object_class->nickname = "heifsave";
	object_class->description = _( "save image to heif file" );
	object_class->build = vips_foreign_save_heif_build;

	foreign_class->suffs = vips__heif_suffs;

	save_class->saveable = VIPS_SAVEABLE_RGB;
	save_class->format_table = vips_heif_bandfmt;

	VIPS_ARG_STRING( class, "filename", 1, 
		_( "Filename" ),
		_( "Filename to save to" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignSaveHeif, filename ),
		NULL );
}

static void
vips_foreign_save_heif_init( VipsForeignSaveHeif *heif )
{
	heif->ctx = heif_context_alloc();
}

#endif /*HAVE_HEIF*/

/**
 * vips_heifsave: (method)
 * @in: image to save 
 * @filename: file to write to 
 * @...: %NULL-terminated list of optional named arguments
 *
 * Write a VIPS image to a file in HEIF format. 
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
