/* load heif images with libheif
 *
 * 19/1/19
 * 	- from heifload.c
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
#define VIPS_DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vips/vips.h>
#include <vips/debug.h>
#include <vips/internal.h>

#ifdef HAVE_HEIF

#include <libheif/heif.h>

#include "pforeign.h"

typedef struct _VipsForeignLoadHeif {
	VipsForeignLoad parent_object;

	/* Filename for load.
	 */
	char *filename; 

	/* Context for this file.
	 */
	struct heif_context *ctx;

	/* Number of top-level images in this file.
	 */
	int n_top;

	/* Array of top-level image IDs.
	 */
	heif_item_id *id;

	/* Handle for the currently selected image.
	 */
	struct heif_image_handle *handle;

	/* Decoded pixel data for the current image.
	 */
	struct heif_image *img;

	/* Valid until img is released.
	 */
	int stride;
	const uint8_t *data;

	/* Our intermediate image.
	 */
	VipsImage *memory;

} VipsForeignLoadHeif;

typedef VipsForeignLoadClass VipsForeignLoadHeifClass;

G_DEFINE_TYPE( VipsForeignLoadHeif, vips_foreign_load_heif, 
	VIPS_TYPE_FOREIGN_LOAD );

static void
vips_foreign_load_heif_dispose( GObject *gobject )
{
	VipsForeignLoadHeif *heif = (VipsForeignLoadHeif *) gobject;

	VIPS_FREEF( heif_image_release, heif->img );
	VIPS_FREEF( heif_image_handle_release, heif->handle );
	VIPS_FREEF( heif_context_free, heif->ctx );
	VIPS_UNREF( heif->memory );
	VIPS_FREE( heif->id );

	G_OBJECT_CLASS( vips_foreign_load_heif_parent_class )->
		dispose( gobject );
}

static void
vips_heif_error( struct heif_error error )
{
	if( error.code ) 
		vips_error( "heifload", "%s", error.message ); 
}

static const char *vips_foreign_load_heif_magic[] = {
	"ftypheic",
	"ftypheix",
	"ftyphevc",
	"ftypheim",
	"ftypheis",
	"ftyphevm",
	"ftyphevs",
	"ftypmif1",	/* nokia alpha_ image */
	"ftypmsf1"	/* nokia animation image */
};

/* THe API has:
 *
 *	enum heif_filetype_result result = heif_check_filetype( buf, 12 );
 *
 * but it's very conservative.
 */
static int
vips_foreign_load_heif_is_a( const char *filename )
{
	unsigned char buf[12];
	int i;

	if( vips__get_bytes( filename, buf, 12 ) != 12 )
		return( 0 );

	for( i = 0; i < VIPS_NUMBER( vips_foreign_load_heif_magic ); i++ )
		if( strncmp( (char *) buf + 4, 
			vips_foreign_load_heif_magic[i], 8 ) == 0 )
			return( 1 );

	return( 0 );
}

/* Set an item as the current one.
 */
static int
vips_foreign_load_heif_set_handle( VipsForeignLoadHeif *heif, heif_item_id id )
{
	struct heif_error error;

	VIPS_FREEF( heif_image_handle_release, heif->handle );

	error = heif_context_get_image_handle( heif->ctx, id, &heif->handle );
	if( error.code ) {
		vips_heif_error( error );
		return( -1 );
	}

	return( 0 );
}

/* Read the primary image header into @out.
 */
static int
vips_foreign_load_heif_set_header( VipsForeignLoadHeif *heif, VipsImage *out )
{
	enum heif_color_profile_type profile_type = 
		heif_image_handle_get_color_profile_type( heif->handle );
	int width = heif_image_handle_get_width( heif->handle );
	int height = heif_image_handle_get_height( heif->handle );
	/* FIXME none of the Nokia test images seem to set this true.
	 */
	gboolean has_alpha = 
		heif_image_handle_has_alpha_channel( heif->handle );
	int bands = has_alpha ? 4 : 3;

	/* Surely, 16 will be enough for anyone.
	 */
	heif_item_id id[16];
	int n_metadata;
	int i;
	struct heif_error error;

	vips_image_pipelinev( out, VIPS_DEMAND_STYLE_SMALLTILE, NULL );
	vips_image_init_fields( out,
		width, height, bands, VIPS_FORMAT_UCHAR, 
		VIPS_CODING_NONE, VIPS_INTERPRETATION_sRGB, 
		1.0, 1.0 );

	n_metadata = heif_image_handle_get_list_of_metadata_block_IDs( 
		heif->handle, NULL, id, VIPS_NUMBER( id ) );
	for( i = 0; i < n_metadata; i++ ) {
		size_t length = heif_image_handle_get_metadata_size( 
			heif->handle, id[i] );
		const char *type = heif_image_handle_get_metadata_type( 
			heif->handle, id[i] );

		unsigned char *data;
		char name[256];

		/* exif has a special name.
		 */
		if( strcasecmp( type, "exif" ) == 0 )
			vips_snprintf( name, 256, VIPS_META_EXIF_NAME );
		else
			vips_snprintf( name, 256, "heif-%s-%d", type, i );

		printf( "metadata type = %s, length = %zd\n", type, length ); 

		if( !(data = VIPS_ARRAY( out, length, unsigned char )) )
			return( -1 );
		error = heif_image_handle_get_metadata( 
			heif->handle, id[i], data );
		if( error.code ) {
			vips_heif_error( error );
			return( -1 );
		}

		/* We need to skip the first four bytes of EXIF, they just
		 * contain the offset.
		 */
		if( strcasecmp( type, "exif" ) == 0 ) {
			data += 4;
			length -= 4;
		}

		vips_image_set_blob( out, name, 
			(VipsCallbackFn) NULL, data, length );

		if( strcasecmp( type, "exif" ) == 0 )
			(void) vips__exif_parse( out );
	}

	switch( profile_type ) {
	case heif_color_profile_type_not_present: 
		printf( "no profile\n" ); 
		break;

	case heif_color_profile_type_nclx: 
		printf( "nclx profile\n" ); 
		break;

	case heif_color_profile_type_rICC: 
		printf( "rICC profile\n" ); 
		break;

	case heif_color_profile_type_prof: 
		printf( "prof profile\n" ); 
		break;

	default:
		printf( "unknown profile type\n" ); 
		break;
	}

	/* FIXME should probably check the profile type ... lcms seems to be
	 * able to load at least rICC and prof.
	 */
	if( heif_image_handle_get_color_profile_type( heif->handle ) ) {
		size_t length = heif_image_handle_get_raw_color_profile_size( 
			heif->handle );

		unsigned char *data;

		if( !(data = VIPS_ARRAY( out, length, unsigned char )) )
			return( -1 );
		error = heif_image_handle_get_raw_color_profile( 
			heif->handle, data );
		if( error.code ) {
			vips_heif_error( error );
			return( -1 );
		}

		printf( "profile data, length = %zd\n", length ); 

		vips_image_set_blob( out, VIPS_META_ICC_NAME, 
			(VipsCallbackFn) NULL, data, length );
	}

	return( 0 );
}

static int
vips_foreign_load_heif_header( VipsForeignLoad *load )
{
	VipsForeignLoadHeif *heif = (VipsForeignLoadHeif *) load;

	struct heif_error error;
	heif_item_id id;
	int i;

	error = heif_context_read_from_file( heif->ctx, heif->filename, NULL );
	if( error.code ) {
		vips_heif_error( error );
		return( -1 );
	}

	heif->n_top = heif_context_get_number_of_top_level_images( heif->ctx );
	heif->id = VIPS_ARRAY( NULL, heif->n_top, heif_item_id );
	heif_context_get_list_of_top_level_image_IDs( heif->ctx, 
		heif->id, heif->n_top );

	printf( "n_top = %d\n", heif->n_top );
	for( i = 0; i < heif->n_top; i++ ) {
		printf( "  id[%d] = %d\n", i, heif->id[i] );
		if( vips_foreign_load_heif_set_handle( heif, heif->id[i] ) )
			return( -1 );
		printf( "    width = %d\n", 
			heif_image_handle_get_width( heif->handle ) );
		printf( "    height = %d\n", 
			heif_image_handle_get_height( heif->handle ) );
		printf( "    depth = %d\n", 
			heif_image_handle_has_depth_image( heif->handle ) );
		printf( "    n_metadata = %d\n", 
			heif_image_handle_get_number_of_metadata_blocks( 
				heif->handle, NULL ) );
		printf( "    colour profile type = %d\n", 
			heif_image_handle_get_color_profile_type( heif->handle ) );
	}

	error = heif_context_get_primary_image_ID( heif->ctx, &id );
	if( error.code ) {
		vips_heif_error( error );
		return( -1 );
	}
	if( vips_foreign_load_heif_set_handle( heif, id ) )
		return( -1 );

	if( vips_foreign_load_heif_set_header( heif, load->out ) )
		return( -1 );

	VIPS_SETSTR( load->out->filename, heif->filename );

	return( 0 );
}

static int
vips_foreign_load_heif_load( VipsForeignLoad *load )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( load );
	VipsForeignLoadHeif *heif = (VipsForeignLoadHeif *) load;

	struct heif_error error;

#ifdef DEBUG
	printf( "vips_foreign_load_heif_load: loading image\n" );
#endif /*DEBUG*/

	/* Decode the image and convert colorspace to RGB, saved as 24bit 
	 * interleaved. 
	 *
	 * FIXME What will this do for RGBA? Or is alpha always separate?
	 */
	error = heif_decode_image( heif->handle, &heif->img, 
		heif_colorspace_RGB, heif_chroma_interleaved_24bit, NULL );
	if( error.code ) {
		vips_heif_error( error );
		return( -1 );
	}

	if( !(heif->data = heif_image_get_plane_readonly( heif->img, 
		heif_channel_interleaved, &heif->stride )) ) {
		vips_error( class->nickname, 
			"%s", _( "unable to get image data" ) );
		return( -1 );
	}

	if( VIPS_IMAGE_SIZEOF_LINE( load->out ) == heif->stride ) {
		printf( "heifload: copying pointer .. \n" );

		/* libheif has decoded to a contigious memory area. We can
		 * just wrap an image around it.
		 */
		if( !(heif->memory = vips_image_new_from_memory( 
			heif->data, VIPS_IMAGE_SIZEOF_IMAGE( load->out ),
			load->out->Xsize, load->out->Ysize, 
			load->out->Bands, load->out->BandFmt )) ) 
			return( -1 );
	}
	else {
		/* Non-contigious memory area. We must copy the data,
		 */
		int y;

		printf( "heifload: copying data .. \n" );
		printf( " stride = %d, sizeof_line = %zd\n", 
			heif->stride, VIPS_IMAGE_SIZEOF_LINE( load->out ) );

		heif->memory = vips_image_new_memory();
		if( vips_foreign_load_heif_set_header( heif, heif->memory ) ||
			vips_image_write_prepare( heif->memory ) ) 
			return( -1 );
		
		for( y = 0; y < heif->memory->Ysize; y++ ) 
			memcpy( VIPS_IMAGE_ADDR( heif->memory, 0, y ),
				heif->data + heif->stride * y, 
				VIPS_IMAGE_SIZEOF_LINE( heif->memory ) );
	}

	if( vips_image_write( heif->memory, load->real ) )
		return( -1 );

	return( 0 );
}

const char *vips__heif_suffs[] = { 
	".heic",
	NULL 
};

static void
vips_foreign_load_heif_class_init( VipsForeignLoadHeifClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->dispose = vips_foreign_load_heif_dispose;
	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "heifload";
	object_class->description = _( "load a HEIF image" );

	foreign_class->suffs = vips__heif_suffs;

	load_class->is_a = vips_foreign_load_heif_is_a;
	load_class->header = vips_foreign_load_heif_header;
	load_class->load = vips_foreign_load_heif_load;

	VIPS_ARG_STRING( class, "filename", 1, 
		_( "Filename" ),
		_( "Filename to load from" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignLoadHeif, filename ),
		NULL );
}

static void
vips_foreign_load_heif_init( VipsForeignLoadHeif *heif )
{
	heif->ctx = heif_context_alloc();
}

#endif /*HAVE_HEIF*/

/**
 * vips_heifload:
 * @filename: file to load
 * @out: (out): decompressed image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Read a HEIF image file into a VIPS image. 
 *
 * See also: vips_image_new_from_file().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_heifload( const char *filename, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "heifload", ap, filename, out );
	va_end( ap );

	return( result );
}
