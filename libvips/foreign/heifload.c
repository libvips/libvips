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

	/* Pages to load.
	 */
	int page;
	int n;

	/* Set to ignore transforms (flip, rotate, crop) stored in the file
	 * header.
	 */
	gboolean ignore_transformations;

	/* Context for this file.
	 */
	struct heif_context *ctx;

	/* Number of top-level images in this file.
	 */
	int n_top;

	/* Size of final output image. 
	 */
	int width;
	int height;

	/* Size of each page.
	 */
	int page_width;
	int page_height;

	/* The page number currently in @handle. 
	 */
	int page_no;

	/* The page number of the primary image.
	 */
	int primary_page;

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
	"ftypheic",	/* A regular heif image */
	"ftypheix",	/* Extended range (>8 bit) image */
	"ftyphevc",	/* Image sequence */
	"ftypheim",	/* Image sequence */
	"ftypheis",	/* Scaleable image */
	"ftyphevm",	/* Multiview sequence */
	"ftyphevs",	/* Scaleable sequence */
	"ftypmif1",	/* Nokia alpha_ image */
	"ftypmsf1"	/* Nokia animation image */
};

/* THe API has:
 *
 *	enum heif_filetype_result result = heif_check_filetype( buf, 12 );
 *
 * but it's very conservative and seems to be missing some of the Noka hief
 * types.
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

static VipsForeignFlags
vips_foreign_load_heif_get_flags( VipsForeignLoad *load )
{
	/* FIXME .. could support random access for grid images.
	 */
	return( VIPS_FOREIGN_SEQUENTIAL );
}

static int
vips_foreign_load_heif_set_page( VipsForeignLoadHeif *heif, int page_no )
{
	if( !heif->handle ||
		page_no != heif->page_no ) {
		struct heif_error error;

		VIPS_FREEF( heif_image_handle_release, heif->handle );
		VIPS_FREEF( heif_image_release, heif->img );
		heif->data = NULL;

		error = heif_context_get_image_handle( heif->ctx, 
			heif->id[page_no], &heif->handle );
		if( error.code ) {
			vips_heif_error( error );
			return( -1 );
		}

		heif->page_no = page_no;
	}

	return( 0 );
}

static int
vips_foreign_load_heif_set_header( VipsForeignLoadHeif *heif, VipsImage *out )
{
	enum heif_color_profile_type profile_type = 
		heif_image_handle_get_color_profile_type( heif->handle );
	/* FIXME ... never seen this return TRUE on any image, strangely.
	 */
	gboolean has_alpha = 
		heif_image_handle_has_alpha_channel( heif->handle );
	int bands = has_alpha ? 4 : 3;

	/* Surely, 16 metadata items will be enough for anyone.
	 */
	int i;
	heif_item_id id[16];
	int n_metadata;
	struct heif_error error;

	/* FIXME .. we always decode to RGB in generate. We should check for
	 * all grey images, perhaps. 
	 */
	vips_image_pipelinev( out, VIPS_DEMAND_STYLE_SMALLTILE, NULL );
	vips_image_init_fields( out,
		heif->page_width, heif->page_height * heif->n, bands, 
		VIPS_FORMAT_UCHAR, VIPS_CODING_NONE, VIPS_INTERPRETATION_sRGB, 
		1.0, 1.0 );

	vips_image_set_int( out, "heif-primary", heif->primary_page );
	vips_image_set_int( out, "n-pages", heif->n_top );
	vips_image_set_int( out, "page-height", heif->page_height );
	VIPS_SETSTR( out->filename, heif->filename );

	/* FIXME .. need to test XMP and IPCT.
	 */
	n_metadata = heif_image_handle_get_list_of_metadata_block_IDs( 
		heif->handle, NULL, id, VIPS_NUMBER( id ) );
	for( i = 0; i < n_metadata; i++ ) {
		size_t length = heif_image_handle_get_metadata_size( 
			heif->handle, id[i] );
		const char *type = heif_image_handle_get_metadata_type( 
			heif->handle, id[i] );

		unsigned char *data;
		char name[256];

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

		/* exif has a special name.
		 *
		 * XMP metadata is just attached with the "mime" type, and
		 * usually start with "<x:xmpmeta".
		 */
		if( strcasecmp( type, "exif" ) == 0 )
			vips_snprintf( name, 256, VIPS_META_EXIF_NAME );
		else if( strcasecmp( type, "mime" ) == 0 &&
			vips_isprefix( "<x:xmpmeta", (const char *) data ) ) 
			snprintf( name, 256, VIPS_META_XMP_NAME ); 
		else
			vips_snprintf( name, 256, "heif-%s-%d", type, i );

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
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( load );
	VipsForeignLoadHeif *heif = (VipsForeignLoadHeif *) load;

	struct heif_error error;
	heif_item_id primary_id;
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

	/* Note page number of primary image.
	 */
	error = heif_context_get_primary_image_ID( heif->ctx, &primary_id );
	if( error.code ) {
		vips_heif_error( error );
		return( -1 );
	}
	for( i = 0; i < heif->n_top; i++ )
		if( heif->id[i] == primary_id )
			heif->primary_page = i;

	/* If @n and @page have not been set, @page defaults to the primary
	 * page.
	 */
	if( !vips_object_argument_isset( VIPS_OBJECT( load ), "page" ) &&
		!vips_object_argument_isset( VIPS_OBJECT( load ), "n" ) )
		heif->page = heif->primary_page;

	if( heif->n == -1 )
		heif->n = heif->n_top - heif->page;
	if( heif->page < 0 ||
		heif->n <= 0 ||
		heif->page + heif->n > heif->n_top ) {
		vips_error( class->nickname, "%s", _( "bad page number" ) ); 
		return( -1 ); 
	}

	/* All pages must be the same size for libvips toilet roll images.
	 */
	if( vips_foreign_load_heif_set_page( heif, heif->page ) )
		return( -1 );
	heif->page_width = heif_image_handle_get_width( heif->handle );
	heif->page_height = heif_image_handle_get_height( heif->handle );
	for( i = heif->page + 1; i < heif->page + heif->n; i++ ) {
		if( vips_foreign_load_heif_set_page( heif, i ) )
			return( -1 );
		if( heif_image_handle_get_width( heif->handle ) != 
				heif->page_width ||
			heif_image_handle_get_height( heif->handle ) != 
				heif->page_height ) {
			vips_error( class->nickname, "%s", 
				_( "not all pages are the same size" ) ); 
			return( -1 ); 
		}
	}

	printf( "n_top = %d\n", heif->n_top );
	for( i = 0; i < heif->n_top; i++ ) {
		printf( "  id[%d] = %d\n", i, heif->id[i] );
		if( vips_foreign_load_heif_set_page( heif, i ) )
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
			heif_image_handle_get_color_profile_type( 
				heif->handle ) );
	}

	if( vips_foreign_load_heif_set_header( heif, load->out ) )
		return( -1 );

	return( 0 );
}

static int
vips_foreign_load_heif_generate( VipsRegion *or, 
	void *seq, void *a, void *b, gboolean *stop )
{
	VipsForeignLoadHeif *heif = (VipsForeignLoadHeif *) a;
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( heif );
        VipsRect *r = &or->valid;

	int page = r->top / heif->page_height + heif->page;
	int line = r->top % heif->page_height;

#ifdef DEBUG_VERBOSE
	printf( "vips_foreign_load_heif_generate: line %d\n", r->top );
#endif /*DEBUG_VERBOSE*/

	g_assert( r->height == 1 );

	if( vips_foreign_load_heif_set_page( heif, page ) )
		return( -1 );

	if( !heif->img ) {
		struct heif_error error;
		struct heif_decoding_options *options;

		/* Decode the image to 24bit interleaved. 
		 *
		 * FIXME What will this do for RGBA? Or is alpha always 
		 * separate?
		 */
		options = heif_decoding_options_alloc();
		options->ignore_transformations = heif->ignore_transformations;
		error = heif_decode_image( heif->handle, &heif->img, 
			heif_colorspace_RGB, heif_chroma_interleaved_24bit, 
			options );
		heif_decoding_options_free( options );
		if( error.code ) {
			vips_heif_error( error );
			return( -1 );
		}
	}

	if( !heif->data ) 
		if( !(heif->data = heif_image_get_plane_readonly( heif->img, 
			heif_channel_interleaved, &heif->stride )) ) {
			vips_error( class->nickname, 
				"%s", _( "unable to get image data" ) );
			return( -1 );
		}

	memcpy( VIPS_REGION_ADDR( or, 0, r->top ),
		heif->data + heif->stride * line, 
		VIPS_IMAGE_SIZEOF_LINE( or->im ) );

	return( 0 );
}

static int
vips_foreign_load_heif_load( VipsForeignLoad *load )
{
	VipsForeignLoadHeif *heif = (VipsForeignLoadHeif *) load;

	VipsImage **t = (VipsImage **) 
		vips_object_local_array( VIPS_OBJECT( load ), 3 );

#ifdef DEBUG
	printf( "vips_foreign_load_heif_load: loading image\n" );
#endif /*DEBUG*/

	t[0] = vips_image_new();
	if( vips_foreign_load_heif_set_header( heif, t[0] ) )
		return( -1 );
	if( vips_image_generate( t[0],
		NULL, vips_foreign_load_heif_generate, NULL, heif, NULL ) ||
		vips_sequential( t[0], &t[1], NULL ) ||
		vips_image_write( t[1], load->real ) )
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

	load_class->get_flags = vips_foreign_load_heif_get_flags;
	load_class->is_a = vips_foreign_load_heif_is_a;
	load_class->header = vips_foreign_load_heif_header;
	load_class->load = vips_foreign_load_heif_load;

	VIPS_ARG_STRING( class, "filename", 1, 
		_( "Filename" ),
		_( "Filename to load from" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignLoadHeif, filename ),
		NULL );

	VIPS_ARG_INT( class, "page", 2,
		_( "Page" ),
		_( "Load this page from the file" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignLoadHeif, page ),
		0, 100000, 0 );

	VIPS_ARG_INT( class, "n", 3,
		_( "n" ),
		_( "Load this many pages" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignLoadHeif, n ),
		-1, 100000, 1 );

	VIPS_ARG_BOOL( class, "ignore_transformations", 4,
		_( "Ignore transformations" ),
		_( "Ignore input transformations" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignLoadHeif, 
			ignore_transformations ),
	       FALSE );

}

static void
vips_foreign_load_heif_init( VipsForeignLoadHeif *heif )
{
	heif->ctx = heif_context_alloc();
	heif->n = 1;
}

#endif /*HAVE_HEIF*/

/**
 * vips_heifload:
 * @filename: file to load
 * @out: (out): decompressed image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @page: %gint, page (top-level image number) to read
 * * @n: %gint, load this many pages
 * * @ignore_transformations: %gboolean, ignore image transformations
 *
 * Read a HEIF image file into a VIPS image. 
 *
 * Use @page to select a page to render, numbering from zero. If neither @n
 * nor @page are set, @page defaults to the primary page, otherwise to 0.
 *
 * Use @n to select the number of pages to render. The default is 1. Pages are
 * rendered in a vertical column. Set to -1 to mean "until the end of the 
 * document". Use vips_grid() to reorganise pages.
 *
 * HEIF images have a primary image. The metadata item `heif-primary` gives 
 * the page number of the primary.
 *
 * HEIF images can have trsnaformations like rotate, flip and crop stored in
 * the header. By default, these are applied during load. Set
 * @ignore_transformations %TRUE to return the untransformed image.
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
