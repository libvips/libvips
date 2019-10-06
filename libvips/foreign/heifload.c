/* load heif images with libheif
 *
 * 19/1/19
 * 	- from niftiload.c
 * 24/7/19 [zhoux2016]
 * 	- always fetch metadata from the main image (thumbs don't have it)
 * 24/7/19
 * 	- close early on minimise 
 * 	- close early on error
 * 1/9/19 [meyermarcel]
 * 	- handle alpha
 * 30/9/19
 * 	- much faster handling of thumbnail=TRUE and missing thumbnail ... we
 * 	  were reselecting the image for each scanline
 * 3/10/19
 * 	- restart after minimise
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
#define VIPS_DEBUG
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
#include <vips/debug.h>
#include <vips/internal.h>

#ifdef HAVE_HEIF_DECODER

#include <libheif/heif.h>

#include "pforeign.h"

#define VIPS_TYPE_FOREIGN_LOAD_HEIF (vips_foreign_load_heif_get_type())
#define VIPS_FOREIGN_LOAD_HEIF( obj ) \
	(G_TYPE_CHECK_INSTANCE_CAST( (obj), \
	VIPS_TYPE_FOREIGN_LOAD_HEIF, VipsForeignLoadHeif ))
#define VIPS_FOREIGN_LOAD_HEIF_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_CAST( (klass), \
	VIPS_TYPE_FOREIGN_LOAD_HEIF, VipsForeignLoadHeifClass))
#define VIPS_IS_FOREIGN_LOAD_HEIF( obj ) \
	(G_TYPE_CHECK_INSTANCE_TYPE( (obj), VIPS_TYPE_FOREIGN_LOAD_HEIF ))
#define VIPS_IS_FOREIGN_LOAD_HEIF_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_TYPE( (klass), VIPS_TYPE_FOREIGN_LOAD_HEIF ))
#define VIPS_FOREIGN_LOAD_HEIF_GET_CLASS( obj ) \
	(G_TYPE_INSTANCE_GET_CLASS( (obj), \
	VIPS_TYPE_FOREIGN_LOAD_HEIF, VipsForeignLoadHeifClass ))

typedef struct _VipsForeignLoadHeif {
	VipsForeignLoad parent_object;

	/* Pages to load.
	 */
	int page;
	int n;

	/* Fetch the thumbnail instead of the image. If there is no thumbnail,
	 * just fetch the image.
	 */
	gboolean thumbnail;

	/* Apply any orientation tags in the header.
	 */
	gboolean autorotate;

	/* Context for this image.
	 */
	struct heif_context *ctx;

	/* Number of top-level images in this file.
	 */
	int n_top;

	/* TRUE for RGBA ... otherwise, RGB.
	 */
	gboolean has_alpha;

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

	/* TRUE if @handle has selected the thumbnail rather than the main 
	 * image.
	 */
	gboolean thumbnail_set;

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

typedef struct _VipsForeignLoadHeifClass {
	VipsForeignLoadClass parent_class;

	/* Open the reader, eg. call heif_context_read_from_memory() etc. This
	 * has to be a vfunc so generate can restart after minimise.
	 */
	int (*open)( VipsForeignLoadHeif *heif );

} VipsForeignLoadHeifClass;

G_DEFINE_ABSTRACT_TYPE( VipsForeignLoadHeif, vips_foreign_load_heif, 
	VIPS_TYPE_FOREIGN_LOAD );

static void
vips_foreign_load_heif_close( VipsForeignLoadHeif *heif )
{
	VIPS_FREEF( heif_image_release, heif->img );
	heif->data = NULL;
	VIPS_FREEF( heif_image_handle_release, heif->handle );
	VIPS_FREEF( heif_context_free, heif->ctx );
}

static void
vips_foreign_load_heif_dispose( GObject *gobject )
{
	VipsForeignLoadHeif *heif = (VipsForeignLoadHeif *) gobject;

	vips_foreign_load_heif_close( heif );
	VIPS_FREE( heif->id );

	G_OBJECT_CLASS( vips_foreign_load_heif_parent_class )->
		dispose( gobject );
}

void
vips__heif_error( struct heif_error *error )
{
	if( error->code ) 
		vips_error( "heif", "%s (%d.%d)", error->message, error->code,
			error->subcode );
}

static const char *heif_magic[] = {
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
vips_foreign_load_heif_is_a( const char *buf, int len )
{
	if( len >= 12 ) {
		int i;

		for( i = 0; i < VIPS_NUMBER( heif_magic ); i++ )
			if( strncmp( buf + 4, heif_magic[i], 8 ) == 0 )
				return( 1 );
	}

	return( 0 );
}

static VipsForeignFlags
vips_foreign_load_heif_get_flags( VipsForeignLoad *load )
{
	/* FIXME .. could support random access for grid images.
	 */
	return( VIPS_FOREIGN_SEQUENTIAL );
}

/* Select a page. If thumbnail is set, select the thumbnail for that page, if
 * there is one.
 */
static int
vips_foreign_load_heif_set_page( VipsForeignLoadHeif *heif, 
	int page_no, gboolean thumbnail )
{
#ifdef DEBUG
	printf( "vips_foreign_load_heif_set_page: %d, thumbnail = %d\n",
		page_no, thumbnail );
#endif /*DEBUG*/

	if( !heif->handle ||
		page_no != heif->page_no ||
		thumbnail != heif->thumbnail_set ) {
		struct heif_error error;

		VIPS_FREEF( heif_image_handle_release, heif->handle );
		VIPS_FREEF( heif_image_release, heif->img );
		heif->data = NULL;
		heif->thumbnail_set = FALSE;

		error = heif_context_get_image_handle( heif->ctx, 
			heif->id[page_no], &heif->handle );
		if( error.code ) {
			vips__heif_error( &error );
			return( -1 );
		}

		if( thumbnail ) {
			heif_item_id thumb_ids[1];
			int n_thumbs;
			struct heif_image_handle *thumb_handle;

			n_thumbs = heif_image_handle_get_list_of_thumbnail_IDs( 
				heif->handle, thumb_ids, 1 );

			if( n_thumbs > 0 ) {
				error = heif_image_handle_get_thumbnail( 
					heif->handle,
					thumb_ids[0], &thumb_handle );
				if( error.code ) {
					vips__heif_error( &error );
					return( -1 );
				}

				VIPS_FREEF( heif_image_handle_release, 
					heif->handle );
				heif->handle = thumb_handle;
			}

			/* If we were asked to select the thumbnail, say we
			 * did, even if there are no thumbnails and we just
			 * selected the main image. 
			 *
			 * If we don't do this, next time around in _generate
			 * we'll try to select the thumbnail again, which will
			 * be horribly slow.
			 */
			heif->thumbnail_set = TRUE;
		}

		heif->page_no = page_no;
	}

	return( 0 );
}

static int
vips_foreign_load_heif_set_header( VipsForeignLoadHeif *heif, VipsImage *out )
{
	int bands;
	int i;
	/* Surely, 16 metadata items will be enough for anyone.
	 */
	heif_item_id id[16];
	int n_metadata;
	struct heif_error error;

	/* We take the metadata from the non-thumbnail first page. HEIC 
	 * thumbnails don't have metadata.
	 */
	if( vips_foreign_load_heif_set_page( heif, heif->page, FALSE ) )
		return( -1 );

	heif->has_alpha = heif_image_handle_has_alpha_channel( heif->handle );
#ifdef DEBUG
	printf( "heif_image_handle_has_alpha_channel() = %d\n", 
		heif->has_alpha );
#endif /*DEBUG*/
	bands = heif->has_alpha ? 4 : 3;

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

#ifdef DEBUG
		printf( "metadata type = %s, length = %zd\n", type, length ); 
#endif /*DEBUG*/

		if( !(data = VIPS_ARRAY( out, length, unsigned char )) )
			return( -1 );
		error = heif_image_handle_get_metadata( 
			heif->handle, id[i], data );
		if( error.code ) {
			vips__heif_error( &error );
			return( -1 );
		}

		/* We need to skip the first four bytes of EXIF, they just
		 * contain the offset.
		 */
		if( g_ascii_strcasecmp( type, "exif" ) == 0 ) {
			data += 4;
			length -= 4;
		}

		/* exif has a special name.
		 *
		 * XMP metadata is just attached with the "mime" type, and
		 * usually start with "<x:xmpmeta".
		 */
		if( g_ascii_strcasecmp( type, "exif" ) == 0 )
			vips_snprintf( name, 256, VIPS_META_EXIF_NAME );
		else if( g_ascii_strcasecmp( type, "mime" ) == 0 &&
			vips_isprefix( "<x:xmpmeta", (const char *) data ) ) 
			vips_snprintf( name, 256, VIPS_META_XMP_NAME );
		else
			vips_snprintf( name, 256, "heif-%s-%d", type, i );

		vips_image_set_blob( out, name, 
			(VipsCallbackFn) NULL, data, length );

		if( g_ascii_strcasecmp( type, "exif" ) == 0 ) 
			(void) vips__exif_parse( out );
	}

#ifdef HAVE_HEIF_COLOR_PROFILE
#ifdef DEBUG
{
	enum heif_color_profile_type profile_type = 
		heif_image_handle_get_color_profile_type( heif->handle );

	printf( "profile type = " ); 
	switch( profile_type ) {
	case heif_color_profile_type_not_present: 
		printf( "none" ); 
		break;

	case heif_color_profile_type_nclx: 
		printf( "nclx" ); 
		break;

	case heif_color_profile_type_rICC: 
		printf( "rICC" ); 
		break;

	case heif_color_profile_type_prof: 
		printf( "prof" ); 
		break;

	default:
		printf( "unknown" ); 
		break;
	}
	printf( "\n" ); 
}
#endif /*DEBUG*/

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
			vips__heif_error( &error );
			return( -1 );
		}

#ifdef DEBUG
		printf( "profile data, length = %zd\n", length ); 
#endif /*DEBUG*/

		vips_image_set_blob( out, VIPS_META_ICC_NAME, 
			(VipsCallbackFn) NULL, data, length );
	}
#endif /*HAVE_HEIF_COLOR_PROFILE*/

	/* If we are using libheif's autorotate, remove the exif one. 
	 */
#ifdef HAVE_HEIF_IMAGE_HANDLE_GET_ISPE_WIDTH
	if( heif->autorotate )
		vips_autorot_remove_angle( out );
#endif /*HAVE_HEIF_IMAGE_HANDLE_GET_ISPE_WIDTH*/

	vips_image_set_int( out, "heif-primary", heif->primary_page );
	vips_image_set_int( out, "n-pages", heif->n_top );
	if( vips_object_argument_isset( VIPS_OBJECT( heif ), "n" ) )
		vips_image_set_int( out, 
			VIPS_META_PAGE_HEIGHT, heif->page_height );

	/* FIXME .. we always decode to RGB in generate. We should check for
	 * all grey images, perhaps. 
	 */
	vips_image_pipelinev( out, VIPS_DEMAND_STYLE_SMALLTILE, NULL );
	vips_image_init_fields( out,
		heif->page_width, heif->page_height * heif->n, bands, 
		VIPS_FORMAT_UCHAR, VIPS_CODING_NONE, VIPS_INTERPRETATION_sRGB, 
		1.0, 1.0 );

	return( 0 );
}

static int
vips_foreign_load_heif_get_width( VipsForeignLoadHeif *heif, 
	struct heif_image_handle *handle )
{
	int width;

	/* _get_ipse_width() fetches the untransformed dimension, but was only
	 * added in 1.3.4. Without it, we just use the transformed dimension
	 * and have to autorotate.
	 */
	width = heif_image_handle_get_width( handle );
#ifdef HAVE_HEIF_IMAGE_HANDLE_GET_ISPE_WIDTH
	if( !heif->autorotate ) 
		width = heif_image_handle_get_ispe_width( handle );
#endif /*HAVE_HEIF_IMAGE_HANDLE_GET_ISPE_WIDTH*/

	return( width );
}

static int
vips_foreign_load_heif_get_height( VipsForeignLoadHeif *heif,
	struct heif_image_handle *handle )
{
	int height;

	height = heif_image_handle_get_height( handle );
#ifdef HAVE_HEIF_IMAGE_HANDLE_GET_ISPE_WIDTH
	if( !heif->autorotate )
		height = heif_image_handle_get_ispe_height( handle );
#endif /*HAVE_HEIF_IMAGE_HANDLE_GET_ISPE_WIDTH*/

	return( height );
}

static int
vips_foreign_load_heif_header( VipsForeignLoad *load )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( load );
	VipsForeignLoadHeif *heif = (VipsForeignLoadHeif *) load;
	VipsForeignLoadHeifClass *heif_class = 
		VIPS_FOREIGN_LOAD_HEIF_GET_CLASS( heif );

	struct heif_error error;
	heif_item_id primary_id;
	int i;

	if( heif_class->open( heif ) )
		return( -1 );

	heif->n_top = heif_context_get_number_of_top_level_images( heif->ctx );
	heif->id = VIPS_ARRAY( NULL, heif->n_top, heif_item_id );
	heif_context_get_list_of_top_level_image_IDs( heif->ctx, 
		heif->id, heif->n_top );

	/* Note page number of primary image.
	 */
	error = heif_context_get_primary_image_ID( heif->ctx, &primary_id );
	if( error.code ) {
		vips__heif_error( &error );
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

#ifdef DEBUG
#ifdef HAVE_HEIF_IMAGE_HANDLE_GET_ISPE_WIDTH
	if( !heif->autorotate )
		printf( "using _get_ispe_width() / _height()\n" );
#endif /*HAVE_HEIF_IMAGE_HANDLE_GET_ISPE_WIDTH*/
	for( i = heif->page; i < heif->page + heif->n; i++ ) {
		heif_item_id thumb_ids[1];
		int n_items;
		int n_thumbs;
		int j;

		if( vips_foreign_load_heif_set_page( heif, i, FALSE ) )
			return( -1 );

		n_thumbs = heif_image_handle_get_number_of_thumbnails( 
			heif->handle );
		n_items = heif_image_handle_get_list_of_thumbnail_IDs( 
			heif->handle, thumb_ids, 1 );

		printf( "page = %d\n", i );
		printf( "n_thumbs = %d\n", n_thumbs );
		printf( "n_items = %d\n", n_items );

		for( j = 0; j < n_items; j++ ) {
			struct heif_image_handle *thumb_handle;

			error = heif_image_handle_get_thumbnail( heif->handle,
				thumb_ids[j], &thumb_handle );
			if( error.code ) {
				vips__heif_error( &error );
				return( -1 );
			}

			printf( "  thumb %d\n", j );
			printf( "    width = %d\n", 
				vips_foreign_load_heif_get_width( heif, 
					thumb_handle ) );
			printf( "    height = %d\n", 
				vips_foreign_load_heif_get_height( heif, 
					thumb_handle ) );
		}
	}
#endif /*DEBUG*/

	/* All pages must be the same size for libvips toilet roll images.
	 */
	if( vips_foreign_load_heif_set_page( heif, 
		heif->page, heif->thumbnail ) )
		return( -1 );
	heif->page_width = vips_foreign_load_heif_get_width( heif, 
		heif->handle );
	heif->page_height = vips_foreign_load_heif_get_height( heif, 
		heif->handle );
	for( i = heif->page + 1; i < heif->page + heif->n; i++ ) {
		if( vips_foreign_load_heif_set_page( heif, 
			i, heif->thumbnail ) )
			return( -1 );
		if( vips_foreign_load_heif_get_width( heif, 
				heif->handle ) != heif->page_width ||
			vips_foreign_load_heif_get_height( heif, 
				heif->handle ) != heif->page_height ) {
			vips_error( class->nickname, "%s", 
				_( "not all pages are the same size" ) ); 
			return( -1 ); 
		}
	}

#ifdef DEBUG
	printf( "n_top = %d\n", heif->n_top );
	for( i = 0; i < heif->n_top; i++ ) {
		printf( "  id[%d] = %d\n", i, heif->id[i] );
		if( vips_foreign_load_heif_set_page( heif, i, FALSE ) )
			return( -1 );
		printf( "    width = %d\n", 
			vips_foreign_load_heif_get_width( heif, 
				heif->handle ) );
		printf( "    height = %d\n", 
			vips_foreign_load_heif_get_height( heif, 
				heif->handle ) );
		printf( "    has_depth = %d\n", 
			heif_image_handle_has_depth_image( heif->handle ) );
		printf( "    has_alpha = %d\n", 
			heif_image_handle_has_alpha_channel( heif->handle ) );
		printf( "    n_metadata = %d\n", 
			heif_image_handle_get_number_of_metadata_blocks( 
				heif->handle, NULL ) );
#ifdef HAVE_HEIF_COLOR_PROFILE
		printf( "    colour profile type = 0x%xd\n", 
			heif_image_handle_get_color_profile_type( 
				heif->handle ) );
#endif /*HAVE_HEIF_COLOR_PROFILE*/
	}
#endif /*DEBUG*/

	if( vips_foreign_load_heif_set_header( heif, load->out ) )
		return( -1 );

	vips_foreign_load_heif_close( heif ); 

	return( 0 );
}

static int
vips_foreign_load_heif_generate( VipsRegion *or, 
	void *seq, void *a, void *b, gboolean *stop )
{
	VipsForeignLoadHeif *heif = (VipsForeignLoadHeif *) a;
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( heif );
	VipsForeignLoadHeifClass *heif_class = 
		VIPS_FOREIGN_LOAD_HEIF_GET_CLASS( heif );
        VipsRect *r = &or->valid;

	int page = r->top / heif->page_height + heif->page;
	int line = r->top % heif->page_height;

#ifdef DEBUG_VERBOSE
	printf( "vips_foreign_load_heif_generate: line %d\n", r->top );
#endif /*DEBUG_VERBOSE*/

	g_assert( r->height == 1 );

	if( heif_class->open( heif ) )
		return( -1 );

	if( vips_foreign_load_heif_set_page( heif, page, heif->thumbnail ) )
		return( -1 );

	if( !heif->img ) {
		struct heif_error error;
		struct heif_decoding_options *options;
		enum heif_chroma chroma = heif->has_alpha ? 
			heif_chroma_interleaved_RGBA :
			heif_chroma_interleaved_RGB;

		/* Only disable transforms if we have been able to fetch the
		 * untransformed dimensions.
		 */
		options = heif_decoding_options_alloc();
#ifdef HAVE_HEIF_IMAGE_HANDLE_GET_ISPE_WIDTH
		options->ignore_transformations = !heif->autorotate;
#endif /*HAVE_HEIF_IMAGE_HANDLE_GET_ISPE_WIDTH*/
		error = heif_decode_image( heif->handle, &heif->img, 
			heif_colorspace_RGB, chroma, 
			options );
		heif_decoding_options_free( options );
		if( error.code ) {
			vips__heif_error( &error );
			return( -1 );
		}

#ifdef DEBUG
{
		const static enum heif_channel channel[] = {
			heif_channel_Y,
			heif_channel_Cb,
			heif_channel_Cr,
			heif_channel_R,
			heif_channel_G,
			heif_channel_B,
			heif_channel_Alpha,
			heif_channel_interleaved
		};

		const static char *channel_name[] = {
			"heif_channel_Y",
			"heif_channel_Cb",
			"heif_channel_Cr",
			"heif_channel_R",
			"heif_channel_G",
			"heif_channel_B",
			"heif_channel_Alpha",
			"heif_channel_interleaved"
		};

		int i;

		printf( "vips_foreign_load_heif_generate:\n" );
		for( i = 0; i < VIPS_NUMBER( channel ); i++ ) {
			printf( "\t%s:\n", channel_name[i] ); 
			printf( "\t\twidth = %d\n", 
				heif_image_get_width( heif->img, 
					channel[i] ) );
			printf( "\t\theight = %d\n", 
				heif_image_get_height( heif->img, 
					channel[i] ) );
			printf( "\t\tbits = %d\n", 
				heif_image_get_bits_per_pixel( heif->img, 
					channel[i] ) );
			printf( "\t\thas_channel = %d\n", 
				heif_image_has_channel( heif->img, 
					channel[i] ) );
		}
}
#endif /*DEBUG*/
	}

	if( !heif->data ) {
		int image_width = heif_image_get_width( heif->img, 
			heif_channel_interleaved );
		int image_height = heif_image_get_height( heif->img, 
			heif_channel_interleaved );

		/* We can sometimes get inconsistency between the dimensions
		 * reported on the handle, and the final image we fetch. Error
		 * out to prevent a segv.
		 */
		if( image_width != heif->page_width ||
			image_height != heif->page_height ) {
			vips_error( class->nickname, 
				"%s", _( "bad image dimensions on decode" ) );
			return( -1 );
		}

		if( !(heif->data = heif_image_get_plane_readonly( heif->img, 
			heif_channel_interleaved, &heif->stride )) ) {
			vips_error( class->nickname, 
				"%s", _( "unable to get image data" ) );
			return( -1 );
		}
	}

	memcpy( VIPS_REGION_ADDR( or, 0, r->top ),
		heif->data + heif->stride * line, 
		VIPS_IMAGE_SIZEOF_LINE( or->im ) );

	return( 0 );
}

static void
vips_foreign_load_heif_minimise( VipsObject *object, VipsForeignLoadHeif *heif )
{
	vips_foreign_load_heif_close( heif );
}

static int
vips_foreign_load_heif_load( VipsForeignLoad *load )
{
	VipsForeignLoadHeif *heif = (VipsForeignLoadHeif *) load;
	VipsForeignLoadHeifClass *class = 
		VIPS_FOREIGN_LOAD_HEIF_GET_CLASS( heif );

	VipsImage **t = (VipsImage **) 
		vips_object_local_array( VIPS_OBJECT( load ), 3 );

#ifdef DEBUG
	printf( "vips_foreign_load_heif_load: loading image\n" );
#endif /*DEBUG*/

	if( class->open( heif ) )
		return( -1 );

	t[0] = vips_image_new();
	if( vips_foreign_load_heif_set_header( heif, t[0] ) )
		return( -1 );

	/* CLose input immediately at end of read.
	 */
	g_signal_connect( t[0], "minimise", 
		G_CALLBACK( vips_foreign_load_heif_minimise ), heif ); 

	if( vips_image_generate( t[0],
		NULL, vips_foreign_load_heif_generate, NULL, heif, NULL ) ||
		vips_sequential( t[0], &t[1], NULL ) ||
		vips_image_write( t[1], load->real ) )
		return( -1 );

	return( 0 );
}

static int
vips_foreign_load_heif_open( VipsForeignLoadHeif *heif )
{
	return( 0 );
}

static void
vips_foreign_load_heif_class_init( VipsForeignLoadHeifClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;
	VipsForeignLoadHeifClass *heif_class = 
		(VipsForeignLoadHeifClass *) class;

	gobject_class->dispose = vips_foreign_load_heif_dispose;
	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "heifload_base";
	object_class->description = _( "load a HEIF image" );

	load_class->get_flags = vips_foreign_load_heif_get_flags;
	load_class->header = vips_foreign_load_heif_header;
	load_class->load = vips_foreign_load_heif_load;

	heif_class->open = vips_foreign_load_heif_open;

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

	VIPS_ARG_BOOL( class, "thumbnail", 4, 
		_( "Thumbnail" ), 
		_( "Fetch thumbnail image" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignLoadHeif, thumbnail ),
		FALSE );

	VIPS_ARG_BOOL( class, "autorotate", 21, 
		_( "Autorotate" ), 
		_( "Rotate image using exif orientation" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignLoadHeif, autorotate ),
		FALSE );

}

static void
vips_foreign_load_heif_init( VipsForeignLoadHeif *heif )
{
	heif->n = 1;
}

typedef struct _VipsForeignLoadHeifFile {
	VipsForeignLoadHeif parent_object;

	/* Filename for load.
	 */
	char *filename; 

} VipsForeignLoadHeifFile;

typedef VipsForeignLoadHeifClass VipsForeignLoadHeifFileClass;

G_DEFINE_TYPE( VipsForeignLoadHeifFile, vips_foreign_load_heif_file, 
	vips_foreign_load_heif_get_type() );

static int
vips_foreign_load_heif_file_is_a( const char *filename )
{
	char buf[12];

	if( vips__get_bytes( filename, (unsigned char *) buf, 12 ) != 12 )
		return( 0 );

	return( vips_foreign_load_heif_is_a( buf, 12 ) );
}

static int
vips_foreign_load_heif_file_header( VipsForeignLoad *load )
{
	VipsForeignLoadHeif *heif = (VipsForeignLoadHeif *) load;
	VipsForeignLoadHeifFile *file = (VipsForeignLoadHeifFile *) load;

	if( VIPS_FOREIGN_LOAD_CLASS( 
		vips_foreign_load_heif_file_parent_class )->header( load ) ) {
		/* Close early if our base class fails to read.
		 */
		vips_foreign_load_heif_close( heif ); 
		return( -1 );
	}

	VIPS_SETSTR( load->out->filename, file->filename );

	return( 0 );
}

const char *vips__heif_suffs[] = { 
	".heic",
	".heif",
	".avif",
	NULL 
};

static int
vips_foreign_load_heif_file_open( VipsForeignLoadHeif *heif )
{
	VipsForeignLoadHeifFile *file = (VipsForeignLoadHeifFile *) heif;

	if( !heif->ctx ) {
		struct heif_error error;

		heif->ctx = heif_context_alloc();

		error = heif_context_read_from_file( heif->ctx, 
			file->filename, NULL );
		if( error.code ) {
			/* Make we close the fd as soon as we can on error.
			 */
			vips_foreign_load_heif_close( heif ); 
			vips__heif_error( &error );
			return( -1 );
		}
	}

	return( VIPS_FOREIGN_LOAD_HEIF_CLASS(
		vips_foreign_load_heif_file_parent_class )->open( heif ) );
}

static void
vips_foreign_load_heif_file_class_init( VipsForeignLoadHeifFileClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;
	VipsForeignLoadHeifClass *heif_class = 
		(VipsForeignLoadHeifClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "heifload";

	foreign_class->suffs = vips__heif_suffs;

	load_class->is_a = vips_foreign_load_heif_file_is_a;
	load_class->header = vips_foreign_load_heif_file_header;

	heif_class->open = vips_foreign_load_heif_file_open;

	VIPS_ARG_STRING( class, "filename", 1, 
		_( "Filename" ),
		_( "Filename to load from" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignLoadHeifFile, filename ),
		NULL );

}

static void
vips_foreign_load_heif_file_init( VipsForeignLoadHeifFile *file )
{
}

typedef struct _VipsForeignLoadHeifBuffer {
	VipsForeignLoadHeif parent_object;

	/* Load from a buffer.
	 */
	VipsArea *buf;

} VipsForeignLoadHeifBuffer;

typedef VipsForeignLoadHeifClass VipsForeignLoadHeifBufferClass;

G_DEFINE_TYPE( VipsForeignLoadHeifBuffer, vips_foreign_load_heif_buffer, 
	vips_foreign_load_heif_get_type() );

static gboolean
vips_foreign_load_heif_buffer_is_a( const void *buf, size_t len )
{
	return( vips_foreign_load_heif_is_a( buf, len ) );
}

static int
vips_foreign_load_heif_buffer_open( VipsForeignLoadHeif *heif )
{
	VipsForeignLoadHeifBuffer *buffer = (VipsForeignLoadHeifBuffer *) heif;

	VIPS_DEBUG_MSG( "vips_foreign_load_heif_buffer_open:\n" );

	if( !heif->ctx ) {
		struct heif_error error;

		heif->ctx = heif_context_alloc();
		error = heif_context_read_from_memory( heif->ctx, 
			buffer->buf->data, buffer->buf->length, NULL );
		if( error.code ) {
			vips__heif_error( &error );
			return( -1 );
		}
	}

	return( VIPS_FOREIGN_LOAD_HEIF_CLASS(
		vips_foreign_load_heif_buffer_parent_class )->open( heif ) );
}

static void
vips_foreign_load_heif_buffer_class_init( 
	VipsForeignLoadHeifBufferClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;
	VipsForeignLoadHeifClass *heif_class = 
		(VipsForeignLoadHeifClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "heifload_buffer";

	load_class->is_a_buffer = vips_foreign_load_heif_buffer_is_a;

	heif_class->open = vips_foreign_load_heif_buffer_open;

	VIPS_ARG_BOXED( class, "buffer", 1, 
		_( "Buffer" ),
		_( "Buffer to load from" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignLoadHeifBuffer, buf ),
		VIPS_TYPE_BLOB );

}

static void
vips_foreign_load_heif_buffer_init( VipsForeignLoadHeifBuffer *buffer )
{
}

#endif /*HAVE_HEIF_DECODER*/

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
 * * @thumbnail: %gboolean, fetch thumbnail instead of image
 * * @autorotate: %gboolean, rotate image upright during load 
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
 * If @thumbnail is %TRUE, then fetch a stored thumbnail rather than the
 * image.
 *
 * Setting @autorotate to %TRUE will make the loader interpret the 
 * orientation tag and automatically rotate the image appropriately during
 * load. 
 *
 * If @autorotate is %FALSE, the metadata field #VIPS_META_ORIENTATION is set 
 * to the value of the orientation tag. Applications may read and interpret 
 * this field
 * as they wish later in processing. See vips_autorot(). Save
 * operations will use #VIPS_META_ORIENTATION, if present, to set the
 * orientation of output images. 
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

/**
 * vips_heifload_buffer:
 * @buf: (array length=len) (element-type guint8): memory area to load
 * @len: (type gsize): size of memory area
 * @out: (out): image to write
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @page: %gint, page (top-level image number) to read
 * * @n: %gint, load this many pages
 * * @thumbnail: %gboolean, fetch thumbnail instead of image
 * * @autorotate: %gboolean, rotate image upright during load 
 *
 * Read a HEIF image file into a VIPS image. 
 * Exactly as vips_heifload(), but read from a memory buffer. 
 *
 * You must not free the buffer while @out is active. The 
 * #VipsObject::postclose signal on @out is a good place to free. 
 *
 * See also: vips_heifload().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_heifload_buffer( void *buf, size_t len, VipsImage **out, ... )
{
	va_list ap;
	VipsBlob *blob;
	int result;

	/* We don't take a copy of the data or free it.
	 */
	blob = vips_blob_new( NULL, buf, len );

	va_start( ap, out );
	result = vips_call_split( "heifload_buffer", ap, blob, out );
	va_end( ap );

	vips_area_unref( VIPS_AREA( blob ) );

	return( result );
}
