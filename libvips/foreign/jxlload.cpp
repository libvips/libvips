/* load jpeg-xl
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
 */
#define DEBUG_VERBOSE
#define DEBUG

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

#ifdef HAVE_LIBJXL

#include <jxl/decode.h>
#include <jxl/decode_cxx.h>
#include <jxl/thread_parallel_runner.h>
#include <jxl/thread_parallel_runner_cxx.h>

#include "pforeign.h"

#define INPUT_BUFFER_SIZE (4096)

typedef struct _VipsForeignLoadJxl {
	VipsForeignLoad parent_object;

	/* Source to load from (set by subclasses).
	 */
	VipsSource *source;

	/* Page set by user, then we translate that into shrink factor.
	 */
	int page;
	int shrink;

	/* Base image properties.
	 */
	JxlBasicInfo info;

	/* Decompress state.
	 */
	JxlThreadParallelRunner *runner;
	JxlDecoder *decoder;

	/* Our input buffer.
	 */
	uint8_t input_buffer[INPUT_BUFFER_SIZE];
	size_t bytes_in_buffer;

	/* Number of errors reported during load -- use this to block load of
	 * corrupted images.
	 */
	int n_errors;

	/* If we need to upsample tiles read from opj.
	 */
	gboolean upsample;

	/* If we need to do ycc->rgb conversion on load.
	 */
	gboolean ycc_to_rgb;
} VipsForeignLoadJxl;

typedef VipsForeignLoadClass VipsForeignLoadJxlClass;

/* We need C linkage for this.
 */
extern "C" {
G_DEFINE_ABSTRACT_TYPE( VipsForeignLoadJxl, vips_foreign_load_jxl, 
	VIPS_TYPE_FOREIGN_LOAD );
}

static void
vips_foreign_load_jxl_dispose( GObject *gobject )
{
	VipsForeignLoadJxl *jxl = (VipsForeignLoadJxl *) gobject;

#ifdef DEBUG
	printf( "vips_foreign_load_jxl_dispose:\n" );
#endif /*DEBUG*/

	VIPS_FREEF( JxlThreadParallelRunnerDestroy, jxl->runner );
	VIPS_FREEF( JxlDecoderDestroy, jxl->decoder );

	G_OBJECT_CLASS( vips_foreign_load_jxl_parent_class )->
		dispose( gobject );
}

static int
vips_foreign_load_jxl_build( VipsObject *object )
{
	VipsObjectClass *klass = VIPS_OBJECT_GET_CLASS( object );
	VipsForeignLoadJxl *jxl = (VipsForeignLoadJxl *) object;

	JxlDecoderStatus status;

#ifdef DEBUG
	printf( "vips_foreign_load_jxl_build:\n" );
#endif /*DEBUG*/

	jxl->runner = JxlThreadParallelRunnerCreate( nullptr, 
		vips_concurrency_get() );
	jxl->decoder = JxlDecoderCreate( nullptr );

	if( JxlDecoderSubscribeEvents( jxl->decoder, 
		JXL_DEC_BASIC_INFO |
		JXL_DEC_COLOR_ENCODING |
		JXL_DEC_FULL_IMAGE ) != JXL_DEC_SUCCESS ) {
		vips_error( klass->nickname, 
			"%s", _( "JxlDecoderSubscribeEvents failed" ) );
		return( -1 );
	}
	if( JxlDecoderSetParallelRunner( jxl->decoder, 
		JxlThreadParallelRunner, jxl->runner ) != JXL_DEC_SUCCESS ) {
		vips_error( klass->nickname, 
			"%s", _( "JxlDecoderSetParallelRunner failed" ) );
		return( -1 );
	}

	if( VIPS_OBJECT_CLASS( vips_foreign_load_jxl_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

static int
vips_foreign_load_jxl_set_header( VipsForeignLoadJxl *jxl, VipsImage *out )
{
	VipsObjectClass *klass = VIPS_OBJECT_GET_CLASS( jxl );
	opj_image_comp_t *first = &jxl->image->comps[0];

	VipsBandFormat format;
	VipsInterpretation interpretation;

	/* OpenJPEG only supports up to 31 bpp. Treat it as 32.
	 */
	if( first->prec <= 8 ) 
		format = first->sgnd ? VIPS_FORMAT_CHAR : VIPS_FORMAT_UCHAR;
	else if( first->prec <= 16 ) 
		format = first->sgnd ? VIPS_FORMAT_SHORT : VIPS_FORMAT_USHORT;
	else
		format = first->sgnd ? VIPS_FORMAT_INT : VIPS_FORMAT_UINT;

	switch( jxl->image->color_space ) {
	case OPJ_CLRSPC_SYCC:
	case OPJ_CLRSPC_EYCC:
		/* Map these to RGB.
		 */
		interpretation = vips_format_sizeof( format ) == 1 ? 
			VIPS_INTERPRETATION_sRGB :
			VIPS_INTERPRETATION_RGB16;
		jxl->ycc_to_rgb = TRUE;
		break;

	case OPJ_CLRSPC_GRAY:
		interpretation = vips_format_sizeof( format ) == 1 ? 
			VIPS_INTERPRETATION_B_W :
			VIPS_INTERPRETATION_GREY16;
		break;

	case OPJ_CLRSPC_SRGB:
		interpretation = vips_format_sizeof( format ) == 1 ? 
			VIPS_INTERPRETATION_sRGB :
			VIPS_INTERPRETATION_RGB16;
		break;

	case OPJ_CLRSPC_CMYK:
		interpretation = VIPS_INTERPRETATION_CMYK;
		break;

	case OPJ_CLRSPC_UNSPECIFIED:
		/* Try to guess something sensible.
		 */
		if( jxl->image->numcomps < 3 )
			interpretation = vips_format_sizeof( format ) == 1 ? 
				VIPS_INTERPRETATION_B_W :
				VIPS_INTERPRETATION_GREY16;
		else
			interpretation = vips_format_sizeof( format ) == 1 ? 
				VIPS_INTERPRETATION_sRGB :
				VIPS_INTERPRETATION_RGB16;

		/* Unspecified with three bands and subsampling on bands 2 and
		 * 3 is usually YCC. 
		 */
		if( jxl->image->numcomps == 3 &&
			jxl->image->comps[0].dx == 1 &&
			jxl->image->comps[0].dy == 1 &&
			jxl->image->comps[1].dx > 1 &&
			jxl->image->comps[1].dy > 1 &&
			jxl->image->comps[2].dx > 1 &&
			jxl->image->comps[2].dy > 1)
			jxl->ycc_to_rgb = TRUE;

		break;

	default:
		vips_error( klass->nickname, 
			_( "unsupported colourspace %d" ), 
			jxl->image->color_space );
		return( -1 );
	}

	/* Even though this is a tiled reader, we hint thinstrip since with
	 * the cache we are quite happy serving that if anything downstream 
	 * would like it.
	 */
        vips_image_pipelinev( out, VIPS_DEMAND_STYLE_THINSTRIP, NULL );

	vips_image_init_fields( out,
		first->w, first->h, jxl->image->numcomps, format, 
		VIPS_CODING_NONE, interpretation, 1.0, 1.0 );

	/* openjpeg allows left and top of the coordinate grid to be
	 * non-zero. These are always in unshrunk coordinates.
	 */
	out->Xoffset = 
		-VIPS_ROUND_INT( (double) jxl->image->x0 / jxl->shrink );
	out->Yoffset = 
		-VIPS_ROUND_INT( (double) jxl->image->y0 / jxl->shrink );

	if( jxl->image->icc_profile_buf &&
		jxl->image->icc_profile_len > 0 )
		vips_image_set_blob_copy( out, VIPS_META_ICC_NAME, 
			jxl->image->icc_profile_buf,
			jxl->image->icc_profile_len );

	/* Map number of layers in image to pages. 
	 */
	if( jxl->info &&
		jxl->info->m_default_tile_info.tccp_info )
		vips_image_set_int( out, VIPS_META_N_PAGES, 
			jxl->info->m_default_tile_info.tccp_info->
				numresolutions );

	return( 0 );
}

static int
vips_foreign_load_jxl_fill_input( VipsForeignLoadJxl *jxl, 
	size_t bytes_remaining )
{
	gint64 bytes_read;

	memcpy( jxl->input_buffer, 
		jxl->input_buffer + jxl->bytes_in_buffer - bytes_remaining,
		bytes_remaining );
	bytes_read = vips_source_read( jxl->source,
		jxl->input_buffer + bytes_remaining,
		INPUT_BUFFER_SIZE - bytes_remaining );
	if( bytes_read < 0 ) 
		return( -1 );
	jxl->bytes_in_buffer = bytes_read + bytes_remaining;

	return( 0 );
}

static void
vips_foreign_load_jxl_print_status( JxlDecoderStatus status )
{
	switch( status ) {
	case JXL_DEC_SUCCESS:
		printf( "JXL_DEC_SUCCESS\n" );
		break;

	case JXL_DEC_ERROR:
		printf( "JXL_DEC_ERROR\n" );
		break;

	case JXL_DEC_NEED_MORE_INPUT:
		printf( "JXL_DEC_NEED_MORE_INPUT\n" );
		break;

	case JXL_DEC_NEED_PREVIEW_OUT_BUFFER:
		printf( "JXL_DEC_NEED_PREVIEW_OUT_BUFFER\n" );
		break;

	case JXL_DEC_NEED_DC_OUT_BUFFER:
		printf( "JXL_DEC_NEED_DC_OUT_BUFFER\n" );
		break;

	case JXL_DEC_NEED_IMAGE_OUT_BUFFER:
		printf( "JXL_DEC_NEED_IMAGE_OUT_BUFFER\n" );
		break;

	case JXL_DEC_JPEG_NEED_MORE_OUTPUT:
		printf( "JXL_DEC_JPEG_NEED_MORE_OUTPUT\n" );
		break;

	case JXL_DEC_BASIC_INFO:
		printf( "JXL_DEC_BASIC_INFO\n" );
		break;

	case JXL_DEC_EXTENSIONS:
		printf( "JXL_DEC_EXTENSIONS\n" );
		break;

	case JXL_DEC_COLOR_ENCODING:
		printf( "JXL_DEC_COLOR_ENCODING\n" );
		break;

	case JXL_DEC_PREVIEW_IMAGE:
		printf( "JXL_DEC_PREVIEW_IMAGE\n" );
		break;

	case JXL_DEC_FRAME:
		printf( "JXL_DEC_FRAME\n" );
		break;

	case JXL_DEC_DC_IMAGE:
		printf( "JXL_DEC_DC_IMAGE\n" );
		break;

	case JXL_DEC_FULL_IMAGE:
		printf( "JXL_DEC_FULL_IMAGE\n" );
		break;

	case JXL_DEC_JPEG_RECONSTRUCTION:
		printf( "JXL_DEC_JPEG_RECONSTRUCTION\n" );
		break;

	default:
		g_assert_not_reached();
	}
}

static JxlDecoderStatus 
vips_foreign_load_jxl_process( VipsForeignLoadJxl *jxl )
{
	JxlDecoderStatus status;

	while( (status = JxlDecoderProcessInput( jx->decoder )) == 
		JXL_DEC_NEED_MORE_INPUT ) {
		size_t bytes_remaining;

		bytes_remaining = JxlDecoderReleaseInput( jxl->decoder );
		if( vips_foreign_load_jxl_fill_input( jxl, bytes_remaining ) )
			return( JXL_DEC_ERROR );
		JxlDecoderSetInput( jxl->decoder,
			jxl->input_buffer, jxl->bytes_remaining );
	}

	printf( "vips_foreign_load_jxl_process: seen " );
	vips_foreign_load_jxl_print_status( status );

	return( status );
}


static int
vips_foreign_load_jxl_header( VipsForeignLoad *load )
{
	VipsObjectClass *klass = VIPS_OBJECT_GET_CLASS( load );
	VipsForeignLoadJxl *jxl = (VipsForeignLoadJxl *) load;

#ifdef DEBUG
	printf( "vips_foreign_load_jxl_header:\n" );
#endif /*DEBUG*/

	if( vips_foreign_load_jxl_fill_input( jxl, 0 ) )
		return( -1 );
	JxlDecoderSetInput( jx->decoder, 
		jxl->input_buffer, jxl->bytes_remaining );

	/* Read to the end of the header.
	 */
	do {
		JxlDecoderStatus status;

		status = vips_foreign_load_jxl_process( jxl );
		if( status == JXL_DEC_ERROR )
			return( -1 );
	} while( status != JXL_DEC_COLOR_ENCODING );

	JxlDecoderGetBasicInfo( jxl->decoder, &jxl->info );


	jxl->format = vips_foreign_load_jxl_get_format( jxl->source );
	vips_source_rewind( jxl->source );
	if( !(jxl->codec = opj_create_decompress( jxl->format )) )
		return( -1 );

	vips_foreign_load_jxl_attach_handlers( jxl, jxl->codec );

	jxl->shrink = 1 << jxl->page;
	jxl->parameters.cp_reduce = jxl->page;
	if( !opj_setup_decoder( jxl->codec, &jxl->parameters ) ) 
		return( -1 );

#ifdef HAVE_LIBJXL_THREADING
	/* Use eg. VIPS_CONCURRENCY etc. to set n-cpus, if this openjpeg has
	 * stable support. 
	 */
	opj_codec_set_threads( jxl->codec, vips_concurrency_get() );
#endif /*HAVE_LIBJXL_THREADING*/

	if( !opj_read_header( jxl->stream, jxl->codec, &jxl->image ) )
		return( -1 );
	if( !(jxl->info = opj_get_cstr_info( jxl->codec )) )
		return( -1 );

#ifdef DEBUG
	vips_foreign_load_jxl_print( jxl );
#endif /*DEBUG*/

	/* We only allow images where all components have the same format.
	 */
	if( jxl->image->numcomps > MAX_BANDS ) {
		vips_error( klass->nickname, 
			"%s", _( "too many image bands" ) );
		return( -1 );
	}
	if( jxl->image->numcomps == 0 ) {
		vips_error( klass->nickname, 
			"%s", _( "no image components" ) );
		return( -1 );
	}
	first = &jxl->image->comps[0];
	for( i = 1; i < jxl->image->numcomps; i++ ) {
		opj_image_comp_t *this = &jxl->image->comps[i];

		if( this->x0 != first->x0 ||
			this->y0 != first->y0 ||
			this->w * this->dx != first->w * first->dx ||
			this->h * this->dy != first->h * first->dy ||
			this->resno_decoded != first->resno_decoded ||
			this->factor != first->factor ) {
			vips_error( klass->nickname, 
				"%s", _( "components differ in geometry" ) );
			return( -1 );
		}

		if( this->prec != first->prec ||
			this->bpp != first->bpp ||
			this->sgnd != first->sgnd ) {
			vips_error( klass->nickname, 
				"%s", _( "components differ in precision" ) );
			return( -1 );
		}

		/* If dx/dy are not 1, we'll need to upsample components during
		 * tile packing.
		 */
		if( this->dx != first->dx ||
			this->dy != first->dy ||
			first->dx != 1 ||
			first->dy != 1 )
			jxl->upsample = TRUE;
	}

	if( vips_foreign_load_jxl_set_header( jxl, load->out ) ) 
		return( -1 );

	VIPS_SETSTR( load->out->filename, 
		vips_connection_filename( VIPS_CONNECTION( jxl->source ) ) );

	return( 0 );
}

#define PACK( TYPE ) { \
	TYPE *tq = (TYPE *) q; \
	\
	for( x = 0; x < length; x++ ) { \
		for( i = 0; i < b; i++ ) \
			tq[i] = planes[i][x]; \
		\
		tq += b; \
	} \
}

#define PACK_UPSAMPLE( TYPE ) { \
	TYPE *tq = (TYPE *) q; \
	\
	for( x = 0; x < length; x++ ) { \
		for( i = 0; i < b; i++ ) { \
			int dx = jxl->image->comps[i].dx; \
			int pixel = planes[i][x / dx]; \
			\
			tq[i] = pixel; \
		} \
		\
		tq += b; \
	} \
}

/* Pack the set of openjpeg components into a libvips region. left/top are the
 * offsets into the tile in pixel coordinates where we should start reading.
 */
static void
vips_foreign_load_jxl_pack( VipsForeignLoadJxl *jxl, 
	VipsImage *image, VipsPel *q, 
	int left, int top, int length )
{
	int *planes[MAX_BANDS];
	int b = jxl->image->numcomps;

	int x, i;

	for( i = 0; i < b; i++ ) {
		opj_image_comp_t *comp = &jxl->image->comps[i];

		planes[i] = comp->data + (top / comp->dy) * comp->w + 
			(left / comp->dx);
	}

	if( jxl->upsample ) 
		switch( image->BandFmt ) {
		case VIPS_FORMAT_CHAR:
		case VIPS_FORMAT_UCHAR:
			PACK_UPSAMPLE( unsigned char );
			break;

		case VIPS_FORMAT_SHORT:
		case VIPS_FORMAT_USHORT:
			PACK_UPSAMPLE( unsigned short );
			break;

		case VIPS_FORMAT_INT:
		case VIPS_FORMAT_UINT:
			PACK_UPSAMPLE( unsigned int );
			break;

		default:
			g_assert_not_reached();
			break;
		}
	else 
		/* Fast no-upsample path.
		 */
		switch( image->BandFmt ) {
		case VIPS_FORMAT_CHAR:
		case VIPS_FORMAT_UCHAR:
			PACK( unsigned char );
			break;

		case VIPS_FORMAT_SHORT:
		case VIPS_FORMAT_USHORT:
			PACK( unsigned short );
			break;

		case VIPS_FORMAT_INT:
		case VIPS_FORMAT_UINT:
			PACK( unsigned int );
			break;

		default:
			g_assert_not_reached();
			break;
		}
}

/* ycc->rgb coversion adapted from openjpeg src/bin/common/color.c
 *
 * See also https://en.wikipedia.org/wiki/YCbCr#JPEG_conversion
 */
#define YCC_TO_RGB( TYPE ) { \
	TYPE *tq = (TYPE *) q; \
	\
	for( x = 0; x < length; x++ ) { \
		int y = tq[0]; \
		int cb = tq[1] - offset; \
		int cr = tq[2] - offset; \
		\
		int r, g, b; \
		\
		r = y + (int)(1.402 * (float)cr); \
		tq[0] = VIPS_CLIP( 0, r, upb ); \
		\
		g = y - (int)(0.344 * (float)cb + 0.714 * (float)cr); \
		tq[1] = VIPS_CLIP( 0, g, upb ); \
		\
		b = y + (int)(1.772 * (float)cb); \
		tq[2] = VIPS_CLIP( 0, b, upb ); \
		\
		tq += 3; \
	} \
}

/* YCC->RGB for a line of pels.
 */
static void
vips_foreign_load_jxl_ycc_to_rgb( VipsForeignLoadJxl *jxl, 
	VipsPel *q, int length )
{
	VipsForeignLoad *load = (VipsForeignLoad *) jxl;
	int prec = jxl->image->comps[0].prec;
	int offset = 1 << (prec - 1);
	int upb = (1 << prec) - 1;

	int x;

	switch( load->out->BandFmt ) {
	case VIPS_FORMAT_CHAR:
	case VIPS_FORMAT_UCHAR:
		YCC_TO_RGB( unsigned char );
		break;

	case VIPS_FORMAT_SHORT:
	case VIPS_FORMAT_USHORT:
		YCC_TO_RGB( unsigned short );
		break;

	case VIPS_FORMAT_INT:
	case VIPS_FORMAT_UINT:
		YCC_TO_RGB( unsigned int );
		break;

	default:
		g_assert_not_reached();
		break;
	}
}

/* Loop over the output region, painting in tiles from the file.
 */
static int
vips_foreign_load_jxl_generate( VipsRegion *out, 
	void *seq, void *a, void *b, gboolean *stop )
{
	VipsForeignLoad *load = (VipsForeignLoad *) a;
	VipsForeignLoadJxl *jxl = (VipsForeignLoadJxl *) load;
	VipsRect *r = &out->valid;

	/* jxl get smaller with the layer size.
	 */
	int tile_width = VIPS_ROUND_UINT( 
		(double) jxl->info->tdx / jxl->shrink );
	int tile_height = VIPS_ROUND_UINT( 
		(double) jxl->info->tdy / jxl->shrink );

	/* ... so tiles_across is always the same.
	 */
	int tiles_across = jxl->info->tw;

	int x, y, z;

#ifdef DEBUG_VERBOSE
	printf( "vips_foreign_load_jxl_generate: "
		"left = %d, top = %d, width = %d, height = %d\n", 
		r->left, r->top, r->width, r->height ); 
#endif /*DEBUG_VERBOSE*/

	/* If openjpeg has flagged an error, the library is not in a known
	 * state and it's not safe to call again.
	 */
	if( jxl->n_errors )
		return( 0 );

	y = 0;
	while( y < r->height ) {
		VipsRect tile, hit;

		/* Not necessary, but it stops static analyzers complaining
		 * about a used-before-set.
		 */
		hit.height = 0;

		x = 0;
		while( x < r->width ) { 
			/* Tile the xy falls in, in tile numbers.
			 */
			int tx = (r->left + x) / tile_width;
			int ty = (r->top + y) / tile_height;

			/* Pixel coordinates of the tile that xy falls in.
			 */
			int xs = tx * tile_width;
			int ys = ty * tile_height;

			int tile_index = ty * tiles_across + tx;

			/* Fetch the tile.
			 */
#ifdef DEBUG_VERBOSE
			printf( "   fetch tile %d\n", tile_index );
#endif /*DEBUG_VERBOSE*/
			if( !opj_get_decoded_tile( jxl->codec, 
				jxl->stream, jxl->image, tile_index ) )
				return( -1 );

			/* Intersect tile with request to get pixels we need
			 * to copy out.
			 */
			tile.left = xs;
			tile.top = ys;
			tile.width = tile_width;
			tile.height = tile_height;
			vips_rect_intersectrect( &tile, r, &hit );

			/* Unpack hit pixels to buffer in vips layout. 
			 */
			for( z = 0; z < hit.height; z++ ) {
				VipsPel *q = VIPS_REGION_ADDR( out, 
					hit.left, hit.top + z );

				vips_foreign_load_jxl_pack( jxl,
					out->im, q,
					hit.left - tile.left,
					hit.top - tile.top + z,
					hit.width ); 

				if( jxl->ycc_to_rgb )
					vips_foreign_load_jxl_ycc_to_rgb( jxl,
						q, hit.width );
			}

			x += hit.width;
		}

		/* This will be the same for all tiles in the row we've just
		 * done.
		 */
		y += hit.height;
	}

	if( load->fail &&
		jxl->n_errors > 0 ) 
		return( -1 );

	return( 0 );
}

static int
vips_foreign_load_jxl_load( VipsForeignLoad *load )
{
	VipsForeignLoadJxl *jxl = (VipsForeignLoadJxl *) load;

	/* jxl tiles get smaller with the layer size, but we don't want tiny
	 * tiles for the libvips tile cache, so leave them at the base size.
	 */
	int tile_width = jxl->info->tdx;
	int tile_height = jxl->info->tdy;
	int tiles_across = jxl->info->tw;

	VipsImage **t = (VipsImage **) 
		vips_object_local_array( VIPS_OBJECT( load ), 3 );

#ifdef DEBUG
	printf( "vips_foreign_load_jxl_load:\n" );
#endif /*DEBUG*/

	t[0] = vips_image_new();
	if( vips_foreign_load_jxl_set_header( jxl, t[0] ) ) 
		return( -1 );

	if( vips_image_generate( t[0], 
		NULL, vips_foreign_load_jxl_generate, NULL, jxl, NULL ) )
		return( -1 );

	/* Copy to out, adding a cache. Enough tiles for two complete 
	 * rows, plus 50%.
	 */
	if( vips_tilecache( t[0], &t[1], 
		"tile_width", tile_width,
		"tile_height", tile_height,
		"max_tiles", 3 * tiles_across,
		NULL ) ) 
		return( -1 );
	if( vips_image_write( t[1], load->real ) ) 
		return( -1 );

	return( 0 );
}

static void
vips_foreign_load_jxl_class_init( VipsForeignLoadJxlClass *klass )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( klass );
	VipsObjectClass *object_class = (VipsObjectClass *) klass;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) klass;

	gobject_class->dispose = vips_foreign_load_jxl_dispose;
	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "jxlload_base";
	object_class->description = _( "load JPEG2000 image" );
	object_class->build = vips_foreign_load_jxl_build;

	load_class->get_flags = vips_foreign_load_jxl_get_flags;
	load_class->header = vips_foreign_load_jxl_header;
	load_class->load = vips_foreign_load_jxl_load;

	VIPS_ARG_INT( klass, "page", 20, 
		_( "Page" ), 
		_( "Load this page from the image" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignLoadJxl, page ),
		0, 100000, 0 );

}

static void
vips_foreign_load_jxl_init( VipsForeignLoadJxl *jxl )
{
}

typedef struct _VipsForeignLoadJxlFile {
	VipsForeignLoadJxl parent_object;

	/* Filename for load.
	 */
	char *filename; 

} VipsForeignLoadJxlFile;

typedef VipsForeignLoadJxlClass VipsForeignLoadJxlFileClass;

/* We need C linkage for this.
 */
extern "C" {
G_DEFINE_TYPE( VipsForeignLoadJxlFile, vips_foreign_load_jxl_file, 
	vips_foreign_load_jxl_get_type() );
}

static int
vips_foreign_load_jxl_file_build( VipsObject *object )
{
	VipsForeignLoadJxl *jxl = (VipsForeignLoadJxl *) object;
	VipsForeignLoadJxlFile *file = (VipsForeignLoadJxlFile *) object;

	if( file->filename &&
		!(jxl->source = vips_source_new_from_file( file->filename )) )
		return( -1 );

	if( VIPS_OBJECT_CLASS( vips_foreign_load_jxl_file_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

const char *vips__jxl_suffs[] = 
	{ ".j2k", ".jp2", ".jpt", ".j2c", ".jpc", NULL };

static int
vips_foreign_load_jxl_is_a( const char *filename )
{
	VipsSource *source;
	gboolean result;

	if( !(source = vips_source_new_from_file( filename )) )
		return( FALSE );
	result = vips_foreign_load_jxl_is_a_source( source );
	VIPS_UNREF( source );

	return( result );
}

static void
vips_foreign_load_jxl_file_class_init( 
	VipsForeignLoadJxlFileClass *klass )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( klass );
	VipsObjectClass *object_class = (VipsObjectClass *) klass;
	VipsForeignClass *foreign_class = (VipsForeignClass *) klass;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) klass;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "jxlload";
	object_class->build = vips_foreign_load_jxl_file_build;

	foreign_class->suffs = vips__jxl_suffs;

	load_class->is_a = vips_foreign_load_jxl_is_a;

	VIPS_ARG_STRING( klass, "filename", 1, 
		_( "Filename" ),
		_( "Filename to load from" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignLoadJxlFile, filename ),
		NULL );

}

static void
vips_foreign_load_jxl_file_init( VipsForeignLoadJxlFile *jxl )
{
}

typedef struct _VipsForeignLoadJxlBuffer {
	VipsForeignLoadJxl parent_object;

	/* Load from a buffer.
	 */
	VipsArea *buf;

} VipsForeignLoadJxlBuffer;

typedef VipsForeignLoadJxlClass VipsForeignLoadJxlBufferClass;

/* We need C linkage for this.
 */
extern "C" {
G_DEFINE_TYPE( VipsForeignLoadJxlBuffer, vips_foreign_load_jxl_buffer, 
	vips_foreign_load_jxl_get_type() );
}

static int
vips_foreign_load_jxl_buffer_build( VipsObject *object )
{
	VipsForeignLoadJxl *jxl = (VipsForeignLoadJxl *) object;
	VipsForeignLoadJxlBuffer *buffer = 
		(VipsForeignLoadJxlBuffer *) object;

	if( buffer->buf )
		if( !(jxl->source = vips_source_new_from_memory( 
			VIPS_AREA( buffer->buf )->data, 
			VIPS_AREA( buffer->buf )->length )) )
			return( -1 );

	if( VIPS_OBJECT_CLASS( vips_foreign_load_jxl_file_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

static gboolean
vips_foreign_load_jxl_buffer_is_a( const void *buf, size_t len )
{
	VipsSource *source;
	gboolean result;

	if( !(source = vips_source_new_from_memory( buf, len )) )
		return( FALSE );
	result = vips_foreign_load_jxl_is_a_source( source );
	VIPS_UNREF( source );

	return( result );
}

static void
vips_foreign_load_jxl_buffer_class_init( 
	VipsForeignLoadJxlBufferClass *klass )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( klass );
	VipsObjectClass *object_class = (VipsObjectClass *) klass;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) klass;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "jxlload_buffer";
	object_class->build = vips_foreign_load_jxl_buffer_build;

	load_class->is_a_buffer = vips_foreign_load_jxl_buffer_is_a;

	VIPS_ARG_BOXED( klass, "buffer", 1, 
		_( "Buffer" ),
		_( "Buffer to load from" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignLoadJxlBuffer, buf ),
		VIPS_TYPE_BLOB );

}

static void
vips_foreign_load_jxl_buffer_init( VipsForeignLoadJxlBuffer *buffer )
{
}

typedef struct _VipsForeignLoadJxlSource {
	VipsForeignLoadJxl parent_object;

	/* Load from a source.
	 */
	VipsSource *source;

} VipsForeignLoadJxlSource;

typedef VipsForeignLoadJxlClass VipsForeignLoadJxlSourceClass;

/* We need C linkage for this.
 */
extern "C" {
G_DEFINE_TYPE( VipsForeignLoadJxlSource, vips_foreign_load_jxl_source, 
	vips_foreign_load_jxl_get_type() );
}

static int
vips_foreign_load_jxl_source_build( VipsObject *object )
{
	VipsForeignLoadJxl *jxl = (VipsForeignLoadJxl *) object;
	VipsForeignLoadJxlSource *source = 
		(VipsForeignLoadJxlSource *) object;

	if( source->source ) {
		jxl->source = source->source;
		g_object_ref( jxl->source );
	}

	if( VIPS_OBJECT_CLASS( 
		vips_foreign_load_jxl_source_parent_class )->
			build( object ) )
		return( -1 );

	return( 0 );
}

static void
vips_foreign_load_jxl_source_class_init( 
	VipsForeignLoadJxlSourceClass *klass )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( klass );
	VipsObjectClass *object_class = (VipsObjectClass *) klass;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) klass;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "jxlload_source";
	object_class->build = vips_foreign_load_jxl_source_build;

	load_class->is_a_source = vips_foreign_load_jxl_is_a_source;

	VIPS_ARG_OBJECT( klass, "source", 1,
		_( "Source" ),
		_( "Source to load from" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignLoadJxlSource, source ),
		VIPS_TYPE_SOURCE );

}

static void
vips_foreign_load_jxl_source_init( 
	VipsForeignLoadJxlSource *jxl )
{
}

#endif /*HAVE_LIBJXL*/

/**
 * vips_jxlload:
 * @filename: file to load
 * @out: (out): decompressed image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @page: %gint, load this page
 *
 * Read a JPEG2000 image. The loader supports 8, 16 and 32-bit int pixel
 * values, signed and unsigned. 
 * It supports greyscale, RGB, YCC, CMYK and
 * multispectral colour spaces. 
 * It will read any ICC profile on
 * the image. 
 *
 * It will only load images where all channels are the same format.
 *
 * Use @page to set the page to load, where page 0 is the base resolution
 * image and higher-numbered pages are x2 reductions. Use the metadata item
 * "n-pages" to find the number of pyramid layers.
 *
 * See also: vips_image_new_from_file().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_jxlload( const char *filename, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "jxlload", ap, filename, out );
	va_end( ap );

	return( result );
}

/**
 * vips_jxlload_buffer:
 * @buf: (array length=len) (element-type guint8): memory area to load
 * @len: (type gsize): size of memory area
 * @out: (out): image to write
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @page: %gint, load this page
 *
 * Exactly as vips_jxlload(), but read from a source. 
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_jxlload_buffer( void *buf, size_t len, VipsImage **out, ... )
{
	va_list ap;
	VipsBlob *blob;
	int result;

	/* We don't take a copy of the data or free it.
	 */
	blob = vips_blob_new( NULL, buf, len );

	va_start( ap, out );
	result = vips_call_split( "jxlload_buffer", ap, blob, out );
	va_end( ap );

	vips_area_unref( VIPS_AREA( blob ) );

	return( result );
}

/**
 * vips_jxlload_source:
 * @source: source to load from
 * @out: (out): decompressed image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @page: %gint, load this page
 *
 * Exactly as vips_jxlload(), but read from a source. 
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_jxlload_source( VipsSource *source, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "jxlload_source", ap, source, out );
	va_end( ap );

	return( result );
}
