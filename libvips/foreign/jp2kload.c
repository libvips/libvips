/* load jpeg2000
 *
 * 18/3/20
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
#include <vips/debug.h>
#include <vips/internal.h>

#ifdef HAVE_LIBOPENJP2

#include <openjpeg.h>

#include "pforeign.h"

/* Surely enough ... does anyone do multispectral imaging with jp2k?
 */
#define MAX_BANDS (100)

typedef struct _VipsForeignLoadJp2k {
	VipsForeignLoad parent_object;

	/* Source to load from (set by subclasses).
	 */
	VipsSource *source;

	/* Page set by user, then we translate that into shrink factor.
	 */
	int page;
	int shrink;

	/* Decompress state.
	 */
        opj_stream_t *stream;		/* Source as an opj stream */
	OPJ_CODEC_FORMAT format;	/* libopenjp2 format */
        opj_codec_t *codec;		/* Decompress codec */
	opj_dparameters_t parameters;	/* Core decompress params */
	opj_image_t *image;		/* Read image to here */ 
	opj_codestream_info_v2_t *info;	/* Tile geometry */

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
} VipsForeignLoadJp2k;

typedef VipsForeignLoadClass VipsForeignLoadJp2kClass;

G_DEFINE_ABSTRACT_TYPE( VipsForeignLoadJp2k, vips_foreign_load_jp2k, 
	VIPS_TYPE_FOREIGN_LOAD );

static void
vips_foreign_load_jp2k_dispose( GObject *gobject )
{
	VipsForeignLoadJp2k *jp2k = (VipsForeignLoadJp2k *) gobject;

#ifdef DEBUG
	printf( "vips_foreign_load_jp2k_dispose:\n" );
#endif /*DEBUG*/

	/*
	 * FIXME ... do we need this? seems to just cause warnings
	 *
	if( jp2k->codec &&
		jp2k->stream ) 
		opj_end_decompress( jp2k->codec, jp2k->stream );
	 *
	 */

	if( jp2k->info )
		opj_destroy_cstr_info( &jp2k->info );
	VIPS_FREEF( opj_destroy_codec, jp2k->codec );
	VIPS_FREEF( opj_stream_destroy, jp2k->stream );
	VIPS_FREEF( opj_image_destroy, jp2k->image );
	VIPS_UNREF( jp2k->source );

	G_OBJECT_CLASS( vips_foreign_load_jp2k_parent_class )->
		dispose( gobject );
}

static OPJ_SIZE_T
vips_foreign_load_jp2k_read_source( void *buffer, size_t length, void *client )
{
	VipsSource *source = VIPS_SOURCE( client );
	gint64 bytes_read = vips_source_read( source, buffer, length );

	/* openjpeg read uses -1 for both EOF and error return.
	 */
	return( bytes_read == 0 ? -1 : bytes_read );
}

static OPJ_OFF_T
vips_foreign_load_jp2k_skip_source( OPJ_OFF_T n_bytes, void *client )
{
	VipsSource *source = VIPS_SOURCE( client );

	if( vips_source_seek( source, n_bytes, SEEK_CUR ) == -1 )
		/* openjpeg skip uses -1 for both end of stream and error.
		 */
		return( -1 );

	return( n_bytes );
}

static OPJ_BOOL
vips_foreign_load_jp2k_seek_source( OPJ_OFF_T position, void *client )
{
	VipsSource *source = VIPS_SOURCE( client );

	if( vips_source_seek( source, position, SEEK_SET ) == -1 )
		/* openjpeg seek uses FALSE for both end of stream and error.
		 */
		return( OPJ_FALSE );

	return( OPJ_TRUE );
}

/* Make a libopenjp2 stream that wraps a VipsSource.
 */
static opj_stream_t *
vips_foreign_load_jp2k_stream( VipsSource *source )
{
	opj_stream_t *stream;

	/* TRUE means a read stream.
	 */
	if( !(stream = opj_stream_create( OPJ_J2K_STREAM_CHUNK_SIZE, TRUE )) ) 
		return( NULL );

	opj_stream_set_user_data( stream, source, NULL );
	/* Unfortunately, jp2k requires the length, so pipe sources will have
	 * to buffer in memory.
	 */
	opj_stream_set_user_data_length( stream,
		vips_source_length( source ) );
	opj_stream_set_read_function( stream, 
		vips_foreign_load_jp2k_read_source );
	opj_stream_set_skip_function( stream, 
		vips_foreign_load_jp2k_skip_source );
	opj_stream_set_seek_function( stream, 
		vips_foreign_load_jp2k_seek_source );

	return( stream );
}

static int
vips_foreign_load_jp2k_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsForeignLoadJp2k *jp2k = (VipsForeignLoadJp2k *) object;

#ifdef DEBUG
	printf( "vips_foreign_load_jp2k_build:\n" );
#endif /*DEBUG*/

	/* Default parameters.
	 */
        jp2k->parameters.decod_format = -1;
        jp2k->parameters.cod_format = -1;
        opj_set_default_decoder_parameters( &jp2k->parameters );

	/* Link the openjpeg stream to our VipsSource.
	 */
	if( jp2k->source ) {
		jp2k->stream = vips_foreign_load_jp2k_stream( jp2k->source );
		if( !jp2k->stream ) {
			vips_error( class->nickname, 
				"%s", _( "unable to create jp2k stream" ) );
			return( -1 );
		}
	}

	if( VIPS_OBJECT_CLASS( vips_foreign_load_jp2k_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

#define JP2_RFC3745_MAGIC "\x00\x00\x00\x0c\x6a\x50\x20\x20\x0d\x0a\x87\x0a"
#define JP2_MAGIC "\x0d\x0a\x87\x0a"
/* position 45: "\xff\x52" */
#define J2K_CODESTREAM_MAGIC "\xff\x4f\xff\x51"

/* Return the image format. OpenJPEG supports several different image types.
 */
static OPJ_CODEC_FORMAT
vips_foreign_load_jp2k_get_format( VipsSource *source )
{
	unsigned char *data;

	if( vips_source_sniff_at_most( source, &data, 12 ) < 12 )
		return( -1 );

	/* There's also OPJ_CODEC_JPT for xxx.jpt files, but we don't support
	 * that.
	 */
	if( memcmp( data, JP2_RFC3745_MAGIC, 12) == 0 || 
		memcmp( data, JP2_MAGIC, 4 ) == 0 ) 
		return( OPJ_CODEC_JP2 );
	else if( memcmp( data, J2K_CODESTREAM_MAGIC, 4 ) == 0 )
		return( OPJ_CODEC_J2K );
	else
		return( -1 );
}

static gboolean
vips_foreign_load_jp2k_is_a_source( VipsSource *source )
{
	return( vips_foreign_load_jp2k_get_format( source ) != -1 ); 
}

static VipsForeignFlags
vips_foreign_load_jp2k_get_flags( VipsForeignLoad *load )
{
	return( VIPS_FOREIGN_PARTIAL );
}

static void 
vips_foreign_load_jp2k_error_callback( const char *msg, void *client )
{
	VipsForeignLoadJp2k *jp2k = (VipsForeignLoadJp2k *) client;
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( jp2k );

	vips_error( class->nickname, "%s", msg ); 
	jp2k->n_errors += 1;
}

/* The openjpeg info and warning callbacks are incredibly chatty.
 */
static void 
vips_foreign_load_jp2k_warning_callback( const char *msg, void *client )
{
#ifdef DEBUG
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( client );

	g_warning( "%s: %s",  class->nickname, msg );
#endif /*DEBUG*/
}

/* The openjpeg info and warning callbacks are incredibly chatty.
 */
static void 
vips_foreign_load_jp2k_info_callback( const char *msg, void *client )
{
#ifdef DEBUG
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( client );

	g_info( "%s: %s",  class->nickname, msg );
#endif /*DEBUG*/
}

static void
vips_foreign_load_jp2k_attach_handlers( VipsForeignLoadJp2k *jp2k,
	opj_codec_t *codec )
{
	opj_set_info_handler( codec, 
		vips_foreign_load_jp2k_info_callback, jp2k );
	opj_set_warning_handler( codec, 
		vips_foreign_load_jp2k_warning_callback, jp2k );
	opj_set_error_handler( codec, 
		vips_foreign_load_jp2k_error_callback, jp2k );
}

#ifdef DEBUG
static void
vips_foreign_load_jp2k_print_image( opj_image_t *image )
{
	printf( "image:\n" );
	printf( "x0 = %u, y0 = %u, x1 = %u, y1 = %u, numcomps = %u, "
		"color_space = %u\n",
		image->x0, image->y0, image->x1, image->y1, 
		image->numcomps, image->color_space ); 
	printf( "icc_profile_buf = %p, icc_profile_len = %x\n", 
		image->icc_profile_buf, image->icc_profile_len ); 
}

static void
vips_foreign_load_jp2k_print( VipsForeignLoadJp2k *jp2k )
{
	int i;

	vips_foreign_load_jp2k_print_image( jp2k->image );

	printf( "components:\n" );
	for( i = 0; i < jp2k->image->numcomps; i++ ) {
		opj_image_comp_t *this = &jp2k->image->comps[i];

		printf( "%i) dx = %u, dy = %u, w = %u, h = %u, "
			"x0 = %u, y0 = %u\n", 
			i, this->dx, this->dy, this->w, this->h, 
			this->x0, this->y0 );
		printf( "    prec = %x, bpp = %x, sgnd = %x, "
			"resno_decoded = %u, factor = %u\n",
			this->prec, this->bpp, this->sgnd, 
			this->resno_decoded, this->factor );
		printf( "    data = %p, alpha = %u\n",
			this->data, this->alpha );
	}

	printf( "info:\n" );
	printf( "tx0 = %u, ty0 = %d, tdx = %u, tdy = %u, tw = %u, th = %u\n",
		jp2k->info->tx0, jp2k->info->ty0, 
		jp2k->info->tdx, jp2k->info->tdy, 
		jp2k->info->tw, jp2k->info->th );
	printf( "nbcomps = %u, tile_info = %p\n", 
		jp2k->info->nbcomps, jp2k->info->tile_info );
}
#endif /*DEBUG*/

static int
vips_foreign_load_jp2k_set_header( VipsForeignLoadJp2k *jp2k, VipsImage *out )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( jp2k );
	opj_image_comp_t *first = &jp2k->image->comps[0];

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

	switch( jp2k->image->color_space ) {
	case OPJ_CLRSPC_SYCC:
	case OPJ_CLRSPC_EYCC:
		/* Map these to RGB.
		 */
		interpretation = vips_format_sizeof( format ) == 1 ? 
			VIPS_INTERPRETATION_sRGB :
			VIPS_INTERPRETATION_RGB16;
		jp2k->ycc_to_rgb = TRUE;
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
		if( jp2k->image->numcomps < 3 )
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
		if( jp2k->image->numcomps == 3 &&
			jp2k->image->comps[0].dx == 1 &&
			jp2k->image->comps[0].dy == 1 &&
			jp2k->image->comps[1].dx > 1 &&
			jp2k->image->comps[1].dy > 1 &&
			jp2k->image->comps[2].dx > 1 &&
			jp2k->image->comps[2].dy > 1)
			jp2k->ycc_to_rgb = TRUE;

		break;

	default:
		vips_error( class->nickname, 
			_( "unsupported colourspace %d" ), 
			jp2k->image->color_space );
		return( -1 );
	}

	/* Even though this is a tiled reader, we hint thinstrip since with
	 * the cache we are quite happy serving that if anything downstream 
	 * would like it.
	 */
        vips_image_pipelinev( out, VIPS_DEMAND_STYLE_THINSTRIP, NULL );

	vips_image_init_fields( out,
		first->w, first->h, jp2k->image->numcomps, format, 
		VIPS_CODING_NONE, interpretation, 1.0, 1.0 );

	/* openjpeg allows left and top of the coordinate grid to be
	 * non-zero. These are always in unshrunk coordinates.
	 */
	out->Xoffset = 
		-VIPS_ROUND_INT( (double) jp2k->image->x0 / jp2k->shrink );
	out->Yoffset = 
		-VIPS_ROUND_INT( (double) jp2k->image->y0 / jp2k->shrink );

	if( jp2k->image->icc_profile_buf &&
		jp2k->image->icc_profile_len > 0 )
		vips_image_set_blob_copy( out, VIPS_META_ICC_NAME, 
			jp2k->image->icc_profile_buf,
			jp2k->image->icc_profile_len );

	/* Map number of layers in image to pages. 
	 */
	if( jp2k->info &&
		jp2k->info->m_default_tile_info.tccp_info )
		vips_image_set_int( out, VIPS_META_N_PAGES, 
			jp2k->info->m_default_tile_info.tccp_info->
				numresolutions );

	return( 0 );
}

static int
vips_foreign_load_jp2k_header( VipsForeignLoad *load )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( load );
	VipsForeignLoadJp2k *jp2k = (VipsForeignLoadJp2k *) load;

	opj_image_comp_t *first;
	int i;

#ifdef DEBUG
	printf( "vips_foreign_load_jp2k_header:\n" );
#endif /*DEBUG*/

	jp2k->format = vips_foreign_load_jp2k_get_format( jp2k->source );
	vips_source_rewind( jp2k->source );
	if( !(jp2k->codec = opj_create_decompress( jp2k->format )) )
		return( -1 );

	vips_foreign_load_jp2k_attach_handlers( jp2k, jp2k->codec );

	jp2k->shrink = 1 << jp2k->page;
	jp2k->parameters.cp_reduce = jp2k->page;
	if( !opj_setup_decoder( jp2k->codec, &jp2k->parameters ) ) 
		return( -1 );

	opj_codec_set_threads( jp2k->codec, vips_concurrency_get() );

	if( !opj_read_header( jp2k->stream, jp2k->codec, &jp2k->image ) )
		return( -1 );
	if( !(jp2k->info = opj_get_cstr_info( jp2k->codec )) )
		return( -1 );

#ifdef DEBUG
	vips_foreign_load_jp2k_print( jp2k );
#endif /*DEBUG*/

	/* We only allow images where all components have the same format.
	 */
	if( jp2k->image->numcomps > MAX_BANDS ) {
		vips_error( class->nickname, 
			"%s", _( "too many image bands" ) );
		return( -1 );
	}
	if( jp2k->image->numcomps == 0 ) {
		vips_error( class->nickname, 
			"%s", _( "no image components" ) );
		return( -1 );
	}
	first = &jp2k->image->comps[0];
	for( i = 1; i < jp2k->image->numcomps; i++ ) {
		opj_image_comp_t *this = &jp2k->image->comps[i];

		if( this->x0 != first->x0 ||
			this->y0 != first->y0 ||
			this->w * this->dx != first->w * first->dx ||
			this->h * this->dy != first->h * first->dy ||
			this->resno_decoded != first->resno_decoded ||
			this->factor != first->factor ) {
			vips_error( class->nickname, 
				"%s", _( "components differ in geometry" ) );
			return( -1 );
		}

		if( this->prec != first->prec ||
			this->bpp != first->bpp ||
			this->sgnd != first->sgnd ) {
			vips_error( class->nickname, 
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
			jp2k->upsample = TRUE;
	}

	if( vips_foreign_load_jp2k_set_header( jp2k, load->out ) ) 
		return( -1 );

	VIPS_SETSTR( load->out->filename, 
		vips_connection_filename( VIPS_CONNECTION( jp2k->source ) ) );

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
			int dx = image->comps[i].dx; \
			int pixel = planes[i][x / dx]; \
			\
			tq[i] = pixel; \
		} \
		\
		tq += b; \
	} \
}

/* Pack a line of openjpeg pixels into libvips format. left/top are the
 * offsets into the opj image in pixel coordinates where we should start 
 * reading.
 *
 * Set upsample if any opj component is subsampled.
 */
static void
vips_foreign_load_jp2k_pack( gboolean upsample, 
	opj_image_t *image, VipsImage *im, 
	VipsPel *q, int left, int top, int length )
{
	int *planes[MAX_BANDS];
	int b = image->numcomps;

	int x, i;

#ifdef DEBUG_VERBOSE
	printf( "vips_foreign_load_jp2k_pack: "
		"upsample = %d, left = %d, top = %d, length = %d\n", 
		upsample, left, top, length ); 
#endif /*DEBUG_VERBOSE*/

	for( i = 0; i < b; i++ ) {
		opj_image_comp_t *comp = &image->comps[i];

		planes[i] = comp->data + (top / comp->dy) * comp->w + 
			(left / comp->dx);
	}

	if( upsample ) 
		switch( im->BandFmt ) {
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
		switch( im->BandFmt ) {
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
vips_foreign_load_jp2k_ycc_to_rgb( opj_image_t *image, VipsImage *im, 
	VipsPel *q, int length )
{
	int prec = image->comps[0].prec;
	int offset = 1 << (prec - 1);
	int upb = (1 << prec) - 1;

	int x;

	switch( im->BandFmt ) {
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
vips_foreign_load_jp2k_generate( VipsRegion *out, 
	void *seq, void *a, void *b, gboolean *stop )
{
	VipsForeignLoad *load = (VipsForeignLoad *) a;
	VipsForeignLoadJp2k *jp2k = (VipsForeignLoadJp2k *) load;
	VipsRect *r = &out->valid;

	/* jp2k get smaller with the layer size.
	 */
	int tile_width = VIPS_ROUND_UINT( 
		(double) jp2k->info->tdx / jp2k->shrink );
	int tile_height = VIPS_ROUND_UINT( 
		(double) jp2k->info->tdy / jp2k->shrink );

	/* ... so tiles_across is always the same.
	 */
	int tiles_across = jp2k->info->tw;

	int x, y, z;

#ifdef DEBUG_VERBOSE
	printf( "vips_foreign_load_jp2k_generate: "
		"left = %d, top = %d, width = %d, height = %d\n", 
		r->left, r->top, r->width, r->height ); 
#endif /*DEBUG_VERBOSE*/

	/* If openjpeg has flagged an error, the library is not in a known
	 * state and it's not safe to call again.
	 */
	if( jp2k->n_errors )
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
			if( !opj_get_decoded_tile( jp2k->codec, 
				jp2k->stream, jp2k->image, tile_index ) )
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

				vips_foreign_load_jp2k_pack( jp2k->upsample, 
					jp2k->image, out->im, q,
					hit.left - tile.left,
					hit.top - tile.top + z,
					hit.width ); 

				if( jp2k->ycc_to_rgb )
					vips_foreign_load_jp2k_ycc_to_rgb( 
						jp2k->image, out->im, q, 
						hit.width );
			}

			x += hit.width;
		}

		/* This will be the same for all tiles in the row we've just
		 * done.
		 */
		y += hit.height;
	}

	if( load->fail &&
		jp2k->n_errors > 0 ) 
		return( -1 );

	return( 0 );
}

static int
vips_foreign_load_jp2k_load( VipsForeignLoad *load )
{
	VipsForeignLoadJp2k *jp2k = (VipsForeignLoadJp2k *) load;

	/* jp2k tiles get smaller with the layer size, but we don't want tiny
	 * tiles for the libvips tile cache, so leave them at the base size.
	 */
	int tile_width = jp2k->info->tdx;
	int tile_height = jp2k->info->tdy;
	int tiles_across = jp2k->info->tw;

	VipsImage **t = (VipsImage **) 
		vips_object_local_array( VIPS_OBJECT( load ), 3 );

#ifdef DEBUG
	printf( "vips_foreign_load_jp2k_load:\n" );
#endif /*DEBUG*/

	t[0] = vips_image_new();
	if( vips_foreign_load_jp2k_set_header( jp2k, t[0] ) ) 
		return( -1 );

	if( vips_image_generate( t[0], 
		NULL, vips_foreign_load_jp2k_generate, NULL, jp2k, NULL ) )
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
vips_foreign_load_jp2k_class_init( VipsForeignLoadJp2kClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->dispose = vips_foreign_load_jp2k_dispose;
	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "jp2kload_base";
	object_class->description = _( "load JPEG2000 image" );
	object_class->build = vips_foreign_load_jp2k_build;

	load_class->get_flags = vips_foreign_load_jp2k_get_flags;
	load_class->header = vips_foreign_load_jp2k_header;
	load_class->load = vips_foreign_load_jp2k_load;

	VIPS_ARG_INT( class, "page", 20, 
		_( "Page" ), 
		_( "Load this page from the image" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignLoadJp2k, page ),
		0, 100000, 0 );

}

static void
vips_foreign_load_jp2k_init( VipsForeignLoadJp2k *jp2k )
{
}

typedef struct _VipsForeignLoadJp2kFile {
	VipsForeignLoadJp2k parent_object;

	/* Filename for load.
	 */
	char *filename; 

} VipsForeignLoadJp2kFile;

typedef VipsForeignLoadJp2kClass VipsForeignLoadJp2kFileClass;

G_DEFINE_TYPE( VipsForeignLoadJp2kFile, vips_foreign_load_jp2k_file, 
	vips_foreign_load_jp2k_get_type() );

static int
vips_foreign_load_jp2k_file_build( VipsObject *object )
{
	VipsForeignLoadJp2k *jp2k = (VipsForeignLoadJp2k *) object;
	VipsForeignLoadJp2kFile *file = (VipsForeignLoadJp2kFile *) object;

	if( file->filename &&
		!(jp2k->source = vips_source_new_from_file( file->filename )) )
		return( -1 );

	if( VIPS_OBJECT_CLASS( vips_foreign_load_jp2k_file_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

const char *vips__jp2k_suffs[] = 
	{ ".j2k", ".jp2", ".jpt", ".j2c", ".jpc", NULL };

static int
vips_foreign_load_jp2k_is_a( const char *filename )
{
	VipsSource *source;
	gboolean result;

	if( !(source = vips_source_new_from_file( filename )) )
		return( FALSE );
	result = vips_foreign_load_jp2k_is_a_source( source );
	VIPS_UNREF( source );

	return( result );
}

static void
vips_foreign_load_jp2k_file_class_init( 
	VipsForeignLoadJp2kFileClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "jp2kload";
	object_class->build = vips_foreign_load_jp2k_file_build;

	foreign_class->suffs = vips__jp2k_suffs;

	load_class->is_a = vips_foreign_load_jp2k_is_a;

	VIPS_ARG_STRING( class, "filename", 1, 
		_( "Filename" ),
		_( "Filename to load from" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignLoadJp2kFile, filename ),
		NULL );

}

static void
vips_foreign_load_jp2k_file_init( VipsForeignLoadJp2kFile *jp2k )
{
}

typedef struct _VipsForeignLoadJp2kBuffer {
	VipsForeignLoadJp2k parent_object;

	/* Load from a buffer.
	 */
	VipsArea *buf;

} VipsForeignLoadJp2kBuffer;

typedef VipsForeignLoadJp2kClass VipsForeignLoadJp2kBufferClass;

G_DEFINE_TYPE( VipsForeignLoadJp2kBuffer, vips_foreign_load_jp2k_buffer, 
	vips_foreign_load_jp2k_get_type() );

static int
vips_foreign_load_jp2k_buffer_build( VipsObject *object )
{
	VipsForeignLoadJp2k *jp2k = (VipsForeignLoadJp2k *) object;
	VipsForeignLoadJp2kBuffer *buffer = 
		(VipsForeignLoadJp2kBuffer *) object;

	if( buffer->buf )
		if( !(jp2k->source = vips_source_new_from_memory( 
			VIPS_AREA( buffer->buf )->data, 
			VIPS_AREA( buffer->buf )->length )) )
			return( -1 );

	if( VIPS_OBJECT_CLASS( vips_foreign_load_jp2k_file_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

static gboolean
vips_foreign_load_jp2k_buffer_is_a( const void *buf, size_t len )
{
	VipsSource *source;
	gboolean result;

	if( !(source = vips_source_new_from_memory( buf, len )) )
		return( FALSE );
	result = vips_foreign_load_jp2k_is_a_source( source );
	VIPS_UNREF( source );

	return( result );
}

static void
vips_foreign_load_jp2k_buffer_class_init( 
	VipsForeignLoadJp2kBufferClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "jp2kload_buffer";
	object_class->build = vips_foreign_load_jp2k_buffer_build;

	load_class->is_a_buffer = vips_foreign_load_jp2k_buffer_is_a;

	VIPS_ARG_BOXED( class, "buffer", 1, 
		_( "Buffer" ),
		_( "Buffer to load from" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignLoadJp2kBuffer, buf ),
		VIPS_TYPE_BLOB );

}

static void
vips_foreign_load_jp2k_buffer_init( VipsForeignLoadJp2kBuffer *buffer )
{
}

typedef struct _VipsForeignLoadJp2kSource {
	VipsForeignLoadJp2k parent_object;

	/* Load from a source.
	 */
	VipsSource *source;

} VipsForeignLoadJp2kSource;

typedef VipsForeignLoadJp2kClass VipsForeignLoadJp2kSourceClass;

G_DEFINE_TYPE( VipsForeignLoadJp2kSource, vips_foreign_load_jp2k_source, 
	vips_foreign_load_jp2k_get_type() );

static int
vips_foreign_load_jp2k_source_build( VipsObject *object )
{
	VipsForeignLoadJp2k *jp2k = (VipsForeignLoadJp2k *) object;
	VipsForeignLoadJp2kSource *source = 
		(VipsForeignLoadJp2kSource *) object;

	if( source->source ) {
		jp2k->source = source->source;
		g_object_ref( jp2k->source );
	}

	if( VIPS_OBJECT_CLASS( 
		vips_foreign_load_jp2k_source_parent_class )->
			build( object ) )
		return( -1 );

	return( 0 );
}

static void
vips_foreign_load_jp2k_source_class_init( 
	VipsForeignLoadJp2kSourceClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "jp2kload_source";
	object_class->build = vips_foreign_load_jp2k_source_build;

	load_class->is_a_source = vips_foreign_load_jp2k_is_a_source;

	VIPS_ARG_OBJECT( class, "source", 1,
		_( "Source" ),
		_( "Source to load from" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignLoadJp2kSource, source ),
		VIPS_TYPE_SOURCE );

}

static void
vips_foreign_load_jp2k_source_init( 
	VipsForeignLoadJp2kSource *jp2k )
{
}

static void 
warning_callback( const char *msg G_GNUC_UNUSED, void *data G_GNUC_UNUSED ) 
{
	/* There are a lot of warnings ...
	 */
}

static void 
error_callback( const char *msg, void *data ) 
{
	printf( "OpenJPEG: %s", msg ); 
	vips_error( "OpenJPEG", "%s", msg ); 
}

typedef struct _TileDecompress {
	VipsSource *source;
        opj_stream_t *stream;
        opj_codec_t *codec;
	opj_image_t *image;
} TileDecompress;

static void
vips__foreign_load_jp2k_decompress_free( TileDecompress *decompress )
{
	VIPS_FREEF( opj_destroy_codec, decompress->codec );
	VIPS_FREEF( opj_image_destroy, decompress->image );
	VIPS_FREEF( opj_stream_destroy, decompress->stream );
	VIPS_UNREF( decompress->source );
}

/* Called from tiff2vips to decode a jp2k-compressed tile. 
 *
 * width/height is the tile size. If this is an edge tile, and smaller than 
 * this, we still write a full-size tile and our caller will clip.
 */
int
vips__foreign_load_jp2k_decompress( VipsImage *out, 
	int width, int height, gboolean ycc_to_rgb, 
	void *from, size_t from_length, 
	void *to, size_t to_length )
{
	size_t pel_size = VIPS_IMAGE_SIZEOF_PEL( out );
	size_t line_size = pel_size * width;

	TileDecompress decompress = { 0 };
	opj_dparameters_t parameters;
	int i;
	gboolean upsample;
	VipsPel *q;
	int y;

#ifdef DEBUG
	printf( "vips__foreign_load_jp2k_decompress: width = %d, height = %d, "
		"ycc_to_rgb = %d, from_length = %zd, to_length = %zd\n",
		width, height, ycc_to_rgb, from_length, to_length );
#endif /*DEBUG*/

	/* Our ycc->rgb only works for exactly 3 bands.
	 */
	ycc_to_rgb = ycc_to_rgb && out->Bands == 3;

	decompress.codec = opj_create_decompress( OPJ_CODEC_J2K );
	opj_set_default_decoder_parameters( &parameters );
	opj_setup_decoder( decompress.codec, &parameters );
	opj_set_warning_handler( decompress.codec, warning_callback, NULL );
	opj_set_error_handler( decompress.codec, error_callback, NULL );

	decompress.source = vips_source_new_from_memory( from, from_length );
	decompress.stream = vips_foreign_load_jp2k_stream( decompress.source );
	if( !opj_read_header( decompress.stream, 
		decompress.codec, &decompress.image ) ) {
		vips_error( "jp2kload", "%s", ( "header error" ) );
		vips__foreign_load_jp2k_decompress_free( &decompress ); 
		return( -1 );
	}

	if( decompress.image->x1 > width || 
		decompress.image->y1 > height ||
		line_size * height > to_length ) {
		vips_error( "jp2kload", "%s", ( "bad dimensions" ) );
		vips__foreign_load_jp2k_decompress_free( &decompress ); 
    		return( -1 );
	}

	if( !opj_decode( decompress.codec, 
		decompress.stream, decompress.image ) ) {
		vips_error( "jp2kload", "%s", ( "decode error" ) );
		vips__foreign_load_jp2k_decompress_free( &decompress ); 
		return( -1 );
	}

	/* Do any components need upsampling?
	 */
	upsample = FALSE;
	for( i = 0; i < decompress.image->numcomps; i++ ) {
		opj_image_comp_t *this = &decompress.image->comps[i];

		if( this->dx > 1 ||
			this->dy > 1 )
			upsample = TRUE;
	}

	/* Unpack hit pixels to buffer in vips layout. 
	 */
	q = to;
	for( y = 0; y < height; y++ ) {
		vips_foreign_load_jp2k_pack( upsample, 
			decompress.image, out, q,
			0, y, width ); 

		if( ycc_to_rgb )
			vips_foreign_load_jp2k_ycc_to_rgb( 
				decompress.image, out, q, 
				width );

		q += line_size;
	}

	vips__foreign_load_jp2k_decompress_free( &decompress ); 

	return( 0 );
}

#else /*!HAVE_LIBOPENJP2*/

int
vips__foreign_load_jp2k_decompress( VipsImage *out, 
	int width, int height, gboolean ycc_to_rgb, 
	void *from, size_t from_length, 
	void *to, size_t to_length )
{
	vips_error( "jp2k", 
		"%s", _( "libvips built without JPEG2000 support" ) );
	return( -1 );
}

#endif /*HAVE_LIBOPENJP2*/

/**
 * vips_jp2kload:
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
vips_jp2kload( const char *filename, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "jp2kload", ap, filename, out );
	va_end( ap );

	return( result );
}

/**
 * vips_jp2kload_buffer:
 * @buf: (array length=len) (element-type guint8): memory area to load
 * @len: (type gsize): size of memory area
 * @out: (out): image to write
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @page: %gint, load this page
 *
 * Exactly as vips_jp2kload(), but read from a source. 
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_jp2kload_buffer( void *buf, size_t len, VipsImage **out, ... )
{
	va_list ap;
	VipsBlob *blob;
	int result;

	/* We don't take a copy of the data or free it.
	 */
	blob = vips_blob_new( NULL, buf, len );

	va_start( ap, out );
	result = vips_call_split( "jp2kload_buffer", ap, blob, out );
	va_end( ap );

	vips_area_unref( VIPS_AREA( blob ) );

	return( result );
}

/**
 * vips_jp2kload_source:
 * @source: source to load from
 * @out: (out): decompressed image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @page: %gint, load this page
 *
 * Exactly as vips_jp2kload(), but read from a source. 
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_jp2kload_source( VipsSource *source, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "jp2kload_source", ap, source, out );
	va_end( ap );

	return( result );
}
