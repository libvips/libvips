/* save as jpeg2000
 *
 * 18/3/20
 * 	- from jp2kload.c
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

/* TODO
 *
 * - could support tiff-like depth parameter
 *
 * - could support png-like bitdepth parameter
 *
 * - could support cp_comment field? not very useful
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <glib/gi18n-lib.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vips/vips.h>
#include <vips/internal.h>

#ifdef HAVE_LIBOPENJP2

#include <openjpeg.h>

#include "pforeign.h"

/* Surely enough ... does anyone do multispectral imaging with jp2k?
 */
#define MAX_BANDS (100)

typedef struct _VipsForeignSaveJp2k {
	VipsForeignSave parent_object;

	/* Where to write (set by subclasses).
	 */
	VipsTarget *target;

	int tile_width;
	int tile_height;

	/* Lossless mode.
	 */
	gboolean lossless;

	/* Quality factor.
	 */
	int Q;

	/* Chroma subsample mode.
	 */
	VipsForeignSubsample subsample_mode;

	/* Encoder state.
	 */
	opj_stream_t *stream;
	opj_codec_t *codec;
	opj_cparameters_t parameters;
	opj_image_t *image;

	/* The line of tiles we are building, and the buffer we
	 * unpack to for output.
	 */
	VipsRegion *strip;
	VipsPel *tile_buffer;

	/* If we need to subsample during unpacking.
	 */
	gboolean subsample;

	/* If we convert RGB to YCC during save.
	 */
	gboolean save_as_ycc;

	/* Accumulate a line of sums here during chroma subsample.
	 */
	VipsPel *accumulate;
} VipsForeignSaveJp2k;

typedef VipsForeignSaveClass VipsForeignSaveJp2kClass;

G_DEFINE_ABSTRACT_TYPE( VipsForeignSaveJp2k, vips_foreign_save_jp2k,
	VIPS_TYPE_FOREIGN_SAVE );

static void
vips_foreign_save_jp2k_dispose( GObject *gobject )
{
	VipsForeignSaveJp2k *jp2k = (VipsForeignSaveJp2k *) gobject;

	VIPS_FREEF( opj_destroy_codec, jp2k->codec );
	VIPS_FREEF( opj_stream_destroy, jp2k->stream );
	VIPS_FREEF( opj_image_destroy, jp2k->image );

	VIPS_UNREF( jp2k->target );
	VIPS_UNREF( jp2k->strip );

	VIPS_FREE( jp2k->tile_buffer );
	VIPS_FREE( jp2k->accumulate );

	G_OBJECT_CLASS( vips_foreign_save_jp2k_parent_class )->
		dispose( gobject );
}

static OPJ_SIZE_T
vips_foreign_save_jp2k_target_write( void *buffer, size_t length, void *client )
{
	VipsTarget *target = VIPS_TARGET( client );

	if( vips_target_write( target, buffer, length ) )
		return( 0 );

	return( length );
}

static OPJ_BOOL
vips_foreign_save_jp2k_target_seek( off_t position, void *client )
{
	VipsTarget *target = VIPS_TARGET( client );

	if( vips_target_seek( target, position, SEEK_SET ) < 0 )
		return( FALSE );

	return( TRUE );
}

static OPJ_OFF_T 
vips_foreign_save_jp2k_target_skip( off_t offset, void *client)
{
	VipsTarget *target = VIPS_TARGET( client );

	if( vips_target_seek( target, offset, SEEK_CUR ) < 0 )
		return( -1 );

        return( offset );
}

/* Make a libopenjp2 output stream that wraps a VipsTarget.
 */
static opj_stream_t *
vips_foreign_save_jp2k_target( VipsTarget *target )
{
	opj_stream_t *stream;

	/* FALSE means a write stream.
	 */
	if( !(stream = opj_stream_create( OPJ_J2K_STREAM_CHUNK_SIZE, FALSE )) )
		return( NULL );

	opj_stream_set_user_data( stream, target, NULL );
	opj_stream_set_write_function( stream,
		vips_foreign_save_jp2k_target_write );
	opj_stream_set_seek_function( stream,
		vips_foreign_save_jp2k_target_seek );
	opj_stream_set_skip_function( stream,
		vips_foreign_save_jp2k_target_skip );

	return( stream );
}

static void
vips_foreign_save_jp2k_error_callback( const char *msg, void *client )
{
	vips_error( "jp2ksave", "%s", msg );
}

/* The openjpeg info and warning callbacks are incredibly chatty.
 */
static void
vips_foreign_save_jp2k_warning_callback( const char *msg, void *client )
{
#ifdef DEBUG
#endif /*DEBUG*/
	g_warning( "jp2ksave: %s", msg );
}

static void
vips_foreign_save_jp2k_info_callback( const char *msg, void *client )
{
#ifdef DEBUG
#endif /*DEBUG*/
	g_info( "jp2ksave: %s", msg );
}

static void
vips_foreign_save_jp2k_attach_handlers( opj_codec_t *codec )
{
	opj_set_info_handler( codec,
		vips_foreign_save_jp2k_info_callback, NULL );
	opj_set_warning_handler( codec,
		vips_foreign_save_jp2k_warning_callback, NULL );
	opj_set_error_handler( codec,
		vips_foreign_save_jp2k_error_callback, NULL );
}

/* See also https://en.wikipedia.org/wiki/YCbCr#JPEG_conversion
 */
#define RGB_TO_YCC( TYPE ) { \
	TYPE *tq = (TYPE *) q; \
	\
	for( x = 0; x < tile->width; x++ ) { \
		int r = tq[0]; \
		int g = tq[1]; \
		int b = tq[2]; \
		\
		int y, cb, cr; \
		\
		y = 0.299 * r + 0.587 * g + 0.114 * b; \
		tq[0] = VIPS_CLIP( 0, y, upb ); \
		\
		cb = offset - (int)(0.168736 * r + 0.331264 * g - 0.5 * b); \
		tq[1] = VIPS_CLIP( 0, cb, upb ); \
		\
		cr = offset - (int)(-0.5 * r + 0.418688 * g + 0.081312 * b); \
		tq[2] = VIPS_CLIP( 0, cr, upb ); \
		\
		tq += 3; \
	} \
}

/* In-place RGB->YCC for a line of pels.
 */
static void
vips_foreign_save_jp2k_rgb_to_ycc( VipsRegion *region,
	VipsRect *tile, int prec )
{
	VipsImage *im = region->im;
	int offset = 1 << (prec - 1);
	int upb = (1 << prec) - 1;

	int x, y;

	g_assert( im->Bands == 3 );

	for( y = 0; y < tile->height; y++ ) {
		VipsPel *q = VIPS_REGION_ADDR( region,
			tile->left, tile->top + y );

		switch( im->BandFmt ) {
		case VIPS_FORMAT_CHAR:
		case VIPS_FORMAT_UCHAR:
			RGB_TO_YCC( unsigned char );
			break;

		case VIPS_FORMAT_SHORT:
		case VIPS_FORMAT_USHORT:
			RGB_TO_YCC( unsigned short );
			break;

		case VIPS_FORMAT_INT:
		case VIPS_FORMAT_UINT:
			RGB_TO_YCC( unsigned int );
			break;

		default:
			g_assert_not_reached();
			break;
		}
	}
}

/* Shrink in three stages:
 *   1. copy the first line of input pels to acc
 *   2. add subsequent lines in comp.dy.
 *   3. horizontal average to output line
 */
#define SHRINK( OUTPUT_TYPE, ACC_TYPE, PIXEL_TYPE ) { \
	ACC_TYPE *acc = (ACC_TYPE *) accumulate; \
	OUTPUT_TYPE *tq = (OUTPUT_TYPE *) q; \
	const int n_pels = comp->dx * comp->dy; \
	\
	PIXEL_TYPE *tp; \
	ACC_TYPE *ap; \
	\
	tp = (PIXEL_TYPE *) p; \
	for( x = 0; x < tile->width; x++ ) { \
		acc[x] = *tp; \
		tp += n_bands; \
	} \
	\
	for( z = 1; z < comp->dy; z++ ) { \
		tp = (PIXEL_TYPE *) (p + z * lskip); \
		for( x = 0; x < tile->width; x++ ) { \
			acc[x] += *tp; \
			tp += n_bands; \
		} \
	} \
	\
	ap = acc; \
	for( x = 0; x < output_width; x++ ) { \
		ACC_TYPE sum; \
		\
		sum = 0; \
		for( z = 0; z < comp->dx; z++ ) \
			sum += ap[z]; \
		\
		tq[x] = (sum + n_pels / 2) / n_pels; \
		ap += comp->dx; \
	} \
}

static void
vips_foreign_save_jp2k_unpack_subsample( VipsRegion *region, VipsRect *tile,
	opj_image_t *image, VipsPel *tile_buffer, VipsPel *accumulate )
{
	VipsImage *im = region->im;
	size_t sizeof_element = VIPS_REGION_SIZEOF_ELEMENT( region );
	size_t lskip = VIPS_REGION_LSKIP( region );
	int n_bands = im->Bands;

	VipsPel *q;
	int x, y, z, i;

	q = tile_buffer;
	for( i = 0; i < n_bands; i++ ) {
		opj_image_comp_t *comp = &image->comps[i];

		/* The number of pixels we write for this component. No
		 * padding.
		 */
		int output_width = VIPS_ROUND_UINT(
			(double) tile->width / comp->dx );
		int output_height = VIPS_ROUND_UINT(
			(double) tile->height / comp->dy );;

		for( y = 0; y < output_height; y++ ) {
			VipsPel *p = i * sizeof_element +
				VIPS_REGION_ADDR( region,
					tile->left, tile->top + y * comp->dy );

			/* Shrink a line of pels to q.
			 */
			switch( im->BandFmt ) {
			case VIPS_FORMAT_CHAR:
				SHRINK( signed char, int, signed char );
				break;

			case VIPS_FORMAT_UCHAR:
				SHRINK( unsigned char, int, unsigned char );
				break;

			case VIPS_FORMAT_SHORT:
				SHRINK( signed short, int, signed short );
				break;

			case VIPS_FORMAT_USHORT:
				SHRINK( unsigned short, int, unsigned short );
				break;

			case VIPS_FORMAT_INT:
				SHRINK( signed int, gint64, signed int );
				break;

			case VIPS_FORMAT_UINT:
				SHRINK( unsigned int, gint64, unsigned int );
				break;

			default:
				g_assert_not_reached();
				break;
			}

			q += sizeof_element * output_width;
		}
	}
}

#define UNPACK( OUT, IN ) { \
	OUT *tq = (OUT *) q; \
	IN *tp = (IN *) p + i; \
	\
	for( x = 0; x < tile->width; x++ ) { \
		tq[x] = *tp; \
		tp += b; \
	} \
}

static void
vips_foreign_save_jp2k_unpack( VipsRegion *region, VipsRect *tile,
	opj_image_t *image, VipsPel *tile_buffer )
{
	VipsImage *im = region->im;
	size_t sizeof_element = VIPS_REGION_SIZEOF_ELEMENT( region );
	size_t sizeof_line = sizeof_element * tile->width;
	size_t sizeof_tile = sizeof_line * tile->height;
	int b = im->Bands;

	int x, y, i;

	for( y = 0; y < tile->height; y++ ) {
		VipsPel *p = VIPS_REGION_ADDR( region,
			tile->left, tile->top + y );

		for( i = 0; i < b; i++ ) {
			VipsPel *q = tile_buffer +
				i * sizeof_tile + y * sizeof_line;

			switch( im->BandFmt ) {
			case VIPS_FORMAT_CHAR:
			case VIPS_FORMAT_UCHAR:
				UNPACK( unsigned char, unsigned char );
				break;

			case VIPS_FORMAT_SHORT:
			case VIPS_FORMAT_USHORT:
				UNPACK( unsigned short, unsigned short );
				break;

			case VIPS_FORMAT_INT:
			case VIPS_FORMAT_UINT:
				UNPACK( unsigned int, unsigned int );
				break;

			default:
				g_assert_not_reached();
				break;
			}
		}
	}
}

static size_t
vips_foreign_save_jp2k_sizeof_tile( VipsForeignSaveJp2k *jp2k, VipsRect *tile )
{
	VipsForeignSave *save = (VipsForeignSave *) jp2k;
	size_t sizeof_element = VIPS_IMAGE_SIZEOF_ELEMENT( save->ready );

	size_t size;
	int i;

	size = 0;
	for( i = 0; i < jp2k->image->numcomps; i++ ) {
		opj_image_comp_t *comp = &jp2k->image->comps[i];

		/* The number of pixels we write for this component. Round to
		 * nearest, and we may have to write half-pixels at the edges.
		 */
		int output_width = VIPS_ROUND_UINT(
			(double) tile->width / comp->dx );
		int output_height = VIPS_ROUND_UINT(
			(double) tile->height / comp->dy );;

		size += output_width * output_height * sizeof_element;
	}

	return( size );
}

static int
vips_foreign_save_jp2k_write_tiles( VipsForeignSaveJp2k *jp2k )
{
	VipsForeignSave *save = (VipsForeignSave *) jp2k;
	VipsImage *im = save->ready;
	int tiles_across = VIPS_ROUND_UP( im->Xsize, jp2k->tile_width ) /
		jp2k->tile_width;

	int x;

	for( x = 0; x < im->Xsize; x += jp2k->tile_width ) {
		VipsRect tile;
		size_t sizeof_tile;
		int tile_index;

		tile.left = x;
		tile.top = jp2k->strip->valid.top;
		tile.width = jp2k->tile_width;
		tile.height = jp2k->tile_height;
		vips_rect_intersectrect( &tile, &jp2k->strip->valid, &tile );

		if( jp2k->save_as_ycc )
			vips_foreign_save_jp2k_rgb_to_ycc( jp2k->strip,
				&tile, jp2k->image->comps[0].prec );

		if( jp2k->subsample )
			vips_foreign_save_jp2k_unpack_subsample( jp2k->strip,
				&tile, jp2k->image,
				jp2k->tile_buffer, jp2k->accumulate );
		else
			vips_foreign_save_jp2k_unpack( jp2k->strip,
				&tile, jp2k->image,
				jp2k->tile_buffer );

		sizeof_tile =
			vips_foreign_save_jp2k_sizeof_tile( jp2k, &tile );
		tile_index = tiles_across * tile.top / jp2k->tile_height +
			x / jp2k->tile_width;
		if( !opj_write_tile( jp2k->codec, tile_index,
			(VipsPel *) jp2k->tile_buffer, sizeof_tile,
			jp2k->stream ) )
			return( -1 );
	}

	return( 0 );
}

static int
vips_foreign_save_jp2k_write_block( VipsRegion *region, VipsRect *area,
	void *a )
{
	VipsForeignSaveJp2k *jp2k = (VipsForeignSaveJp2k *) a;
	VipsForeignSave *save = (VipsForeignSave *) jp2k;

#ifdef DEBUG_VERBOSE
	printf( "vips_foreign_save_jp2k_write_block: y = %d, nlines = %d\n",
		area->top, area->height );
#endif /*DEBUG_VERBOSE*/

	for(;;) {
		VipsRect *to = &jp2k->strip->valid;

		VipsRect hit;
		VipsRect new;
		VipsRect image;

		/* The intersection with the strip is the fresh pixels we
		 * have.
		 */
		vips_rect_intersectrect( area, to, &hit );

		/* Write the new pixels into the strip.
		 */
		vips_region_copy( region, jp2k->strip,
			&hit, hit.left, hit.top );

		/* Have we failed to reach the bottom of the strip? We must
		 * have run out of fresh pixels, so we are done.
		 */
		if( VIPS_RECT_BOTTOM( &hit ) !=
			VIPS_RECT_BOTTOM( &jp2k->strip->valid ) )
			break;

		/* We have reached the bottom of the strip. Write this line of
		 * pixels and move the strip down.
		 */
		if( vips_foreign_save_jp2k_write_tiles( jp2k ) )
			return( -1 );

		new.left = 0;
		new.top = jp2k->strip->valid.top + jp2k->tile_height;
		new.width = save->ready->Xsize;
		new.height = jp2k->tile_height;
		image.left = 0;
		image.top = 0;
		image.width = save->ready->Xsize;
		image.height = save->ready->Ysize;
		vips_rect_intersectrect( &new, &image, &new);

		/* End of image?
		 */
		if( vips_rect_isempty( &new ) )
			break;

		if( vips_region_buffer( jp2k->strip, &new ) )
			return( -1 );
	}

	return( 0 );
}

/* We can't call opj_calloc on win, sadly.
 */
#define VIPS_OPJ_CALLOC( N, TYPE ) \
	((TYPE *) calloc( (N), sizeof( TYPE ) ))

/* Allocate an openjpeg image structure. Openjpeg has opj_image_create(), but
 * that always allocates memory for each channel, and we don't want that when
 * we are doing tiled write.
 */
static opj_image_t *
vips_opj_image_create( OPJ_UINT32 numcmpts,
	opj_image_cmptparm_t *cmptparms, OPJ_COLOR_SPACE clrspc,
	gboolean allocate )
{
	OPJ_UINT32 compno;
	opj_image_t *image = NULL;

	if( !(image = VIPS_OPJ_CALLOC( 1, opj_image_t )) )
		return( NULL );

        image->color_space = clrspc;
        image->numcomps = numcmpts;
        image->comps = VIPS_OPJ_CALLOC( image->numcomps, opj_image_comp_t );
        if( !image->comps ) {
            opj_image_destroy( image );
            return( NULL );
        }

        for( compno = 0; compno < numcmpts; compno++ ) {
		opj_image_comp_t *comp = &image->comps[compno];

		comp->dx = cmptparms[compno].dx;
		comp->dy = cmptparms[compno].dy;
		comp->w = cmptparms[compno].w;
		comp->h = cmptparms[compno].h;
		comp->x0 = cmptparms[compno].x0;
		comp->y0 = cmptparms[compno].y0;
		comp->prec = cmptparms[compno].prec;
		comp->sgnd = cmptparms[compno].sgnd;

		if( comp->h != 0 &&
			(OPJ_SIZE_T) comp->w > SIZE_MAX / comp->h /
				sizeof( OPJ_INT32 ) ) {
			opj_image_destroy( image );
			return( NULL );
		}

		/* Allocation is optional.
		 */
		if( allocate ) {
			size_t bytes = (size_t) comp->w * comp->h *
                                sizeof( OPJ_INT32 );

			comp->data = (OPJ_INT32*) opj_image_data_alloc( bytes );
			if( !comp->data ) {
				opj_image_destroy( image );
				return NULL;
			}
			memset( comp->data, 0, bytes );
		}
	}

	return( image );
}

static opj_image_t *
vips_foreign_save_jp2k_new_image( VipsImage *im,
	int width, int height,
	gboolean subsample, gboolean save_as_ycc, gboolean allocate )
{
	OPJ_COLOR_SPACE color_space;
	int expected_bands;
	int bits_per_pixel;
	opj_image_cmptparm_t comps[MAX_BANDS];
	opj_image_t *image;
	int i;

	if( im->Bands > MAX_BANDS )
		return( NULL );

	/* CIELAB etc. do not seem to be well documented.
	 */
	switch( im->Type ) {
	case VIPS_INTERPRETATION_B_W:
	case VIPS_INTERPRETATION_GREY16:
		color_space = OPJ_CLRSPC_GRAY;
		expected_bands = 1;
		break;

	case VIPS_INTERPRETATION_sRGB:
	case VIPS_INTERPRETATION_RGB16:
		color_space = save_as_ycc ? OPJ_CLRSPC_SYCC : OPJ_CLRSPC_SRGB;
		expected_bands = 3;
		break;

	case VIPS_INTERPRETATION_CMYK:
		color_space = OPJ_CLRSPC_CMYK;
		expected_bands = 4;
		break;

	default:
		color_space = OPJ_CLRSPC_UNSPECIFIED;
		expected_bands = im->Bands;
		break;
	}

	switch( im->BandFmt ) {
	case VIPS_FORMAT_CHAR:
	case VIPS_FORMAT_UCHAR:
		bits_per_pixel = 8;
		break;

	case VIPS_FORMAT_SHORT:
	case VIPS_FORMAT_USHORT:
		bits_per_pixel = 16;
		break;

	case VIPS_FORMAT_INT:
	case VIPS_FORMAT_UINT:
		/* OpenJPEG only supports up to 31.
		 */
		bits_per_pixel = 31;
		break;

	default:
		g_assert_not_reached();
		break;
	}

	for( i = 0; i < im->Bands; i++ ) {
		comps[i].dx = (subsample && i > 0) ? 2 : 1;
		comps[i].dy = (subsample && i > 0) ? 2 : 1;
		comps[i].w = width;
		comps[i].h = height;
		comps[i].x0 = 0;
		comps[i].y0 = 0;
		comps[i].prec = bits_per_pixel;
		comps[i].sgnd = !vips_band_format_isuint( im->BandFmt );
	}

	image = vips_opj_image_create( im->Bands, comps, color_space,
		allocate );
	image->x1 = width;
	image->y1 = height;

	/* Tag alpha channels.
	 */
	for( i = 0; i < im->Bands; i++ )
		image->comps[i].alpha = i >= expected_bands;

	return( image );
}

/* Compression profile derived from the BM's recommendations, see:
 *
 * https://purl.pt/24107/1/iPres2013_PDF/An%20Analysis%20of%20Contemporary%20JPEG2000%20Codecs%20for%20Image%20Format%20Migration.pdf
 *
 * Some of these settings (eg. numresolution) are overridden later.
 */
static void
vips_foreign_save_jp2k_set_profile( opj_cparameters_t *parameters,
	gboolean lossless, int Q )
{
	if( lossless )
		parameters->irreversible = FALSE;
	else {
		int i;

		/* Equivalent command-line flags:
		 *
		 *   -I -p RPCL -n 7 \
		 *   	-c[256,256],[256,256],[256,256],[256,256],[256,256],[256,256],[256,256] \
		 *   	-b 64,64
		 */

		parameters->irreversible = TRUE;
		parameters->prog_order = OPJ_RPCL;
		parameters->cblockw_init = 64;
		parameters->cblockh_init = 64;
		parameters->cp_disto_alloc = 1;
		parameters->cp_fixed_quality = TRUE;
		parameters->tcp_numlayers = 1;
		parameters->numresolution = 7;

		/* No idea what this does, but opj_compress sets it.
		 */
		parameters->csty = 1;

		parameters->res_spec = 7;
		for( i = 0; i < parameters->res_spec; i++ ) {
			parameters->prch_init[i] = 256;
			parameters->prcw_init[i] = 256;
			parameters->tcp_distoratio[i] = Q + 10 * i;
		}
	}
}

static int
vips_foreign_save_jp2k_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsForeignSave *save = (VipsForeignSave *) object;
	VipsForeignSaveJp2k *jp2k = (VipsForeignSaveJp2k *) object;

	size_t sizeof_tile;
	size_t sizeof_line;
	VipsRect strip_position;

	if( VIPS_OBJECT_CLASS( vips_foreign_save_jp2k_parent_class )->
		build( object ) )
		return( -1 );

	/* Analyze our arguments.
	 */

	if( !vips_band_format_isint( save->ready->BandFmt ) ) {
		vips_error( class->nickname,
			"%s", _( "not an integer format" ) );
		return( -1 );
	}

	switch( jp2k->subsample_mode ) {
	case VIPS_FOREIGN_SUBSAMPLE_AUTO:
		jp2k->subsample =
			!jp2k->lossless &&
			jp2k->Q < 90 &&
			(save->ready->Type == VIPS_INTERPRETATION_sRGB ||
			 save->ready->Type == VIPS_INTERPRETATION_RGB16) &&
			save->ready->Bands == 3;
		break;

	case VIPS_FOREIGN_SUBSAMPLE_ON:
		jp2k->subsample = TRUE;
		break;

	case VIPS_FOREIGN_SUBSAMPLE_OFF:
		jp2k->subsample = FALSE;
		break;

	default:
		g_assert_not_reached();
		break;
	}

	if( jp2k->subsample )
		jp2k->save_as_ycc = TRUE;

	/* Set parameters for compressor.
	 */
	opj_set_default_encoder_parameters( &jp2k->parameters );

	/* Set compression profile.
	 */
	vips_foreign_save_jp2k_set_profile( &jp2k->parameters,
		jp2k->lossless, jp2k->Q );

	/* Always tile.
	 */
	jp2k->parameters.tile_size_on = OPJ_TRUE;
	jp2k->parameters.cp_tdx = jp2k->tile_width;
	jp2k->parameters.cp_tdy = jp2k->tile_height;

	/* Makes many-band, non-subsampled images smaller, somehow.
	 */
	jp2k->parameters.tcp_mct = save->ready->Bands >= 3 && !jp2k->subsample;

	/* Number of layers to write. Smallest layer is c. 2^5 on the smallest
	 * axis.
	 */
	jp2k->parameters.numresolution = VIPS_MAX( 1,
		log( VIPS_MIN( save->ready->Xsize, save->ready->Ysize ) ) /
		log( 2 ) - 5 );
#ifdef DEBUG
	printf( "vips_foreign_save_jp2k_build: numresolutions = %d\n",
		jp2k->parameters.numresolution );
#endif /*DEBUG*/

	/* Set up compressor.
	 */

        /* Save as a jp2 file.
         */
	jp2k->codec = opj_create_compress( OPJ_CODEC_JP2 );
	vips_foreign_save_jp2k_attach_handlers( jp2k->codec );

	/* FALSE means don't alloc memory for image planes (we write in
	 * tiles, not whole images).
	 */
	if( !(jp2k->image = vips_foreign_save_jp2k_new_image( save->ready,
		save->ready->Xsize, save->ready->Ysize,
		jp2k->subsample, jp2k->save_as_ycc, FALSE )) )
		return( -1 );
        if( !opj_setup_encoder( jp2k->codec, &jp2k->parameters, jp2k->image ) )
		return( -1 );

	opj_codec_set_threads( jp2k->codec, vips_concurrency_get() );

	if( !(jp2k->stream = vips_foreign_save_jp2k_target( jp2k->target )) )
		return( -1 );

	if( !opj_start_compress( jp2k->codec, jp2k->image, jp2k->stream ) )
		return( -1 );

	/* The buffer we repack tiles to for write. Large enough for one
	 * complete tile.
	 */
	sizeof_tile = VIPS_IMAGE_SIZEOF_PEL( save->ready ) *
		jp2k->tile_width * jp2k->tile_height;
	if( !(jp2k->tile_buffer = VIPS_ARRAY( NULL, sizeof_tile, VipsPel )) )
		return( -1 );

	/* We need a line of sums for chroma subsample. At worst, gint64.
	 */
	sizeof_line = sizeof( gint64 ) * jp2k->tile_width;
	if( !(jp2k->accumulate = VIPS_ARRAY( NULL, sizeof_line, VipsPel )) )
		return( -1 );

	/* The line of tiles we are building. It's used by the bg thread, so
	 * no ownership.
	 */
	jp2k->strip = vips_region_new( save->ready );
        vips__region_no_ownership( jp2k->strip );

	/* Position strip at the top of the image, the height of a row of
	 * tiles.
	 */
	strip_position.left = 0;
	strip_position.top = 0;
	strip_position.width = save->ready->Xsize;
	strip_position.height = jp2k->tile_height;
	if( vips_region_buffer( jp2k->strip, &strip_position ) )
		return( -1 );

	/* Write data.
	 */
	if( vips_sink_disc( save->ready,
		vips_foreign_save_jp2k_write_block, jp2k ) )
		return( -1 );

	opj_end_compress( jp2k->codec, jp2k->stream );

	if( vips_target_end( jp2k->target ) )
		return( -1 );

	return( 0 );
}

static void
vips_foreign_save_jp2k_class_init( VipsForeignSaveJp2kClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;
	VipsForeignSaveClass *save_class = (VipsForeignSaveClass *) class;

	gobject_class->dispose = vips_foreign_save_jp2k_dispose;
	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "jp2ksave_base";
	object_class->description = _( "save image in JPEG2000 format" );
	object_class->build = vips_foreign_save_jp2k_build;

	foreign_class->suffs = vips__jp2k_suffs;

	save_class->saveable = VIPS_SAVEABLE_ANY;

	VIPS_ARG_INT( class, "tile_width", 11,
		_( "Tile width" ),
		_( "Tile width in pixels" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveJp2k, tile_width ),
		1, 32768, 512 );

	VIPS_ARG_INT( class, "tile_height", 12,
		_( "Tile height" ),
		_( "Tile height in pixels" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveJp2k, tile_height ),
		1, 32768, 512 );

	VIPS_ARG_BOOL( class, "lossless", 13,
		_( "Lossless" ),
		_( "Enable lossless compression" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveJp2k, lossless ),
		FALSE );

	VIPS_ARG_ENUM( class, "subsample_mode", 19,
		_( "Subsample mode" ),
		_( "Select chroma subsample operation mode" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveJp2k, subsample_mode ),
		VIPS_TYPE_FOREIGN_SUBSAMPLE,
		VIPS_FOREIGN_SUBSAMPLE_OFF );

	VIPS_ARG_INT( class, "Q", 14,
		_( "Q" ),
		_( "Q factor" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveJp2k, Q ),
		1, 100, 48 );

}

static void
vips_foreign_save_jp2k_init( VipsForeignSaveJp2k *jp2k )
{
	jp2k->tile_width = 512;
	jp2k->tile_height = 512;

	/* Chosen to give about the same filesize as regular jpg Q75.
	 */
	jp2k->Q = 48;

	jp2k->subsample_mode = VIPS_FOREIGN_SUBSAMPLE_OFF;
}

typedef struct _VipsForeignSaveJp2kFile {
	VipsForeignSaveJp2k parent_object;

	/* Filename for save.
	 */
	char *filename;

} VipsForeignSaveJp2kFile;

typedef VipsForeignSaveJp2kClass VipsForeignSaveJp2kFileClass;

G_DEFINE_TYPE( VipsForeignSaveJp2kFile, vips_foreign_save_jp2k_file,
	vips_foreign_save_jp2k_get_type() );

static int
vips_foreign_save_jp2k_file_build( VipsObject *object )
{
	VipsForeignSaveJp2k *jp2k = (VipsForeignSaveJp2k *) object;
	VipsForeignSaveJp2kFile *file = (VipsForeignSaveJp2kFile *) object;

	if( !(jp2k->target = vips_target_new_to_file( file->filename )) )
		return( -1 );

	if( VIPS_OBJECT_CLASS( vips_foreign_save_jp2k_file_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

static void
vips_foreign_save_jp2k_file_class_init( VipsForeignSaveJp2kFileClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "jp2ksave";
	object_class->build = vips_foreign_save_jp2k_file_build;

	VIPS_ARG_STRING( class, "filename", 1,
		_( "Filename" ),
		_( "Filename to load from" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveJp2kFile, filename ),
		NULL );

}

static void
vips_foreign_save_jp2k_file_init( VipsForeignSaveJp2kFile *file )
{
}

typedef struct _VipsForeignSaveJp2kBuffer {
	VipsForeignSaveJp2k parent_object;

	/* Save to a buffer.
	 */
	VipsArea *buf;

} VipsForeignSaveJp2kBuffer;

typedef VipsForeignSaveJp2kClass VipsForeignSaveJp2kBufferClass;

G_DEFINE_TYPE( VipsForeignSaveJp2kBuffer, vips_foreign_save_jp2k_buffer,
	vips_foreign_save_jp2k_get_type() );

static int
vips_foreign_save_jp2k_buffer_build( VipsObject *object )
{
	VipsForeignSaveJp2k *jp2k = (VipsForeignSaveJp2k *) object;
	VipsForeignSaveJp2kBuffer *buffer =
		(VipsForeignSaveJp2kBuffer *) object;

	VipsBlob *blob;

	if( !(jp2k->target = vips_target_new_to_memory()) )
		return( -1 );

	if( VIPS_OBJECT_CLASS( vips_foreign_save_jp2k_buffer_parent_class )->
		build( object ) )
		return( -1 );

	g_object_get( jp2k->target, "blob", &blob, NULL );
	g_object_set( buffer, "buffer", blob, NULL );
	vips_area_unref( VIPS_AREA( blob ) );

	return( 0 );
}

static void
vips_foreign_save_jp2k_buffer_class_init(
	VipsForeignSaveJp2kBufferClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "jp2ksave_buffer";
	object_class->build = vips_foreign_save_jp2k_buffer_build;

	VIPS_ARG_BOXED( class, "buffer", 1,
		_( "Buffer" ),
		_( "Buffer to save to" ),
		VIPS_ARGUMENT_REQUIRED_OUTPUT,
		G_STRUCT_OFFSET( VipsForeignSaveJp2kBuffer, buf ),
		VIPS_TYPE_BLOB );

}

static void
vips_foreign_save_jp2k_buffer_init( VipsForeignSaveJp2kBuffer *buffer )
{
}

typedef struct _VipsForeignSaveJp2kTarget {
	VipsForeignSaveJp2k parent_object;

	VipsTarget *target;
} VipsForeignSaveJp2kTarget;

typedef VipsForeignSaveJp2kClass VipsForeignSaveJp2kTargetClass;

G_DEFINE_TYPE( VipsForeignSaveJp2kTarget, vips_foreign_save_jp2k_target,
	vips_foreign_save_jp2k_get_type() );

static int
vips_foreign_save_jp2k_target_build( VipsObject *object )
{
	VipsForeignSaveJp2k *jp2k = (VipsForeignSaveJp2k *) object;
	VipsForeignSaveJp2kTarget *target =
		(VipsForeignSaveJp2kTarget *) object;

	if( target->target ) {
		jp2k->target = target->target;
		g_object_ref( jp2k->target );
	}

	if( VIPS_OBJECT_CLASS( vips_foreign_save_jp2k_target_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

static void
vips_foreign_save_jp2k_target_class_init(
	VipsForeignSaveJp2kTargetClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "jp2ksave_target";
	object_class->build = vips_foreign_save_jp2k_target_build;

	VIPS_ARG_OBJECT( class, "target", 1,
		_( "Target" ),
		_( "Target to save to" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveJp2kTarget, target ),
		VIPS_TYPE_TARGET );

}

static void
vips_foreign_save_jp2k_target_init( VipsForeignSaveJp2kTarget *target )
{
}

/* Stuff we track during tile compress.
 */
typedef struct _TileCompress {
        opj_codec_t *codec;
	opj_image_t *image;
	opj_stream_t *stream;
	VipsPel *accumulate;
} TileCompress;

/* Unpack from @tile within @region to the int data pointers on @image with
 * subsampling.
 */
static void
vips_foreign_save_jp2k_unpack_subsample_image( VipsRegion *region,
	VipsRect *tile, opj_image_t *image, VipsPel *accumulate )
{
	VipsImage *im = region->im;
	size_t sizeof_element = VIPS_REGION_SIZEOF_ELEMENT( region );
	size_t lskip = VIPS_REGION_LSKIP( region );
	int n_bands = im->Bands;

	int x, y, z, i;

	for( i = 0; i < n_bands; i++ ) {
		opj_image_comp_t *comp = &image->comps[i];
		int *q = comp->data;

		/* The number of pixels we write for this component. Lines
		 * align to scanlines on comp.
		 */
		int output_width = VIPS_ROUND_UINT(
			(double) comp->w / comp->dx );
		int output_height = VIPS_ROUND_UINT(
			(double) comp->h / comp->dy );

		for( y = 0; y < output_height; y++ ) {
			VipsPel *p = i * sizeof_element +
				VIPS_REGION_ADDR( region,
					tile->left, tile->top + y * comp->dy );

			/* Shrink a line of pels to q.
			 */
			switch( im->BandFmt ) {
			case VIPS_FORMAT_CHAR:
				SHRINK( int, int, signed char );
				break;

			case VIPS_FORMAT_UCHAR:
				SHRINK( int, int, unsigned char );
				break;

			case VIPS_FORMAT_SHORT:
				SHRINK( int, int, signed short );
				break;

			case VIPS_FORMAT_USHORT:
				SHRINK( int, int, unsigned short );
				break;

			case VIPS_FORMAT_INT:
				SHRINK( int, gint64, signed int );
				break;

			case VIPS_FORMAT_UINT:
				SHRINK( int, gint64, unsigned int );
				break;

			default:
				g_assert_not_reached();
				break;
			}

			q += output_width;
		}
	}
}

/* Unpack from @tile within @region to the int data pointers on @image. No
 * subsampling.
 */
static void
vips_foreign_save_jp2k_unpack_image( VipsRegion *region, VipsRect *tile,
	opj_image_t *image )
{
	VipsImage *im = region->im;
	int b = im->Bands;

	int x, y, i;

	for( y = 0; y < tile->height; y++ ) {
		VipsPel *p = VIPS_REGION_ADDR( region,
			tile->left, tile->top + y );

		for( i = 0; i < b; i++ ) {
			opj_image_comp_t *comp = &image->comps[i];
                        int *q = comp->data + y * comp->w;

			switch( im->BandFmt ) {
			case VIPS_FORMAT_CHAR:
			case VIPS_FORMAT_UCHAR:
				UNPACK( int, unsigned char );
				break;

			case VIPS_FORMAT_SHORT:
			case VIPS_FORMAT_USHORT:
				UNPACK( int, unsigned short );
				break;

			case VIPS_FORMAT_INT:
			case VIPS_FORMAT_UINT:
				UNPACK( int, unsigned int );
				break;

			default:
				g_assert_not_reached();
				break;
			}
		}
	}
}

void
vips__foreign_load_jp2k_compress_free( TileCompress *compress )
{
	VIPS_FREEF( opj_destroy_codec, compress->codec );
	VIPS_FREEF( opj_image_destroy, compress->image );
	VIPS_FREEF( opj_stream_destroy, compress->stream );
	VIPS_FREE( compress->accumulate );
}

/* Compress area @tile within @region and write to @target as a @tile_width by
 * @tile_height jp2k compressed image. This is called from eg. vips2tiff to
 * write jp2k-compressed tiles.
 *
 * You'd think we could reuse things like the encoder between calls but ...
 * nope, openjpeg does not allow that.
 */
int
vips__foreign_load_jp2k_compress( VipsRegion *region,
	VipsRect *tile, VipsTarget *target,
	int tile_width, int tile_height,
        gboolean save_as_ycc, gboolean subsample, gboolean lossless, int Q )
{
	TileCompress compress = { 0 };
	opj_cparameters_t parameters;
	size_t sizeof_line;

	/* Our rgb->ycc only works for exactly 3 bands.
	 */
	save_as_ycc = save_as_ycc && region->im->Bands == 3;
	subsample = subsample && save_as_ycc;

	/* Set compression params.
	 */
	opj_set_default_encoder_parameters( &parameters );

	/* Set compression profile.
	 */
	vips_foreign_save_jp2k_set_profile( &parameters, lossless, Q );

	/* Makes three band images smaller, somehow.
	 */
	parameters.tcp_mct = region->im->Bands >= 3 ? 1 : 0;

	/* Create output image. TRUE means we alloc memory for the image
	 * planes.
	 */
	if( !(compress.image = vips_foreign_save_jp2k_new_image( region->im,
		tile_width, tile_height, subsample, save_as_ycc, TRUE )) ) {
		vips__foreign_load_jp2k_compress_free( &compress );
		return( -1 );
	}

	/* We need a line of sums for chroma subsample. At worst, gint64.
	 */
	sizeof_line = sizeof( gint64 ) * tile->width;
	if( !(compress.accumulate =
		VIPS_ARRAY( NULL, sizeof_line, VipsPel )) ) {
		vips__foreign_load_jp2k_compress_free( &compress );
		return( -1 );
	}

        /* tiff needs a jpeg2000 codestream, not a jp2 file.
         */
	compress.codec = opj_create_compress( OPJ_CODEC_J2K );
	vips_foreign_save_jp2k_attach_handlers( compress.codec );
        if( !opj_setup_encoder( compress.codec,
		&parameters, compress.image ) ) {
		vips__foreign_load_jp2k_compress_free( &compress );
		return( -1 );
	}

	opj_codec_set_threads( compress.codec, vips_concurrency_get() );

	if( save_as_ycc )
		vips_foreign_save_jp2k_rgb_to_ycc( region,
			tile, compress.image->comps[0].prec );

	/* we need to unpack to the int arrays on comps[i].data
	 */
	if( subsample )
		vips_foreign_save_jp2k_unpack_subsample_image( region,
			tile, compress.image,
			compress.accumulate );
	else
		vips_foreign_save_jp2k_unpack_image( region,
			tile, compress.image );

	if( !(compress.stream = vips_foreign_save_jp2k_target( target )) ) {
		vips__foreign_load_jp2k_compress_free( &compress );
		return( -1 );
	}

	if( !opj_start_compress( compress.codec,
		compress.image, compress.stream ) ) {
		vips__foreign_load_jp2k_compress_free( &compress );
		return( -1 );
	}

	if( !opj_encode( compress.codec, compress.stream ) ) {
		vips__foreign_load_jp2k_compress_free( &compress );
		return( -1 );
	}

	opj_end_compress( compress.codec, compress.stream );

	vips__foreign_load_jp2k_compress_free( &compress );

	return( 0 );
}

#else /*!HAVE_LIBOPENJP2*/

int
vips__foreign_load_jp2k_compress( VipsRegion *region,
	VipsRect *tile, VipsTarget *target,
	int tile_width, int tile_height,
        gboolean save_as_ycc, gboolean subsample, gboolean lossless, int Q )
{
	vips_error( "jp2k",
		"%s", _( "libvips built without JPEG2000 support" ) );
	return( -1 );
}

#endif /*HAVE_LIBOPENJP2*/

/**
 * vips_jp2ksave: (method)
 * @in: image to save
 * @filename: file to write to
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @Q: %gint, quality factor
 * * @lossless: %gboolean, enables lossless compression
 * * @tile_width: %gint for tile size
 * * @tile_height: %gint for tile size
 * * @subsample_mode: #VipsForeignSubsample, chroma subsampling mode
 *
 * Write a VIPS image to a file in JPEG2000 format.
 * The saver supports 8, 16 and 32-bit int pixel
 * values, signed and unsigned. It supports greyscale, RGB, CMYK and
 * multispectral images.
 *
 * Use @Q to set the compression quality factor. The default value
 * produces file with approximately the same size as regular JPEG Q 75.
 *
 * Set @lossless to enable lossless compresion.
 *
 * Use @tile_width and @tile_height to set the tile size. The default is 512.
 *
 * Chroma subsampling is normally disabled for compatibility. Set
 * @subsample_mode to auto to enable chroma subsample for Q < 90. Subsample
 * mode uses YCC rather than RGB colourspace, and many jpeg2000 decoders do
 * not support this.
 *
 * This operation always writes a pyramid.
 *
 * See also: vips_image_write_to_file(), vips_jp2kload().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_jp2ksave( VipsImage *in, const char *filename, ... )
{
	va_list ap;
	int result;

	va_start( ap, filename );
	result = vips_call_split( "jp2ksave", ap, in, filename );
	va_end( ap );

	return( result );
}

/**
 * vips_jp2ksave_buffer: (method)
 * @in: image to save
 * @buf: (array length=len) (element-type guint8): return output buffer here
 * @len: (type gsize): return output length here
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @Q: %gint, quality factor
 * * @lossless: %gboolean, enables lossless compression
 * * @tile_width: %gint for tile size
 * * @tile_height: %gint for tile size
 * * @subsample_mode: #VipsForeignSubsample, chroma subsampling mode
 *
 * As vips_jp2ksave(), but save to a target.
 *
 * See also: vips_jp2ksave(), vips_image_write_to_target().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_jp2ksave_buffer( VipsImage *in, void **buf, size_t *len, ... )
{
	va_list ap;
	VipsArea *area;
	int result;

	area = NULL;

	va_start( ap, len );
	result = vips_call_split( "jp2ksave_buffer", ap, in, &area );
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
 * vips_jp2ksave_target: (method)
 * @in: image to save
 * @target: save image to this target
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @Q: %gint, quality factor
 * * @lossless: %gboolean, enables lossless compression
 * * @tile_width: %gint for tile size
 * * @tile_height: %gint for tile size
 * * @subsample_mode: #VipsForeignSubsample, chroma subsampling mode
 *
 * As vips_jp2ksave(), but save to a target.
 *
 * See also: vips_jp2ksave(), vips_image_write_to_target().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_jp2ksave_target( VipsImage *in, VipsTarget *target, ... )
{
	va_list ap;
	int result;

	va_start( ap, target );
	result = vips_call_split( "jp2ksave_target", ap, in, target );
	va_end( ap );

	return( result );
}
