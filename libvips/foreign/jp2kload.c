/* load jp2k from a file
 *
 * 29/6/18
 * 	- from fitsload.c
 * 9/9/19
 * 	- use double for all floating point scalar metadata, like other loaders
 * 	- remove stray use of "n" property
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
#define DEBUG
#define VIPS_DEBUG

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

typedef struct _VipsForeignLoadJp2k {
	VipsForeignLoad parent_object;

	/* Source to load from (set by subclasses).
	 */
	VipsSource *source;

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

} VipsForeignLoadJp2k;

typedef VipsForeignLoadClass VipsForeignLoadJp2kClass;

G_DEFINE_ABSTRACT_TYPE( VipsForeignLoadJp2k, vips_foreign_load_jp2k, 
	VIPS_TYPE_FOREIGN_LOAD );

static void
vips_foreign_load_jp2k_dispose( GObject *gobject )
{
	VipsForeignLoadJp2k *jp2k = (VipsForeignLoadJp2k *) gobject;

	if( jp2k->codec &&
		jp2k->stream ) 
		opj_end_decompress( jp2k->codec,  jp2k->stream );
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

	if( vips_source_seek( source, n_bytes, SEEK_CUR ) )
		return( -1 );

	/* openjpeg skip uses -1 for both end of stream and error.
	 */
	return( n_bytes );
}

static OPJ_BOOL
vips_foreign_load_jp2k_seek_source( OPJ_OFF_T position, void *client )
{
	VipsSource *source = VIPS_SOURCE( client );

	if( vips_source_seek( source, position, SEEK_SET ) )
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

static void 
vips_foreign_load_jp2k_warning_callback( const char *msg, void *client )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( client );

	g_warning( "%s: %s",  class->nickname, msg );
}

static void 
vips_foreign_load_jp2k_info_callback( const char *msg, void *client )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( client );

	g_info( "%s: %s",  class->nickname, msg );
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
	printf( "nbcomps = %u\n", 
		jp2k->info->nbcomps );

}
#endif /*DEBUG*/

static int
vips_foreign_load_jp2k_set_header( VipsForeignLoadJp2k *jp2k, VipsImage *out )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( jp2k );

	opj_image_comp_t *first;
	int i;
	VipsBandFormat format;
	VipsInterpretation interpretation;

	/* We only allow images with all components having the same format.
	 */
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
			this->w != first->w ||
			this->h != first->h ||
			this->dx != first->dx ||
			this->dy != first->dy ||
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
	}

	if( first->w != jp2k->image->x1 ||
		first->h != jp2k->image->y1 ) {
		vips_error( class->nickname, 
			"%s", _( "components not same size as image" ) );
		return( -1 );
	}

	switch( first->prec ) {
	case 8:
		format = VIPS_FORMAT_UCHAR;
		break;

	case 16:
		format = VIPS_FORMAT_USHORT;
		break;

	default:
		vips_error( class->nickname, 
			_( "unsupported precision %d" ), first->prec );
		return( -1 );
	}

	switch( jp2k->image->color_space ) {
	case OPJ_CLRSPC_SRGB:
		interpretation = format == VIPS_FORMAT_UCHAR ? 
			VIPS_INTERPRETATION_sRGB :
			VIPS_INTERPRETATION_RGB16;
		break;

	case OPJ_CLRSPC_GRAY:
		interpretation = format == VIPS_FORMAT_UCHAR ? 
			VIPS_INTERPRETATION_B_W :
			VIPS_INTERPRETATION_GREY16;
		break;

	case OPJ_CLRSPC_CMYK:
		interpretation = VIPS_INTERPRETATION_CMYK;
		break;

	case OPJ_CLRSPC_UNSPECIFIED:
		if( jp2k->image->numcomps < 3 )
			interpretation = format == VIPS_FORMAT_UCHAR ?
				VIPS_INTERPRETATION_B_W :
				VIPS_INTERPRETATION_GREY16;
		else
			interpretation = format == VIPS_FORMAT_UCHAR ? 
				VIPS_INTERPRETATION_sRGB :
				VIPS_INTERPRETATION_RGB16;
		break;

	default:
		vips_error( class->nickname, 
			_( "unsupported colourspace %d" ), 
			jp2k->image->color_space );
		return( -1 );
	}

	vips_image_pipelinev( out, VIPS_DEMAND_STYLE_SMALLTILE, NULL );
	vips_image_init_fields( out,
		jp2k->image->x1, jp2k->image->y1, jp2k->image->numcomps, 
		format, 
		VIPS_CODING_NONE, interpretation, 1.0, 1.0 );

	/* openjpeg allows left and top of the coordinate grid to be
	 * non-zero. 
	 */
	out->Xoffset = -jp2k->image->x0;
	out->Yoffset = -jp2k->image->y0;

	if( jp2k->image->icc_profile_buf &&
		jp2k->image->icc_profile_len > 0 )
		vips_image_set_blob_copy( out, VIPS_META_ICC_NAME, 
			jp2k->image->icc_profile_buf,
			jp2k->image->icc_profile_len );

	return( 0 );
}

static int
vips_foreign_load_jp2k_header( VipsForeignLoad *load )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( load );
	VipsForeignLoadJp2k *jp2k = (VipsForeignLoadJp2k *) load;

	jp2k->format = vips_foreign_load_jp2k_get_format( jp2k->source );
	if( !(jp2k->codec = opj_create_decompress( jp2k->format )) ) {
		vips_error( class->nickname, 
			"%s", _( "format not supported by openjpeg" ) );
		return( -1 );
	}

	vips_foreign_load_jp2k_attach_handlers( jp2k, jp2k->codec );

	/* Useful:
	 *	jp2k->parameters.cp_reduce ... shrink on load factor
	 */
	if( !opj_setup_decoder( jp2k->codec, &jp2k->parameters ) ) 
		return( -1 );

	/* Use eg. VIPS_CONCURRENCY etc. to set n-cpus. 
	 */
	opj_codec_set_threads( jp2k->codec, vips_concurrency_get() );

	if( vips_source_rewind( jp2k->source ) ||
		!opj_read_header( jp2k->stream, jp2k->codec, &jp2k->image ) )
		return( -1 );

	if( !(jp2k->info = opj_get_cstr_info( jp2k->codec )) ) {
		vips_error( class->nickname, 
			"%s", _( "unable to read codec info" ) );
		return( -1 );
	}

#ifdef DEBUG
	vips_foreign_load_jp2k_print( jp2k );
#endif /*DEBUG*/

	if( vips_foreign_load_jp2k_set_header( jp2k, load->out ) ) 
		return( -1 );

	VIPS_SETSTR( load->out->filename, 
		vips_connection_filename( VIPS_CONNECTION( jp2k->source ) ) );

	return( 0 );
}

/* Loop over the output region, painting in tiles from the file.
 */
static int
vips_foreign_load_jp2k_generate( VipsRegion *out, 
	void *seq, void *a, void *b, gboolean *stop )
{
	VipsForeignLoadJp2k *jp2k = (VipsForeignLoadJp2k *) a;
	int tile_width = jp2k->info->tdx;
	int tile_height = jp2k->info->tdy;
	VipsRect *r = &out->valid;

	int tile_index;

	tile_index = 0;
#ifdef DEBUG
	printf( "vips_foreign_load_jp2k_generate: decoding tile_index %d\n", 
		tile_index );
#endif /*DEBUG*/
	if( !opj_get_decoded_tile( jp2k->codec, jp2k->stream, jp2k->image, 
		tile_index ) )
		return( -1 );

#ifdef DEBUG
	printf( "vips_foreign_load_jp2k_generate: decode success!\n" );
#endif /*DEBUG*/

	vips_foreign_load_jp2k_print_image( jp2k->image );

	return( 0 );
}

static int
vips_foreign_load_jp2k_load( VipsForeignLoad *load )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( load );
	VipsForeignLoadJp2k *jp2k = (VipsForeignLoadJp2k *) load;
	int tile_width = jp2k->info->tdx;
	int tile_height = jp2k->info->tdy;

	VipsImage **t = (VipsImage **) 
		vips_object_local_array( VIPS_OBJECT( load ), 3 );

#ifdef DEBUG
	printf( "vips_foreign_load_jp2k_load: loading image\n" );
#endif /*DEBUG*/

	/* Tile cache: keep enough for two complete rows of tiles.
	 */
	t[0] = vips_image_new();
	if( vips_foreign_load_jp2k_set_header( jp2k, t[0] ) ) 
		return( -1 );

	if( vips_image_generate( t[0], 
		NULL, vips_foreign_load_jp2k_generate, NULL, jp2k, NULL ) )
		return( -1 );

	/* Copy to out, adding a cache. Enough tiles for a complete 
	 * row, plus 50%.
	 */
	if( vips_tilecache( t[0], &t[1], 
		"tile_width", tile_width,
		"tile_height", tile_height,
		"max_tiles", (int) (1.5 * (1 + t[0]->Xsize / tile_width)),
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
		!(jp2k->source = 
			vips_source_new_from_file( file->filename )) )
		return( -1 );

	if( VIPS_OBJECT_CLASS( vips_foreign_load_jp2k_file_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

const char *vips_foreign_jp2k_suffs[] = 
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

	foreign_class->suffs = vips_foreign_jp2k_suffs;

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

#endif /*HAVE_LIBOPENJP2*/

/**
 * vips_jp2kload:
 * @filename: file to load
 * @out: (out): decompressed image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Read a JP2k image file into a VIPS image. 
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
 * vips_jp2kload_source:
 * @source: source to load from
 * @out: (out): decompressed image
 * @...: %NULL-terminated list of optional named arguments
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
