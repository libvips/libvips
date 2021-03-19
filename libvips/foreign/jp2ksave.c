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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

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

	/* Encoder state.
	 */
	opj_stream_t *stream;
	opj_codec_t *codec;
	opj_cparameters_t parameters;
	opj_image_cmptparm_t comps[MAX_BANDS];
	opj_image_t *image;

	/* The line of tiles we are building, and a contiguous buffer we
	 * repack to for output.
	 */
	VipsRegion *strip;
	VipsPel *tile_buffer;
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

	G_OBJECT_CLASS( vips_foreign_save_jp2k_parent_class )->
		dispose( gobject );
}

static OPJ_SIZE_T
vips_foreign_save_jp2k_write_target( void *buffer, size_t length, void *client )
{
	VipsTarget *target = VIPS_TARGET( client );

	if( vips_target_write( target, buffer, length ) )
		return( 0 );

	return( length );
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
		vips_foreign_save_jp2k_write_target );

	return( stream );
}

static void 
vips_foreign_save_jp2k_error_callback( const char *msg, void *client )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( client );

	vips_error( class->nickname, "%s", msg ); 
}

/* The openjpeg info and warning callbacks are incredibly chatty.
 */
static void 
vips_foreign_save_jp2k_warning_callback( const char *msg, void *client )
{
#ifdef DEBUG
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( client );

	g_warning( "%s: %s",  class->nickname, msg );
#endif /*DEBUG*/
}

/* The openjpeg info and warning callbacks are incredibly chatty.
 */
static void 
vips_foreign_save_jp2k_info_callback( const char *msg, void *client )
{
#ifdef DEBUG
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( client );

	g_info( "%s: %s",  class->nickname, msg );
#endif /*DEBUG*/
}

static void
vips_foreign_save_jp2k_attach_handlers( VipsForeignSaveJp2k *jp2k,
	opj_codec_t *codec )
{
	opj_set_info_handler( codec, 
		vips_foreign_save_jp2k_info_callback, jp2k );
	opj_set_warning_handler( codec, 
		vips_foreign_save_jp2k_warning_callback, jp2k );
	opj_set_error_handler( codec, 
		vips_foreign_save_jp2k_error_callback, jp2k );
}

#define UNPACK( TYPE ) { \
	TYPE **tplanes = (TYPE **) planes; \
	TYPE *tp = (TYPE *) p; \
	\
	for( x = 0; x < tile->width; x++ ) \
		for( i = 0; i < b; i++ ) \
			*(tplanes[i])++ = *tp++; \
}

static void
vips_foreign_save_jp2k_unpack( VipsForeignSaveJp2k *jp2k, VipsRect *tile )
{
	VipsForeignSave *save = (VipsForeignSave *) jp2k;
	size_t sizeof_element = VIPS_IMAGE_SIZEOF_ELEMENT( save->ready );
	int b = save->ready->Bands;

	VipsPel *planes[MAX_BANDS];
	int x, y, i;

	for( i = 0; i < b; i++ )
		planes[i] = jp2k->tile_buffer +
			i * sizeof_element * tile->width * tile->height;

	for( y = 0; y < tile->height; y++ ) {
		VipsPel *p = VIPS_REGION_ADDR( jp2k->strip, 
			tile->left, tile->top + y );

		switch( save->ready->BandFmt ) {
		case VIPS_FORMAT_UCHAR:
			UNPACK( unsigned char );
			break;

		case VIPS_FORMAT_USHORT:
			UNPACK( unsigned short );
			break;

		default:
			g_assert_not_reached();
			break;
		}
	}
}

static int
vips_foreign_save_jp2k_write_tiles( VipsForeignSaveJp2k *jp2k )
{
	VipsForeignSave *save = (VipsForeignSave *) jp2k;
	size_t sizeof_pel = VIPS_IMAGE_SIZEOF_PEL( save->ready );
	int tiles_across = 
		VIPS_ROUND_UP( save->ready->Xsize, jp2k->tile_width ) /
			jp2k->tile_width;

	int x;

	for( x = 0; x < save->ready->Xsize; x += jp2k->tile_width ) {
		VipsRect tile;
		size_t sizeof_tile;
		int tile_index;

		tile.left = x;
		tile.top = jp2k->strip->valid.top;
		tile.width = jp2k->tile_width;
		tile.height = jp2k->tile_height;
		vips_rect_intersectrect( &tile, &jp2k->strip->valid, &tile );

		vips_foreign_save_jp2k_unpack( jp2k, &tile );

		sizeof_tile = sizeof_pel * tile.width * tile.height;
		tile_index = tiles_across * tile.top / jp2k->tile_height +
			x / jp2k->tile_width;
		if( !opj_write_tile( jp2k->codec, tile_index, 
			jp2k->tile_buffer, sizeof_tile, jp2k->stream ) )
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
		VipsRect hit;
		int y;
		VipsRect strip_position;

		/* The intersection with the strip is the fresh pixels we
		 * have. 
		 */
		vips_rect_intersectrect( area, &(jp2k->strip->valid), &hit );

		/* Copy the new pixels into the strip.
		 */
		for( y = 0; y < hit.height; y++ ) {
			VipsPel *p = VIPS_REGION_ADDR( region, 
				0, hit.top + y );
			VipsPel *q = VIPS_REGION_ADDR( jp2k->strip, 
				0, hit.top + y );

			memcpy( q, p, VIPS_IMAGE_SIZEOF_LINE( region->im ) );
		}

		/* Have we failed to reach the bottom of the strip? We must
		 * have run out of fresh pixels, so we are done.
		 */
		if( VIPS_RECT_BOTTOM( &hit ) != 
			VIPS_RECT_BOTTOM( &jp2k->strip->valid ) ) 
			break;

		/* We have reached the bottom of the strip. Write this line of
		 * pixels and ove the strip down.
		 */
		if( vips_foreign_save_jp2k_write_tiles( jp2k ) )
			return( -1 );

		strip_position.left = 0;
		strip_position.top = jp2k->strip->valid.top + jp2k->tile_height;
		strip_position.width = save->ready->Xsize;
		strip_position.height = jp2k->tile_height;
		if( vips_region_buffer( jp2k->strip, &strip_position ) )
			return( -1 );
	}

	return( 0 );
}

static int
vips_foreign_save_jp2k_build( VipsObject *object )
{
	VipsForeignSave *save = (VipsForeignSave *) object;
	VipsForeignSaveJp2k *jp2k = (VipsForeignSaveJp2k *) object;

	OPJ_COLOR_SPACE color_space;
	int expected_bands;
	int i;
	size_t sizeof_tile;
	VipsRect strip_position;

	if( VIPS_OBJECT_CLASS( vips_foreign_save_jp2k_parent_class )->
		build( object ) )
		return( -1 );

	/* A JPEG2000 codestream.
	 */
	jp2k->codec = opj_create_compress( OPJ_CODEC_J2K );

	vips_foreign_save_jp2k_attach_handlers( jp2k, jp2k->codec );

	opj_set_default_encoder_parameters( &jp2k->parameters );

	/* Always tile.
	 */
	jp2k->parameters.tile_size_on = OPJ_TRUE;
	jp2k->parameters.cp_tdx = jp2k->tile_width;
	jp2k->parameters.cp_tdy = jp2k->tile_height;

	/*
	jp2k->parameters.tcp_numlayers = 1;
	jp2k->parameters.decod_format = 17;
	jp2k->parameters.tcp_mct = 1;
	 */

	/* Enable YCC encoding for RGB images.
	    if ((parameters.tcp_mct == 1) && (image->numcomps < 3)) {
                fprintf(stderr, "RGB->YCC conversion cannot be used:\n");
                fprintf(stderr, "Input image has less than 3 components\n");
	 */

	/* CIELAB etc. do not seem to be well documented.
	 */
	switch( save->ready->Type ) {
	case VIPS_INTERPRETATION_B_W:
	case VIPS_INTERPRETATION_GREY16:
		color_space = OPJ_CLRSPC_GRAY;
		expected_bands = 1;
		break;

	case VIPS_INTERPRETATION_sRGB:
	case VIPS_INTERPRETATION_RGB16:
		color_space = OPJ_CLRSPC_SRGB;
		expected_bands = 3;
		break;

	case VIPS_INTERPRETATION_CMYK:
		color_space = OPJ_CLRSPC_CMYK;
		expected_bands = 4;
		break;

	default:
		color_space = OPJ_CLRSPC_UNSPECIFIED;
		expected_bands = save->ready->Bands;
		break;
	}

	for( i = 0; i < save->ready->Bands; i++ ) {
		jp2k->comps[i].dx = 1;
		jp2k->comps[i].dy = 1;
		jp2k->comps[i].w = save->ready->Xsize;
		jp2k->comps[i].h = save->ready->Ysize;
		jp2k->comps[i].x0 = 0;
		jp2k->comps[i].y0 = 0;
		jp2k->comps[i].prec = jp2k->comps[i].bpp = 
			save->ready->BandFmt == VIPS_FORMAT_UCHAR ? 8 : 16;
		jp2k->comps[i].sgnd = 0;
		//jp2k->comps[i].alpha = i >= expected_bands;
	}
	jp2k->image = opj_image_create( save->ready->Bands, 
		jp2k->comps, color_space );
	jp2k->image->x1 = save->ready->Xsize;
	jp2k->image->y1 = save->ready->Ysize;

        if( !opj_setup_encoder( jp2k->codec, &jp2k->parameters, jp2k->image ) ) 
		return( -1 );

	opj_codec_set_threads( jp2k->codec, vips_concurrency_get() );

	if( !(jp2k->stream = vips_foreign_save_jp2k_target( jp2k->target )) )
		return( -1 );

	if( !opj_start_compress( jp2k->codec,  jp2k->image,  jp2k->stream ) )
		return( -1 );

	/* The buffer we repack tiles to for write. Large enough for one
	 * complete tile.
	 */
	sizeof_tile = VIPS_IMAGE_SIZEOF_PEL( save->ready ) *
		jp2k->tile_width * jp2k->tile_height;
	if( !(jp2k->tile_buffer = VIPS_ARRAY( NULL, sizeof_tile, VipsPel )) )
		return( -1 );

	/* The line of tiles we are building.
	 */
	jp2k->strip = vips_region_new( save->ready );

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

	vips_target_finish( jp2k->target );

	return( 0 );
}

/* Save a bit of typing.
 */
#define UC VIPS_FORMAT_UCHAR
#define US VIPS_FORMAT_USHORT

static int vips_jp2k_bandfmt[10] = {
/* UC  C   US  S   UI  I   F   X   D   DX */
   UC, UC, US, US, US, US, US, US, US, US
};

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
	object_class->description = _( "save image in HEIF format" );
	object_class->build = vips_foreign_save_jp2k_build;

	foreign_class->suffs = vips__jp2k_suffs;

	save_class->saveable = VIPS_SAVEABLE_ANY;
	save_class->format_table = vips_jp2k_bandfmt;

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

}

static void
vips_foreign_save_jp2k_init( VipsForeignSaveJp2k *jp2k )
{
	jp2k->tile_width = 512;
	jp2k->tile_height = 512;
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

#endif /*HAVE_LIBOPENJP2*/

/**
 * vips_jp2ksave: (method)
 * @in: image to save 
 * @filename: file to write to 
 * @...: %NULL-terminated list of optional named arguments
 *
 * Write a VIPS image to a file in JPEG2000 format. 
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
 * vips_jp2ksave_target: (method)
 * @in: image to save 
 * @target: save image to this target
 * @...: %NULL-terminated list of optional named arguments
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
