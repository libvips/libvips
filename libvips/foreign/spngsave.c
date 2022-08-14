/* save to spng
 *
 * 2/12/11
 * 	- wrap a class around the spng writer
 * 16/7/12
 * 	- compression should be 0-9, not 1-10
 * 20/6/18 [felixbuenemann]
 * 	- support spng8 palette write with palette, colours, Q, dither
 * 24/6/20
 * 	- add @bitdepth, deprecate @colours
 * 11/11/21
 * 	- use libspng for save
 * 15/7/22 [lovell]
 * 	- default filter to none
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
#include <glib/gi18n-lib.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vips/vips.h>

#include "pforeign.h"
#include "quantise.h"

#ifdef HAVE_SPNG

#include <spng.h>

typedef struct _VipsForeignSaveSpng {
	VipsForeignSave parent_object;

	int compression;
	gboolean interlace;
	char *profile;
	VipsForeignPngFilter filter;
	gboolean palette;
	int Q;
	double dither;
	int bitdepth;
	int effort;

	/* Set by subclasses.
	 */
	VipsTarget *target;

	/* Write state.
	 */
	spng_ctx *ctx;
	GSList *text_chunks;
	VipsImage *memory;
	size_t sizeof_line;
	VipsPel *line;

	/* Deprecated.
	 */
	int colours;

} VipsForeignSaveSpng;

typedef VipsForeignSaveClass VipsForeignSaveSpngClass;

G_DEFINE_ABSTRACT_TYPE( VipsForeignSaveSpng, vips_foreign_save_spng, 
	VIPS_TYPE_FOREIGN_SAVE );

static void
vips_foreign_save_spng_dispose( GObject *gobject )
{
	VipsForeignSaveSpng *spng = (VipsForeignSaveSpng *) gobject;

	GSList *p;

	VIPS_UNREF( spng->target );
	VIPS_UNREF( spng->memory );
	VIPS_FREEF( spng_ctx_free, spng->ctx );

	for( p = spng->text_chunks; p; p = p->next ) {
		struct spng_text *text = (struct spng_text *) p->data;

		VIPS_FREE( text->text );
		VIPS_FREE( text );
	}
	VIPS_FREEF( g_slist_free, spng->text_chunks );

	VIPS_FREE( spng->line );

	G_OBJECT_CLASS( vips_foreign_save_spng_parent_class )->
		dispose( gobject );
}

static int
vips_foreign_save_spng_text( VipsForeignSaveSpng *spng, 
	const char *keyword, const char *value )
{
	struct spng_text *text = VIPS_NEW( NULL, struct spng_text );

	vips_strncpy( text->keyword, keyword, sizeof( text->keyword ) );
	/* FIXME ... is this right?
	 */
	text->type = SPNG_TEXT;
	text->length = strlen( value );
	text->text = g_strdup( value );

	spng->text_chunks = g_slist_prepend( spng->text_chunks, text );
	
	return( 0 );
}

static void *
vips_foreign_save_spng_comment( VipsImage *image, 
	const char *field, GValue *value, void *user_data )
{
	VipsForeignSaveSpng *spng = (VipsForeignSaveSpng *) user_data;

	if( vips_isprefix( "png-comment-", field ) ) { 
		const char *value;
		int i;
		char key[256];

		if( vips_image_get_string( image, field, &value ) )
			return( image );

		if( strlen( field ) > 256 ||
			sscanf( field, "png-comment-%d-%80s", &i, key ) != 2 ) {
			vips_error( "vips2png", 
				"%s", _( "bad png comment key" ) );
			return( image );
		}

		vips_foreign_save_spng_text( spng, key, value );
	}

	return( NULL );
}

static int
vips_foreign_save_spng_metadata( VipsForeignSaveSpng *spng, VipsImage *in ) 
{
	struct spng_iccp iccp;
	uint32_t n_text;
	struct spng_text *text_chunk_array;
	int i;
	GSList *p;

	if( spng->profile ) {
		VipsBlob *blob;

		if( vips_profile_load( spng->profile, &blob, NULL ) )
			return( -1 );
		if( blob ) {
			size_t length;
			const void *data = vips_blob_get( blob, &length );
			char *basename = g_path_get_basename( spng->profile );

#ifdef DEBUG
			printf( "write_vips: attaching %zd bytes "
				"of ICC profile\n", length );
#endif /*DEBUG*/

			vips_strncpy( iccp.profile_name, basename, 
				sizeof( iccp.profile_name ) );
			iccp.profile_len = length;
			iccp.profile = (void *) data;
			spng_set_iccp( spng->ctx, &iccp );

			vips_area_unref( (VipsArea *) blob );
			g_free( basename );
		}
	}
	else if( vips_image_get_typeof( in, VIPS_META_ICC_NAME ) ) {
		const void *data;
		size_t length;

		if( vips_image_get_blob( in, VIPS_META_ICC_NAME,
			&data, &length ) )
			return( -1 );

#ifdef DEBUG
		printf( "write_vips: attaching %zd bytes "
			"of ICC profile\n", length );
#endif /*DEBUG*/

		vips_strncpy( iccp.profile_name, "", 
			sizeof( iccp.profile_name ) );
		iccp.profile_len = length;
		iccp.profile = (void *) data;

		spng_set_iccp( spng->ctx, &iccp );
	}

	if( vips_image_get_typeof( in, VIPS_META_XMP_NAME ) ) {
		const void *data;
		size_t length;
		char *str;

		if( vips_image_get_blob( in,
			VIPS_META_XMP_NAME, &data, &length ) )
			return( -1 );

		/* The blob form of the XMP metadata is missing the
		 * terminating \0 bytes, we have to paste it back,
		 * unfortunately. See pngload.
		 */
		str = g_malloc( length + 1 );
		vips_strncpy( str, data, length + 1 );
		vips_foreign_save_spng_text( spng, "XML:com.adobe.xmp", str );
		g_free( str );
	}

	if( vips_image_map( in, vips_foreign_save_spng_comment, spng ) )
		return( -1 );

	n_text = g_slist_length( spng->text_chunks );
	text_chunk_array = VIPS_ARRAY( NULL, n_text, struct spng_text );
	for( i = 0, p = spng->text_chunks; p; p = p->next, i++ ) {
		struct spng_text *text = (struct spng_text *) p->data;

		text_chunk_array[i] = *text;
	}
#ifdef DEBUG
	printf( "attaching %u text items\n", n_text );
#endif /*DEBUG*/
	spng_set_text( spng->ctx, text_chunk_array, n_text );
	VIPS_FREE( text_chunk_array );

	return( 0 );
}

/* Pack a line of 1/2/4 bit index values.
 */
static void
vips_foreign_save_spng_pack( VipsForeignSaveSpng *spng, 
	VipsPel *q, VipsPel *p, size_t n )
{
        int pixel_mask = 8 / spng->bitdepth - 1;
	int shift = 8 - spng->bitdepth;

        VipsPel bits;
        size_t x;

        bits = 0;
        for( x = 0; x < n; x++ ) {
                bits <<= spng->bitdepth;
		bits |= p[x] >> shift;

                if( (x & pixel_mask) == pixel_mask )
                        *q++ = bits;
        }

        /* Any left-over bits? Need to be left-aligned.
         */
        if( (x & pixel_mask) != 0 ) {
                /* The number of bits we've collected and must
                 * left-align and flush.
                 */
                int collected_bits = (x & pixel_mask) << (spng->bitdepth - 1);

                *q++ = bits << (8 - collected_bits);
        }
}

static int 
vips_foreign_save_spng_write_fn( spng_ctx *ctx, void *user, 
	void *data, size_t n )
{
	VipsForeignSaveSpng *spng = (VipsForeignSaveSpng *) user;

	if( vips_target_write( spng->target, data, n ) )
		return( SPNG_IO_ERROR );

	return( 0 );
}

static int
vips_foreign_save_spng_write_block( VipsRegion *region, VipsRect *area, 
	void *user )
{
	VipsForeignSaveSpng *spng = (VipsForeignSaveSpng *) user;
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( spng );

	int y;
	int error;

	/* The area to write is always a set of complete scanlines.
	 */
	g_assert( area->left == 0 );
	g_assert( area->width == region->im->Xsize );
	g_assert( area->top + area->height <= region->im->Ysize );

	for( y = 0; y < area->height; y++ ) {
		VipsPel *line;
		size_t sizeof_line;

		line = VIPS_REGION_ADDR( region, 0, area->top + y );
		sizeof_line = VIPS_REGION_SIZEOF_LINE( region );

		if( spng->bitdepth < 8 ) {
			vips_foreign_save_spng_pack( spng,
				spng->line, line, sizeof_line );
			line = spng->line;
			sizeof_line = spng->sizeof_line;
		}

		if( (error = spng_encode_row( spng->ctx, line, sizeof_line )) )
			break;
	}

	/* You can get SPNG_EOI for the final scanline.
	 */
	if( error && 
		error != SPNG_EOI ) {
		vips_error( class->nickname, "%s", spng_strerror( error ) ); 
		return( -1 );
	}

	return( 0 );
}

static int
vips_foreign_save_spng_write( VipsForeignSaveSpng *spng, VipsImage *in ) 
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( spng );
	VipsForeignSave *save = (VipsForeignSave *) spng;

	int error;
	struct spng_ihdr ihdr;
	struct spng_phys phys;
	struct spng_plte plte = { 0 };
	struct spng_trns trns = { 0 };
	int fmt;
	enum spng_encode_flags encode_flags;

	spng->ctx = spng_ctx_new( SPNG_CTX_ENCODER );

	if( (error = spng_set_png_stream( spng->ctx, 
		vips_foreign_save_spng_write_fn, spng )) ) {
		vips_error( class->nickname, "%s", spng_strerror( error ) ); 
		return( -1 );
	}

#ifdef HAVE_QUANTIZATION
	if( spng->palette ) {
		VipsImage *im_index;
		VipsImage *im_palette;
		int palette_count;
		int i;

		if( vips__quantise_image( in, &im_index, &im_palette, 
			1 << spng->bitdepth, 
			spng->Q, 
			spng->dither, 
			spng->effort, 
			FALSE ) )
			return( -1 );

		/* PNG is 8-bit index only.
		 */
		palette_count = im_palette->Xsize;
		g_assert( palette_count <= 256 );

		for( i = 0; i < palette_count; i++ ) {
			VipsPel *p = (VipsPel *) 
				VIPS_IMAGE_ADDR( im_palette, i, 0 );
			struct spng_plte_entry *entry =
				&plte.entries[plte.n_entries];

			entry->red = p[0];
			entry->green = p[1];
			entry->blue = p[2];
			plte.n_entries += 1;

			/* Quantizr and libimagequant sort the pallette
			 * by transparency, so trns.type3_alpha[] and
			 * plte.entries[] will use the same indexing.
			 */
			g_assert( i == 0 || p[3] >= p[-1] );
			if( p[3] != 255 ) {
				trns.type3_alpha[trns.n_type3_entries] = p[3];
				trns.n_type3_entries += 1;
			}
		}

#ifdef DEBUG
		printf( "attaching %d entry palette\n", plte.n_entries );
		if( trns.n_type3_entries )
			printf( "attaching %d transparency values\n", 
			     trns.n_type3_entries );
#endif /*DEBUG*/

		VIPS_UNREF( im_palette );

		in = spng->memory = im_index;
	}
#endif /*HAVE_QUANTIZATION*/

	ihdr.width = in->Xsize;
	ihdr.height = in->Ysize;
	ihdr.bit_depth = spng->bitdepth;

	/* Low-bitdepth write needs an extra buffer for packing pixels.
	 */
	if( spng->bitdepth < 8 ) {
		spng->sizeof_line = 1 + VIPS_IMAGE_SIZEOF_LINE( in ) / 
			(8 / spng->bitdepth);

		if( !(spng->line = 
			vips_malloc( NULL, VIPS_IMAGE_SIZEOF_LINE( in ) )) )
			return( -1 );
	}

	switch( in->Bands ) {
	case 1:
		if( spng->palette )
			ihdr.color_type = SPNG_COLOR_TYPE_INDEXED; 
		else
			ihdr.color_type = SPNG_COLOR_TYPE_GRAYSCALE;
		break;

	case 2:
		ihdr.color_type = SPNG_COLOR_TYPE_GRAYSCALE_ALPHA; 
		break;

	case 3:
		ihdr.color_type = SPNG_COLOR_TYPE_TRUECOLOR;
		break;

	case 4: 
		ihdr.color_type = SPNG_COLOR_TYPE_TRUECOLOR_ALPHA; 
		break;

	default:
		vips_error( class->nickname, "%s", _( "bad bands" ) );
		return( -1 );
	}

	ihdr.compression_method = 0;
	ihdr.filter_method = 0;
	ihdr.interlace_method = spng->interlace ? 1 : 0;
	if( (error = spng_set_ihdr( spng->ctx, &ihdr )) ) {
		vips_error( class->nickname, "%s", spng_strerror( error ) ); 
		return( -1 );
	}

	spng_set_option( spng->ctx, 
		SPNG_IMG_COMPRESSION_LEVEL, spng->compression );
	spng_set_option( spng->ctx, 
		SPNG_TEXT_COMPRESSION_LEVEL, spng->compression );
	spng_set_option( spng->ctx, 
		SPNG_FILTER_CHOICE, spng->filter );

	/* Set resolution. png uses pixels per meter.
	 */
	phys.unit_specifier = 1;
	phys.ppu_x = VIPS_RINT( in->Xres * 1000.0 );
	phys.ppu_y = VIPS_RINT( in->Xres * 1000.0 );
	spng_set_phys( spng->ctx, &phys );

	/* Metadata.
	 */
	if( !save->strip &&
		vips_foreign_save_spng_metadata( spng, in ) )
		return( -1 );

#ifdef HAVE_QUANTIZATION
	if( spng->palette ) {
		spng_set_plte( spng->ctx, &plte );
		if( trns.n_type3_entries ) 
			spng_set_trns( spng->ctx, &trns );
	}
#endif /*HAVE_QUANTIZATION*/

	/* SPNG_FMT_PNG is a special value that matches the format in ihdr 
	 */
	fmt = SPNG_FMT_PNG;
	encode_flags = SPNG_ENCODE_PROGRESSIVE | SPNG_ENCODE_FINALIZE;
	if( (error = spng_encode_image( spng->ctx, 
		NULL, -1, fmt, encode_flags )) ) {
		vips_error( class->nickname, "%s", spng_strerror( error ) ); 
		return( -1 );
	}

	if( spng->interlace ) {
		/* Force the input into memory, if it's not there already.
		 */
		if( !spng->memory ) {
			if( !(spng->memory = vips_image_copy_memory( in )) )
				return( -1 );
			in = spng->memory;
		}

		do {
			struct spng_row_info row_info;
			VipsPel *line;
			size_t sizeof_line;

			if( (error = 
				spng_get_row_info( spng->ctx, &row_info )) )
				break;

			line = VIPS_IMAGE_ADDR( in, 0, row_info.row_num );
			sizeof_line = VIPS_IMAGE_SIZEOF_LINE( in );

			if( spng->bitdepth < 8 ) {
				vips_foreign_save_spng_pack( spng,
					spng->line, line, sizeof_line );
				line = spng->line;
				sizeof_line = spng->sizeof_line;
			}

			error = spng_encode_row( spng->ctx, line, sizeof_line );
		} while( !error );

		if( error != SPNG_EOI ) {
			vips_error( class->nickname, 
				"%s", spng_strerror( error ) ); 
			return( -1 );
		}
	}
	else {
		if( vips_sink_disc( in, 
			vips_foreign_save_spng_write_block, spng ) )
			return( -1 );
	}

	if( vips_target_end( spng->target ) )
		return( -1 );

	return( 0 );
}

static int
vips_foreign_save_spng_build( VipsObject *object )
{
	VipsForeignSave *save = (VipsForeignSave *) object;
	VipsForeignSaveSpng *spng = (VipsForeignSaveSpng *) object;

	VipsImage *in;

	if( VIPS_OBJECT_CLASS( vips_foreign_save_spng_parent_class )->
		build( object ) )
		return( -1 );

	in = save->ready;
	g_object_ref( in );

	/* If no output bitdepth has been specified, use input Type to pick.
	 */
        if( !vips_object_argument_isset( object, "bitdepth" ) ) 
		spng->bitdepth = 
                        in->Type == VIPS_INTERPRETATION_RGB16 ||
                        in->Type == VIPS_INTERPRETATION_GREY16 ? 16 : 8;

	/* Deprecated "colours" arg just sets bitdepth large enough to hold
	 * that many colours.
	 */
        if( vips_object_argument_isset( object, "colours" ) ) 
		spng->bitdepth = ceil( log2( spng->colours ) );

	/* Cast in down to 8 bit if we can.
	 */
	if( spng->bitdepth <= 8 ) { 
		VipsImage *x;

		if( vips_cast( in, &x, VIPS_FORMAT_UCHAR, NULL ) ) {
			g_object_unref( in );
			return( -1 );
		}
		g_object_unref( in );
		in = x;
	}

	/* If this is a RGB or RGBA image and a low bit depth has been
	 * requested, enable palettisation.
	 */
        if( in->Bands > 2 &&
		spng->bitdepth < 8 )
		spng->palette = TRUE;

        /* Disable palettization for >8 bit save.
         */
        if( spng->bitdepth >= 8 )
		spng->palette = FALSE;

	if( vips_foreign_save_spng_write( spng, in ) ) {
		g_object_unref( in );
		return( -1 );
	}

	g_object_unref( in );

	return( 0 );
}

/* Except for 8-bit inputs, we send everything else to 16. We decide on spng8
 * vs. spng16 based on Type in_build(), see above.
 */
#define UC VIPS_FORMAT_UCHAR
#define US VIPS_FORMAT_USHORT
static int bandfmt_spng[10] = {
/* UC  C   US  S   UI  I   F   X   D   DX */
   UC, UC, US, US, US, US, US, US, US, US
};

static void
vips_foreign_save_spng_class_init( VipsForeignSaveSpngClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;
	VipsForeignSaveClass *save_class = (VipsForeignSaveClass *) class;

	gobject_class->dispose = vips_foreign_save_spng_dispose;
	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "spngsave_base";
	object_class->description = _( "save spng" );
	object_class->build = vips_foreign_save_spng_build;

	foreign_class->suffs = vips__png_suffs;

	save_class->saveable = VIPS_SAVEABLE_RGBA;
	save_class->format_table = bandfmt_spng;

	VIPS_ARG_INT( class, "compression", 6, 
		_( "Compression" ), 
		_( "Compression factor" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveSpng, compression ),
		0, 9, 6 );

	VIPS_ARG_BOOL( class, "interlace", 7, 
		_( "Interlace" ), 
		_( "Interlace image" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveSpng, interlace ),
		FALSE );

	VIPS_ARG_STRING( class, "profile", 11, 
		_( "Profile" ), 
		_( "ICC profile to embed" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveSpng, profile ),
		NULL );

	VIPS_ARG_FLAGS( class, "filter", 12,
		_( "Filter" ),
		_( "libspng row filter flag(s)" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveSpng, filter ),
		VIPS_TYPE_FOREIGN_PNG_FILTER,
		VIPS_FOREIGN_PNG_FILTER_NONE );

	VIPS_ARG_BOOL( class, "palette", 13,
		_( "Palette" ),
		_( "Quantise to 8bpp palette" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveSpng, palette ),
		FALSE );

	VIPS_ARG_INT( class, "Q", 15,
		_( "Quality" ),
		_( "Quantisation quality" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveSpng, Q ),
		0, 100, 100 );

	VIPS_ARG_DOUBLE( class, "dither", 16,
		_( "Dithering" ),
		_( "Amount of dithering" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveSpng, dither ),
		0.0, 1.0, 1.0 );

	VIPS_ARG_INT( class, "bitdepth", 17,
		_( "Bit depth" ),
		_( "Write as a 1, 2, 4, 8 or 16 bit image" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveSpng, bitdepth ),
		0, 16, 0 );

	VIPS_ARG_INT( class, "effort", 18,
		_( "Effort" ),
		_( "Quantisation CPU effort" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveSpng, effort ),
		1, 10, 7 );

	VIPS_ARG_INT( class, "colours", 14,
		_( "Colours" ),
		_( "Max number of palette colours" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT | VIPS_ARGUMENT_DEPRECATED,
		G_STRUCT_OFFSET( VipsForeignSaveSpng, colours ),
		2, 256, 256 );

}

static void
vips_foreign_save_spng_init( VipsForeignSaveSpng *spng )
{
	spng->compression = 6;
	spng->filter = VIPS_FOREIGN_PNG_FILTER_NONE;
	spng->Q = 100;
	spng->dither = 1.0;
	spng->effort = 7;
}

typedef struct _VipsForeignSaveSpngTarget {
	VipsForeignSaveSpng parent_object;

	VipsTarget *target;
} VipsForeignSaveSpngTarget;

typedef VipsForeignSaveSpngClass VipsForeignSaveSpngTargetClass;

G_DEFINE_TYPE( VipsForeignSaveSpngTarget, vips_foreign_save_spng_target, 
	vips_foreign_save_spng_get_type() );

static int
vips_foreign_save_spng_target_build( VipsObject *object )
{
	VipsForeignSaveSpng *spng = (VipsForeignSaveSpng *) object;
	VipsForeignSaveSpngTarget *target = 
		(VipsForeignSaveSpngTarget *) object;

	spng->target = target->target;
	g_object_ref( spng->target );

	if( VIPS_OBJECT_CLASS( vips_foreign_save_spng_target_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

static void
vips_foreign_save_spng_target_class_init( VipsForeignSaveSpngTargetClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "pngsave_target";
	object_class->description = _( "save image to target as PNG" );
	object_class->build = vips_foreign_save_spng_target_build;

	VIPS_ARG_OBJECT( class, "target", 1,
		_( "Target" ),
		_( "Target to save to" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignSaveSpngTarget, target ),
		VIPS_TYPE_TARGET );

}

static void
vips_foreign_save_spng_target_init( VipsForeignSaveSpngTarget *target )
{
}

typedef struct _VipsForeignSaveSpngFile {
	VipsForeignSaveSpng parent_object;

	char *filename; 
} VipsForeignSaveSpngFile;

typedef VipsForeignSaveSpngClass VipsForeignSaveSpngFileClass;

G_DEFINE_TYPE( VipsForeignSaveSpngFile, vips_foreign_save_spng_file, 
	vips_foreign_save_spng_get_type() );

static int
vips_foreign_save_spng_file_build( VipsObject *object )
{
	VipsForeignSaveSpng *spng = (VipsForeignSaveSpng *) object;
	VipsForeignSaveSpngFile *file = (VipsForeignSaveSpngFile *) object;

	if( !(spng->target = vips_target_new_to_file( file->filename )) )
		return( -1 );

	if( VIPS_OBJECT_CLASS( vips_foreign_save_spng_file_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

static void
vips_foreign_save_spng_file_class_init( VipsForeignSaveSpngFileClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "pngsave";
	object_class->description = _( "save image to file as PNG" );
	object_class->build = vips_foreign_save_spng_file_build;

	VIPS_ARG_STRING( class, "filename", 1, 
		_( "Filename" ),
		_( "Filename to save to" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignSaveSpngFile, filename ),
		NULL );
}

static void
vips_foreign_save_spng_file_init( VipsForeignSaveSpngFile *file )
{
}

typedef struct _VipsForeignSaveSpngBuffer {
	VipsForeignSaveSpng parent_object;

	VipsArea *buf;
} VipsForeignSaveSpngBuffer;

typedef VipsForeignSaveSpngClass VipsForeignSaveSpngBufferClass;

G_DEFINE_TYPE( VipsForeignSaveSpngBuffer, vips_foreign_save_spng_buffer, 
	vips_foreign_save_spng_get_type() );

static int
vips_foreign_save_spng_buffer_build( VipsObject *object )
{
	VipsForeignSaveSpng *spng = (VipsForeignSaveSpng *) object;
	VipsForeignSaveSpngBuffer *buffer = 
		(VipsForeignSaveSpngBuffer *) object;

	VipsBlob *blob;

	if( !(spng->target = vips_target_new_to_memory()) )
		return( -1 );

	if( VIPS_OBJECT_CLASS( vips_foreign_save_spng_buffer_parent_class )->
		build( object ) )
		return( -1 );

	g_object_get( spng->target, "blob", &blob, NULL );
	g_object_set( buffer, "buffer", blob, NULL );
	vips_area_unref( VIPS_AREA( blob ) );

	return( 0 );
}

static void
vips_foreign_save_spng_buffer_class_init( VipsForeignSaveSpngBufferClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "pngsave_buffer";
	object_class->description = _( "save image to buffer as PNG" );
	object_class->build = vips_foreign_save_spng_buffer_build;

	VIPS_ARG_BOXED( class, "buffer", 1, 
		_( "Buffer" ),
		_( "Buffer to save to" ),
		VIPS_ARGUMENT_REQUIRED_OUTPUT, 
		G_STRUCT_OFFSET( VipsForeignSaveSpngBuffer, buf ),
		VIPS_TYPE_BLOB );
}

static void
vips_foreign_save_spng_buffer_init( VipsForeignSaveSpngBuffer *buffer )
{
}

#endif /*HAVE_SPNG*/
