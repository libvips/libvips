/* load PNG with libspng
 *
 * 1/5/20
 * 	- from pngload.c
 * 19/2/21 781545872
 * 	- read out background, if we can
 * 29/8/21 joshuamsager
 *	-  add "unlimited" flag to png load
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
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <glib/gi18n-lib.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vips/vips.h>
#include <vips/buf.h>
#include <vips/internal.h>

#include "pforeign.h"

#ifdef HAVE_SPNG

#include <spng.h>

typedef struct _VipsForeignLoadPng {
	VipsForeignLoad parent_object;

	/* Set by subclasses.
	 */
	VipsSource *source;

	/* Remove DoS limits.
	 */
	gboolean unlimited;

	spng_ctx *ctx;
	struct spng_ihdr ihdr;
	enum spng_format fmt;
	int bands;
	VipsInterpretation interpretation;
	VipsBandFormat format;
	int y_pos;
} VipsForeignLoadPng;

typedef VipsForeignLoadClass VipsForeignLoadPngClass;

G_DEFINE_ABSTRACT_TYPE( VipsForeignLoadPng, vips_foreign_load_png, 
	VIPS_TYPE_FOREIGN_LOAD );

static void
vips_foreign_load_png_dispose( GObject *gobject )
{
	VipsForeignLoadPng *png = (VipsForeignLoadPng *) gobject;

	VIPS_FREEF( spng_ctx_free, png->ctx );
	VIPS_UNREF( png->source );

	G_OBJECT_CLASS( vips_foreign_load_png_parent_class )->
		dispose( gobject );
}

static int 
vips_foreign_load_png_stream( spng_ctx *ctx, void *user, 
	void *dest, size_t length )
{
	VipsSource *source = VIPS_SOURCE( user );

	while( length > 0 ) {
		gint64 bytes_read;

		bytes_read = vips_source_read( source, dest, length );
		if( bytes_read < 0 )
			return( SPNG_IO_ERROR );
		if( bytes_read == 0 )
			return( SPNG_IO_EOF );

		dest += bytes_read;
		length -= bytes_read;
	}

	return( 0 );
}

static VipsForeignFlags
vips_foreign_load_png_get_flags_source( VipsSource *source )
{
	spng_ctx *ctx;
	struct spng_ihdr ihdr;
	VipsForeignFlags flags;

	ctx = spng_ctx_new( SPNG_CTX_IGNORE_ADLER32 );
	spng_set_crc_action( ctx, SPNG_CRC_USE, SPNG_CRC_USE );
	if( vips_source_rewind( source ) ) 
		return( 0 );
	spng_set_png_stream( ctx, 
		vips_foreign_load_png_stream, source );
	if( spng_get_ihdr( ctx, &ihdr ) ) {
		spng_ctx_free( ctx );
		return( 0 );
	}
	spng_ctx_free( ctx );

	flags = 0;
	if( ihdr.interlace_method != SPNG_INTERLACE_NONE )
		flags |= VIPS_FOREIGN_PARTIAL;
	else
		flags |= VIPS_FOREIGN_SEQUENTIAL;

	return( flags );
}

static VipsForeignFlags
vips_foreign_load_png_get_flags( VipsForeignLoad *load )
{
	VipsForeignLoadPng *png = (VipsForeignLoadPng *) load;

	return( vips_foreign_load_png_get_flags_source( png->source ) );
}

static VipsForeignFlags
vips_foreign_load_png_get_flags_filename( const char *filename )
{
	VipsSource *source;
	VipsForeignFlags flags;

	if( !(source = vips_source_new_from_file( filename )) )
		return( 0 );
	flags = vips_foreign_load_png_get_flags_source( source );
	VIPS_UNREF( source );

	return( flags );
}

/* Set the png text data as metadata on the vips image. These are always
 * null-terminated strings.
 */
static void
vips_foreign_load_png_set_text( VipsImage *out, 
	int i, const char *key, const char *value ) 
{
#ifdef DEBUG
	printf( "vips_foreign_load_png_set_text: key %s, value %s\n", 
		key, value );
#endif /*DEBUG*/

	if( strcmp( key, "XML:com.adobe.xmp" ) == 0 ) {
		/* Save as an XMP tag. This must be a BLOB, for compatibility
		 * for things like the XMP blob that the tiff loader adds.
		 *
		 * Note that this will remove the null-termination from the
		 * string. We must carefully reattach this.
		 */
		vips_image_set_blob_copy( out, 
			VIPS_META_XMP_NAME, value, strlen( value ) );
	}
	else  {
		char name[256];

		/* Save as a string comment. Some PNGs have EXIF data as
		 * text segments, unfortunately.
		 */
		vips_snprintf( name, 256, "png-comment-%d-%s", i, key );

		vips_image_set_string( out, name, value );
	}
}

static int
vips_foreign_load_png_set_header( VipsForeignLoadPng *png, VipsImage *image )
{
	double xres, yres;
	struct spng_iccp iccp;
	struct spng_exif exif;
	struct spng_phys phys;
	struct spng_bkgd bkgd;
	guint32 n_text;

	/* Get resolution. Default to 72 pixels per inch.
	 */
	xres = 72.0 / 25.4;
	yres = 72.0 / 25.4;
	if( !spng_get_phys( png->ctx, &phys ) ) {
		/* unit 1 means pixels per metre, otherwise unspecified.
		 */
		xres = phys.unit_specifier == 1 ? 
			phys.ppu_x / 1000.0 : phys.ppu_x;
		yres = phys.unit_specifier == 1 ? 
			phys.ppu_y / 1000.0 : phys.ppu_y;
	}

	vips_image_init_fields( image,
		png->ihdr.width, png->ihdr.height, png->bands,
		png->format, VIPS_CODING_NONE, png->interpretation, 
		xres, yres );

	VIPS_SETSTR( image->filename, 
		vips_connection_filename( VIPS_CONNECTION( png->source ) ) );

	if( vips_image_pipelinev( image, VIPS_DEMAND_STYLE_THINSTRIP, NULL ) )
		return( -1 );

	if( !spng_get_iccp( png->ctx, &iccp ) ) 
		vips_image_set_blob_copy( image, 
			VIPS_META_ICC_NAME, iccp.profile, iccp.profile_len );

	if( !spng_get_text( png->ctx, NULL, &n_text ) ) {
		struct spng_text *text;

		/* Very large numbers of text chunks are used in DoS
		 * attacks.
		 */
		if( !png->unlimited && n_text > MAX_PNG_TEXT_CHUNKS ) {
			g_warning( _( "%d text chunks, "
				"only %d text chunks will be loaded" ),
				n_text, MAX_PNG_TEXT_CHUNKS );
			n_text = MAX_PNG_TEXT_CHUNKS;
		}

		text = VIPS_ARRAY( VIPS_OBJECT( png ), 
			n_text, struct spng_text );
		if( !spng_get_text( png->ctx, text, &n_text ) ) {
			guint32 i;

			for( i = 0; i < n_text; i++ ) 
				/* .text is always a null-terminated C string.
				 */
				vips_foreign_load_png_set_text( image, 
					i, text[i].keyword, text[i].text );
		}
	}

	if( !spng_get_exif( png->ctx, &exif ) ) 
		vips_image_set_blob_copy( image, VIPS_META_EXIF_NAME, 
			exif.data, exif.length );

	/* Attach original palette bit depth, if any, as metadata.
	 */
	if( png->ihdr.color_type == SPNG_COLOR_TYPE_INDEXED )
		vips_image_set_int( image, 
			"palette-bit-depth", png->ihdr.bit_depth );

	/* Let our caller know. These are very expensive to decode.
	 */
	if( png->ihdr.interlace_method != SPNG_INTERLACE_NONE ) 
		vips_image_set_int( image, "interlaced", 1 ); 

	if( !spng_get_bkgd( png->ctx, &bkgd ) ) {
		const int scale = image->BandFmt == 
			VIPS_FORMAT_UCHAR ? 1 : 256;

		double array[3];
		int n;

		switch( png->ihdr.color_type ) { 
		case SPNG_COLOR_TYPE_GRAYSCALE:
		case SPNG_COLOR_TYPE_GRAYSCALE_ALPHA:
			array[0] = bkgd.gray / scale;
			n = 1;
			break;

		case SPNG_COLOR_TYPE_TRUECOLOR:
		case SPNG_COLOR_TYPE_TRUECOLOR_ALPHA:
			array[0] = bkgd.red / scale;
			array[1] = bkgd.green / scale;
			array[2] = bkgd.blue / scale;
			n = 3;
			break;

		case SPNG_COLOR_TYPE_INDEXED:
		default:
			/* Not sure what to do here. I suppose we should read
			 * the palette.
			 */
			n = 0;
			break;
		}

		if( n > 0 ) 
			vips_image_set_array_double( image, "background", 
				array, n );
	}

	return( 0 );
}

static int
vips_foreign_load_png_header( VipsForeignLoad *load )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( load );
	VipsForeignLoadPng *png = (VipsForeignLoadPng *) load;

	int flags;
	int error;
	struct spng_trns trns;

	/* In non-fail mode, ignore CRC errors.
	 */
	flags = 0;
	if( load->fail_on >= VIPS_FAIL_ON_ERROR )
		flags |= SPNG_CTX_IGNORE_ADLER32;
	png->ctx = spng_ctx_new( flags );
	if( load->fail_on >= VIPS_FAIL_ON_ERROR )
		/* Ignore and don't calculate checksums.
		 */
		spng_set_crc_action( png->ctx, SPNG_CRC_USE, SPNG_CRC_USE );

	/* Set limits to avoid decompression bombs. Set chunk limits to 60mb
	 * -- we've seen 50mb XMP blocks in the wild.
	 *
	 * No need to test the decoded image size -- the user can do that if
	 * they wish.
	 */
	if ( !png->unlimited ) {
		spng_set_image_limits( png->ctx, 
			VIPS_MAX_COORD, VIPS_MAX_COORD );
		spng_set_chunk_limits( png->ctx, 
			60 * 1024 * 1024, 60 * 1024 * 1024 );
	}

	if( vips_source_rewind( png->source ) ) 
		return( -1 );
	spng_set_png_stream( png->ctx, 
		vips_foreign_load_png_stream, png->source );
	if( (error = spng_get_ihdr( png->ctx, &png->ihdr )) ) {
		vips_error( class->nickname, "%s", spng_strerror( error ) ); 
		return( -1 );
	}

#ifdef DEBUG
	printf( "width: %d\nheight: %d\nbit depth: %d\ncolor type: %d\n",
		png->ihdr.width, png->ihdr.height,
		png->ihdr.bit_depth, png->ihdr.color_type );
	printf( "compression method: %d\nfilter method: %d\n"
		"interlace method: %d\n",
		png->ihdr.compression_method, png->ihdr.filter_method,
		png->ihdr.interlace_method );
#endif /*DEBUG*/

	/* Just convert to host-endian if nothing else applies.
	 */ 
	png->fmt = SPNG_FMT_PNG;

	switch( png->ihdr.color_type ) {
	case SPNG_COLOR_TYPE_INDEXED: 
		png->bands = 3; 
		break;

	case SPNG_COLOR_TYPE_GRAYSCALE_ALPHA: 
	case SPNG_COLOR_TYPE_GRAYSCALE: 
		png->bands = 1; 
		break;

	case SPNG_COLOR_TYPE_TRUECOLOR: 
	case SPNG_COLOR_TYPE_TRUECOLOR_ALPHA: 
		png->bands = 3; 
		break;

	default:
		vips_error( class->nickname, "%s", _( "unknown color type" ) );
		return( -1 );
	}

	/* Set libvips format and interpretation.
	 */
	if( png->ihdr.bit_depth > 8 ) {
		if( png->bands < 3 )
			png->interpretation = VIPS_INTERPRETATION_GREY16;
		else
			png->interpretation = VIPS_INTERPRETATION_RGB16;

		png->format = VIPS_FORMAT_USHORT;
	}
	else {
		if( png->bands < 3 )
			png->interpretation = VIPS_INTERPRETATION_B_W;
		else
			png->interpretation = VIPS_INTERPRETATION_sRGB;

		png->format = VIPS_FORMAT_UCHAR;
	}

	/* Expand palette images.
	 */
	if( png->ihdr.color_type == SPNG_COLOR_TYPE_INDEXED )
		png->fmt = SPNG_FMT_RGB8;

	/* Expand <8 bit images to full bytes.
	 */
	if( png->ihdr.color_type == SPNG_COLOR_TYPE_GRAYSCALE &&
		png->ihdr.bit_depth < 8 )
		png->fmt = SPNG_FMT_G8;

	/* Try reading the optional transparency chunk. This will cause all
	 * chunks up to the first IDAT to be read in, so it can fail if any
	 * chunk has an error.
	 */
	error = spng_get_trns( png->ctx, &trns );
	if( error &&
		error != SPNG_ECHUNKAVAIL ) {
		vips_error( class->nickname, "%s", spng_strerror( error ) ); 
		return( -1 );
	}

	/* Expand transparency.
	 *
	 * The _ALPHA types should not have the optional trns chunk (they 
	 * always have a transparent band), see 
	 * https://www.w3.org/TR/2003/REC-PNG-20031110/#11tRNS
	 *
	 * It's quick and safe to call spng_get_trns() again, and we now know 
	 * it will only fail for no transparency chunk.
	 */
	if( png->ihdr.color_type == SPNG_COLOR_TYPE_GRAYSCALE_ALPHA || 
		png->ihdr.color_type == SPNG_COLOR_TYPE_TRUECOLOR_ALPHA ) 
		png->bands += 1;
	else if( !spng_get_trns( png->ctx, &trns ) ) {
		png->bands += 1;

		if( png->ihdr.color_type == SPNG_COLOR_TYPE_TRUECOLOR ) {
			if( png->ihdr.bit_depth == 16 ) 
				png->fmt = SPNG_FMT_RGBA16;
			else 
				png->fmt = SPNG_FMT_RGBA8;
		}
		else if( png->ihdr.color_type == SPNG_COLOR_TYPE_INDEXED ) 
			png->fmt = SPNG_FMT_RGBA8;
		else if( png->ihdr.color_type == SPNG_COLOR_TYPE_GRAYSCALE ) {
			if( png->ihdr.bit_depth == 16 ) 
				png->fmt = SPNG_FMT_GA16;
			else 
				png->fmt = SPNG_FMT_GA8;
		}
	}

	vips_source_minimise( png->source );

	if( vips_foreign_load_png_set_header( png, load->out ) )
		return( -1 );

	return( 0 );
}

static void
vips_foreign_load_png_minimise( VipsObject *object, VipsForeignLoadPng *png )
{
	vips_source_minimise( png->source );
}

static int
vips_foreign_load_png_generate( VipsRegion *or, 
	void *seq, void *a, void *b, gboolean *stop )
{
        VipsRect *r = &or->valid;
	VipsForeignLoad *load = VIPS_FOREIGN_LOAD( a );
	VipsForeignLoadPng *png = (VipsForeignLoadPng *) load;
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( png );

	int y;
	int error;

#ifdef DEBUG
	printf( "vips_foreign_load_png_generate: line %d, %d rows\n", 
		r->top, r->height );
	printf( "vips_foreign_load_png_generate: y_top = %d\n", png->y_pos );
#endif /*DEBUG*/

	/* We're inside a tilecache where tiles are the full image width, so
	 * this should always be true.
	 */
	g_assert( r->left == 0 );
	g_assert( r->width == or->im->Xsize );
	g_assert( VIPS_RECT_BOTTOM( r ) <= or->im->Ysize );

	/* Tiles should always be a strip in height, unless it's the final
	 * strip.
	 */
	g_assert( r->height == VIPS_MIN( VIPS__FATSTRIP_HEIGHT, 
		or->im->Ysize - r->top ) ); 

	/* And check that y_pos is correct. It should be, since we are inside
	 * a vips_sequential().
	 */
	if( r->top != png->y_pos ) {
		vips_error( class->nickname, 
			_( "out of order read at line %d" ), png->y_pos );
		return( -1 );
	}

	for( y = 0; y < r->height; y++ ) {
		/* libspng returns EOI when successfully reading the 
		 * final line of input.
		 */
		error = spng_decode_row( png->ctx, 
			VIPS_REGION_ADDR( or, 0, r->top + y ),
			VIPS_REGION_SIZEOF_LINE( or ) );
		if( error != 0 &&
			error != SPNG_EOI ) { 
			/* We've failed to read some pixels. Knock this 
			 * operation out of cache. 
			 */
			vips_operation_invalidate( VIPS_OPERATION( png ) ); 

#ifdef DEBUG
			printf( "vips_foreign_load_png_generate:\n" ); 
			printf( "  spng_decode_row() failed, line %d\n", 
				r->top + y ); 
			printf( "  thread %p\n", g_thread_self() );
			printf( "  error %s\n", spng_strerror( error ) ); 
#endif /*DEBUG*/

			g_warning( "%s: %s", 
				class->nickname, spng_strerror( error ) );

			/* And bail if trunc is on. 
			 */
			if( load->fail_on >= VIPS_FAIL_ON_TRUNCATED ) {
				vips_error( class->nickname, 
					"%s", _( "libspng read error" ) ); 
				return( -1 );
			}
		}

		png->y_pos += 1;
	}

	return( 0 );
}

static int
vips_foreign_load_png_load( VipsForeignLoad *load )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( load );
	VipsForeignLoadPng *png = (VipsForeignLoadPng *) load;
	VipsImage **t = (VipsImage **) 
		vips_object_local_array( VIPS_OBJECT( load ), 3 );

	enum spng_decode_flags flags;
	int error;

	if( vips_source_decode( png->source ) )
		return( -1 );

	/* Decode transparency, if available.
	 */
	flags = SPNG_DECODE_TRNS;

	if( png->ihdr.interlace_method != SPNG_INTERLACE_NONE ) {
		/* Arg awful interlaced image. We have to load to a huge mem 
		 * buffer, then copy to out.
		 */
		t[0] = vips_image_new_memory();
		if( vips_foreign_load_png_set_header( png, t[0] ) ||
			vips_image_write_prepare( t[0] ) )
			return( -1 );

		if( (error = spng_decode_image( png->ctx, 
			VIPS_IMAGE_ADDR( t[0], 0, 0 ), 
			VIPS_IMAGE_SIZEOF_IMAGE( t[0] ), 
			png->fmt, flags )) ) {
			vips_error( class->nickname, 
				"%s", spng_strerror( error ) ); 
			return( -1 );
		}

		/* We've now finished reading the file.
		 */
		vips_source_minimise( png->source );

		if( vips_image_write( t[0], load->real ) )
			return( -1 );
	}
	else {
		t[0] = vips_image_new();

		if( vips_foreign_load_png_set_header( png, t[0] ) )
			return( -1 );

		/* We can decode these progressively.
		 */
		flags |= SPNG_DECODE_PROGRESSIVE;

		if( (error = spng_decode_image( png->ctx, NULL, 0, 
			png->fmt, flags )) ) {
			vips_error( class->nickname, 
				"%s", spng_strerror( error ) ); 
			return( -1 );
		}

		/* Close input immediately at end of read.
		 */
		g_signal_connect( t[0], "minimise",
			G_CALLBACK( vips_foreign_load_png_minimise ), png );

		if( vips_image_generate( t[0], 
				NULL, vips_foreign_load_png_generate, NULL, 
				png, NULL ) ||
			vips_sequential( t[0], &t[1], 
				"tile_height", VIPS__FATSTRIP_HEIGHT, 
				NULL ) ||
			vips_image_write( t[1], load->real ) )
			return( -1 );
	}

	return( 0 );
}

static void
vips_foreign_load_png_class_init( VipsForeignLoadPngClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->dispose = vips_foreign_load_png_dispose;
	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "pngload_base";
	object_class->description = _( "load png base class" );

	/* We are fast at is_a(), so high priority.
	 */
	foreign_class->priority = 200;

	load_class->get_flags_filename = 
		vips_foreign_load_png_get_flags_filename;
	load_class->get_flags = vips_foreign_load_png_get_flags;
	load_class->header = vips_foreign_load_png_header;
	load_class->load = vips_foreign_load_png_load;

	VIPS_ARG_BOOL( class, "unlimited", 23,
		_( "Unlimited" ),
		_( "Remove all denial of service limits" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignLoadPng, unlimited ),
		FALSE );
}

static void
vips_foreign_load_png_init( VipsForeignLoadPng *png )
{
}

typedef struct _VipsForeignLoadPngSource {
	VipsForeignLoadPng parent_object;

	/* Load from a source.
	 */
	VipsSource *source;

} VipsForeignLoadPngSource;

typedef VipsForeignLoadPngClass VipsForeignLoadPngSourceClass;

G_DEFINE_TYPE( VipsForeignLoadPngSource, vips_foreign_load_png_source, 
	vips_foreign_load_png_get_type() );

static int
vips_foreign_load_png_source_build( VipsObject *object )
{
	VipsForeignLoadPng *png = (VipsForeignLoadPng *) object;
	VipsForeignLoadPngSource *source = (VipsForeignLoadPngSource *) object;

	if( source->source ) {
		png->source = source->source;
		g_object_ref( png->source );
	}

	if( VIPS_OBJECT_CLASS( vips_foreign_load_png_source_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

static gboolean
vips_foreign_load_png_source_is_a_source( VipsSource *source )
{
	static unsigned char signature[8] = { 137, 80, 78, 71, 13, 10, 26, 10 };

	const unsigned char *p;

	if( (p = vips_source_sniff( source, 8 )) &&
		memcmp( p, signature, 8 ) == 0 )
		return( TRUE ); 

	return( FALSE ); 
}

static void
vips_foreign_load_png_source_class_init( VipsForeignLoadPngSourceClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsOperationClass *operation_class = VIPS_OPERATION_CLASS( class );
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "pngload_source";
	object_class->description = _( "load png from source" );
	object_class->build = vips_foreign_load_png_source_build;

	operation_class->flags |= VIPS_OPERATION_NOCACHE;

	load_class->is_a_source = vips_foreign_load_png_source_is_a_source;

	VIPS_ARG_OBJECT( class, "source", 1,
		_( "Source" ),
		_( "Source to load from" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignLoadPngSource, source ),
		VIPS_TYPE_SOURCE );

}

static void
vips_foreign_load_png_source_init( VipsForeignLoadPngSource *source )
{
}

typedef struct _VipsForeignLoadPngFile {
	VipsForeignLoadPng parent_object;

	/* Filename for load.
	 */
	char *filename; 

} VipsForeignLoadPngFile;

typedef VipsForeignLoadPngClass VipsForeignLoadPngFileClass;

G_DEFINE_TYPE( VipsForeignLoadPngFile, vips_foreign_load_png_file, 
	vips_foreign_load_png_get_type() );

static int
vips_foreign_load_png_file_build( VipsObject *object )
{
	VipsForeignLoadPng *png = (VipsForeignLoadPng *) object;
	VipsForeignLoadPngFile *file = (VipsForeignLoadPngFile *) object;

	if( file->filename &&
		!(png->source = vips_source_new_from_file( file->filename )) )
		return( -1 );

	if( VIPS_OBJECT_CLASS( vips_foreign_load_png_file_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

static gboolean
vips_foreign_load_png_file_is_a( const char *filename )
{
	VipsSource *source;
	gboolean result;

	if( !(source = vips_source_new_from_file( filename )) )
		return( FALSE );
	result = vips_foreign_load_png_source_is_a_source( source );
	VIPS_UNREF( source );

	return( result );
}

const char *vips_foreign_load_png_file_suffs[] = { ".png", NULL };

static void
vips_foreign_load_png_file_class_init( VipsForeignLoadPngFileClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "pngload";
	object_class->description = _( "load png from file" );
	object_class->build = vips_foreign_load_png_file_build;

	foreign_class->suffs = vips_foreign_load_png_file_suffs;

	load_class->is_a = vips_foreign_load_png_file_is_a;

	VIPS_ARG_STRING( class, "filename", 1, 
		_( "Filename" ),
		_( "Filename to load from" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignLoadPngFile, filename ),
		NULL );
}

static void
vips_foreign_load_png_file_init( VipsForeignLoadPngFile *file )
{
}

typedef struct _VipsForeignLoadPngBuffer {
	VipsForeignLoadPng parent_object;

	/* Load from a buffer.
	 */
	VipsBlob *blob;

} VipsForeignLoadPngBuffer;

typedef VipsForeignLoadPngClass VipsForeignLoadPngBufferClass;

G_DEFINE_TYPE( VipsForeignLoadPngBuffer, vips_foreign_load_png_buffer, 
	vips_foreign_load_png_get_type() );

static int
vips_foreign_load_png_buffer_build( VipsObject *object )
{
	VipsForeignLoadPng *png = (VipsForeignLoadPng *) object;
	VipsForeignLoadPngBuffer *buffer = (VipsForeignLoadPngBuffer *) object;

	if( buffer->blob &&
		!(png->source = vips_source_new_from_memory( 
			VIPS_AREA( buffer->blob )->data, 
			VIPS_AREA( buffer->blob )->length )) )
		return( -1 );

	if( VIPS_OBJECT_CLASS( vips_foreign_load_png_buffer_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

static gboolean
vips_foreign_load_png_buffer_is_a_buffer( const void *buf, size_t len )
{
	VipsSource *source;
	gboolean result;

	if( !(source = vips_source_new_from_memory( buf, len )) )
		return( FALSE );
	result = vips_foreign_load_png_source_is_a_source( source );
	VIPS_UNREF( source );

	return( result );
}

static void
vips_foreign_load_png_buffer_class_init( VipsForeignLoadPngBufferClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "pngload_buffer";
	object_class->description = _( "load png from buffer" );
	object_class->build = vips_foreign_load_png_buffer_build;

	load_class->is_a_buffer = vips_foreign_load_png_buffer_is_a_buffer;

	VIPS_ARG_BOXED( class, "buffer", 1, 
		_( "Buffer" ),
		_( "Buffer to load from" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignLoadPngBuffer, blob ),
		VIPS_TYPE_BLOB );

}

static void
vips_foreign_load_png_buffer_init( VipsForeignLoadPngBuffer *buffer )
{
}

#endif /*HAVE_SPNG*/
