/* load PNG with libspng
 *
 * 5/12/11
 * 	- from pngload.c
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

/* Notes:
 *
 * an enum for interlace_method would be nice ... ADAM7 == 1, 
 *   no interlace == 0.
 * an equivalent of png_sig_cmp() from libpng (is_a_png on a memory area)
 */

/*
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

	spng_ctx *ctx;
	struct spng_ihdr ihdr;
	struct spng_trns trns;
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

/* libspng read callbacks should copy length bytes to dest and return 0 
 * or SPNG_IO_EOF/SPNG_IO_ERROR on error.
 */
static int 
vips_foreign_load_png_stream( spng_ctx *ctx, void *user, 
	void *dest, size_t length )
{
	VipsSource *source = VIPS_SOURCE( user );

	gint64 bytes_read;

	bytes_read = vips_source_read( source, dest, length );
	if( bytes_read < 0 )
		return( SPNG_IO_ERROR );
	if( bytes_read < length )
		return( SPNG_IO_EOF);

	return( 0 );
}

static VipsForeignFlags
vips_foreign_load_png_get_flags_source( VipsSource *source )
{
	spng_ctx *ctx;
	struct spng_ihdr ihdr;
	VipsForeignFlags flags;

	ctx = spng_ctx_new( 0 );
	spng_set_crc_action( ctx, SPNG_CRC_USE, SPNG_CRC_USE );
	spng_set_png_stream( ctx, 
		vips_foreign_load_png_stream, source );
	if( spng_get_ihdr( ctx, &ihdr ) ) {
		spng_ctx_free( ctx );
		return( 0 );
	}
	spng_ctx_free( ctx );

	flags = 0;
	if( ihdr.interlace_method != 0 )
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

static void
vips_foreign_load_png_set_header( VipsForeignLoadPng *png, VipsImage *image )
{
	vips_image_init_fields( image,
		png->ihdr.width, png->ihdr.height, png->bands,
		png->format, VIPS_CODING_NONE, png->interpretation, 
		1.0, 1.0 );
	VIPS_SETSTR( image->filename, 
		vips_connection_filename( VIPS_CONNECTION( png->source ) ) );

	/* 0 is no interlace.
	 */
	if( png->ihdr.interlace_method == 0 ) 
		/* Sequential mode needs thinstrip to work with things like
		 * vips_shrink().
		 */
		vips_image_pipelinev( image, 
			VIPS_DEMAND_STYLE_THINSTRIP, NULL );
	else 
		/* Interlaced images are read via a huge memory buffer.
		 */
		vips_image_pipelinev( image, VIPS_DEMAND_STYLE_ANY, NULL );
}

static int
vips_foreign_load_png_header( VipsForeignLoad *load )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( load );
	VipsForeignLoadPng *png = (VipsForeignLoadPng *) load;

	int flags;
	int error;

	/* In non-fail mode, ignore CRC errors.
	 */
	flags = 0;
	if( !load->fail )
		flags |= SPNG_CTX_IGNORE_ADLER32;
	png->ctx = spng_ctx_new( flags );
	if( !load->fail )
		/* Ignore and don't calculate checksums.
		 */
		spng_set_crc_action( png->ctx, SPNG_CRC_USE, SPNG_CRC_USE );

	if( vips_source_rewind( png->source ) ) 
		return( -1 );
	spng_set_png_stream( png->ctx, 
		vips_foreign_load_png_stream, png->source );
	if( (error = spng_get_ihdr( png->ctx, &png->ihdr )) ) {
		vips_error( class->nickname, "%s", spng_strerror( error ) ); 
		return( -1 );
	}

	/*
	printf( "width: %d\nheight: %d\nbit depth: %d\ncolor type: %d\n",
		png->ihdr.width, png->ihdr.height,
		png->ihdr.bit_depth, png->ihdr.color_type );
	printf( "compression method: %d\nfilter method: %d\n"
		"interlace method: %d\n",
		png->ihdr.compression_method, png->ihdr.filter_method,
		png->ihdr.interlace_method );
	 */

	/* For now, libspng always outputs RGBA.
	 */
	png->interpretation = VIPS_INTERPRETATION_sRGB;
	png->bands = 4;

	if( png->ihdr.bit_depth == 16 ) {
		png->fmt = SPNG_FMT_RGBA16;
		png->format = VIPS_FORMAT_USHORT;
		if( png->interpretation == VIPS_INTERPRETATION_B_W )
			png->interpretation = VIPS_INTERPRETATION_GREY16;
		if( png->interpretation == VIPS_INTERPRETATION_sRGB )
			png->interpretation = VIPS_INTERPRETATION_RGB16;
	}
	else {
		png->fmt = SPNG_FMT_RGBA8;
		png->format = VIPS_FORMAT_UCHAR;
	}

	/* FIXME ... get resolution, profile, exif, xmp, etc. etc.
	 */

	vips_source_minimise( png->source );

	vips_foreign_load_png_set_header( png, load->out );

	return( 0 );
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
		error = spng_decode_row( png->ctx, 
			VIPS_REGION_ADDR( or, 0, r->top + y ),
			VIPS_REGION_SIZEOF_LINE( or ) );
		/* libspng returns EOI when successfully reading the 
		 * final line of input.
		 */
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

			/* And bail if fail is on. We have to add an error
			 * message, since the handler we install just does
			 * g_warning().
			 */
			if( load->fail ) {
				vips_error( class->nickname, 
					"%s", _( "libpng read error" ) ); 
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

	int error;

	if( vips_source_decode( png->source ) )
		return( -1 );

	if( png->ihdr.interlace_method != 0 ) {
		/* Arg awful interlaced image. We have to load to a huge mem 
		 * buffer, then copy to out.
		 */
		t[0] = vips_image_new_memory();
		vips_foreign_load_png_set_header( png, t[0] );
		if( vips_image_write_prepare( t[0] ) )
			return( -1 );

		if( (error = spng_decode_image( png->ctx, 
			VIPS_IMAGE_ADDR( t[0], 0, 0 ), 
			VIPS_IMAGE_SIZEOF_IMAGE( t[0] ), 
			png->fmt, 0 )) ) {
			vips_error( class->nickname, 
				"%s", spng_strerror( error ) ); 
			return( -1 );
		}

		if( vips_image_write( t[0], load->real ) )
			return( -1 );
	}
	else {
		t[0] = vips_image_new();
		vips_foreign_load_png_set_header( png, t[0] );

		/* Initialize for progressive decoding.
		 */
		if( (error = spng_decode_image( png->ctx, NULL, 0, 
			png->fmt, SPNG_DECODE_PROGRESSIVE )) ) {
			vips_error( class->nickname, 
				"%s", spng_strerror( error ) ); 
			return( -1 );
		}

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
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "pngload_source";
	object_class->description = _( "load png from source" );
	object_class->build = vips_foreign_load_png_source_build;

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
