/* read with libwebp
 *
 * 6/8/13
 * 	- from png2vips.c
 * 24/2/14
 * 	- oops, buffer path was broken, thanks Lovell
 * 28/2/16
 * 	- add @shrink
 * 7/11/16
 * 	- support XMP/ICC/EXIF metadata
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

#ifdef HAVE_LIBWEBP

#include <stdlib.h>
#include <string.h>

#include <webp/decode.h>
#ifdef HAVE_LIBWEBPMUX
#include <webp/mux.h>
#endif /*HAVE_LIBWEBPMUX*/

#include <vips/vips.h>
#include <vips/internal.h>

#include "pforeign.h"

/* How many bytes do we need to read from the start of the file to be able to
 * validate the header?
 *
 * This doesn't seem to be documented anywhere :-( guess a value.
 */
#define MINIMAL_HEADER (100)

/* What we track during a read.
 */
typedef struct {
	/* File source.
	 */
	char *filename;

	/* Memory source. We use gint64 rather than size_t since we use
	 * vips_file_length() and vips__mmap() for file sources.
	 */
	const void *data;
	gint64 length;

	/* Shrink-on-load factor. Use this to set scaled_width.
	 */
	int shrink;

	/* Size we are decoding to.
	 */
	int width;
	int height;

	/* If we are opening a file object, the fd.
	 */
	int fd;

	/* Decoder config.
	 */
	WebPDecoderConfig config;

	/* Incremental decoder state.
	 */
	WebPIDecoder *idec;
} Read;

int
vips__iswebp_buffer( const void *buf, size_t len )
{
	if( len >= MINIMAL_HEADER &&
		WebPGetInfo( buf, MINIMAL_HEADER, NULL, NULL ) )
		return( 1 );

	return( 0 );
}

int
vips__iswebp( const char *filename )
{
	unsigned char header[MINIMAL_HEADER];

	if( vips__get_bytes( filename, header, MINIMAL_HEADER ) &&
		vips__iswebp_buffer( header, MINIMAL_HEADER ) )
		return( 1 );

	return( 0 );
}

static int
read_free( Read *read )
{
	VIPS_FREEF( WebPIDelete, read->idec );
	WebPFreeDecBuffer( &read->config.output );

	if( read->fd > 0 &&
		read->data &&
		read->length > 0 ) { 
		vips__munmap( read->data, read->length ); 
		read->data = NULL;
		read->length = 0;
	}

	VIPS_FREEF( vips_tracked_close, read->fd ); 
	VIPS_FREE( read->filename );
	VIPS_FREE( read );

	return( 0 );
}

static Read *
read_new( const char *filename, const void *data, size_t length, int shrink )
{
	Read *read;

	if( !(read = VIPS_NEW( NULL, Read )) )
		return( NULL );

	read->filename = g_strdup( filename );
	read->data = data;
	read->length = length;
	read->shrink = shrink;
	read->fd = 0;
	read->idec = NULL;

	if( read->filename ) { 
		/* libwebp makes streaming from a file source very hard. We 
		 * have to read to a full memory buffer, then copy to out.
		 *
		 * mmap the input file, it's slightly quicker.
		 */
		if( (read->fd = vips__open_image_read( read->filename )) < 0 ||
			(read->length = vips_file_length( read->fd )) < 0 ||
			!(read->data = vips__mmap( read->fd, 
				FALSE, read->length, 0 )) ) {
			read_free( read );
			return( NULL );
		}
	}

	WebPInitDecoderConfig( &read->config );
	if( WebPGetFeatures( read->data, MINIMAL_HEADER, 
		&read->config.input ) != VP8_STATUS_OK ) {
		read_free( read );
		return( NULL );
	}

	if( read->config.input.has_alpha )
		read->config.output.colorspace = MODE_RGBA;
	else
		read->config.output.colorspace = MODE_RGB;

	read->config.options.use_threads = 1;

	read->width = VIPS_RINT( (float) read->config.input.width / read->shrink );
	read->height = VIPS_RINT( (float) read->config.input.height / read->shrink );

	if( read->width == 0 ||
		read->height == 0 ) {
		vips_error( "webp", "%s", _( "bad setting for shrink" ) ); 
		return( NULL ); 
	}

	if( read->shrink > 1 ) { 
		read->config.options.use_scaling = 1;
		read->config.options.scaled_width = read->width;
		read->config.options.scaled_height = read->height; 
	}

	return( read );
}

/* Map vips metadata names to webp names.
 */
const VipsWebPNames vips__webp_names[] = {
	{ VIPS_META_ICC_NAME, "ICCP", 0x20 },
	{ VIPS_META_XMP_NAME, "XMP ", 0x04 },
	{ VIPS_META_EXIF_NAME, "EXIF", 0x08 }
};
const int vips__n_webp_names = VIPS_NUMBER( vips__webp_names ); 

static int
read_header( Read *read, VipsImage *out )
{
	vips_image_init_fields( out,
		read->width, read->height,
		read->config.input.has_alpha ? 4 : 3,
		VIPS_FORMAT_UCHAR, VIPS_CODING_NONE,
		VIPS_INTERPRETATION_sRGB,
		1.0, 1.0 );

	vips_image_pipelinev( out, VIPS_DEMAND_STYLE_THINSTRIP, NULL );

#ifdef HAVE_LIBWEBPMUX
{
	WebPData bitstream;
	WebPMux *mux;
	int i;

	/* We have to parse the whole file again to get the metadata out.
	 *
	 * Don't make parse failure an error. We don't want to refuse to read
	 * any pixels because of some malformed metadata.
	 */
	bitstream.bytes = read->data;
	bitstream.size = read->length;
	if( !(mux = WebPMuxCreate( &bitstream, 0 )) ) {
		vips_warn( "webp", "%s", _( "unable to read image metadata" ) ); 
		return( 0 ); 
	}

	for( i = 0; i < vips__n_webp_names; i++ ) { 
		const char *vips = vips__webp_names[i].vips;
		const char *webp = vips__webp_names[i].webp;

		WebPData data;

		if( WebPMuxGetChunk( mux, webp, &data ) == WEBP_MUX_OK ) { 
			void *blob;

			if( !(blob = vips_malloc( NULL, data.size )) ) {
				WebPMuxDelete( mux ); 
				return( -1 ); 
			}

			memcpy( blob, data.bytes, data.size );
			vips_image_set_blob( out, vips, 
				(VipsCallbackFn) vips_free, blob, data.size );
		}
	}

	WebPMuxDelete( mux ); 

	/* We may have read some exif ... parse into the header.
	 */
	if( vips__exif_parse( out ) )
		return( -1 ); 
}
#endif /*HAVE_LIBWEBPMUX*/

	return( 0 );
}

int
vips__webp_read_file_header( const char *filename, VipsImage *out, int shrink ) 
{
	Read *read;

	if( !(read = read_new( filename, NULL, 0, shrink )) ) {
		vips_error( "webp2vips",
			_( "unable to open \"%s\"" ), filename ); 
		return( -1 );
	}

	if( read_header( read, out ) ) {
		read_free( read );
		return( -1 );
	}

	read_free( read );

	return( 0 );
}

static int
read_image( Read *read, VipsImage *out )
{
	VipsImage **t = (VipsImage **) 
		vips_object_local_array( VIPS_OBJECT( out ), 3 );

	t[0] = vips_image_new_memory();
	if( read_header( read, t[0] ) )
		return( -1 );
	if( vips_image_write_prepare( t[0] ) ) 
		return( -1 );

	read->config.output.u.RGBA.rgba = VIPS_IMAGE_ADDR( t[0], 0, 0 );
	read->config.output.u.RGBA.stride = VIPS_IMAGE_SIZEOF_LINE( t[0] );
	read->config.output.u.RGBA.size = VIPS_IMAGE_SIZEOF_IMAGE( t[0] );
	read->config.output.is_external_memory = 1;

	if( WebPDecode( (uint8_t *) read->data, read->length, 
		&read->config) != VP8_STATUS_OK ) {
		vips_error( "webp2vips", "%s", _( "unable to read pixels" ) ); 
		return( -1 );
	}

	if( vips_image_write( t[0], out ) )
		return( -1 );

	return( 0 );
}

int
vips__webp_read_file( const char *filename, VipsImage *out, int shrink ) 
{
	Read *read;

	if( !(read = read_new( filename, NULL, 0, shrink )) ) {
		vips_error( "webp2vips",
			_( "unable to open \"%s\"" ), filename ); 
		return( -1 );
	}

	if( read_image( read, out ) )
		return( -1 );

	read_free( read );

	return( 0 );
}

int
vips__webp_read_buffer_header( const void *buf, size_t len, VipsImage *out,
	int shrink ) 
{
	Read *read;

	if( !(read = read_new( NULL, buf, len, shrink )) ) {
		vips_error( "webp2vips",
			"%s", _( "unable to open buffer" ) ); 
		return( -1 );
	}

	if( read_header( read, out ) ) {
		read_free( read );
		return( -1 );
	}

	read_free( read );

	return( 0 );
}

int
vips__webp_read_buffer( const void *buf, size_t len, VipsImage *out, 
	int shrink ) 
{
	Read *read;

	if( !(read = read_new( NULL, buf, len, shrink )) ) {
		vips_error( "webp2vips",
			"%s", _( "unable to open buffer" ) ); 
		return( -1 );
	}

	if( read_image( read, out ) )
		return( -1 );

	read_free( read );

	return( 0 );
}

#endif /*HAVE_LIBWEBP*/
