/* read with libwebp
 *
 * 6/8/13
 * 	- from png2vips.c
 * 24/2/14
 * 	- oops, buffer path was broken, thanks Lovell
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

#ifdef HAVE_LIBWEBP

#include <stdlib.h>
#include <string.h>

#include <webp/decode.h>

#include <vips/vips.h>
#include <vips/internal.h>

#include "webp.h"

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
		vips__munmap( (void *) read->data, read->length ); 
		read->data = NULL;
		read->length = 0;
	}

	VIPS_FREEF( vips_tracked_close, read->fd ); 
	VIPS_FREE( read->filename );
	VIPS_FREE( read );

	return( 0 );
}

static Read *
read_new( const char *filename, const void *data, size_t length )
{
	Read *read;

	if( !(read = VIPS_NEW( NULL, Read )) )
		return( NULL );

	read->filename = g_strdup( filename );
	read->data = data;
	read->length = length;
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
	read->config.options.use_threads = TRUE;

	return( read );
}

static int
read_header( Read *read, VipsImage *out )
{
	vips_image_init_fields( out,
		read->config.input.width, read->config.input.height,
		read->config.input.has_alpha ? 4 : 3,
		VIPS_FORMAT_UCHAR, VIPS_CODING_NONE,
		VIPS_INTERPRETATION_sRGB,
		1.0, 1.0 );

	vips_image_pipelinev( out, VIPS_DEMAND_STYLE_THINSTRIP, NULL );

	return( 0 );
}

int
vips__webp_read_file_header( const char *filename, VipsImage *out ) 
{
	Read *read;

	if( !(read = read_new( filename, NULL, 0 )) ) {
		vips_error( "webp2vips",
			_( "unable to open \"%s\"" ), filename ); 
		return( -1 );
	}

	if( read_header( read, out ) )
		return( -1 );

	read_free( read );

	return( 0 );
}

typedef uint8_t *(*webp_decoder)( const uint8_t* data, size_t data_size,
	   uint8_t* output_buffer, size_t output_buffer_size, 
	   int output_stride );

static int
read_image( Read *read, VipsImage *out )
{
	VipsImage **t = (VipsImage **) 
		vips_object_local_array( VIPS_OBJECT( out ), 3 );
	webp_decoder decoder;

	t[0] = vips_image_new_memory();
	if( read_header( read, t[0] ) )
		return( -1 );
	if( vips_image_write_prepare( t[0] ) ) 
		return( -1 );

	if( t[0]->Bands == 3 )
		decoder = WebPDecodeRGBInto;
	else
		decoder = WebPDecodeRGBAInto;

	if( !decoder( (uint8_t *) read->data, read->length, 
		VIPS_IMAGE_ADDR( t[0], 0, 0 ), 
		VIPS_IMAGE_SIZEOF_IMAGE( t[0] ),
		VIPS_IMAGE_SIZEOF_LINE( t[0] ) ) ) { 
		vips_error( "webp2vips", "%s", _( "unable to read pixels" ) ); 
		return( -1 );
	}

	if( vips_image_write( t[0], out ) )
		return( -1 );

	return( 0 );
}

int
vips__webp_read_file( const char *filename, VipsImage *out ) 
{
	Read *read;

	if( !(read = read_new( filename, NULL, 0 )) ) {
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
vips__webp_read_buffer_header( const void *buf, size_t len, VipsImage *out ) 
{
	Read *read;

	if( !(read = read_new( NULL, buf, len )) ) {
		vips_error( "webp2vips",
			"%s", _( "unable to open buffer" ) ); 
		return( -1 );
	}

	if( read_header( read, out ) )
		return( -1 );

	read_free( read );

	return( 0 );
}

int
vips__webp_read_buffer( const void *buf, size_t len, VipsImage *out ) 
{
	Read *read;

	if( !(read = read_new( NULL, buf, len )) ) {
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
